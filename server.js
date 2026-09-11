// ============================================================
// SOCIAL SYNC - LIVE INTELLIGENCE BACKEND
// SIH 2026
// Backend-only upgrade
//
// Sources:
//   1. Google Trends RSS
//   2. Google News RSS
//   3. CISA Known Exploited Vulnerabilities
//   4. CISA Cybersecurity Advisories
//   5. CERT-EU Security Advisories
//   6. FIRST EPSS
//
// Removed:
//   - Reddit
//   - NVD
//
// No frontend changes required.
// ============================================================

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";

const ROOT_DIR = __dirname;
const STATIC_DIR = path.join(ROOT_DIR, "static");
const INDEX_FILE = path.join(ROOT_DIR, "index.html");

const REFRESH_INTERVAL = 2 * 60 * 1000;

// ------------------------------------------------------------
// SOURCE CONFIGURATION
// ------------------------------------------------------------

const SOURCES = {
    trends: {
        name: "Google Trends",
        type: "trend",
        url: "https://trends.google.com/trending/rss?geo=IN"
    },

    news: {
        name: "Google News",
        type: "news"
    },

    cisaKev: {
        name: "CISA KEV",
        type: "vulnerability",
        url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    },

    cisaAdvisories: {
        name: "CISA Cybersecurity Advisories",
        type: "advisory",
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories?feed=rss"
    },

    certEu: {
        name: "CERT-EU Security Advisories",
        type: "advisory",
        url: "https://www.cert.europa.eu/publications/security-advisories/2026"
    },

    epss: {
        name: "FIRST EPSS",
        type: "risk",
        url: "https://api.first.org/data/v1/epss"
    }
};

// ------------------------------------------------------------
// RUNTIME STATE
// ------------------------------------------------------------

let intelligence = {
    updatedAt: null,

    trends: [],
    threats: [],
    vulnerabilities: [],
    advisories: [],
    evidence: [],
    predictions: [],

    sourceStatus: {
        "Google Trends": "starting",
        "Google News": "starting",
        "CISA KEV": "starting",
        "CISA Cybersecurity Advisories": "starting",
        "CERT-EU Security Advisories": "starting",
        "FIRST EPSS": "starting"
    },

    sourceErrors: {},

    metrics: {
        trendSignals: 0,
        threatSignals: 0,
        vulnerabilitySignals: 0,
        advisorySignals: 0,
        predictionSignals: 0
    }
};

let previousSnapshot = null;
let history = [];

const subscribers = new Set();

// ------------------------------------------------------------
// HTTP HELPERS
// ------------------------------------------------------------

function fetchUrl(url, options = {}) {
    return new Promise((resolve, reject) => {
        const request = https.get(
            url,
            {
                headers: {
                    "User-Agent":
                        "Social-Sync-SIH2026/1.0 cybersecurity-intelligence-dashboard",
                    "Accept":
                        options.accept ||
                        "application/json, application/rss+xml, application/xml, text/html;q=0.9, */*;q=0.8"
                },
                timeout: options.timeout || 15000
            },
            (response) => {
                let body = "";

                response.setEncoding("utf8");

                response.on("data", chunk => {
                    body += chunk;
                });

                response.on("end", () => {
                    if (response.statusCode >= 200 && response.statusCode < 300) {
                        resolve({
                            statusCode: response.statusCode,
                            headers: response.headers,
                            body
                        });
                    } else {
                        reject(
                            new Error(
                                `HTTP ${response.statusCode} from ${url}`
                            )
                        );
                    }
                });
            }
        );

        request.on("timeout", () => {
            request.destroy(new Error(`Timeout: ${url}`));
        });

        request.on("error", reject);
    });
}

function safeJson(text) {
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function nowISO() {
    return new Date().toISOString();
}

function cleanText(value, max = 500) {
    if (!value) return "";

    return String(value)
        .replace(/<[^>]*>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, max);
}

function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ------------------------------------------------------------
// XML / RSS PARSING
// ------------------------------------------------------------

function getXmlItems(xml) {
    const items = [];
    const matches = xml.match(/<item[\s\S]*?<\/item>/gi) || [];

    for (const item of matches) {
        const title =
            getXmlTag(item, "title") ||
            getXmlTag(item, "name");

        const link =
            getXmlTag(item, "link") ||
            getXmlTag(item, "guid");

        const description =
            getXmlTag(item, "description") ||
            getXmlTag(item, "summary");

        const pubDate =
            getXmlTag(item, "pubDate") ||
            getXmlTag(item, "published") ||
            getXmlTag(item, "updated");

        if (title) {
            items.push({
                title: cleanText(title),
                link: cleanText(link, 1000),
                description: cleanText(description),
                pubDate: cleanText(pubDate)
            });
        }
    }

    return items;
}

function getXmlTag(xml, tag) {
    const regex = new RegExp(
        `<${escapeRegex(tag)}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${escapeRegex(tag)}>`,
        "i"
    );

    const match = xml.match(regex);

    return match ? match[1].trim() : "";
}

// ------------------------------------------------------------
// GOOGLE TRENDS
// ------------------------------------------------------------

async function fetchGoogleTrends() {
    try {
        const response = await fetchUrl(SOURCES.trends.url, {
            timeout: 12000
        });

        const items = getXmlItems(response.body);

        const results = items.slice(0, 30).map((item, index) => ({
            id: `TREND-${index + 1}`,
            keyword: item.title,
            title: item.title,
            traffic: null,
            source: "Google Trends",
            region: "IN",
            observedAt: nowISO(),
            link: item.link || null,
            description: item.description || ""
        }));

        intelligence.sourceStatus["Google Trends"] = "available";
        delete intelligence.sourceErrors["Google Trends"];

        return results;
    } catch (error) {
        intelligence.sourceStatus["Google Trends"] = "unavailable";
        intelligence.sourceErrors["Google Trends"] = error.message;

        return [];
    }
}

// ------------------------------------------------------------
// GOOGLE NEWS
// ------------------------------------------------------------

const NEWS_QUERIES = [
    "social media phishing",
    "social media scam",
    "social media malware",
    "social media bot attack",
    "social media disinformation",
    "cyber attack social media",
    "account takeover social media",
    "credential theft social media"
];

async function fetchGoogleNews() {
    const all = [];

    for (const query of NEWS_QUERIES) {
        try {
            const url =
                "https://news.google.com/rss/search?q=" +
                encodeURIComponent(query) +
                "&hl=en-IN&gl=IN&ceid=IN:en";

            const response = await fetchUrl(url, {
                timeout: 12000
            });

            const items = getXmlItems(response.body);

            for (const item of items.slice(0, 12)) {
                all.push({
                    id: `NEWS-${sha256(item.title).slice(0, 12)}`,
                    title: item.title,
                    description: item.description,
                    link: item.link,
                    publishedAt: item.pubDate || null,
                    source: "Google News",
                    query,
                    category: classifyThreat(
                        `${item.title} ${item.description}`
                    )
                });
            }
        } catch (error) {
            // Continue with other queries.
        }
    }

    const unique = new Map();

    for (const item of all) {
        unique.set(item.title.toLowerCase(), item);
    }

    const results = Array.from(unique.values())
        .slice(0, 80);

    if (results.length > 0) {
        intelligence.sourceStatus["Google News"] = "available";
        delete intelligence.sourceErrors["Google News"];
    } else {
        intelligence.sourceStatus["Google News"] = "unavailable";
        intelligence.sourceErrors["Google News"] =
            "No news items returned";
    }

    return results;
}

// ------------------------------------------------------------
// CISA KEV
// ------------------------------------------------------------

async function fetchCisaKev() {
    try {
        const response = await fetchUrl(SOURCES.cisaKev.url, {
            timeout: 15000,
            accept: "application/json"
        });

        const data = safeJson(response.body);

        if (!data || !Array.isArray(data.vulnerabilities)) {
            throw new Error("Invalid CISA KEV response");
        }

        const results = data.vulnerabilities
            .slice(-100)
            .reverse()
            .map((item, index) => ({
                id:
                    item.cveID ||
                    `CISA-KEV-${index + 1}`,

                cve:
                    item.cveID ||
                    null,

                vendor:
                    item.vendorProject ||
                    "Unknown",

                product:
                    item.product ||
                    "Unknown",

                vulnerability:
                    item.vulnerabilityName ||
                    "Known exploited vulnerability",

                description:
                    item.shortDescription ||
                    "",

                dateAdded:
                    item.dateAdded ||
                    null,

                dueDate:
                    item.dueDate ||
                    null,

                knownRansomware:
                    item.knownRansomwareUse ||
                    "Unknown",

                source:
                    "CISA KEV",

                risk:
                    "HIGH",

                type:
                    "Known Exploited Vulnerability"
            }));

        intelligence.sourceStatus["CISA KEV"] = "available";
        delete intelligence.sourceErrors["CISA KEV"];

        return results;
    } catch (error) {
        intelligence.sourceStatus["CISA KEV"] = "unavailable";
        intelligence.sourceErrors["CISA KEV"] = error.message;

        return [];
    }
}

// ------------------------------------------------------------
// CISA CYBERSECURITY ADVISORIES
// ------------------------------------------------------------

async function fetchCisaAdvisories() {
    try {
        const response = await fetchUrl(
            SOURCES.cisaAdvisories.url,
            {
                timeout: 15000,
                accept:
                    "application/rss+xml, application/xml, text/xml, */*"
            }
        );

        const items = getXmlItems(response.body);

        const results = items
            .slice(0, 50)
            .map((item, index) => ({
                id:
                    `CISA-ADV-${sha256(
                        item.title + item.pubDate
                    ).slice(0, 12)}`,

                title: item.title,

                description:
                    item.description ||
                    "CISA cybersecurity advisory",

                publishedAt:
                    item.pubDate ||
                    null,

                link:
                    item.link ||
                    "https://www.cisa.gov/news-events/cybersecurity-advisories",

                source:
                    "CISA Cybersecurity Advisories",

                category:
                    classifyThreat(
                        `${item.title} ${item.description}`
                    ),

                severity:
                    calculateAdvisorySeverity(item.title)
            }));

        if (results.length === 0) {
            throw new Error("No CISA advisory records returned");
        }

        intelligence.sourceStatus[
            "CISA Cybersecurity Advisories"
        ] = "available";

        delete intelligence.sourceErrors[
            "CISA Cybersecurity Advisories"
        ];

        return results;
    } catch (error) {
        intelligence.sourceStatus[
            "CISA Cybersecurity Advisories"
        ] = "unavailable";

        intelligence.sourceErrors[
            "CISA Cybersecurity Advisories"
        ] = error.message;

        return [];
    }
}

// ------------------------------------------------------------
// CERT-EU SECURITY ADVISORIES
// ------------------------------------------------------------

async function fetchCertEuAdvisories() {
    try {
        const response = await fetchUrl(
            SOURCES.certEu.url,
            {
                timeout: 15000,
                accept:
                    "text/html, application/xhtml+xml, */*"
            }
        );

        const html = response.body;

        const results = [];

        // CERT-EU pages expose advisory headings such as:
        // 2026-012: Critical Vulnerabilities in Check Point Products

        const regex =
            /(\d{4}-\d{3}):\s*([^<\n]{10,250})/g;

        let match;

        while (
            (match = regex.exec(html)) !== null &&
            results.length < 40
        ) {
            const advisoryId = match[1];
            const title = cleanText(match[2]);

            if (!title) continue;

            results.push({
                id:
                    `CERT-EU-${advisoryId}`,

                advisoryId,

                title,

                description:
                    "CERT-EU public security advisory",

                publishedAt:
                    null,

                link:
                    `https://www.cert.europa.eu/publications/security-advisories/${advisoryId}/`,

                source:
                    "CERT-EU Security Advisories",

                category:
                    classifyThreat(title),

                severity:
                    calculateAdvisorySeverity(title)
            });
        }

        // Remove duplicates.
        const unique = new Map();

        for (const item of results) {
            unique.set(item.id, item);
        }

        const finalResults =
            Array.from(unique.values());

        if (finalResults.length === 0) {
            throw new Error(
                "No CERT-EU advisory records parsed"
            );
        }

        intelligence.sourceStatus[
            "CERT-EU Security Advisories"
        ] = "available";

        delete intelligence.sourceErrors[
            "CERT-EU Security Advisories"
        ];

        return finalResults;
    } catch (error) {
        intelligence.sourceStatus[
            "CERT-EU Security Advisories"
        ] = "unavailable";

        intelligence.sourceErrors[
            "CERT-EU Security Advisories"
        ] = error.message;

        return [];
    }
}

// ------------------------------------------------------------
// FIRST EPSS
// ------------------------------------------------------------

async function fetchEpss() {
    try {
        const response = await fetchUrl(
            SOURCES.epss.url,
            {
                timeout: 15000,
                accept: "application/json"
            }
        );

        const data = safeJson(response.body);

        if (!data || !Array.isArray(data.data)) {
            throw new Error("Invalid FIRST EPSS response");
        }

        const results = data.data
            .slice(0, 100)
            .map(item => ({
                cve:
                    item.cve || null,

                epss:
                    Number(item.epss || 0),

                percentile:
                    Number(item.percentile || 0),

                source:
                    "FIRST EPSS",

                risk:
                    epssRisk(Number(item.epss || 0))
            }));

        intelligence.sourceStatus["FIRST EPSS"] = "available";
        delete intelligence.sourceErrors["FIRST EPSS"];

        return results;
    } catch (error) {
        intelligence.sourceStatus["FIRST EPSS"] = "unavailable";
        intelligence.sourceErrors["FIRST EPSS"] = error.message;

        return [];
    }
}

// ------------------------------------------------------------
// THREAT CLASSIFICATION
// ------------------------------------------------------------

function classifyThreat(text) {
    const value = String(text || "").toLowerCase();

    if (
        /phish|credential|login|account takeover|password theft|fake login/.test(
            value
        )
    ) {
        return {
            label: "Credential-Phishing Attempt",
            code: "THREAT-PHI-001"
        };
    }

    if (
        /scam|fraud|social engineering|impersonat|financial fraud|romance scam/.test(
            value
        )
    ) {
        return {
            label: "Social Engineering / Scam Signal",
            code: "THREAT-SCM-001"
        };
    }

    if (
        /malware|trojan|ransomware|spyware|infostealer|backdoor|botnet/.test(
            value
        )
    ) {
        return {
            label: "Malware Distribution Signal",
            code: "THREAT-MAL-001"
        };
    }

    if (
        /bot|automated|coordinated|command and control|c2|c&c/.test(
            value
        )
    ) {
        return {
            label: "Automated / Coordinated Activity",
            code: "THREAT-BOT-001"
        };
    }

    if (
        /disinformation|misinformation|influence operation|information operation|propaganda/.test(
            value
        )
    ) {
        return {
            label: "Potential Coordinated Disinformation",
            code: "THREAT-DIS-001"
        };
    }

    if (
        /extremist|radicalization|terrorist recruitment/.test(
            value
        )
    ) {
        return {
            label: "Potential Radicalization Signal",
            code: "THREAT-RAD-001"
        };
    }

    if (
        /vulnerability|exploit|rce|remote code execution|privilege escalation/.test(
            value
        )
    ) {
        return {
            label: "Vulnerability Exploitation Signal",
            code: "THREAT-VUL-001"
        };
    }

    return {
        label: "Cybersecurity Threat Signal",
        code: "THREAT-GEN-001"
    };
}

// ------------------------------------------------------------
// SEVERITY
// ------------------------------------------------------------

function calculateAdvisorySeverity(title) {
    const value = String(title || "").toLowerCase();

    if (/critical|zero.?day|actively exploited/.test(value)) {
        return "CRITICAL";
    }

    if (/high|rce|remote code execution|ransomware/.test(value)) {
        return "HIGH";
    }

    if (/medium|moderate/.test(value)) {
        return "MEDIUM";
    }

    return "INFO";
}

function epssRisk(score) {
    if (score >= 0.8) return "CRITICAL";
    if (score >= 0.5) return "HIGH";
    if (score >= 0.2) return "MEDIUM";
    return "LOW";
}

// ------------------------------------------------------------
// THREAT FEED CONSTRUCTION
// ------------------------------------------------------------

function buildThreatFeed(news, cisa, certEu) {
    const feed = [];

    for (const item of news) {
        feed.push({
            id: item.id,
            title: item.title,
            description: item.description,
            source: item.source,
            observedAt: item.publishedAt || nowISO(),
            category: item.category,
            type: "social-cyber-signal",
            risk: threatRisk(item.category),
            link: item.link
        });
    }

    for (const item of cisa) {
        feed.push({
            id: item.id,
            title: item.vulnerability,
            description: item.description,
            source: item.source,
            observedAt: item.dateAdded || nowISO(),
            category: {
                label:
                    "Known Exploited Vulnerability",
                code: "THREAT-VUL-KEV"
            },
            type: "known-exploited-vulnerability",
            risk: "HIGH",
            cve: item.cve,
            link:
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        });
    }

    for (const item of certEu) {
        feed.push({
            id: item.id,
            title: item.title,
            description: item.description,
            source: item.source,
            observedAt: item.publishedAt || nowISO(),
            category: {
                label:
                    item.category.label ||
                    "Cybersecurity Advisory",
                code:
                    item.category.code ||
                    "THREAT-ADV-001"
            },
            type: "security-advisory",
            risk: item.severity,
            link: item.link
        });
    }

    return feed.slice(0, 150);
}

function threatRisk(category) {
    if (!category) return "MEDIUM";

    switch (category.code) {
        case "THREAT-PHI-001":
        case "THREAT-MAL-001":
        case "THREAT-BOT-001":
            return "HIGH";

        case "THREAT-SCM-001":
        case "THREAT-DIS-001":
        case "THREAT-RAD-001":
            return "MEDIUM";

        default:
            return "LOW";
    }
}

// ------------------------------------------------------------
// PREDICTION ENGINE
// ------------------------------------------------------------

function buildPredictions(threats, trends, advisories) {
    const buckets = {
        phishing: 0,
        scams: 0,
        malware: 0,
        coordination: 0,
        disinformation: 0,
        vulnerability: 0
    };

    for (const threat of threats) {
        const code =
            threat.category &&
            threat.category.code;

        if (code === "THREAT-PHI-001") buckets.phishing++;
        if (code === "THREAT-SCM-001") buckets.scams++;
        if (code === "THREAT-MAL-001") buckets.malware++;
        if (code === "THREAT-BOT-001") buckets.coordination++;
        if (code === "THREAT-DIS-001") buckets.disinformation++;
        if (
            code === "THREAT-VUL-001" ||
            code === "THREAT-VUL-KEV"
        ) {
            buckets.vulnerability++;
        }
    }

    const predictions = [];

    function addPrediction(
        type,
        code,
        count,
        confidenceBase
    ) {
        if (count === 0) return;

        const trendBoost =
            Math.min(trends.length, 20) * 0.5;

        const advisoryBoost =
            Math.min(advisories.length, 20) * 0.3;

        const score = Math.min(
            99,
            Math.round(
                confidenceBase +
                count * 2 +
                trendBoost +
                advisoryBoost
            )
        );

        predictions.push({
            id: code,
            type,
            score,
            confidence:
                score >= 80
                    ? "HIGH"
                    : score >= 55
                        ? "MEDIUM"
                        : "LOW",

            window: "Next 24–48 hours",

            explanation:
                `Detected ${count} related live intelligence signals, ` +
                `${trends.length} current trend signals and ` +
                `${advisories.length} security advisories.`,

            signalCount: count,

            generatedAt: nowISO()
        });
    }

    addPrediction(
        "Credential-Phishing Campaign",
        "PRED-PHI-001",
        buckets.phishing,
        45
    );

    addPrediction(
        "Social Engineering / Scam Surge",
        "PRED-SCM-001",
        buckets.scams,
        40
    );

    addPrediction(
        "Malware Distribution Surge",
        "PRED-MAL-001",
        buckets.malware,
        50
    );

    addPrediction(
        "Automated Coordination Surge",
        "PRED-BOT-001",
        buckets.coordination,
        40
    );

    addPrediction(
        "Coordinated Disinformation Signal",
        "PRED-DIS-001",
        buckets.disinformation,
        35
    );

    addPrediction(
        "Vulnerability Exploitation Risk",
        "PRED-VUL-001",
        buckets.vulnerability,
        55
    );

    return predictions;
}

// ------------------------------------------------------------
// EVIDENCE
// ------------------------------------------------------------

function buildEvidence(threats, advisories, vulnerabilities) {
    const evidence = [];

    const all = [
        ...threats.slice(0, 30),
        ...advisories.slice(0, 20),
        ...vulnerabilities.slice(0, 20)
    ];

    for (const item of all) {
        const raw =
            `${item.title || ""}|` +
            `${item.description || ""}|` +
            `${item.source || ""}`;

        evidence.push({
            id:
                item.id ||
                `EVID-${sha256(raw).slice(0, 12)}`,

            source:
                item.source || "Unknown",

            title:
                item.title ||
                item.vulnerability ||
                "Cybersecurity evidence",

            hash:
                sha256(raw),

            observedAt:
                item.observedAt ||
                item.publishedAt ||
                item.dateAdded ||
                nowISO(),

            verification:
                "Public-source evidence"
        });
    }

    return evidence.slice(0, 100);
}

// ------------------------------------------------------------
// SNAPSHOT REFRESH
// ------------------------------------------------------------

async function refreshIntelligence() {
    console.log("");
    console.log("==========================================");
    console.log("SOCIAL SYNC - LIVE INTELLIGENCE REFRESH");
    console.log("==========================================");
    console.log(new Date().toISOString());

    const [
        trends,
        news,
        cisaKev,
        cisaAdvisories,
        certEu,
        epss
    ] = await Promise.all([
        fetchGoogleTrends(),
        fetchGoogleNews(),
        fetchCisaKev(),
        fetchCisaAdvisories(),
        fetchCertEuAdvisories(),
        fetchEpss()
    ]);

    const threats =
        buildThreatFeed(
            news,
            cisaKev,
            certEu
        );

    const predictions =
        buildPredictions(
            threats,
            trends,
            [
                ...cisaAdvisories,
                ...certEu
            ]
        );

    const evidence =
        buildEvidence(
            threats,
            [
                ...cisaAdvisories,
                ...certEu
            ],
            cisaKev
        );

    const snapshot = {
        timestamp: nowISO(),

        trends,
        threats,

        vulnerabilities:
            cisaKev,

        advisories: [
            ...cisaAdvisories,
            ...certEu
        ],

        epss,

        predictions,

        evidence,

        sourceStatus:
            intelligence.sourceStatus,

        sourceErrors:
            intelligence.sourceErrors,

        metrics: {
            trendSignals:
                trends.length,

            threatSignals:
                threats.length,

            vulnerabilitySignals:
                cisaKev.length,

            advisorySignals:
                cisaAdvisories.length +
                certEu.length,

            predictionSignals:
                predictions.length
        }
    };

    previousSnapshot = intelligence;

    intelligence = {
        updatedAt: snapshot.timestamp,

        ...snapshot
    };

    // Keep a small rolling history for trend/prediction comparison.
    history.push({
        timestamp: snapshot.timestamp,

        metrics: snapshot.metrics,

        predictionCount:
            predictions.length,

        threatCount:
            threats.length
    });

    if (history.length > 60) {
        history.shift();
    }

    broadcast();

    console.log("");
    console.log(
        `Trends: ${trends.length}`
    );

    console.log(
        `Threats: ${threats.length}`
    );

    console.log(
        `CISA KEV: ${cisaKev.length}`
    );

    console.log(
        `CISA Advisories: ${cisaAdvisories.length}`
    );

    console.log(
        `CERT-EU Advisories: ${certEu.length}`
    );

    console.log(
        `FIRST EPSS: ${epss.length}`
    );

    console.log(
        "Source status:",
        JSON.stringify(
            intelligence.sourceStatus
        )
    );

    console.log(
        "Refresh completed:",
        snapshot.timestamp
    );

    console.log("==========================================");

    return snapshot;
}

// ------------------------------------------------------------
// API RESPONSE HELPERS
// ------------------------------------------------------------

function sendJson(res, status, data) {
    const body = JSON.stringify(data);

    res.writeHead(status, {
        "Content-Type":
            "application/json; charset=utf-8",

        "Cache-Control":
            "no-store, no-cache, must-revalidate",

        "Access-Control-Allow-Origin":
            "*"
    });

    res.end(body);
}

function sendText(res, status, text) {
    res.writeHead(status, {
        "Content-Type":
            "text/plain; charset=utf-8",

        "Access-Control-Allow-Origin":
            "*"
    });

    res.end(text);
}

// ------------------------------------------------------------
// STATIC FILE SERVER
// ------------------------------------------------------------

const MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2"
};

function serveStatic(req, res) {
    let requestPath =
        decodeURIComponent(
            req.url.split("?")[0]
        );

    if (requestPath === "/") {
        requestPath = "/index.html";
    }

    let baseDir = ROOT_DIR;

    if (
        requestPath.startsWith("/static/")
    ) {
        baseDir = STATIC_DIR;
        requestPath =
            requestPath.replace(
                /^\/static/,
                ""
            );
    }

    const filePath =
        path.normalize(
            path.join(
                baseDir,
                requestPath
            )
        );

    // Prevent directory traversal.
    if (
        !filePath.startsWith(
            path.normalize(baseDir)
        )
    ) {
        return sendText(
            res,
            403,
            "Forbidden"
        );
    }

    fs.readFile(
        filePath,
        (error, data) => {
            if (error) {
                return sendText(
                    res,
                    404,
                    "Not Found"
                );
            }

            const ext =
                path.extname(filePath)
                    .toLowerCase();

            res.writeHead(200, {
                "Content-Type":
                    MIME_TYPES[ext] ||
                    "application/octet-stream",

                "Cache-Control":
                    "no-cache"
            });

            res.end(data);
        }
    );
}

// ------------------------------------------------------------
// SSE
// ------------------------------------------------------------

function subscribe(res) {
    res.writeHead(200, {
        "Content-Type":
            "text/event-stream; charset=utf-8",

        "Cache-Control":
            "no-cache, no-transform",

        "Connection":
            "keep-alive",

        "Access-Control-Allow-Origin":
            "*"
    });

    res.write(
        `data: ${JSON.stringify(intelligence)}\n\n`
    );

    subscribers.add(res);

    res.on("close", () => {
        subscribers.delete(res);
    });
}

function broadcast() {
    const payload =
        `data: ${JSON.stringify(
            intelligence
        )}\n\n`;

    for (const client of subscribers) {
        try {
            client.write(payload);
        } catch {
            subscribers.delete(client);
        }
    }
}

// ------------------------------------------------------------
// API ROUTER
// ------------------------------------------------------------

function handleApi(req, res) {
    const url =
        new URL(
            req.url,
            `http://${req.headers.host || "localhost"}`
        );

    const route = url.pathname;

    // Health
    if (route === "/api/health") {
        return sendJson(res, 200, {
            status: "ok",

            service:
                "social-sync-api",

            mode:
                "live-public-intelligence",

            timestamp:
                intelligence.updatedAt,

            sources:
                intelligence.sourceStatus
        });
    }

    // Complete summary
    if (route === "/api/threats/summary") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            metrics:
                intelligence.metrics,

            sourceStatus:
                intelligence.sourceStatus,

            sourceErrors:
                intelligence.sourceErrors,

            threats:
                intelligence.threats.slice(0, 50),

            vulnerabilities:
                intelligence.vulnerabilities.slice(0, 50),

            advisories:
                intelligence.advisories.slice(0, 50),

            predictions:
                intelligence.predictions
        });
    }

    // Threat feed
    if (route === "/api/threats/feed") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            count:
                intelligence.threats.length,

            data:
                intelligence.threats
        });
    }

    // Trends
    if (route === "/api/trends") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            count:
                intelligence.trends.length,

            data:
                intelligence.trends
        });
    }

    // Evidence
    if (route === "/api/evidence") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            count:
                intelligence.evidence.length,

            data:
                intelligence.evidence
        });
    }

    // Prediction
    if (route === "/api/prediction") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            horizon:
                "24–48 hours",

            predictions:
                intelligence.predictions,

            history
        });
    }

    // Sources
    if (route === "/api/sources") {
        return sendJson(res, 200, {
            status: "ok",

            timestamp:
                intelligence.updatedAt,

            sources:
                Object.entries(
                    intelligence.sourceStatus
                ).map(
                    ([name, status]) => ({
                        name,
                        status,

                        error:
                            intelligence.sourceErrors[
                                name
                            ] || null
                    })
                )
        });
    }

    // SSE
    if (route === "/api/stream") {
        return subscribe(res);
    }

    return sendJson(res, 404, {
        status: "error",
        message: "API route not found"
    });
}

// ------------------------------------------------------------
// SERVER
// ------------------------------------------------------------

const server = http.createServer(
    async (req, res) => {
        try {
            if (
                req.method === "OPTIONS"
            ) {
                res.writeHead(204, {
                    "Access-Control-Allow-Origin":
                        "*",

                    "Access-Control-Allow-Methods":
                        "GET,OPTIONS",

                    "Access-Control-Allow-Headers":
                        "Content-Type"
                });

                return res.end();
            }

            if (
                req.url.startsWith("/api/")
            ) {
                return handleApi(
                    req,
                    res
                );
            }

            return serveStatic(
                req,
                res
            );
        } catch (error) {
            console.error(
                "Request error:",
                error
            );

            sendJson(res, 500, {
                status: "error",
                message:
                    "Internal server error"
            });
        }
    }
);

// ------------------------------------------------------------
// STARTUP
// ------------------------------------------------------------

server.listen(
    PORT,
    HOST,
    async () => {
        console.log("");
        console.log(
            "=========================================="
        );
        console.log(
            " SOCIAL SYNC - LIVE INTELLIGENCE BACKEND"
        );
        console.log(
            "=========================================="
        );

        console.log(
            `Server: http://${HOST}:${PORT}`
        );

        console.log(
            "Cyber sources:"
        );

        console.log(
            "  ✓ CISA Known Exploited Vulnerabilities"
        );

        console.log(
            "  ✓ CISA Cybersecurity Advisories"
        );

        console.log(
            "  ✓ CERT-EU Security Advisories"
        );

        console.log(
            "  ✓ FIRST EPSS"
        );

        console.log(
            "Trend sources:"
        );

        console.log(
            "  ✓ Google Trends"
        );

        console.log(
            "  ✓ Google News"
        );

        console.log(
            "Removed unreliable dependencies:"
        );

        console.log(
            "  ✗ Reddit"
        );

        console.log(
            "  ✗ NVD"
        );

        console.log(
            `Refresh interval: ${REFRESH_INTERVAL / 1000}s`
        );

        console.log(
            "=========================================="
        );

        // Initial refresh
        await refreshIntelligence();

        // Automatic refresh
        setInterval(
            () => {
                refreshIntelligence()
                    .catch(error => {
                        console.error(
                            "Refresh error:",
                            error
                        );
                    });
            },
            REFRESH_INTERVAL
        );
    }
);

// ------------------------------------------------------------
// GRACEFUL SHUTDOWN
// ------------------------------------------------------------

function shutdown(signal) {
    console.log(
        `${signal} received. Shutting down...`
    );

    for (const client of subscribers) {
        try {
            client.end();
        } catch {}
    }

    server.close(() => {
        process.exit(0);
    });
}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);