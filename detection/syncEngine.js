/**
 * syncEngine.js — Sentinel Browse Extension
 *
 * SELF-CONTAINED SYNCHRONOUS URL ANALYZER
 * ========================================
 * Used exclusively by chrome.webRequest.onBeforeRequest blocking listener.
 *
 * DESIGN RULES (MV3 service worker compliance):
 *   ✓ Zero async/await — function MUST be synchronous for blocking listener
 *   ✓ Zero external API calls — no network, no chrome.storage
 *   ✓ Zero dynamic imports — all logic inlined or from domainWhitelist.js
 *   ✓ Fail-open — any error returns { status: "safe" }
 *   ✓ < 10ms execution time target
 *
 * WHY async CRASHES the service worker:
 *   In MV3, the blocking webRequest handler runs in the service worker context.
 *   If the handler returns a Promise (or is async), Chrome treats the
 *   blocking decision as unresolved and MAY allow the request anyway — or
 *   in some builds it throws an internal error that marks the service worker
 *   as faulted. This file is the single source of truth for the sync path.
 *
 * The full async pipeline (Safe Browsing, overlay, history) runs in
 * webNavigation.onCompleted separately — this file never touches it.
 */

import {
    isTrustedDomain,
    isSearchEngineQuery,
    getRootDomain,
    getHostname,
} from "./domainWhitelist.js";

// ─── Configuration ─────────────────────────────────────────────────────────

/** TLDs that are disproportionately abused in phishing / malware. */
const HIGH_RISK_TLDS = new Set([
    "xyz", "tk", "ml", "ga", "cf", "gq",
    "top", "club", "online", "site", "web",
    "ru", "cn", "pw", "cc", "ws",
    "info", "biz", "click", "link", "live",
    "stream", "zip", "mov",
]);

/** Phishing credential-harvesting keywords — checked in HOSTNAME only. */
const PHISHING_KEYWORDS = new Set([
    "login", "signin", "logon",
    "verify", "verification", "validate",
    "account", "accounts",
    "secure", "security",
    "password", "passwd", "credential",
    "wallet", "banking",
    "confirm", "confirmation",
    "update", "upgrade",
    "recover", "recovery",
    "suspend", "suspended",
    "appleid", "apple-id",
]);

/** Urgency/pressure words — must co-occur with a keyword for intent flag. */
const URGENCY_WORDS = new Set([
    "urgent", "urgently",
    "immediately", "immediate",
    "now", "asap",
    "alert", "warning", "critical",
    "expire", "expires", "expiring",
    "limited", "action", "locked", "lock",
    "blocked", "unusual", "activity",
    "deadline",
]);

/** Known phishing root domains — direct dataset match. */
const PHISHING_DATASET = new Set([
    "paypal-login-secure.com", "paypa1-account.com",
    "paypal-update-required.net", "amazon-update-account.xyz",
    "amazon-account-alert.net", "banking-verify-now.com",
    "secure-bankofamerica.com", "chase-security-alert.com",
    "facebook-verification.net", "facebook-login-secure.com",
    "apple-id-verify.com", "apple-account-locked.net",
    "microsoft-support-alert.com", "google-account-recovery.xyz",
    "crypto-wallet-recover.xyz", "phishing-site.net",
    "secure-verify-login.com", "account-suspended-alert.com",
    "login-secure-update.com", "verify-account-now.xyz",
    "metamask-security.net", "coinbase-verify.net",
    "malicious.com",
]);

// ─── Pure helper functions (no side-effects) ───────────────────────────────

function safeGetHostname(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function safeGetPathname(url) {
    try { return new URL(url).pathname.toLowerCase(); } catch { return ""; }
}

function tokenize(text) {
    return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function getTLD(hostname) {
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts[parts.length - 1] : "";
}

function countHyphens(hostname) {
    return (hostname.match(/-/g) || []).length;
}

function usesIpAddress(hostname) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function hasPunycode(hostname) {
    return hostname.split(".").some((label) => label.startsWith("xn--"));
}

function hasPercentEncodingInHostOrPath(url) {
    try {
        const parsed = new URL(url);
        return /%[0-9a-f]{2}/i.test(parsed.hostname + parsed.pathname);
    } catch { return false; }
}

// ─── Signal detectors ──────────────────────────────────────────────────────

/**
 * Dataset match — exact root-domain check against known phishing domains.
 * @returns {{ flag: boolean, reason: string }}
 */
function checkDatasetSync(hostname) {
    const root = getRootDomain(hostname);
    if (PHISHING_DATASET.has(root) || PHISHING_DATASET.has(hostname)) {
        return { flag: true, reason: `Domain "${root}" matched phishing dataset` };
    }
    return { flag: false, reason: "" };
}

/**
 * Domain intelligence — TLD risk, hyphens, depth, IP address.
 * @returns {{ score: number, signals: string[] }}
 */
function checkDomainIntelligence(hostname) {
    const signals = [];
    let score = 0;
    const tld = getTLD(hostname);

    if (tld && HIGH_RISK_TLDS.has(tld)) {
        score += 2;
        signals.push(`High-risk TLD (.${tld})`);
    }
    const hyphens = countHyphens(hostname);
    if (hyphens >= 3) { score += 2; signals.push(`Heavy hyphen use (${hyphens} hyphens)`); }
    else if (hyphens >= 2) { score += 1; signals.push(`Multiple hyphens (${hyphens})`); }

    const parts = hostname.split(".").filter(Boolean);
    if (parts.length >= 5) { score += 2; signals.push("Deep subdomain nesting"); }
    else if (parts.length === 4) { score += 1; signals.push("Elevated subdomain depth"); }

    if (hostname.length > 45) { score += 1; signals.push("Unusually long hostname"); }
    if (usesIpAddress(hostname)) { score += 2; signals.push("Raw IP address as host"); }

    return { score, signals };
}

/**
 * Obfuscation detection — punycode, percent-encoding in host/path.
 * @returns {{ score: number, signals: string[] }}
 */
function checkObfuscation(url, hostname) {
    const signals = [];
    let score = 0;

    if (hasPunycode(hostname)) {
        score += 3;
        signals.push(`Punycode domain (${hostname}) — possible homoglyph attack`);
    }
    if (hasPercentEncodingInHostOrPath(url)) {
        score += 2;
        signals.push("Percent-encoding in hostname or path");
    }

    return { score, signals };
}

/**
 * Intent detection — phishing keyword + urgency word COMBINED.
 * Single keyword alone → no flag.
 * @returns {{ hasIntent: boolean, keywords: string[], urgency: string[] }}
 */
function checkIntent(hostname, pathname) {
    const hostnameTokens = tokenize(hostname);
    const allTokens = tokenize(hostname + " " + pathname);

    const keywords = hostnameTokens.filter((t) => PHISHING_KEYWORDS.has(t));
    const urgency = allTokens.filter((t) => URGENCY_WORDS.has(t));
    const hasIntent = keywords.length > 0 && urgency.length > 0;

    return { hasIntent, keywords, urgency };
}

// ─── Main synchronous analyzer ─────────────────────────────────────────────

/**
 * analyzeUrlSync — fully synchronous URL risk analysis.
 *
 * MALICIOUS if:
 *   • dataset match                           (hard override)
 *   • intent + domain anomaly + obfuscation  (three-group combination)
 *   • intent + domain anomaly, combined score > 6
 *   • punycode (homoglyph) + intent
 *
 * SUSPICIOUS if:
 *   • 1–2 weak signals (no malicious combination met)
 *
 * SAFE if:
 *   • trusted domain / search engine (hard bypass)
 *   • OR no meaningful signal combination
 *
 * @param {string} url
 * @returns {{
 *   status: "safe"|"suspicious"|"malicious",
 *   trustScore: number,
 *   score: number,
 *   reasons: string[],
 *   signals: { intent: boolean, obfuscation: boolean, domainRisk: boolean, reputation: boolean },
 *   appliedRule: string
 * }}
 */
export function analyzeUrlSync(url) {
    try {
        const input = String(url || "");
        if (!input || !/^https?:\/\//i.test(input)) {
            return buildResult("safe", [], 0, "NON_HTTP_URL");
        }

        // ── Trusted domain / search engine → ALWAYS SAFE ────────────────────
        if (isTrustedDomain(input) || isSearchEngineQuery(input)) {
            return buildResult("safe", ["Trusted domain or search engine"], -5, "TRUSTED_OVERRIDE");
        }

        const hostname = safeGetHostname(input);
        const pathname = safeGetPathname(input);

        if (!hostname) {
            return buildResult("safe", [], 0, "NO_HOSTNAME");
        }

        const reasons = [];
        let totalScore = 0;

        // ── Signal: Dataset match (hard malicious) ───────────────────────────
        const dataset = checkDatasetSync(hostname);
        if (dataset.flag) {
            reasons.push(dataset.reason);
            return buildResult("malicious", reasons, 10, "DATASET_MATCH",
                { intent: false, obfuscation: false, domainRisk: true, reputation: true });
        }

        // ── Signal: Domain intelligence ──────────────────────────────────────
        const domain = checkDomainIntelligence(hostname);
        totalScore += domain.score;
        reasons.push(...domain.signals);

        // ── Signal: Obfuscation ──────────────────────────────────────────────
        const obfusc = checkObfuscation(input, hostname);
        totalScore += obfusc.score;
        reasons.push(...obfusc.signals);

        // ── Signal: Intent (keyword + urgency) ──────────────────────────────
        const intent = checkIntent(hostname, pathname);
        if (intent.hasIntent) {
            totalScore += 3;
            reasons.push(`Phishing intent: [${intent.keywords.join(",")}] + urgency [${intent.urgency.join(",")}]`);
        } else if (intent.keywords.length > 0) {
            // Keyword only (no urgency) = weak signal
            totalScore += 1;
            reasons.push(`Phishing keyword in domain (no urgency — weak): ${intent.keywords.join(", ")}`);
        }

        const hasDomainRisk = domain.score >= 2;
        const hasObfuscation = obfusc.score > 0;
        const hasIntent = intent.hasIntent;

        // ── Decision ─────────────────────────────────────────────────────────
        let status;
        let appliedRule;

        if (hasIntent && hasDomainRisk && hasObfuscation) {
            status = "malicious";
            appliedRule = "INTENT+DOMAIN+OBFUSC";
        } else if (hasIntent && hasDomainRisk && totalScore > 6) {
            status = "malicious";
            appliedRule = "INTENT+DOMAIN+HIGH_SCORE";
        } else if (hasPunycode(hostname) && hasIntent) {
            status = "malicious";
            appliedRule = "PUNYCODE+INTENT";
        } else if (totalScore >= 2) {
            status = "suspicious";
            appliedRule = `WEAK_SIGNALS (score=${totalScore})`;
        } else {
            status = "safe";
            appliedRule = "NO_SIGNALS";
            reasons.length = 0; // don't surface empty noise for safe URLs
        }

        return buildResult(status, reasons, totalScore, appliedRule, {
            intent: hasIntent,
            obfuscation: hasObfuscation,
            domainRisk: hasDomainRisk,
            reputation: false, // Safe Browsing not available in sync path
        });

    } catch (err) {
        // Fail-open — never block on error
        console.warn("[Sentinel][Sync] analyzeUrlSync error:", err);
        return buildResult("safe", [], 0, "ERROR_FAIL_OPEN");
    }
}

// ─── Result builder ───────────────────────────────────────────────────────

function buildResult(status, reasons = [], score = 0, appliedRule = "", signals = {}) {
    return {
        status,
        score,
        trustScore: Math.max(0, Math.min(100, 100 - score * 10)),
        reasons: Array.isArray(reasons) ? [...reasons] : [],
        signals: {
            intent: Boolean(signals.intent),
            obfuscation: Boolean(signals.obfuscation),
            domainRisk: Boolean(signals.domainRisk),
            reputation: Boolean(signals.reputation),
        },
        appliedRule,
    };
}
