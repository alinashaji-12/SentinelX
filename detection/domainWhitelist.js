/**
 * domainWhitelist.js — Sentinel Browse Extension
 *
 * Centralized domain trust registry and context-aware URL classification.
 * Used by signature.js and advancedEngine.js to prevent false positives.
 */

/**
 * Tier-1 trusted root domains (eTLD+1 only — no subdomains).
 * Matching is done via EXACT root-domain comparison, NOT endsWith(),
 * so "google.com.fake-site.xyz" will never match "google.com".
 */
export const TRUSTED_ROOT_DOMAINS = new Set([
    "google.com",
    "googleapis.com",
    "googlevideo.com",
    "youtube.com",
    "youtu.be",
    "bing.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "github.com",
    "githubusercontent.com",
    "npmjs.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazonaws.com",
    "aws.amazon.com",
    "wikipedia.org",
    "wikimedia.org",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "mozilla.org",
    "firefox.com",
    "cloudflare.com",
    "openai.com",
    "chatgpt.com",
    "stripe.com",
    "paypal.com",
    "netflix.com",
    "reddit.com",
    "stackoverflow.com",
    "stackexchange.com",
    "medium.com",
    "wordpress.org",
    "wordpress.com",
    "gov.in",
    "nic.in",
    "edu",
    "ac.uk",
    "duckduckgo.com",
    "yahoo.com",
]);

/**
 * Search engine hosts whose query pages must not be penalized for
 * containing keywords like "login", "verify", "secure" in the query string.
 */
export const SEARCH_ENGINE_HOSTS = new Set([
    "google.com",
    "www.google.com",
    "bing.com",
    "www.bing.com",
    "search.yahoo.com",
    "duckduckgo.com",
    "baidu.com",
    "yandex.com",
    "yandex.ru",
    "ecosia.org",
    "startpage.com",
    "brave.com",
    "search.brave.com",
]);

/**
 * Extracts the root eTLD+1 domain from a full hostname.
 *
 * Examples:
 *   "www.google.com"           → "google.com"
 *   "mail.accounts.google.com" → "google.com"
 *   "google.com.fake-site.xyz" → "fake-site.xyz"   ← NOT google.com ✓
 *   "github.com"               → "github.com"
 *   "192.168.1.1"              → "192.168.1.1"
 *
 * Strategy: uses the last two hostname labels (a.b format) as the root
 * unless the second-to-last label is a known two-char country code (e.g. "co.uk").
 *
 * @param {string} hostname — lowercase hostname from URL API
 * @returns {string} root domain (eTLD+1)
 */
export function getRootDomain(hostname) {
    if (!hostname) return "";

    // IP addresses pass through unchanged.
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;

    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;

    // Handle common two-part TLDs: co.uk, com.au, gov.in, ac.uk, org.uk, net.au…
    const knownDoubleTLDs = new Set([
        "co.uk", "co.in", "co.nz", "co.jp", "co.za", "co.ke", "co.id",
        "com.au", "com.br", "com.sg", "com.my", "com.hk", "com.pk", "com.ng",
        "gov.uk", "gov.in", "gov.au", "gov.sg",
        "org.uk", "net.uk", "ac.uk", "edu.au",
    ]);

    const lastTwo = parts.slice(-2).join(".");
    const lastThree = parts.slice(-3).join(".");

    if (knownDoubleTLDs.has(lastTwo)) {
        // e.g. something.gov.uk → use last 3 parts
        return parts.slice(-3).join(".");
    }

    // Default: use last 2 parts
    return lastTwo;
}

/**
 * Extracts hostname from any URL string safely.
 * @param {string} url
 * @returns {string} lowercase hostname or ""
 */
export function getHostname(url) {
    try {
        return new URL(String(url || "")).hostname.toLowerCase();
    } catch {
        return "";
    }
}

/**
 * Returns true ONLY when the root domain of the URL exactly matches
 * a known trusted domain.
 *
 * Prevents spoofing: "google.com.evil.xyz" → root = "evil.xyz" → NOT trusted.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function isTrustedDomain(url) {
    const hostname = getHostname(url);
    if (!hostname) return false;
    const root = getRootDomain(hostname);
    return TRUSTED_ROOT_DOMAINS.has(root);
}

/**
 * Returns true when the URL is a search engine results/query page.
 *
 * Conditions (must both be true):
 *   1. Host is in SEARCH_ENGINE_HOSTS
 *   2. URL path starts with "/search" OR query contains "q=" OR "query="
 *
 * This prevents `google.com/search?q=login+verify` from being flagged.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function isSearchEngineQuery(url) {
    try {
        const parsed = new URL(String(url || ""));
        const host = parsed.hostname.toLowerCase();
        const isSearchHost = SEARCH_ENGINE_HOSTS.has(host);
        if (!isSearchHost) return false;

        const path = parsed.pathname.toLowerCase();
        const query = parsed.search.toLowerCase();
        const isQuery =
            path.startsWith("/search") ||
            path.startsWith("/find") ||
            query.includes("q=") ||
            query.includes("query=") ||
            query.includes("p=");

        return isQuery;
    } catch {
        return false;
    }
}
