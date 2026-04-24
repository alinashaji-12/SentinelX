
// ══════════════════════════════════════════════════════════════════════
// SECTION 9b — SSL / TLS CERTIFICATE ANALYSIS ENGINE
// ══════════════════════════════════════════════════════════════════════
//
// Detects 7 SSL/TLS threat categories using Chrome's webRequest API:
//   1. insecure_http      — plain HTTP navigation (no TLS at all)
//   2. invalid_ssl        — certificate validation failed / untrusted CA
//   3. expired_cert       — validTo timestamp in the past
//   4. self_signed_cert   — issuer == subject (no trusted CA chain)
//   5. domain_mismatch    — SAN/CN does not match the visited hostname
//   6. weak_encryption    — SHA-1, MD5, RC4, or DES cipher detected
//   7. mixed_content      — HTTPS page loads plain HTTP sub-resources
//
// Architecture:
//   • onHeadersReceived captures securityDetails per main-frame URL.
//   • onBeforeRequest tracks HTTP sub-resource requests on HTTPS pages.
//   • Both caches keyed by normalized URL / tabId.
//   • consumeSSLSignals(url, tabId) drains both and returns typed signals.
//   • Signals are merged into result.signals at Step 5.5 of the analysis
//     flow (onBeforeNavigate), before adaptive scoring and ML enrichment.
//
// False-positive guards:
//   • localhost / 127.0.0.1 excluded from HTTP-only check.
//   • securityDetails only trusted when it is a non-null object.
//   • Weak cipher detection uses explicit deprecated algorithm strings.

/** Per-URL SSL metadata cache populated by webRequest.onHeadersReceived. */
const _SSL_CACHE = new Map();

/** Per-tab HTTP sub-resource tracker for mixed-content detection. */
const _MIXED_CONTENT_CACHE = new Map();

/** Hostnames excluded from the plain-HTTP signal. */
const _SSL_SAFE_HTTP_DOMAINS = new Set(["localhost", "127.0.0.1", "::1"]);

/** Deprecated cipher / protocol substrings that indicate weak encryption. */
const _WEAK_CIPHER_PATTERNS = [
  "SHA1", "SHA-1", "MD5", "RC4", "DES", "EXPORT", "NULL",
  "TLS 1.0", "TLS 1.1",
];

/**
 * Converts raw webRequest securityDetails + URL into Sentinel signal strings.
 *
 * @param {string}      url        - request URL being analyzed
 * @param {object|null} secDetails - chrome.webRequest securityDetails object
 * @param {number}      tabId      - tab making the request
 * @returns {string[]} Array of signal strings (may be empty)
 */
function analyzeSSL(url, secDetails, tabId) {
  const signals = [];

  // 1. HTTP (no TLS) ──────────────────────────────────────────────────
  const isHTTPS = url.startsWith("https://");
  if (!isHTTPS) {
    let hostname = "";
    try { hostname = new URL(url).hostname; } catch {}
    if (!_SSL_SAFE_HTTP_DOMAINS.has(hostname)) {
      signals.push("insecure_http");
    }
    return signals;   // HTTP pages cannot have cert signals
  }

  // 2–7. Certificate-level checks require securityDetails ─────────────
  if (!secDetails || typeof secDetails !== "object") {
    return signals;   // absence of data ≠ presence of problem
  }

  // 2. Invalid / untrusted certificate
  if (secDetails.certificateId === 0) {
    signals.push("invalid_ssl");
  }

  // 3. Expired certificate
  const validTo = typeof secDetails.validTo === "number" ? secDetails.validTo : null;
  if (validTo !== null && validTo < Date.now() / 1000) {
    signals.push("expired_cert");
  }

  // 4. Self-signed certificate (issuer == subject, no trusted CA chain)
  const issuer  = String(secDetails.issuer      || "").trim().toLowerCase();
  const subject = String(secDetails.subjectName || "").trim().toLowerCase();
  if (issuer && subject && issuer === subject) {
    signals.push("self_signed_cert");
  }

  // 5. Domain mismatch (SAN / CN does not match request hostname)
  try {
    const requestHost = new URL(url).hostname.toLowerCase();
    const sanList = Array.isArray(secDetails.sanList) ? secDetails.sanList : [];
    const commonName = String(secDetails.subjectName || "").toLowerCase();

    const matchesSAN = sanList.some(san => {
      const s = String(san).toLowerCase();
      if (s === requestHost) return true;
      if (s.startsWith("*.")) {
        const base = s.slice(2);
        return requestHost.endsWith("." + base) || requestHost === base;
      }
      return false;
    });
    const matchesCN = commonName && (
      commonName === requestHost ||
      (commonName.startsWith("*.") && requestHost.endsWith("." + commonName.slice(2)))
    );

    if (!matchesSAN && !matchesCN && (sanList.length > 0 || commonName)) {
      signals.push("domain_mismatch");
    }
  } catch {}

  // 6. Weak encryption (deprecated cipher / protocol)
  const cryptoStr = [
    secDetails.cipher || "",
    secDetails.keyExchangeGroup || "",
    secDetails.protocol || "",
  ].join(" ");

  if (_WEAK_CIPHER_PATTERNS.some(p => cryptoStr.includes(p))) {
    signals.push("weak_encryption");
  }

  // 7. Mixed content (checked via _MIXED_CONTENT_CACHE, populated separately)
  if (tabId !== undefined && _MIXED_CONTENT_CACHE.has(tabId)) {
    const httpResources = _MIXED_CONTENT_CACHE.get(tabId);
    if (httpResources && httpResources.size > 0) {
      signals.push("mixed_content");
    }
  }

  if (signals.length > 0) {
    console.log("[Sentinel-SSL]", {
      url: url.slice(0, 80),
      signals,
      protocol: secDetails.protocol || "?",
      cipher:   (secDetails.cipher  || "?").slice(0, 40),
    });
  }

  return signals;
}

/**
 * Drains and returns any SSL signals cached for this URL+tab.
 * Consumes the cache entry (deletes it) so signals inject exactly once.
 *
 * @param {string} url   - normalized URL key
 * @param {number} tabId - tab ID for mixed-content lookup
 * @returns {string[]}
 */
function consumeSSLSignals(url, tabId) {
  const cached = _SSL_CACHE.get(url);
  _SSL_CACHE.delete(url);
  const fromCache = cached ? cached.signals : analyzeSSL(url, null, tabId);
  return Array.isArray(fromCache) ? fromCache : [];
}

// webRequest.onHeadersReceived — capture securityDetails per main-frame URL
// Fires after the TLS handshake is complete and response headers arrive.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.frameId !== 0) return;
    if (!details.url.startsWith("https://")) return;

    const secDetails  = details.securityDetails || null;
    const sslSignals  = analyzeSSL(details.url, secDetails, details.tabId);

    if (sslSignals.length > 0) {
      _SSL_CACHE.set(details.url, { signals: sslSignals, details: secDetails });
    }

    // Clear mixed-content log for this tab when a new HTTPS main page loads
    _MIXED_CONTENT_CACHE.delete(details.tabId);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

// webRequest.onBeforeRequest — detect mixed content (HTTP sub-resources on HTTPS pages)
// Purely observational — does NOT use blocking mode.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === "main_frame") return;
    if (!details.url.startsWith("http://")) return;
    const tabId = details.tabId;
    if (tabId < 0) return;

    if (!_MIXED_CONTENT_CACHE.has(tabId)) {
      _MIXED_CONTENT_CACHE.set(tabId, new Set());
    }
    _MIXED_CONTENT_CACHE.get(tabId).add(details.url.slice(0, 120));
  },
  { urls: ["http://*/*"] }
);

// Housekeeping: clear mixed-content cache on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  _MIXED_CONTENT_CACHE.delete(tabId);
});

