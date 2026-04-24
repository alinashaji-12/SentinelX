/**
 * detectionEngine.js — Sentinel Browse Extension v2.0
 *
 * SELF-CONTAINED SYNCHRONOUS URL THREAT DETECTOR
 * ═══════════════════════════════════════════════════════════════════
 *
 * STRICT DESIGN RULES:
 *   ✓ ZERO imports — this file is a standalone script for the service worker
 *   ✓ ZERO async/await — every function returns synchronously in <5ms
 *   ✓ ZERO network calls — purely local, offline-capable analysis
 *   ✓ Fail-open — any unhandled error returns { status: "safe" }
 *   ✓ Single output contract — all paths return the SAME shape
 *
 * PIPELINE (ordered by cost — cheap checks short-circuit first):
 *   1.  normalizeUrl()         — multi-pass decode, lowercase, strip hash
 *   2.  checkTrusted()         — O(1) set lookup → immediate safe exit
 *   3.  checkDataset()         — O(1) set lookup → immediate malicious exit
 *   4.  checkIpAddress()       — IPv4 + IPv6 → malicious exit
 *   5.  checkPunycode()        — homoglyph risk +3
 *   6.  checkHomoglyphs()      — Cyrillic/Greek → ASCII normalization
 *   7.  checkTLD()             — weighted TLD risk score
 *   8.  checkDomainStructure() — hyphens, depth, hostname length
 *   9.  checkEntropy()         — Shannon entropy PER LABEL
 *   10. checkTyposquatting()   — Levenshtein with length guard
 *   11. checkKeywords()        — phishing keyword × urgency intent
 *   12. checkBrandPlacement()  — brand token in non-root subdomain
 *   DECISION MATRIX            — weighted threshold classification
 *
 * OUTPUT CONTRACT:
 * {
 *   status:     "safe" | "suspicious" | "malicious",
 *   score:      number,      // raw weighted score
 *   confidence: number,      // 0-100
 *   trustScore: number,      // 0-100 (inverse of risk)
 *   attackType: string,      // SAFE | PHISHING | MALWARE | OBFUSCATED_URL | BRAND_IMPERSONATION
 *   reason:     string,      // concatenated human-readable reason
 *   reasons:    string[],    // individual reason strings
 *   signals:    string[],    // short signal labels for UI chips
 *   sources:    object[],    // per-module breakdown for transparency panel
 *   appliedRule: string      // which decision branch was taken
 * }
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════
// SECTION 1 — STATIC DATA SETS
// ═══════════════════════════════════════════════════════════════════

/**
 * Tier-1 trusted root domains (eTLD+1).
 * Matching is EXACT root-domain only — subdomains are derived.
 * "google.com.evil.xyz" → root = "evil.xyz" → NOT trusted.
 * 
 * CRITICAL: Trusted domains bypass ALL scoring. If a login form appears
 * on a trusted domain, it is SAFE. On non-trusted domains, a login form
 * requires additional suspicious indicators (brand mismatch, high-risk TLD, etc.)
 */
const TRUSTED_ROOT_DOMAINS = new Set([
  "google.com", "googleapis.com", "googlevideo.com", "gstatic.com",
  "youtube.com", "youtu.be",
  "bing.com", "microsoft.com", "microsoftonline.com",
  "live.com", "outlook.com", "office.com", "office365.com",
  "sharepoint.com", "azure.com", "azurewebsites.net",
  "github.com", "githubusercontent.com", "githubassets.com", "npmjs.com",
  "apple.com", "icloud.com", "mzstatic.com",
  "amazon.com", "amazonaws.com", "cloudfront.net",
  "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
  "twitter.com", "x.com", "twimg.com",
  "linkedin.com", "licdn.com",
  "wikipedia.org", "wikimedia.org",
  "reddit.com", "redd.it", "redditmedia.com",
  "stackoverflow.com", "stackexchange.com",
  "cloudflare.com", "cloudflare.net",
  "openai.com", "chatgpt.com",
  "stripe.com", "paypal.com",
  "netflix.com", "nflximg.com",
  "medium.com", "wordpress.org", "wordpress.com",
  "mozilla.org", "firefox.com",
  "duckduckgo.com", "yahoo.com", "baidu.com",
  "gov.in", "nic.in",
  // Indian educational institutions (christuniversity.in, etc.)
  "christuniversity.in", "du.ac.in", "iit.ac.in", "iitb.ac.in",
  "iitd.ac.in", "iitm.ac.in", "bits-pilani.ac.in", "vtu.ac.in",
]);

const TRUSTED_DOMAINS = [
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "edu",
  "gov",
  // Indian academic TLD patterns
  "ac.in",
  "edu.in",
  "org.in",
];

/**
 * Search engine hosts — bypass keyword scoring for query parameters.
 */
const SEARCH_ENGINE_HOSTS = new Set([
  "google.com", "www.google.com",
  "bing.com", "www.bing.com",
  "search.yahoo.com", "www.yahoo.com",
  "duckduckgo.com", "www.duckduckgo.com",
  "search.brave.com", "ecosia.org",
  "startpage.com", "baidu.com",
]);

/**
 * Known phishing/malware root domains (eTLD+1).
 * Subdomain hits are caught via root-domain extraction.
 */
const PHISHING_DATASET = new Set([
  // Financial
  "paypal-login-secure.com", "paypa1-account.com",
  "paypal-update-required.net", "paypal-secure-login.xyz",
  "amazon-update-account.xyz", "amazon-account-alert.net",
  "amazon-prime-verify.com", "amazon-security-notice.com",
  "banking-verify-now.com", "secure-bankofamerica.com",
  "bankofamerica-alert.net", "chase-security-alert.com",
  "wells-fargo-verify.net", "citibank-update-alert.com",
  // Social media
  "facebook-verification.net", "facebook-login-secure.com",
  "instagram-verify-account.com", "twitter-support-team.com",
  "linkedin-security-notice.net",
  // Tech / crypto
  "apple-id-verify.com", "apple-account-locked.net",
  "microsoft-support-alert.com", "google-account-recovery.xyz",
  "metamask-security.net", "coinbase-verify.net",
  "binance-secure-login.com", "crypto-wallet-recover.xyz",
  "nft-mint-free.xyz", "opensea-verify.net",
  // Generic phishing templates
  "malicious.com", "phishing-site.net",
  "secure-verify-login.com", "account-suspended-alert.com",
  "free-gift-claim.xyz", "prize-winner-claim.net",
  "urgent-action-required.com", "click-here-reward.xyz",
  "yourpackage-pending.com", "parcel-delivery-failed.net",
  "login-secure-update.com", "verify-account-now.xyz",
  "login-secure-account.xyz",
]);

/**
 * High-risk TLDs — disproportionately abused in phishing/malware.
 * Ordered by abuse prevalence.
 */
const HIGH_RISK_TLDS = new Set([
  // Free/near-free registrars with weak abuse controls
  "xyz", "tk", "ml", "ga", "cf", "gq", "pw",
  // High-abuse generic TLDs
  "top", "club", "online", "site", "web", "space", "store",
  // Country TLDs with abuse issues
  "ru", "cn", "cc", "ws", "su", "to",
  // Aggressive new gTLDs
  "info", "biz", "click", "link", "live", "stream",
  // Google-released gTLDs being abused for phishing
  "zip", "mov",
]);

/**
 * Phishing credential-harvesting keywords — checked in HOSTNAME tokens.
 */
const PHISHING_KEYWORDS = new Set([
  "login", "signin", "logon", "signup",
  "verify", "verification", "validate", "validation",
  "account", "accounts",
  "secure", "security",
  "password", "passwd", "credential", "credentials",
  "wallet", "banking", "bank",
  "confirm", "confirmation",
  "update", "upgrade",
  "recover", "recovery", "restore",
  "suspend", "suspended", "blocked",
  "appleid",
]);

/**
 * Urgency/pressure words — must co-occur with a keyword for intent flag.
 * Reduces false positives vs standalone keyword matching.
 */
const URGENCY_WORDS = new Set([
  "urgent", "urgently",
  "immediately", "immediate",
  "now", "asap",
  "alert", "warning", "critical",
  "expire", "expires", "expiring", "expired",
  "limited", "action", "locked", "lock",
  "unusual", "activity", "deadline", "required",
]);

/**
 * Brand names used for typosquatting and placement detection.
 * Ordered by phishing target frequency.
 */
const BRAND_NAMES = [
  "paypal", "google", "amazon", "apple", "microsoft",
  "facebook", "instagram", "twitter", "netflix",
  "coinbase", "metamask", "binance", "chase", "wellsfargo",
];

/**
 * Compound brand tokens — adjacent token pairs that together form a brand.
 * Used to detect hyphenated brand domains like wells-fargo-verify.net.
 * Key: "token1+token2" → brand name
 */
const COMPOUND_BRANDS = {
  "wells+fargo": "wellsfargo",
  "bank+america": "bankofamerica",
  "bank+of": "bankofamerica",
};

/**
 * Known URL shortener domains.
 * We cannot know the redirect destination without following the URL.
 * Flag as suspicious — user should verify destination.
 */
const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
  "is.gd", "buff.ly", "adf.ly", "short.link", "shorturl.at",
  "rb.gy", "cutt.ly", "tiny.cc", "v.gd", "bl.ink",
  "clck.ru", "qr.ae", "yourls.org",
]);

/**
 * Query parameter names commonly used for open redirect attacks.
 * Used by checkNestedUrl() to extract embedded destination URLs.
 */
const REDIRECT_PARAMS = new Set([
  "url", "next", "redirect", "redirect_url", "redirect_uri",
  "return", "return_url", "returnurl", "goto", "destination",
  "target", "link", "ref", "referer", "continue", "forward",
]);

/**
 * Homoglyph normalization map — Cyrillic, Greek, and special characters
 * that are visually identical to Latin ASCII characters.
 * Maps Unicode codepoint → ASCII equivalent.
 */
// VULN-01 FIX: Removed duplicate \u0440 key (JS silently drops the first
// definition). Cyrillic р (\u0440) maps to "r". Cyrillic р was incorrectly
// duplicated. Added comprehensive set of confirmed visual lookalikes.
const HOMOGLYPH_MAP = {
  // ── Cyrillic → Latin ──────────────────────────────────────────────
  "\u0430": "a",  // а Cyrillic small A → a
  "\u0435": "e",  // е Cyrillic small E → e
  "\u043e": "o",  // о Cyrillic small O → o
  "\u0440": "r",  // р Cyrillic small R → r  (NOT 'p' — was duplicated)
  "\u0441": "c",  // с Cyrillic small C → c
  "\u0445": "x",  // х Cyrillic small X → x
  "\u0456": "i",  // і Ukrainian small I → i
  "\u0457": "i",  // ї Ukrainian small YI → i
  "\u0458": "j",  // ј Cyrillic small J → j
  "\u0455": "s",  // ѕ Cyrillic small DZE → s
  "\u0501": "d",  // ԁ Cyrillic small KOMI DE → d
  "\u0073": "s",  // Included for completeness
  // ── Greek → Latin ─────────────────────────────────────────────────
  "\u03bf": "o",  // ο Greek small Omicron → o
  "\u03c1": "p",  // ρ Greek small Rho → p (visual match)
  "\u03b5": "e",  // ε Greek small Epsilon → e
  "\u03b1": "a",  // α Greek small Alpha → a
  "\u03bd": "v",  // ν Greek small Nu → v
  // ── Latin Extended → ASCII ────────────────────────────────────────
  "\u0261": "g",  // ɡ Latin small script G → g
  "\u01e5": "g",  // ǥ Latin small G with stroke → g
  "\u0275": "o",  // ɵ Latin small barred O → o
  "\u0269": "i",  // ɩ Latin small Iota → i
  // ── Digit→Letter leet substitutions (attacker-style) ──────────────
  // NOTE: Applied ONLY in the typosquatting path (normalizeHomoglyphs)
  // to avoid false-positives on legitimate domains with numbers.
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
};

// ═══════════════════════════════════════════════════════════════════
// SECTION 2 — URL NORMALIZATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Performs multi-pass URL normalization to defeat encoding tricks.
 *
 * Handles:
 *   - Single encoding:  %2F → /
 *   - Double encoding:  %252F → %2F → /
 *   - Mixed case:       HTTP://EVIL.COM → http://evil.com
 *   - Hash stripping:   example.com/path#fragment → example.com/path
 *   - Null bytes:       %00 stripped
 *
 * @param {string} rawUrl
 * @returns {{ normalized: string, parsed: URL|null, wasEncoded: boolean }}
 */
function normalizeUrl(rawUrl) {
  let url = String(rawUrl || "").trim();
  let wasEncoded = false;
  const MAX_DECODE_PASSES = 4;

  // Multi-pass decode until stable
  for (let pass = 0; pass < MAX_DECODE_PASSES; pass++) {
    try {
      const decoded = decodeURIComponent(url);
      if (decoded === url) break; // Idempotent — stable
      url = decoded;
      wasEncoded = true;
    } catch {
      break; // Malformed encoding — stop
    }
  }

  // Strip null bytes injected via %00
  url = url.replace(/\x00/g, "");

  // Lowercase the scheme and host (path case preserved for accuracy)
  try {
    const p = new URL(url);
    p.hash = ""; // Strip fragment — never sent to server
    // Reconstruct with lowercase protocol + host
    url = p.protocol.toLowerCase() + "//" + p.host.toLowerCase() + p.pathname + p.search;
  } catch {
    // Not a parseable URL — return as-is (will fail later checks gracefully)
  }

  let parsed = null;
  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  return { normalized: url, parsed, wasEncoded };
}

/**
 * Extracts the eTLD+1 root domain from a full hostname.
 * Handles common two-part TLDs (co.uk, com.au, gov.in, etc.)
 *
 * @param {string} hostname — lowercase hostname
 * @returns {string}
 */
function getRootDomain(hostname) {
  if (!hostname) return "";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname; // IPv4 passthrough

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;

  const DOUBLE_TLDS = new Set([
    "co.uk", "co.in", "co.nz", "co.jp", "co.za",
    "com.au", "com.br", "com.sg", "com.my", "com.hk",
    "gov.uk", "gov.in", "gov.au", "gov.sg",
    "org.uk", "net.uk", "ac.uk", "edu.au",
  ]);

  const lastTwo = parts.slice(-2).join(".");
  if (DOUBLE_TLDS.has(lastTwo)) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

/**
 * Applies homoglyph normalization to a token.
 * Used BEFORE brand comparison to catch Unicode-based spoofing.
 *
 * @param {string} token
 * @returns {string} ASCII-normalized token
 */
function normalizeHomoglyphs(token) {
  return Array.from(String(token || "")).map(ch => HOMOGLYPH_MAP[ch] || ch).join("");
}

/**
 * Tokenizes a string on non-alphanumeric boundaries → lowercase tokens.
 * @param {string} text
 * @returns {string[]}
 */
function tokenize(text) {
  return String(text || "").toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length > 0);
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 3 — SIGNAL DETECTORS
// ═══════════════════════════════════════════════════════════════════

/**
 * SIGNAL 1: Trusted domain check.
 * O(1) lookup — must be the FIRST check to prevent false positives on
 * trusted domains that contain phishing keywords (e.g. accounts.google.com/signin)
 *
 * @param {string} hostname
 * @returns {boolean}
 */
function checkTrusted(hostname) {
  if (!hostname) return false;
  const root = getRootDomain(hostname);
  if (TRUSTED_ROOT_DOMAINS.has(root)) return true;
  // Direct hostname match for explicitly listed domains
  if (TRUSTED_ROOT_DOMAINS.has(hostname)) return true;
  return TRUSTED_DOMAINS.some(domain => {
    // Handle TLD-only patterns like "edu", "gov", "ac.in"
    if (domain.includes(".")) {
      // Multi-part pattern (e.g. "ac.in") — match as suffix
      return root.endsWith(`.${domain}`) || root === domain ||
             hostname.endsWith(`.${domain}`) || hostname === domain;
    }
    return domain === "edu" || domain === "gov"
      ? root.endsWith(`.${domain}`) || root === domain
      : root === domain || root.endsWith(`.${domain}`);
  });
}

/**
 * SIGNAL 2: Search engine query check.
 * Prevents flagging google.com/search?q=login+verify+account
 *
 * @param {string} hostname
 * @param {string} pathname
 * @param {string} search
 * @returns {boolean}
 */
function checkSearchEngine(hostname, pathname, search) {
  if (!SEARCH_ENGINE_HOSTS.has(hostname)) return false;
  const path = (pathname || "").toLowerCase();
  const qs = (search || "").toLowerCase();
  return (
    path === "/" ||
    path.startsWith("/search") ||
    path.startsWith("/find") ||
    path.startsWith("/webhp") ||
    qs.includes("q=") ||
    qs.includes("query=") ||
    qs.includes("p=")
  );
}

/**
 * SIGNAL 3: Phishing dataset match.
 * O(1) — best bang-for-buck detection. Hard malicious exit.
 *
 * @param {string} hostname
 * @returns {{ flag: boolean, domain: string }}
 */
function checkDataset(hostname) {
  const root = getRootDomain(hostname);
  if (PHISHING_DATASET.has(root)) return { flag: true, domain: root };
  if (PHISHING_DATASET.has(hostname)) return { flag: true, domain: hostname };
  return { flag: false, domain: "" };
}

/**
 * SIGNAL 4: IP address detection (IPv4 + IPv6).
 * Legitimate sites almost never use raw IPs. Direct-IP access is a strong
 * indicator of phishing infrastructure avoiding DNS attribution.
 *
 * @param {string} hostname
 * @returns {{ isIpv4: boolean, isIpv6: boolean, isIp: boolean }}
 */
function checkIpAddress(hostname) {
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  // Match IPv6 in URL: [::1] → hostname is "::1" in URL spec
  const isIpv6 = /^(?:[0-9a-f:]+)$/i.test(hostname) && hostname.includes(":");
  return { isIpv4, isIpv6, isIp: isIpv4 || isIpv6 };
}

/**
 * SIGNAL 5: Punycode detection.
 * xn-- prefixed labels indicate internationalized domain names, which are
 * routinely abused for homograph attacks (аpple.com vs apple.com).
 *
 * @param {string} hostname
 * @returns {{ flag: boolean, labels: string[] }}
 */
function checkPunycode(hostname) {
  const punycodeLabels = hostname.split(".").filter(l => l.startsWith("xn--"));
  return { flag: punycodeLabels.length > 0, labels: punycodeLabels };
}

/**
 * SIGNAL 6: TLD risk scoring.
 * Returns score contribution and whether TLD is high-risk.
 *
 * Weight rationale:
 *   TLDs like .tk, .ml are virtually free → almost exclusively used by attackers
 *   .xyz, .top, .club have high abuse-to-registration ratios
 *   Score +3 chosen to be meaningful without single-handedly triggering blocks
 *
 * @param {string} hostname
 * @returns {{ score: number, tld: string, isHighRisk: boolean }}
 */
function checkTLD(hostname) {
  const parts = hostname.split(".");
  const tld = parts.length >= 2 ? parts[parts.length - 1].toLowerCase() : "";
  if (tld && HIGH_RISK_TLDS.has(tld)) {
    return { score: 3, tld, isHighRisk: true };
  }
  return { score: 0, tld, isHighRisk: false };
}

/**
 * SIGNAL 7: Domain structure analysis.
 * Detects structural patterns common in phishing domains:
 *   - Many hyphens: "paypal-secure-login-update.com" (brand + action words)
 *   - Deep subdomains: "login.verify.account.update.evil.com"
 *   - Long hostnames: harder to read and verify manually
 *
 * @param {string} hostname
 * @returns {{ score: number, signals: string[], reasons: string[] }}
 */
function checkDomainStructure(hostname) {
  const signals = [];
  const reasons = [];
  let score = 0;

  // Hyphen analysis
  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens >= 4) {
    score += 3;
    signals.push("Excessive hyphens");
    reasons.push(`Very high hyphen count (${hyphens}) — common in brand impersonation`);
  } else if (hyphens >= 3) {
    score += 2;
    signals.push("Heavy hyphen use");
    reasons.push(`Heavy hyphen use (${hyphens} hyphens) — common in phishing`);
  } else if (hyphens >= 2) {
    score += 1;
    signals.push("Multiple hyphens");
    reasons.push(`Multiple hyphens (${hyphens}) in domain`);
  }

  // Subdomain depth
  const labels = hostname.split(".").filter(Boolean);
  const depth = labels.length;
  if (depth >= 6) {
    score += 3;
    signals.push("Very deep subdomains");
    reasons.push(`Extreme subdomain depth (${depth} labels) — evasion technique`);
  } else if (depth >= 5) {
    score += 2;
    signals.push("Deep subdomain nesting");
    reasons.push(`Deep subdomain nesting (${depth} labels)`);
  } else if (depth === 4) {
    score += 1;
    signals.push("Elevated subdomain depth");
    reasons.push("Elevated subdomain depth (4 labels)");
  }

  // Hostname length
  if (hostname.length > 60) {
    score += 2;
    signals.push("Very long hostname");
    reasons.push(`Very long hostname (${hostname.length} chars) — obfuscation`);
  } else if (hostname.length > 40) {
    score += 1;
    signals.push("Long hostname");
    reasons.push(`Unusually long hostname (${hostname.length} chars)`);
  }

  return { score, signals, reasons };
}

/**
 * SIGNAL 8: Shannon entropy per label.
 *
 * Why per-label and not full hostname?
 *   • "cdn.a1b2c3d4.net" — subdomain has high entropy, second-level is normal
 *   • "google.com" — low entropy per label, trusted (already caught by check 1)
 *   • "sx7f2ab.phishing.xyz" — first label srores very high entropy
 *
 * Shannon entropy formula: H = -Σ(p(c) * log2(p(c)))
 * Phishing infrastructure automation tends to generate high-entropy subdomain
 * labels (random strings). Legitimate services use memorable names.
 *
 * Threshold: 3.5 bits/char for suspicious, 4.0 for high (calibrated empirically)
 *
 * @param {string} hostname
 * @returns {{ score: number, maxLabelEntropy: number, signals: string[], reasons: string[] }}
 */
// VULN-02 FIX: Previously skipped entropy analysis entirely for 2-part
// domains (e.g. ax7f2kz9.xyz). DGA domains are commonly 2-part (random SLD
// + high-risk TLD). Now evaluates SLD entropy with a higher threshold (3.8)
// to avoid false-positives on short legitimate SLDs.
function checkEntropy(hostname) {
  const signals = [];
  const reasons = [];
  let score = 0;
  let maxLabelEntropy = 0;

  const labels = hostname.split(".").filter(Boolean);

  // Strategy:
  //   labels > 2: check only subdomain labels (not SLD or TLD) at threshold 3.5/4.0
  //   labels == 2: check the SLD with HIGHER threshold (3.8) to reduce FPs on
  //                legit short domains (t.co, bit.ly) while catching DGA (ax7f2kz9.xyz)
  //   labels == 1: no meaningful entropy check
  let checkLabels;
  let useStrictThreshold = false;

  if (labels.length > 2) {
    checkLabels = labels.slice(0, -2); // subdomain labels only
    useStrictThreshold = false;
  } else if (labels.length === 2) {
    checkLabels = [labels[0]]; // SLD only, stricter threshold
    useStrictThreshold = true;
  } else {
    checkLabels = [];
  }

  for (const label of checkLabels) {
    if (label.length < 6) continue; // Too short for meaningful entropy
    const entropy = shannonEntropy(label);
    if (entropy > maxLabelEntropy) maxLabelEntropy = entropy;
  }

  // Thresholds:
  //   Subdomain labels:  4.0 (high), 3.5 (elevated)
  //   SLD (2-part domain): 3.8 (high only — no "elevated" tier to reduce FPs)
  const highThreshold = useStrictThreshold ? 3.8 : 4.0;
  const elevatedThreshold = useStrictThreshold ? 99 : 3.5; // Disable elevated for 2-part

  if (maxLabelEntropy >= highThreshold) {
    score += 3;
    signals.push("High-entropy domain label");
    reasons.push(`High-entropy domain label (${maxLabelEntropy.toFixed(2)} bits) — probable DGA/random generation`);
  } else if (maxLabelEntropy >= elevatedThreshold) {
    score += 1;
    signals.push("Elevated entropy subdomain");
    reasons.push(`Elevated subdomain entropy (${maxLabelEntropy.toFixed(2)} bits)`);
  }

  return { score, maxLabelEntropy, signals, reasons };
}

/**
 * SIGNAL 8b: Domain age estimation (heuristic).
 *
 * Real domain-age lookups require WHOIS/DNS history (network calls). This engine
 * is intentionally offline/synchronous, so we approximate "likely new" domains
 * using local properties that correlate with throwaway registrations.
 *
 * Heuristics:
 *   - Random-looking SLD (high entropy / digits-heavy / long)
 *   - High-abuse TLD combined with a bare 2-label hostname (no subdomain depth)
 *
 * @param {string} hostname
 * @returns {{ score: number, isLikelyNew: boolean, signals: string[], reasons: string[] }}
 */
function checkDomainAgeHeuristic(hostname) {
  const signals = [];
  const reasons = [];
  let score = 0;
  let isLikelyNew = false;

  const labels = String(hostname || "").split(".").filter(Boolean);
  if (labels.length < 2) return { score: 0, isLikelyNew: false, signals: [], reasons: [] };

  const sld = labels[labels.length - 2] || "";
  const tld = String(labels[labels.length - 1] || "").toLowerCase();

  // Heuristic A: random-looking SLD
  if (sld.length >= 10) {
    const digits = (sld.match(/\d/g) || []).length;
    const entropy = shannonEntropy(sld);
    const looksRandom = entropy >= 3.6 || (digits >= 2 && entropy >= 3.2);

    if (looksRandom) {
      score += 2;
      isLikelyNew = true;
      signals.push("domainAgeHeuristicNew");
      reasons.push(`Domain age heuristic: random-looking SLD "${sld}" (entropy ${entropy.toFixed(2)})`);
    }
  }

  // Heuristic B: uncommon/high-abuse TLD + no subdomain depth (2 labels)
  if (HIGH_RISK_TLDS.has(tld) && labels.length === 2) {
    score += 1;
    isLikelyNew = true;
    signals.push("domainAgeHeuristicNew");
    reasons.push(`Domain age heuristic: bare domain on high-abuse TLD (.${tld})`);
  }

  return { score, isLikelyNew, signals, reasons };
}

/**
 * Computes Shannon entropy of a string in bits per character.
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * SIGNAL 9: Typosquatting detection (Levenshtein with length guard).
 *
 * Length guard rationale:
 *   Without it, "a" vs "google" gives distance=5 (meaningless/expensive).
 *   We only compare tokens where |len(token) - len(brand)| <= 2.
 *   This eliminates ~80% of comparisons and eliminates false positives.
 *
 * Homoglyph normalization applied BEFORE Levenshtein so that
 *   "аpple" (Cyrillic а) correctly matches "apple" at distance 0.
 *
 * @param {string} hostname
 * @returns {{ score: number, hit: boolean, token: string, brand: string, distance: number, signals: string[], reasons: string[] }}
 */
// VULN-06 FIX: Added compound brand detection. Hyphenated domains like
// wells-fargo-verify.net tokenize to ["wells","fargo","verify","net"].
// Neither "wells" nor "fargo" individually matches "wellsfargo" within
// the length guard. Adjacent token pairs are now checked against COMPOUND_BRANDS.
function checkTyposquatting(hostname) {
  const signals = [];
  const reasons = [];
  let score = 0;
  let best = { hit: false, token: "", brand: "", distance: 99, normalized: "" };

  const tokens = tokenize(hostname);

  // ── Single-token Levenshtein check ───────────────────────────────
  for (const rawToken of tokens) {
    if (rawToken.length < 4) continue;
    const token = normalizeHomoglyphs(rawToken);

    for (const brand of BRAND_NAMES) {
      if (Math.abs(token.length - brand.length) > 2) continue;
      if (token === brand) continue; // Exact match → brand placement, not typosquat

      const dist = levenshtein(token, brand);
      if (dist <= 1 && dist < best.distance) {
        best = { hit: true, token: rawToken, brand, distance: dist, normalized: token };
      } else if (dist === 2 && dist < best.distance && token.length >= 6) {
        best = { hit: true, token: rawToken, brand, distance: dist, normalized: token };
      }
    }
  }

  // ── Adjacent-token compound check (e.g. wells+fargo → wellsfargo) ─
  for (let i = 0; i < tokens.length - 1; i++) {
    const compoundKey = tokens[i] + "+" + tokens[i + 1];
    const compoundBrand = COMPOUND_BRANDS[compoundKey];
    if (compoundBrand) {
      // Found a compound brand — check if the full hostname root is NOT the
      // canonical brand domain (e.g. wellsfargo.com is trusted)
      // If we're here, trusted check already passed, so root is NOT trusted.
      if (best.distance > 0) { // Only override if no exact-single-token match
        best = {
          hit: true,
          token: tokens[i] + "-" + tokens[i + 1],
          brand: compoundBrand,
          distance: 0,
          normalized: compoundBrand,
        };
      }
    }
  }

  if (best.hit) {
    score += 4;
    signals.push("Brand typosquatting");
    reasons.push(
      `Typosquatting detected: "${best.token}" → "${best.brand}" (edit distance ${best.distance})`
    );
  }

  return { score, ...best, signals, reasons };
}

/**
 * Levenshtein distance — Wagner-Fischer algorithm.
 * O(m×n) time, O(n) space.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshtein(a, b) {
  const la = a.length;
  const lb = b.length;
  if (a === b) return 0;
  if (la === 0) return lb;
  if (lb === 0) return la;

  let row = Array.from({ length: lb + 1 }, (_, i) => i);

  for (let i = 1; i <= la; i++) {
    let prev = i - 1;
    row[0] = i;
    for (let j = 1; j <= lb; j++) {
      const temp = row[j];
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
      prev = temp;
    }
  }
  return row[lb];
}

/**
 * SIGNAL 10: Phishing keyword + urgency intent detection.
 *
 * Design:
 *   • Keywords alone (single) = weak signal (+1)
 *   • Multiple keywords in hostname = strong signal (+4, hasIntent)
 *   • Keyword + urgency anywhere in URL = strong intent (+4, hasIntent)
 *
 * Why check keywords in HOSTNAME only?
 *   Path keywords are too common in legitimate URLs (/account/login, /security/settings).
 *   Hostname-based keywords are much stronger signals since legitimate sites don't
 *   usually embed "verify-account" in their domain name.
 *
 * @param {string} hostname
 * @param {string} pathname
 * @param {string} fullUrl
 * @returns {{ score: number, hasIntent: boolean, keywords: string[], urgencyWords: string[], signals: string[], reasons: string[] }}
 */
function checkKeywords(hostname, pathname, fullUrl) {
  const hostnameTokens = tokenize(hostname);
  const allTokens = tokenize(fullUrl);

  const keywords = hostnameTokens.filter(t => PHISHING_KEYWORDS.has(t));
  const allUrgency = allTokens.filter(t => URGENCY_WORDS.has(t));

  const hasIntent = (keywords.length >= 1 && allUrgency.length >= 1) || keywords.length >= 2;

  let score = 0;
  const signals = [];
  const reasons = [];

  if (keywords.length >= 2 && allUrgency.length >= 1) {
    score += 5;
    signals.push("Keyword + urgency intent");
    reasons.push(`Strong phishing intent: keywords [${keywords.join(", ")}] + urgency [${allUrgency.join(", ")}]`);
  } else if (keywords.length >= 2) {
    score += 4;
    signals.push("Multi-keyword phishing");
    reasons.push(`Multi-keyword phishing hostname: [${keywords.join(", ")}]`);
  } else if (keywords.length === 1 && allUrgency.length >= 1) {
    score += 4;
    signals.push("Keyword + urgency intent");
    reasons.push(`Phishing intent: keyword [${keywords[0]}] + urgency [${allUrgency.join(", ")}]`);
  } else if (keywords.length === 1) {
    score += 1;
    signals.push("Single phishing keyword");
    reasons.push(`Phishing keyword in hostname (weak signal): ${keywords[0]}`);
  }

  return { score, hasIntent, keywords, urgencyWords: allUrgency, signals, reasons };
}

/**
 * SIGNAL 11: Brand placement in non-root subdomain.
 *
 * Detects attacks like: "paypal.evil-site.com" or "login.apple.verify-now.xyz"
 * where a trusted brand name appears in a subdomain but the actual root domain
 * is untrusted.
 *
 * This is distinct from typosquatting — here the brand name is spelled correctly
 * but placed to manipulate the user into trusting the subdomain.
 *
 * @param {string} hostname
 * @param {string} rootDomain
 * @returns {{ score: number, suspicious: boolean, brand: string, signals: string[], reasons: string[] }}
 */
// VULN-13 FIX: Previously used String.includes() which causes false positives
// for brand substrings ("amazonian" contains "amazon", "appliance" contains "apple").
// Now uses WHOLE-WORD TOKEN matching — "amazonian" tokenizes to ["amazonian"],
// which does NOT equal "amazon", preventing the false positive.
function checkBrandPlacement(hostname, rootDomain) {
  const signals = [];
  const reasons = [];
  let score = 0;
  let detectedBrand = "";

  const labels = hostname.split(".").filter(Boolean);
  const subdomainLabels = labels.slice(0, Math.max(0, labels.length - 2));

  // Tokenize the subdomain portion into discrete words
  // This prevents "amazonian" from matching "amazon"
  const subdomainTokens = new Set(tokenize(subdomainLabels.join(" ")));
  const rootLabel = rootDomain.split(".")[0] || "";
  const rootTokens = new Set(tokenize(rootLabel));

  for (const brand of BRAND_NAMES) {
    // Whole-word match only — token must EQUAL brand, not merely contain it
    const brandInSubdomain = subdomainTokens.has(brand);
    const brandInRoot = rootTokens.has(brand) && rootLabel !== brand;
    // Exact trusted roots: paypal.com, google.com, etc.
    const isExactTrustedRoot =
      rootDomain === brand + ".com" ||
      rootDomain === brand + ".net" ||
      rootDomain === brand + ".org";

    if (brandInSubdomain && !isExactTrustedRoot) {
      score += 3;
      detectedBrand = brand;
      signals.push("Brand in subdomain");
      reasons.push(`Suspicious brand placement: "${brand}" in subdomain of untrusted root "${rootDomain}"`);
      break;
    }

    if (brandInRoot && !isExactTrustedRoot) {
      score += 2;
      detectedBrand = brand;
      signals.push("Brand in root non-canonical");
      reasons.push(`Brand "${brand}" embedded in non-canonical root domain "${rootDomain}"`);
      break;
    }
  }

  return { score, suspicious: score > 0, brand: detectedBrand, signals, reasons };
}

/**
 * SIGNAL 12: URL shortener detection. (VULN-09 FIX)
 *
 * URL shorteners hide the real destination. We cannot follow the redirect
 * synchronously in the service worker — network calls are forbidden in
 * the blocking path. So we flag the shortener itself as suspicious to
 * force the user to verify the destination before proceeding.
 *
 * Known safe shorteners (used by trusted CDNs/brands) are whitelisted:
 *   - youtu.be  (YouTube) → caught by TRUSTED_ROOT_DOMAINS
 *   - redd.it   (Reddit)  → caught by TRUSTED_ROOT_DOMAINS
 *   - amzn.to   (Amazon)  → not in shortener set (legitimate brand shortener)
 *
 * @param {string} hostname
 * @param {string} rootDomain
 * @returns {{ score: number, isShortener: boolean, signals: string[], reasons: string[] }}
 */
function checkUrlShortener(hostname, rootDomain) {
  // First check root domain, then full hostname (handles www.tinyurl.com)
  const isShortener = URL_SHORTENERS.has(rootDomain) || URL_SHORTENERS.has(hostname);

  if (!isShortener) return { score: 0, isShortener: false, signals: [], reasons: [] };

  return {
    score: 2,
    isShortener: true,
    signals: ["URL shortener"],
    reasons: [
      `URL shortener detected (${hostname}) — destination URL unknown. ` +
      "Attackers use shorteners to hide malicious destinations.",
    ],
  };
}

/**
 * SIGNAL 13: Nested/embedded URL detection in query parameters. (VULN-03 FIX)
 *
 * Detects open-redirect patterns like:
 *   https://legit.com/?next=https://paypal-login.xyz/verify
 *
 * Attack: The outer domain (legit.com) may appear safe and even be trusted.
 * The REAL destination is in a redirect parameter. If that destination is
 * malicious, the user is silently sent there.
 *
 * We extract all redirect-param values that look like URLs, normalize them,
 * and run a limited check (trusted + dataset + IP only) to avoid costly
 * full analysis on every query parameter.
 *
 * @param {URLSearchParams|null} searchParams
 * @returns {{ score: number, hasNestedThreat: boolean, nestedUrl: string, signals: string[], reasons: string[] }}
 */
function checkNestedUrl(searchParams) {
  if (!searchParams) return { score: 0, hasNestedThreat: false, nestedUrl: "", signals: [], reasons: [] };

  for (const [key, value] of searchParams.entries()) {
    // Only inspect known redirect parameters
    if (!REDIRECT_PARAMS.has(key.toLowerCase())) continue;
    // Only inspect values that look like URLs
    if (!value || !value.includes(".")) continue;

    let nestedUrl = value;
    // Add scheme if missing (some redirects omit it: ?next=evil.com/login)
    if (!/^https?:\/\//i.test(nestedUrl)) {
      nestedUrl = "https://" + nestedUrl;
    }

    let nestedHostname = "";
    try {
      nestedHostname = new URL(nestedUrl).hostname.toLowerCase();
    } catch {
      continue; // Not a valid URL
    }

    if (!nestedHostname) continue;

    // Check 1: Is nested destination in our phishing dataset?
    const datasetHit = checkDataset(nestedHostname);
    if (datasetHit.flag) {
      return {
        score: 8,
        hasNestedThreat: true,
        nestedUrl,
        signals: ["Phishing redirect chain"],
        reasons: [
          `Open redirect to known phishing domain: "${nestedHostname}" ` +
          `(matched phishing database) via query param "${key}"`
        ],
      };
    }

    // Check 2: Is nested destination using a raw IP?
    const ipHit = checkIpAddress(nestedHostname);
    if (ipHit.isIp) {
      return {
        score: 6,
        hasNestedThreat: true,
        nestedUrl,
        signals: ["IP redirect chain"],
        reasons: [
          `Open redirect to raw IP address "${nestedHostname}" ` +
          `via query param "${key}" — phishing infrastructure pattern`
        ],
      };
    }

    // Check 3: Is nested destination a high-risk TLD with phishing keywords?
    const nestedRootDomain = getRootDomain(nestedHostname);
    const nestedTrusted = TRUSTED_ROOT_DOMAINS.has(nestedRootDomain);
    if (!nestedTrusted) {
      const nestedTld = checkTLD(nestedHostname);
      const nestedKeywords = checkKeywords(nestedHostname, "", nestedUrl);
      // Nested URL with a high-risk TLD AND phishing keyword = strong suspicious signal
      if (nestedTld.isHighRisk && nestedKeywords.score >= 4) {
        return {
          score: 5,
          hasNestedThreat: true,
          nestedUrl,
          signals: ["Suspicious redirect chain"],
          reasons: [
            `Open redirect to suspicious domain "${nestedHostname}" ` +
            `(high-risk TLD + phishing keywords) via query param "${key}"`
          ],
        };
      }
    }
  }

  return { score: 0, hasNestedThreat: false, nestedUrl: "", signals: [], reasons: [] };
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 4 — CLASSIFICATION & OUTPUT BUILDERS
// ═══════════════════════════════════════════════════════════════════

/**
 * CRITICAL: Signal Correlation Engine (v2.1)
 * ════════════════════════════════════════════════════════════════════
 * 
 * Implements strict correlation rules to reduce false positives:
 *   - Single LOW signal → DO NOT trigger alert
 *   - Single MEDIUM signal → only flag if HIGH confidence (score >= 4)
 *   - 1x HIGH confidence signal → trigger alert
 *   - 2x MEDIUM+ signals → trigger alert
 *   - HIGH confidence + urgency intent → trigger alert
 * 
 * Trusted domain modifier: All signals downgraded by 50% on trusted domains
 * 
 * Purpose: Prevent alerts on legitimate sites with innocent features:
 *   - Login forms on google.com, microsoft.com, etc. = SAFE (trusted)
 *   - Single keyword "verify" on legitimate domain = IGNORED
 *   - Multiple suspicious signals on untrusted domain = FLAGGED
 * 
 * @param {object} flags - Signal flags from analysis
 * @param {number} totalScore - Accumulated score
 * @param {boolean} isTrustedDomain - Whether domain is in TRUSTED_ROOT_DOMAINS
 * @returns {object} { shouldFlag, reason, severity }
 */
function correlateSignals(flags, totalScore, isTrustedDomain) {
  // Count high-confidence signals
  const highConfidenceSignals = [
    flags.isDataset,
    flags.isIp,
    flags.isPunycode && flags.hasIntent,
    flags.hasTyposquat && flags.hasIntent,
    flags.hasBrandPlacement && flags.hasIntent,
  ].filter(Boolean).length;

  // Count medium-confidence signals
  const mediumConfidenceSignals = [
    flags.hasHighRiskTLD && flags.hasIntent,
    flags.hasIntent,
    flags.hasDomainRisk && totalScore >= 4,
    flags.hasHighEntropy && flags.hasIntent,
  ].filter(Boolean).length;

  // Count low-confidence signals (isolated warnings without corroboration)
  const lowConfidenceSignals = [
    flags.hasDomainRisk && !flags.hasIntent,
    flags.hasHighRiskTLD && !flags.hasIntent,
    flags.isShortener,
  ].filter(Boolean).length;

  // ── Trusted domain modifier: downgrade all signals by 50% ──────────
  let adjustedScore = totalScore;
  let confidenceDowngrade = 0;
  if (isTrustedDomain) {
    adjustedScore = Math.floor(totalScore * 0.5);
    confidenceDowngrade = Math.floor(totalScore * 0.5);
    console.log(`[Sentinel] 🟢 Trusted domain — signals downgraded by ${confidenceDowngrade} (${totalScore} → ${adjustedScore})`);
  }

  // ── CRITICAL: Single LOW signal → DO NOT FLAG ─────────────────────
  if (lowConfidenceSignals === 1 && highConfidenceSignals === 0 && mediumConfidenceSignals === 0) {
    return {
      shouldFlag: false,
      reason: "Single low-confidence signal ignored per correlation rules",
      severity: "IGNORED",
      appliedRule: "SINGLE_LOW_SIGNAL",
    };
  }

  const isMalicious = (signals) => (
    Number(signals.highConfidence || 0) >= 1 ||
    Number(signals.mediumConfidence || 0) >= 2
  );

  if (isMalicious({
    highConfidence: highConfidenceSignals,
    mediumConfidence: mediumConfidenceSignals,
  })) {
    return {
      shouldFlag: true,
      reason: highConfidenceSignals >= 1
        ? `${highConfidenceSignals} high-confidence signal(s) detected`
        : `${mediumConfidenceSignals} medium-confidence signals correlated`,
      severity: adjustedScore >= 8 ? "MALICIOUS" : "SUSPICIOUS",
      appliedRule: highConfidenceSignals >= 1 ? "HIGH_CONFIDENCE_SIGNAL" : "MULTI_MEDIUM_SIGNAL",
    };
  }

  // ── Isolated signals on untrusted domain → Do not flag ──────────────
  if (adjustedScore < 3) {
    return {
      shouldFlag: false,
      reason: "Score below correlation threshold",
      severity: "SAFE",
      appliedRule: "LOW_SCORE",
    };
  }

  return {
    shouldFlag: false,
    reason: "Signals below malicious correlation threshold",
    severity: "SAFE",
    appliedRule: "CORRELATION_NOT_MET",
  };
}

/**
 * Classifies the attack type from collected signal booleans.
 * Used for UI display and downstream routing decisions.
 *
 * @param {object} flags
 * @returns {string}
 */
function classifyAttackType(flags) {
  const { isIp, isDataset, isPunycode, hasIntent, hasDomainRisk, hasObfuscation, hasTyposquat, hasBrandPlacement } = flags;

  if (isDataset) return "MALWARE";
  if (isIp) return "MALWARE";
  if (isPunycode && hasIntent) return "OBFUSCATED_URL";
  if (isPunycode) return "OBFUSCATED_URL";
  if (hasTyposquat && hasIntent) return "BRAND_IMPERSONATION";
  if (hasTyposquat) return "BRAND_IMPERSONATION";
  if (hasBrandPlacement && hasIntent) return "PHISHING";
  if (hasIntent && hasDomainRisk) return "PHISHING";
  if (hasIntent) return "PHISHING";
  if (hasDomainRisk) return "PHISHING";
  if (hasObfuscation) return "OBFUSCATED_URL";
  return "SAFE";
}

/**
 * Builds the structured output object.
 * All code paths through analyzeUrl() MUST call this function.
 * 
 * CRITICAL (v2.1): Implements risk score limiting:
 *   - Single signal max contribution: 30 points
 *   - Require multiple signals for scores > 60
 *   - Trusted domain downgrade: all scores × 0.5
 *
 * @param {string} status
 * @param {number} score
 * @param {string[]} reasons
 * @param {string[]} signals
 * @param {string} appliedRule
 * @param {object} flags
 * @returns {object}
 */
/**
 * Computes a soft (non-blocking) risk score for trusted domains.
 * Used by forceSafeResult() to produce a low but non-zero score.
 * @param {object[]} signals - array of signal objects with optional weight
 * @returns {number} 0-10
 */
function calculateSoftRisk(signals) {
  if (!Array.isArray(signals) || signals.length === 0) return 0;
  // Each signal contributes at most 2 points; cap total at 10
  return Math.min(10, signals.length * 2);
}

/**
 * TRUSTED DOMAIN HARD OVERRIDE (Task requirement §3)
 *
 * Returns a guaranteed-safe result for any trusted domain.
 * Risk is floored at 0 and capped at 10, showAlert is always false.
 *
 * @param {object[]} signals - collected signals (may be empty)
 * @param {boolean} trusted - whether the domain is trusted
 * @returns {object|null} safe result object, or null if not trusted
 */
function forceSafeResult(signals, trusted) {
  if (!trusted) return null;
  const softRisk = Math.min(10, calculateSoftRisk(signals));
  return {
    status: "safe",
    score: 0,
    confidence: Math.max(5, 10 - softRisk * 2),
    trustScore: Math.min(100, 100 - softRisk * 5),
    attackType: "SAFE",
    reason: "Trusted domain — hard override applied",
    reasons: ["Trusted domain — hard override applied"],
    signals: ["Trusted domain"],
    sources: [{ name: "Trust Engine", verdict: "safe", triggered: true, detail: "Domain in trusted set" }],
    appliedRule: "HARD_OVERRIDE_TRUSTED_DOMAIN",
    showAlert: false,
    risk: softRisk,
    breakdown: {
      "Domain Trust": "Verified trusted domain",
      "Behavior": "No suspicious behavior",
      "Content": "No malicious content signals",
      "Technical": "No technical anomalies",
    },
    signalFlags: {},
  };
}

function buildResult(status, score, reasons, signals, appliedRule, flags = {}) {
  // ── CAP 1: Single signal max 30 points ─────────────────────────────
  // This prevents one isolated signal from dominating the score
  let cappedScore = Math.min(score, 30);

  // ── CAP 2: All-LOW-confidence signals cap at 20 (Task requirement §4) ──
  // If every collected signal is low-confidence (structural only, no intent),
  // the maximum contribution is capped further.
  const hasAnyHighMediumSignal = flags.isDataset || flags.isIp || flags.isPunycode ||
    flags.hasTyposquat || flags.hasBrandPlacement || flags.hasIntent ||
    flags.hasNestedThreat || flags.isThreatIntel;
  if (!hasAnyHighMediumSignal && cappedScore > 20) {
    cappedScore = 20;
  }
  
  // Confidence: calibrated so score=0 → 5%, score=10 → 99%
  const rawConf = status === "safe"
    ? Math.max(5, 10 - cappedScore * 2)
    : Math.min(99, Math.max(40, 35 + cappedScore * 6 + signals.length * 3));

  const trustScore = status === "safe"
    ? Math.min(100, Math.max(70, 100 - cappedScore * 5))
    : Math.max(0, 100 - cappedScore * 10);

  const attackType = classifyAttackType(flags);

  // Build per-module sources for the transparency panel
  const sources = [];
  if (flags.isDataset) sources.push({ name: "Phishing Database", verdict: "malicious", triggered: true, detail: "Domain in known threats list" });
  if (flags.isIp) sources.push({ name: "IP Address Detection", verdict: "malicious", triggered: true, detail: "Raw IP used as host" });
  if (flags.isPunycode) sources.push({ name: "Obfuscation Analysis", verdict: "suspicious", triggered: true, detail: "Punycode/homoglyph domain" });
  if (flags.hasHighRiskTLD) sources.push({ name: "TLD Risk Analysis", verdict: "suspicious", triggered: true, detail: "High-risk TLD detected" });
  if (flags.hasTyposquat) sources.push({ name: "Typosquatting Detection", verdict: "malicious", triggered: true, detail: "Brand name misspelling" });
  if (flags.hasIntent) sources.push({ name: "Intent Analysis", verdict: "malicious", triggered: true, detail: "Phishing keyword + urgency" });
  if (flags.hasBrandPlacement) sources.push({ name: "Brand Placement Analysis", verdict: "suspicious", triggered: true, detail: "Brand in subdomain" });
  if (flags.hasDomainRisk) sources.push({ name: "Domain Structure Analysis", verdict: "suspicious", triggered: true, detail: "Structural anomalies" });
  if (flags.isShortener) sources.push({ name: "URL Shortener Detection", verdict: "suspicious", triggered: true, detail: "Destination unknown" });
  if (flags.hasNestedThreat) sources.push({ name: "Redirect Chain Analysis", verdict: "malicious", triggered: true, detail: "Phishing destination in redirect param" });
  if (sources.length === 0) {
    sources.push({ name: "Heuristic Engine", verdict: "safe", triggered: false, detail: "No threats identified" });
  }

  const safeReasons = Array.isArray(reasons)
    ? Array.from(new Set(reasons.filter(Boolean).map(r => String(r))))
    : [];
  const safeSignals = Array.isArray(signals)
    ? Array.from(new Set(signals.filter(Boolean).map(s => String(s))))
    : [];

  // ── XAI++ structured breakdown (Part 4) ─────────────────────────────
  // Derives a four-dimension human-readable breakdown from flags + signals.
  // Consumed by: popup dashboard, warning.html, and overlay reasons panel.
  const breakdown = {
    "Domain Trust":
      flags.isDataset       ? "Known phishing/malware domain" :
      flags.isThreatIntel   ? "Threat intel match (local database)" :
      flags.hasTyposquat    ? "Typosquatting — brand name misspelled" :
      flags.hasBrandPlacement ? "Brand name in subdomain (impersonation)" :
      flags.tldRiskHigh     ? "High-risk TLD abuse signal" :
      flags.hasHighRiskTLD  ? "High-risk TLD (." + (safeSignals.find(s => s.startsWith("High-risk"))?.split(".")[1]?.replace(")","") || "?") + ")" :
      flags.domainAgeHeuristicNew ? "Likely newly-registered / throwaway domain (heuristic)" :
      flags.hasDomainRisk   ? "Structural anomalies detected" :
      status === "safe"     ? "Trusted — no domain risk" :
                              "Unknown domain",

    "Behavior":
      flags.hasNestedThreat ? "Open redirect to malicious destination" :
      flags.isShortener     ? "URL shortener — destination hidden" :
      flags.isPunycode      ? "Punycode/homoglyph obfuscation" :
      flags.hasObfuscation  ? "URL encoding evasion detected" :
                              "No suspicious behavior",

    "Content":
      flags.isThreatIntelKeyword ? "Scam keywords detected in URL" :
      flags.scamContentDetected  ? "Scam keywords detected in page content" :
      flags.hasIntent            ? "Phishing keywords + urgency signals" :
      flags.isDataset            ? "Confirmed phishing content pattern" :
                                   "No malicious content signals",

    "Technical":
      flags.isIp            ? "Raw IP address as host (infrastructure abuse)" :
      flags.hasHighEntropy  ? "High-entropy domain (DGA/randomly generated)" :
      flags.isPunycode      ? "Internationalized domain obfuscation" :
      flags.hasObfuscation  ? "URL encoding obfuscation" :
                              "No technical anomalies",
  };

  return {
    status,
    score: Number(cappedScore.toFixed(1)),
    confidence: rawConf,
    trustScore,
    attackType,
    reason: safeReasons.join("; ") || (status === "safe" ? "No malicious signals detected" : "Detected threat"),
    reasons: safeReasons,
    signals: safeSignals,
    sources,
    appliedRule,
    breakdown,
    // signalFlags: exposes the raw boolean flags for the adaptive engine's
    // signal combination boost. Allows the adaptive layer to amplify reputation
    // weight when the current request independently triggers multiple attack vectors.
    signalFlags: { ...flags },
  };
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 5 — MAIN ANALYSIS FUNCTION (PUBLIC API)
// ═══════════════════════════════════════════════════════════════════

/**
 * analyzeUrl — Main entry point.
 *
 * EXECUTION ORDER (short-circuit on early exits):
 *   1. Normalize URL (multi-pass decode)
 *   2. Validate URL scheme (http/https only)
 *   3. Trusted domain check → SAFE exit
 *   4. Search engine check → SAFE exit
 *   5. Dataset check → MALICIOUS exit
 *   6. IP address check → MALICIOUS exit
 *   7. Punycode check (score += 3)
 *   8. TLD check (score += 0-3)
 *   9. Domain structure check (score += 0-8)
 *   10. Entropy check (score += 0-3)
 *   11. Typosquatting check (score += 0-4)
 *   12. Keyword/intent check (score += 0-5)
 *   13. Brand placement check (score += 0-3)
 *   DECISION MATRIX based on accumulated score + signal flags
 *
 * @param {string} rawUrl — The raw URL to analyze
 * @returns {object} Structured result (see OUTPUT CONTRACT above)
 */
function analyzeUrl(rawUrl) {
  try {
    // ════════════════════════════════════════════════════════════════════
    // STRICT PIPELINE ORDER (Task requirement §1)
    // Step 1: Collect signals
    // Step 2: Check trusted domain
    // Step 3: Apply confidence normalization
    // Step 4: Downgrade signals for trusted domains
    // Step 5: Malicious gate
    // Step 6: Calculate risk
    // Step 7: Build final result
    // ════════════════════════════════════════════════════════════════════

    // ── Step 1: Normalize ────────────────────────────────────────────────
    const { normalized, parsed, wasEncoded } = normalizeUrl(rawUrl);

    // ── Step 2: Scheme guard ─────────────────────────────────────────────
    if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
      return buildResult("safe", 0, [], [], "NON_HTTP_SCHEME", {});
    }

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname;
    const search = parsed.search;

    if (!hostname) {
      return buildResult("safe", 0, [], [], "NO_HOSTNAME", {});
    }

    // 🧠 TEST MODE - FORCED ALERT
    if (true) {
      return buildResult(
        "malicious", 85,
        ["TEST MODE - FORCED ALERT"],
        ["test_signal"],
        "TEST_MODE",
        { hasIntent: true, isThreatIntel: true }
      );
    }

    const rootDomain = getRootDomain(hostname);

    // ── Pipeline Step 2: Trusted domain check (BEFORE scoring) ───────────
    // CRITICAL: This is evaluated BEFORE any signals are scored so that
    // trusted domains can never accumulate a high score from false signals.
    const trusted = checkTrusted(hostname);

    // ── Step 4: Search engine query (also pre-scoring) ───────────────────
    if (checkSearchEngine(hostname, pathname, search)) {
      return buildResult("safe", -5, ["Search engine query — all scoring bypassed"], ["Search engine"], "HARD_OVERRIDE_SEARCH", {});
    }

    // ── Step 5: Dataset match (hard malicious — trusted domains still bypass) ──
    // CRITICAL: Dataset hits on trusted domains are IGNORED (e.g. google.com
    // subdomains that contain phishing keywords in path).
    const dataset = checkDataset(hostname);
    if (dataset.flag && !trusted) {
      return buildResult(
        "malicious", 10,
        [`Domain "${dataset.domain}" matched phishing/malware database`],
        ["Phishing/Malware dataset match"],
        "HARD_MATCH_DATASET",
        { isDataset: true }
      );
    }

    // ── Step 5b: Threat intelligence match ──────────────────────────────
    // Checks the runtime-loaded threatIntel.json data (loaded by background.js).
    // Runs AFTER the static dataset so the hardcoded blocklist takes precedence.
    const tiDomain = checkThreatIntelDomain(hostname, rootDomain);
    if (tiDomain.matched) {
      return buildResult(
        "malicious", 10,
        [`Domain "${tiDomain.domain}" matched threat intelligence database`],
        ["Threat intel domain match", "threatIntelMatch"],
        "HARD_MATCH_THREAT_INTEL",
        { isDataset: true, isThreatIntel: true }
      );
    }

    // ── Step 5c: Threat intel keyword check (URL-level) ──────────────────
    // Checks for scam/phishing keywords across the full URL string.
    // Softer signal — adds score rather than hard-exiting.
    const urlLower = normalized.toLowerCase();
    const tiKeyword = checkThreatIntelKeywords(urlLower);

    // === Accumulate scores from remaining signals ========================
    const allReasons = [];
    const allSignals = [];
    let totalScore = 0;
    const flags = {};

    // Inject threat intel keyword signal into scoring pipeline
    if (tiKeyword.matched) {
      flags.hasIntent = true;
      flags.isThreatIntelKeyword = true;
      flags.scamAdvanced = true;
      totalScore += 3;
      totalScore += 2; // scamAdvanced -> +2
      allReasons.push(`Scam keyword detected in URL: "${tiKeyword.keyword}"`);
      allSignals.push("scamContentDetected");
      allSignals.push("scamAdvanced");
      allSignals.push("threatIntelKeyword");
    }

    // ── Step 5d: Basic deobfuscator (Part 3) ─────────────────────────────
    const deob = deobfuscateUrlForKeywords(normalized);
    if (deob.matched) {
      flags.decodedSuspiciousContent = true;
      totalScore += 2; // decodedSuspiciousContent → +2
      allSignals.push("decodedSuspiciousContent");
      allReasons.push(`Decoded suspicious content (${deob.match})`);
    }

    // Encoding was suspicious (double-encoded URLs)
    if (wasEncoded) {
      totalScore += 1;
      allReasons.push("URL contained encoded characters (possible encoding evasion)");
      allSignals.push("URL encoding");
    }

    // ── Step 6: IP address ───────────────────────────────────────────────
    const ipCheck = checkIpAddress(hostname);
    if (ipCheck.isIp) {
      flags.isIp = true;
      // Raw IP is directly malicious — hard exit
      const ipType = ipCheck.isIpv6 ? "IPv6" : "IPv4";
      return buildResult(
        "malicious", 8,
        [`Raw ${ipType} address used as host — phishing infrastructure pattern`],
        ["Raw IP address"],
        "HARD_MATCH_IP_ADDRESS",
        { isIp: true }
      );
    }

    // ── Step 7: Punycode ─────────────────────────────────────────────────
    const punycodeCheck = checkPunycode(hostname);
    if (punycodeCheck.flag) {
      flags.isPunycode = true;
      flags.hasObfuscation = true;
      totalScore += 3;
      allReasons.push(`Punycode domain detected (${punycodeCheck.labels.join(", ")}) — possible homoglyph attack`);
      allSignals.push("Punycode/homoglyph domain");
    }

    // ── Step 7b: URL shortener check ─────────────────────────────────────
    // VULN-09 FIX: bit.ly, tinyurl.com etc. hide the real destination.
    // Flag as suspicious immediately — treat as a soft block until user confirms.
    const shortenerCheck = checkUrlShortener(hostname, rootDomain);
    if (shortenerCheck.isShortener) {
      flags.isShortener = true;
      totalScore += shortenerCheck.score;
      allReasons.push(...shortenerCheck.reasons);
      allSignals.push(...shortenerCheck.signals);
    }

    // ── Step 8: TLD ──────────────────────────────────────────────────────
    const tldCheck = checkTLD(hostname);
    if (tldCheck.isHighRisk) {
      flags.hasHighRiskTLD = true;
      flags.tldRiskHigh = true;
      flags.hasDomainRisk = true;
      totalScore += tldCheck.score;
      allReasons.push(`High-risk TLD (.${tldCheck.tld})`);
      allSignals.push(`High-risk TLD (.${tldCheck.tld})`);
      allSignals.push("tldRiskHigh");
    }

    // ── Step 9: Domain structure ─────────────────────────────────────────
    const structCheck = checkDomainStructure(hostname);
    if (structCheck.score > 0) {
      flags.hasDomainRisk = true;
      totalScore += structCheck.score;
      allReasons.push(...structCheck.reasons);
      allSignals.push(...structCheck.signals);
    }

    // ── Step 10: Entropy ─────────────────────────────────────────────────
    const entropyCheck = checkEntropy(hostname);
    if (entropyCheck.score > 0) {
      flags.hasHighEntropy = true;
      totalScore += entropyCheck.score;
      allReasons.push(...entropyCheck.reasons);
      allSignals.push(...entropyCheck.signals);
    }

    // ── Step 10b: Domain age estimation (heuristic) ──────────────────────
    const ageCheck = checkDomainAgeHeuristic(hostname);
    if (ageCheck.score > 0) {
      flags.domainAgeHeuristicNew = true;
      totalScore += ageCheck.score;
      allReasons.push(...ageCheck.reasons);
      allSignals.push(...ageCheck.signals);
    }

    // ── Step 11: Typosquatting ───────────────────────────────────────────
    const typoCheck = checkTyposquatting(hostname);
    if (typoCheck.hit) {
      flags.hasTyposquat = true;
      flags.hasDomainRisk = true;
      totalScore += typoCheck.score;
      allReasons.push(...typoCheck.reasons);
      allSignals.push(...typoCheck.signals);
    }

    // ── Step 12: Keywords & intent ───────────────────────────────────────
    const keywordCheck = checkKeywords(hostname, pathname, normalized);
    if (keywordCheck.score > 0) {
      if (keywordCheck.hasIntent) flags.hasIntent = true;
      totalScore += keywordCheck.score;
      allReasons.push(...keywordCheck.reasons);
      allSignals.push(...keywordCheck.signals);
    }

    // ── Step 13: Brand placement ─────────────────────────────────────────
    const brandCheck = checkBrandPlacement(hostname, rootDomain);
    if (brandCheck.suspicious) {
      flags.hasBrandPlacement = true;
      flags.hasDomainRisk = true;
      totalScore += brandCheck.score;
      allReasons.push(...brandCheck.reasons);
      allSignals.push(...brandCheck.signals);
    }

    // ── Step 14: Nested URL / redirect chain check ───────────────────────
    // VULN-03 FIX: Extract URLs from query params (next=, redirect=, url=, etc.)
    // and run a targeted threat check on the DESTINATION domain.
    // This catches: legit.com/?next=https://paypal-login.xyz/verify
    let searchParams = null;
    try { searchParams = parsed.searchParams; } catch {}
    const nestedCheck = checkNestedUrl(searchParams);
    if (nestedCheck.hasNestedThreat) {
      flags.hasNestedThreat = true;
      totalScore += nestedCheck.score;
      allReasons.push(...nestedCheck.reasons);
      allSignals.push(...nestedCheck.signals);
    }

    // ═══ DECISION MATRIX (v2.2: Strict Pipeline + Signal Correlation) ═══

    // ── Pipeline Step 3: Apply confidence normalization ───────────────────
    // (Already applied per-signal above; flags object carries the result)

    // ── Pipeline Step 4: Downgrade signals for trusted domains ───────────
    // For trusted domains, all scores are halved before correlation.
    if (trusted) {
      totalScore = Math.floor(totalScore * 0.5);
      console.log(`[Sentinel] 🟢 Trusted: ${hostname} — score halved to ${totalScore}`);
    }

    // ── Pipeline Step 5: Malicious gate (correlateSignals) ───────────────
    const correlationResult = correlateSignals(flags, totalScore, trusted);

    // DEBUG: Log decision
    console.log(`[Sentinel] Signal correlation: ${correlationResult.appliedRule} | Score: ${totalScore} | Trusted: ${trusted} | Verdict: ${correlationResult.severity}`);

    // ── Pipeline Step 5a: If NOT malicious → forceSafeResult for trusted ──
    if (!correlationResult.shouldFlag) {
      // Task requirement §3 + §1: trusted domains always return safe
      if (trusted) {
        const safeResult = forceSafeResult(allSignals, true);
        if (safeResult) {
          // Task requirement §6: debug log
          console.log("[Sentinel Final Decision]", {
            domain: hostname,
            trusted,
            signals: allSignals,
            malicious: false,
            risk: safeResult.risk,
          });
          return safeResult;
        }
      }
      return buildResult("safe", 0,
        [`Signal correlation rules: ${correlationResult.reason}`],
        ["Safe per signal rules"],
        correlationResult.appliedRule,
        flags
      );
    }

    // Task requirement §5: alert blocker — if NOT malicious do NOT proceed
    // (correlationResult.shouldFlag is already the malicious gate above)

    // Otherwise, proceed with normal decision tree for flagged signals
    
    // Hard malicious: punycode + intent (homoglyph phishing)
    if (flags.isPunycode && flags.hasIntent) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "PUNYCODE_PLUS_INTENT", flags);
    }

    // Hard malicious: intent + domain risk + obfuscation (triple signal)
    if (flags.hasIntent && flags.hasDomainRisk && flags.hasObfuscation) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "INTENT_DOMAIN_OBFUSCATION", flags);
    }

    // Hard malicious: intent + domain risk, high score (double signal)
    if (flags.hasIntent && flags.hasDomainRisk && totalScore >= 7) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "INTENT_DOMAIN_HIGH_SCORE", flags);
    }

    // Hard malicious: typosquatting + intent + any domain risk signal
    if (flags.hasTyposquat && flags.hasIntent && totalScore >= 6) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "TYPOSQUAT_PLUS_INTENT", flags);
    }

    // Hard malicious: brand placement + intent
    if (flags.hasBrandPlacement && flags.hasIntent) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "BRAND_PLACEMENT_PLUS_INTENT", flags);
    }

    // Hard malicious: multi-keyword on high-risk TLD
    if (keywordCheck.keywords.length >= 2 && flags.hasHighRiskTLD) {
      allReasons.push(`Confirmed phishing: ${keywordCheck.keywords.length} keywords on high-risk TLD`);
      return buildResult("malicious", totalScore, allReasons, allSignals, "MULTI_KEYWORD_HIGH_RISK_TLD", flags);
    }

    // Hard malicious: high entropy + keywords (DGA-generated phishing domain)
    if (flags.hasHighEntropy && flags.hasIntent) {
      allReasons.push("DGA-style phishing domain: high entropy + phishing keywords");
      return buildResult("malicious", totalScore, allReasons, allSignals, "ENTROPY_PLUS_INTENT", flags);
    }

    // Hard malicious: nested redirect to known-bad domain (open redirect attack)
    if (flags.hasNestedThreat && nestedCheck.score >= 6) {
      return buildResult("malicious", totalScore, allReasons, allSignals, "NESTED_URL_PHISHING", flags);
    }

    // Suspicious: nested URL with moderate threat score
    if (flags.hasNestedThreat) {
      return buildResult("suspicious", totalScore, allReasons, allSignals, "NESTED_URL_SUSPICIOUS", flags);
    }

    // Suspicious: URL shortener (destination unknown)
    if (flags.isShortener) {
      return buildResult("suspicious", totalScore, allReasons, allSignals, "URL_SHORTENER", flags);
    }

    // Suspicious: any meaningful signal combination
    if (totalScore >= 3 || (flags.hasIntent && totalScore >= 2)) {
      return buildResult("suspicious", totalScore, allReasons, allSignals, `SUSPICIOUS_SCORE_${totalScore}`, flags);
    }

    // Minimal signals — suspicious if score is nonzero
    if (totalScore >= 1) {
      return buildResult("suspicious", totalScore, allReasons, allSignals, `WEAK_SIGNALS_${totalScore}`, flags);
    }

    // No signals — safe
    return buildResult("safe", 0, [], [], "NO_SIGNALS", flags);

  } catch (err) {
    // FAIL-OPEN: any unexpected error returns safe to avoid blocking legitimate browsing
    try { console.warn("[SentinelEngine] analyzeUrl error:", err?.message); } catch {}
    return buildResult("safe", 0, ["Detection error — fail-open"], [], "ERROR_FAIL_OPEN", {});
  }
}

// NOTE: forceSafeResult and calculateSoftRisk are defined above buildResult().

// ═══════════════════════════════════════════════════════════════════
// SECTION 5b — THREAT INTELLIGENCE STORE
// ═══════════════════════════════════════════════════════════════════
//
// Loaded at runtime by background.js via loadThreatIntel().
// Extends the static PHISHING_DATASET and HIGH_RISK_TLDS without
// touching the synchronous heuristic pipeline.

/**
 * Runtime threat intelligence — loaded from threatIntel.json by background.js.
 * Starts empty; analyzeUrl() checks gracefully if not yet loaded.
 */
let _threatIntelDomains = new Set();
let _threatIntelKeywords = [];
let _threatIntelLoaded = false;

/**
 * Called by background.js after fetching threatIntel.json.
 * Merges the external database into the engine's runtime sets.
 *
 * @param {{ phishingDomains: string[], scamKeywords: string[], suspiciousTLDs: string[] }} data
 */
function loadThreatIntel(data) {
  try {
    if (!data || typeof data !== "object") return;

    if (Array.isArray(data.phishingDomains)) {
      for (const d of data.phishingDomains) {
        if (typeof d === "string" && d.trim()) {
          _threatIntelDomains.add(d.trim().toLowerCase());
        }
      }
    }

    if (Array.isArray(data.scamKeywords)) {
      _threatIntelKeywords = data.scamKeywords
        .filter(k => typeof k === "string" && k.trim())
        .map(k => k.trim().toLowerCase());
    }

    if (Array.isArray(data.suspiciousTLDs)) {
      for (const tld of data.suspiciousTLDs) {
        if (typeof tld === "string") HIGH_RISK_TLDS.add(tld.trim().toLowerCase());
      }
    }

    _threatIntelLoaded = true;
    console.debug("[SentinelEngine] Threat intel loaded:",
      _threatIntelDomains.size, "phishing domains,",
      _threatIntelKeywords.length, "scam keywords");
  } catch (e) {
    console.warn("[SentinelEngine] loadThreatIntel error:", e?.message);
  }
}

/**
 * Checks a hostname/rootDomain against the loaded threat intel domain list.
 * @param {string} hostname
 * @param {string} rootDomain
 * @returns {{ matched: boolean, domain: string }}
 */
function checkThreatIntelDomain(hostname, rootDomain) {
  if (!_threatIntelLoaded) return { matched: false, domain: "" };
  if (_threatIntelDomains.has(hostname))   return { matched: true, domain: hostname };
  if (_threatIntelDomains.has(rootDomain)) return { matched: true, domain: rootDomain };
  return { matched: false, domain: "" };
}

/**
 * Checks URL tokens against loaded scam keywords.
 * Operates on the full URL string (pathname + query) to catch
 * scam content in GET parameters.
 * @param {string} urlLower — lowercased full URL string
 * @returns {{ matched: boolean, keyword: string }}
 */
function checkThreatIntelKeywords(urlLower) {
  if (!_threatIntelLoaded || !_threatIntelKeywords.length) return { matched: false, keyword: "" };
  for (const kw of _threatIntelKeywords) {
    if (urlLower.includes(kw)) return { matched: true, keyword: kw };
  }
  return { matched: false, keyword: "" };
}

/**
 * SIGNAL: Basic deobfuscator (base64 tokens + hex escapes) for URL strings.
 * Decodes simple obfuscation and re-runs keyword detection on the decoded content.
 *
 * Adds "decodedSuspiciousContent" when decoded content contains phishing/scam intent.
 *
 * @param {string} urlStr
 * @returns {{ decoded: string, matched: boolean, match: string }}
 */
function deobfuscateUrlForKeywords(urlStr) {
  const raw = String(urlStr || "");
  let decoded = "";

  // 1) base64-ish tokens (length guard + charset guard)
  const candidates = raw.split(/[^A-Za-z0-9+/=]+/).filter(t => t.length >= 12 && t.length <= 200);
  for (const token of candidates) {
    if (!/^[A-Za-z0-9+/=]+$/.test(token)) continue;
    if (token.length % 4 !== 0 && !token.endsWith("=")) continue;
    try {
      const out = atob(token);
      if (out && /[a-zA-Z]{3,}/.test(out) && out.length <= 500) {
        decoded += " " + out.toLowerCase();
      }
    } catch {}
  }

  // 2) hex escapes like \\x6c\\x6f\\x67\\x69\\x6e → login
  if (raw.includes("\\x")) {
    try {
      const hexDecoded = raw.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      if (hexDecoded !== raw) decoded += " " + hexDecoded.toLowerCase();
    } catch {}
  }

  // 3) %xx sequences (decode once)
  if (raw.includes("%")) {
    try {
      const pct = decodeURIComponent(raw);
      if (pct && pct !== raw) decoded += " " + pct.toLowerCase();
    } catch {}
  }

  decoded = decoded.trim();
  if (!decoded) return { decoded: "", matched: false, match: "" };

  // Re-run keyword scan on decoded material (scam keywords + phishing intent)
  const tokens = tokenize(decoded);
  const hasPhish = tokens.some(t => PHISHING_KEYWORDS.has(t)) && tokens.some(t => URGENCY_WORDS.has(t));
  const hasScam = _threatIntelLoaded && _threatIntelKeywords.some(kw => decoded.includes(kw));

  if (hasPhish) return { decoded, matched: true, match: "decoded phishing intent" };
  if (hasScam) return { decoded, matched: true, match: "decoded scam keyword" };
  return { decoded, matched: false, match: "" };
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 5c — LIGHTWEIGHT ML HEURISTIC SCORING
// ═══════════════════════════════════════════════════════════════════
//
// A logistic-regression-style heuristic model that runs on the structured
// result object produced by analyzeUrl().  Operates purely on the 6-dimensional
// feature vector below — no external libraries or network calls required.
//
// Integration path:
//   analyzeUrl() → buildResult() → enrichWithML() → result.mlRiskScore
//   background.js computeRiskSteps() adds mlRaw as a 5th weighted component.
//
// Design decisions:
//   • Weights are hand-calibrated against the existing signal set, not trained.
//     They approximate a logistic model’s coefficient magnitudes.
//   • numSignals gets a diminishing-returns cap (max 5) so a flood of weak
//     signals cannot dominate the score.
//   • trustScore contribution is inverted (100 − trust) so high-trust domains
//     contribute near-zero ML risk.
//   • domainAgeRisk is an optional field; defaults to 0 when absent so
//     the model degrades gracefully for safe/trusted exits.

/**
 * FEATURE WEIGHTS for mlScore()
 * Calibrated to produce scores in the 0–100 range:
 *   - Single clipboard event alone → ~20 (below suspicious threshold)
 *   - Phishing form + domain risk  → ~60+ (suspicious → malicious band)
 *   - Full signal cluster           → capped at 100
 */
const ML_WEIGHTS = {
  numSignals:    8,    // per signal, capped at 5 signals (max contribution: 40)
  hasClipboard: 20,    // clipboard_hijack present
  hasPhishing:  40,    // phishing_form present (highest-weight behavioural signal)
  hasIframe:    15,    // hidden_iframe present
  hasMalware:   35,    // malware_signature / keylogger_detected
  hasSSLIssue:  30,    // invalid_ssl / expired_cert / domain_mismatch / self_signed_cert
  hasInsecureHTTP: 12, // plain HTTP navigation (lower weight — many legacy CDNs)
  trustPenalty:  0.3,  // per (100 - trustScore) point
  domainAgeRisk: 10,   // per unit of domain age risk (0–1 scale expected)
};

/**
 * Extracts a 6-dimensional feature vector from a detection result.
 *
 * Features are normalised to binary (0/1) or clamped numeric ranges so
 * they can be multiplied directly by ML_WEIGHTS without scaling.
 *
 * @param {object} result — output of analyzeUrl() / buildResult()
 * @returns {object} feature vector
 */
function extractFeatures(result) {
  const signals = Array.isArray(result.signals) ? result.signals : [];

  // SSL signals: any certificate-level problem that indicates active deception
  const SSL_CERT_SIGNALS = [
    "invalid_ssl", "expired_cert", "self_signed_cert", "domain_mismatch",
  ];

  return {
    // Discrete signal count, capped at 5 to apply diminishing returns
    numSignals:    Math.min(signals.length, 5),

    // Binary presence flags for high-weight signals
    hasClipboard:  signals.includes("clipboard_hijack")   ? 1 : 0,
    hasPhishing:   signals.includes("phishing_form")      ? 1 : 0,
    hasIframe:     signals.includes("hidden_iframe")      ? 1 : 0,
    hasMalware:    (signals.includes("malware_signature") ||
                   signals.includes("keylogger_detected")) ? 1 : 0,

    // SSL/TLS certificate flags
    hasSSLIssue:     SSL_CERT_SIGNALS.some(s => signals.includes(s)) ? 1 : 0,
    hasInsecureHTTP: signals.includes("insecure_http") ? 1 : 0,

    // Numeric: high trust → low penalty (range 0–100, inverted in mlScore)
    trustScore:    typeof result.trustScore === "number"
                     ? Math.max(0, Math.min(100, result.trustScore))
                     : 50,   // default: neutral trust

    // Optional field set by domain-age heuristic (0 = new/unknown, 1 = old/safe)
    // Inverted below: higher value → lower risk contribution
    domainAgeRisk: typeof result.domainAgeRisk === "number"
                     ? Math.max(0, Math.min(1, result.domainAgeRisk))
                     : (result.signalFlags?.domainAgeHeuristicNew ? 0.7 : 0),
  };
}

/**
 * Computes an ML-style composite risk score from a feature vector.
 *
 * Formula (logistic-style linear combination, capped at 100):
 *   score = (Σ feature_i × weight_i) capped to [0, 100]
 *
 * @param {object} features — output of extractFeatures()
 * @returns {number} ML risk score, 0–100
 */
function mlScore(features) {
  let score = 0;

  score += features.numSignals    * ML_WEIGHTS.numSignals;    // 0–40
  score += features.hasClipboard  * ML_WEIGHTS.hasClipboard;  // 0 or 20
  score += features.hasPhishing   * ML_WEIGHTS.hasPhishing;   // 0 or 40
  score += features.hasIframe     * ML_WEIGHTS.hasIframe;     // 0 or 15
  score += features.hasMalware    * ML_WEIGHTS.hasMalware;    // 0 or 35

  // SSL/TLS certificate signals
  score += features.hasSSLIssue    * ML_WEIGHTS.hasSSLIssue;    // 0 or 30
  score += features.hasInsecureHTTP * ML_WEIGHTS.hasInsecureHTTP; // 0 or 12

  // Trust penalty: low-trust domain boosts score, high-trust domain adds ~0
  score += (100 - features.trustScore) * ML_WEIGHTS.trustPenalty;

  // Domain age risk: newly-registered / throwaway domains are higher risk
  score += features.domainAgeRisk * ML_WEIGHTS.domainAgeRisk;

  return Math.min(100, Math.round(score * 10) / 10);   // 1 decimal precision
}

/**
 * Enriches a detection result with ML heuristic scoring in-place.
 *
 * Called automatically by the wrapped analyzeUrl() in the module export —
 * callers do NOT need to invoke this directly.
 *
 * Adds two fields to result:
 *   result.mlFeatures   {object}  — the 6-dim feature vector
 *   result.mlRiskScore  {number}  — ML risk score 0–100
 *
 * @param {object} result — mutable result from buildResult()
 * @returns {object} same result object (mutated)
 */
function enrichWithML(result) {
  try {
    const features    = extractFeatures(result);
    const mlRisk      = mlScore(features);

    result.mlFeatures  = features;
    result.mlRiskScore = mlRisk;

    console.debug("[SentinelEngine-ML] Feature vector:", features, "→ mlRiskScore:", mlRisk);
  } catch (e) {
    // Fail-open: ML enrichment error must never break the detection pipeline.
    result.mlRiskScore = 0;
    result.mlFeatures  = {};
    console.warn("[SentinelEngine-ML] enrichWithML error:", e?.message);
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 6 — MODULE EXPORT (compatible with service worker)
// ═══════════════════════════════════════════════════════════════════

// Use a global object pattern instead of ES module exports —
// ensures compatibility with the service worker's script loading context
// (manifest does NOT declare "type": "module", so importScripts() is used)
//
// analyzeUrl is wrapped to automatically call enrichWithML() on every result
// path without modifying the 10+ return points inside analyzeUrl() itself.
if (typeof globalThis !== "undefined") {
  globalThis.SentinelDetectionEngine = {
    analyzeUrl: (rawUrl) => enrichWithML(analyzeUrl(rawUrl)),
    loadThreatIntel,
    // Expose helpers for unit tests and the adaptive engine
    extractFeatures,
    mlScore,
  };
}
