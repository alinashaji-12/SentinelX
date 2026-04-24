/**
 * advancedDetection.js — Sentinel Browse Extension (PRODUCTION UPGRADE)
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * PHASE 4: PRODUCTION-GRADE ENHANCEMENTS
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * Adds 8 production-level detection improvements:
 * 1. Brand-impersonation detection
 * 2. Homograph/lookalike detection (ASCII visuals)
 * 3. URL decode + re-analyze
 * 4. Keyword fuzzy matching (leetspeak)
 * 5. Query parameter inspection
 * 6. Shortener heuristic analysis
 * 7. IP risk classification (public vs private)
 * 8. Keyword clustering score boost
 *
 * ═════════════════════════════════════════════════════════════════════════════
 */

import { getHostname, getRootDomain, isTrustedDomain } from "./domainWhitelist.js";

// ─── BRAND NAMES (Common phishing targets) ──────────────────────────────────

const PROTECTED_BRANDS = new Set([
  "google", "google drive", "gmail",
  "paypal",
  "amazon", "aws",
  "apple", "icloud", "itunes",
  "microsoft", "office", "outlook",
  "facebook", "instagram", "whatsapp",
  "twitter", "x.com",
  "linkedin",
  "coinbase", "binance", "blockchain", "metamask",
  "chase", "bank of america", "wells fargo", "bank",
  "netflix", "spotify", "adobe", "dropbox"
]);

// ─── HOMOGRAPH CHARACTER MAP ───────────────────────────────────────────────

const HOMOGRAPH_MAP = {
  "0": ["o"], // zero → o
  "O": ["0"], // O → zero
  "1": ["i", "l"], // one → i or l
  "i": ["1", "l"],
  "l": ["1", "i"],
  "I": ["1", "l"],
  "5": ["s"],
  "s": ["5"],
  "@": ["a"],
  "a": ["@"],
  "$": ["s"],
};

// ─── LEETSPEAK VARIATIONS ──────────────────────────────────────────────────

function generateLeetVariations(word) {
  // v3rify, l0gin, acc0unt, p@yp@l
  const variations = new Set([word]);

  // Simple substitutions
  variations.add(word.replace(/e/g, "3"));
  variations.add(word.replace(/o/g, "0"));
  variations.add(word.replace(/a/g, "@"));
  variations.add(word.replace(/a/g, "4"));
  variations.add(word.replace(/s/g, "5"));
  variations.add(word.replace(/i/g, "1"));
  variations.add(word.replace(/l/g, "1"));
  variations.add(word.replace(/t/g, "7"));

  return variations;
}

// ─── HELPER: Safe URL Decode ───────────────────────────────────────────────

function safeDecodeUrl(url) {
  try {
    return decodeURIComponent(url);
  } catch {
    return url;
  }
}

// ─── HELPER: Extract keywords from URL path/query ─────────────────────────

function extractUrlSegments(url) {
  try {
    const parsed = new URL(url);
    const segments = new Set();

    // Path segments
    parsed.pathname.split(/[/\-_]/).forEach(seg => {
      if (seg.length > 2) segments.add(seg.toLowerCase());
    });

    // Query parameter names & values
    parsed.searchParams.forEach((value, key) => {
      segments.add(key.toLowerCase());
      segments.add(value.toLowerCase());
    });

    return segments;
  } catch {
    return new Set();
  }
}

// ─── HELPER: Check if IP is public vs private ──────────────────────────────

function classifyIPRisk(ip) {
  // Private/reserved ranges
  if (/^192\.168\./.test(ip)) return "private";      // 192.168.x.x
  if (/^10\./.test(ip)) return "private";             // 10.x.x.x
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return "private"; // 172.16-31.x.x
  if (/^127\./.test(ip)) return "private";            // 127.x.x.x (localhost)
  if (/^169\.254\./.test(ip)) return "private";       // 169.254.x.x (link-local)
  if (/^0\./.test(ip)) return "private";              // 0.x.x.x (this network)
  if (/^255\./.test(ip)) return "private";            // 255.255.255.255 (broadcast)

  return "public"; // Routable public IP
}

// ─── 1. BRAND IMPERSONATION DETECTION ───────────────────────────────────────

export function detectBrandImpersonation(url) {
  const hostname = getHostname(url);

  if (!hostname) {
    return { flagged: false, brand: null, score: 0, reason: "" };
  }

  // Check if any protected brand name appears in domain string
  for (const brand of PROTECTED_BRANDS) {
    if (hostname.includes(brand)) {
      // Root domain is NOT the brand itself (paypal.com is safe)
      const rootDomain = getRootDomain(hostname);
      if (!rootDomain.includes(brand) || brand !== rootDomain.split(".")[0]) {
        return {
          flagged: true,
          brand,
          score: 3,
          reason: `Brand "${brand}" impersonated in domain string (subdomain spoof)`,
        };
      }
    }
  }

  return { flagged: false, brand: null, score: 0, reason: "" };
}

// ─── 2. HOMOGRAPH/LOOKALIKE DETECTION ──────────────────────────────────────

export function detectHomographAttack(url) {
  const hostname = getHostname(url);

  if (!hostname) {
    return { flagged: false, substitutions: [], score: 0, reason: "" };
  }

  const substitutions = [];

  // Check for suspicious character substitutions
  for (const char of hostname) {
    if (HOMOGRAPH_MAP[char]) {
      substitutions.push(char);
    }
  }

  if (substitutions.length >= 2) {
    return {
      flagged: true,
      substitutions,
      score: 2,
      reason: `Homograph characters detected: ${substitutions.join(", ")} (may be visual spoof)`,
    };
  }

  return { flagged: false, substitutions: [], score: 0, reason: "" };
}

// ─── 3. URL DECODE + RE-ANALYZE ────────────────────────────────────────────

export function analyzeDecodedUrl(url, phishingKeywords = []) {
  const decoded = safeDecodeUrl(url);

  if (decoded === url) {
    return { flagged: false, decodedUrl: url, matches: [], score: 0 };
  }

  // Re-check for keywords in decoded version
  const matches = [];
  for (const keyword of phishingKeywords) {
    if (decoded.includes(keyword)) {
      matches.push(keyword);
    }
  }

  return {
    flagged: matches.length > 0,
    decodedUrl: decoded,
    matches,
    score: matches.length > 0 ? 2 : 0,
    reason: matches.length > 0
      ? `Detected keywords in decoded URL: ${matches.join(", ")}`
      : "No keywords found in decoded URL",
  };
}

// ─── 4. KEYWORD FUZZY MATCHING (Leetspeak) ────────────────────────────────

export function detectLeetspeakEvasion(url, keywords = []) {
  const urlLower = url.toLowerCase();
  const segments = extractUrlSegments(url);
  const detectedVariations = [];

  for (const keyword of keywords) {
    const variations = generateLeetVariations(keyword);
    for (const variant of variations) {
      if (urlLower.includes(variant)) {
        detectedVariations.push(`${keyword}→${variant}`);
        break;
      }
    }
  }

  return {
    flagged: detectedVariations.length > 0,
    variations: detectedVariations,
    score: detectedVariations.length > 0 ? 2 : 0,
    reason:
      detectedVariations.length > 0
        ? `Detected leetspeak keyword variations: ${detectedVariations.join(", ")}`
        : "No leetspeak variations detected",
  };
}

// ─── 5. QUERY PARAMETER INSPECTION ────────────────────────────────────────

export function inspectRedirectParameters(url) {
  const redirectParams = ["redirect", "url", "next", "return_to", "goto", "back", "callback", "return", "from"];
  const hostname = getHostname(url);

  try {
    const parsed = new URL(url);
    const suspiciousRedirects = [];

    for (const param of redirectParams) {
      const value = parsed.searchParams.get(param);
      if (value) {
        // Check if redirect target is untrusted
        if (!isTrustedDomain(value)) {
          // Extract domain from redirect value if it looks like a URL
          let redirectHost = value;
          try {
            redirectHost = new URL(value).hostname;
          } catch {
            // Value might not be a full URL; use as-is
          }

          suspiciousRedirects.push({
            param,
            value: value.substring(0, 50), // truncate for display
            host: redirectHost,
          });
        }
      }
    }

    return {
      flagged: suspiciousRedirects.length > 0,
      redirects: suspiciousRedirects,
      score: suspiciousRedirects.length > 0 ? 3 : 0,
      reason:
        suspiciousRedirects.length > 0
          ? `Redirect parameter points to untrusted domain: ${suspiciousRedirects
              .map((r) => `${r.param}=${r.host}`)
              .join(", ")}`
          : "No suspicious redirect parameters",
    };
  } catch {
    return {
      flagged: false,
      redirects: [],
      score: 0,
      reason: "Could not parse URL for redirect parameters",
    };
  }
}

// ─── 6. SHORTENER HEURISTIC (No expansion, logic-based) ──────────────────

export function analyzeShortenerPath(url) {
  const shorteners = new Set([
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy"
  ]);

  const hostname = getHostname(url);

  // Detect if using shortener
  let isShortener = false;
  for (const s of shorteners) {
    if (hostname === s || hostname.endsWith(`.${s}`)) {
      isShortener = true;
      break;
    }
  }

  if (!isShortener) {
    return { flagged: false, isShortener: false, score: 0 };
  }

  // If shortener, analyze the path for clues about destination
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();

    // Suspicious keywords in shortener path (attacker may name it suggestively)
    const suspiciousKeywords = ["fake", "login", "verify", "account", "phish", "hack"];
    const foundKeywords = suspiciousKeywords.filter(kw => path.includes(kw));

    if (foundKeywords.length > 0) {
      return {
        flagged: true,
        isShortener: true,
        score: 2,
        reason: `Shortener with suspicious path keywords: ${foundKeywords.join(", ")}`,
      };
    }
  } catch {
    // Ignore parsing errors
  }

  return {
    flagged: true,
    isShortener: true,
    score: 1,
    reason: "URL shortener used (destination unknown)",
  };
}

// ─── 7. IP RISK CLASSIFICATION ────────────────────────────────────────────

export function classifyIpRisk(url) {
  const hostname = getHostname(url);

  // Basic IP regex
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

  if (!ipRegex.test(hostname)) {
    return { flagged: false, ip: null, riskLevel: "not_ip", score: 0 };
  }

  const riskLevel = classifyIPRisk(hostname);

  return {
    flagged: true,
    ip: hostname,
    riskLevel,
    score: riskLevel === "public" ? 3 : 1, // public IPs score higher
    reason:
      riskLevel === "public"
        ? `Public IP address used (high-risk phishing infrastructure): ${hostname}`
        : `Private IP address used: ${hostname}`,
  };
}

// ─── 8. KEYWORD CLUSTERING SCORE BOOST ─────────────────────────────────────

export function applyKeywordClusteringBoost(keywordMatches = []) {
  const count = keywordMatches.length;

  if (count <= 1) {
    return { boostScore: 0, boost: 1.0 }; // No boost
  } else if (count === 2) {
    return { boostScore: 1, boost: 1.3 }; // +1 point, 1.3x multiplier
  } else if (count >= 3) {
    return { boostScore: 2, boost: 1.6 }; // +2 points, 1.6x multiplier (escalation)
  }

  return { boostScore: 0, boost: 1.0 };
}

/**
 * UNIFIED PRODUCTION ANALYSIS
 * Integrates all 8 enhancements into a single scoring function.
 * Call this BEFORE the main advancedEngine.analyzeUrl() for pre-processing.
 *
 * @param {string} url
 * @param {string[]} phishingKeywords
 * @returns {object}
 */
export function analyzeUrlEnhanced(url, phishingKeywords = []) {
  const results = {
    brand: null,
    homograph: null,
    decoded: null,
    leetspeak: null,
    redirect: null,
    shortener: null,
    ipRisk: null,
    clusterBoost: null,

    totalEnhancedScore: 0,
    enhancedSignals: [],
  };

  // 1. Brand impersonation
  results.brand = detectBrandImpersonation(url);
  if (results.brand.flagged) {
    results.totalEnhancedScore += results.brand.score;
    results.enhancedSignals.push(`Brand-impersonation: ${results.brand.brand}`);
  }

  // 2. Homograph attack
  results.homograph = detectHomographAttack(url);
  if (results.homograph.flagged) {
    results.totalEnhancedScore += results.homograph.score;
    results.enhancedSignals.push(`Homograph-attack: ${results.homograph.substitutions.join(", ")}`);
  }

  // 3. Decode + re-analyze
  results.decoded = analyzeDecodedUrl(url, phishingKeywords);
  if (results.decoded.flagged) {
    results.totalEnhancedScore += results.decoded.score;
    results.enhancedSignals.push(`Decoded-keywords: ${results.decoded.matches.join(", ")}`);
  }

  // 4. Leetspeak evasion
  results.leetspeak = detectLeetspeakEvasion(url, phishingKeywords);
  if (results.leetspeak.flagged) {
    results.totalEnhancedScore += results.leetspeak.score;
    results.enhancedSignals.push(`Leetspeak-variations: ${results.leetspeak.variations.join(", ")}`);
  }

  // 5. Redirect parameters
  results.redirect = inspectRedirectParameters(url);
  if (results.redirect.flagged) {
    results.totalEnhancedScore += results.redirect.score;
    results.enhancedSignals.push(`Redirect-abuse: ${results.redirect.redirects.length} param(s)`);
  }

  // 6. Shortener analysis
  results.shortener = analyzeShortenerPath(url);
  if (results.shortener.flagged) {
    results.totalEnhancedScore += results.shortener.score;
    results.enhancedSignals.push(`Shortener-risky: ${results.shortener.reason}`);
  }

  // 7. IP risk classification
  results.ipRisk = classifyIpRisk(url);
  if (results.ipRisk.flagged) {
    results.totalEnhancedScore += results.ipRisk.score;
    results.enhancedSignals.push(`IP-${results.ipRisk.riskLevel}: ${results.ipRisk.ip}`);
  }

  // 8. Keyword clustering boost (based on detected keywords)
  results.clusterBoost = applyKeywordClusteringBoost(phishingKeywords);
  if (results.clusterBoost.boostScore > 0) {
    results.totalEnhancedScore += results.clusterBoost.boostScore;
    results.enhancedSignals.push(`Keyword-cluster-boost: ${results.clusterBoost.boostScore} (${phishingKeywords.length} keywords)`);
  }

  return results;
}
