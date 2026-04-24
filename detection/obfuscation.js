/**
 * obfuscation.js — Sentinel Browse Extension
 *
 * Obfuscation Detection module.
 * Detects techniques attackers use to hide the true nature of a URL:
 *   - URL percent-encoding (%XX) in the HOSTNAME (not just query)
 *   - Base64-like patterns in path/query
 *   - Punycode internationalized domain names (xn--)
 *   - URL shortener services
 *   - Double-encoding (decoded string differs from single-decode)
 *
 * IMPORTANT:
 *   - Trusted and search-engine domains bypass all checks.
 *   - URL encoding in the QUERY STRING alone is NOT flagged (legitimate).
 *   - Only encoding found in the HOSTNAME or PATH triggers a flag.
 *   - Each technique is tracked individually for the multi-signal engine.
 */

import { isTrustedDomain, isSearchEngineQuery } from "./domainWhitelist.js";

const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "is.gd", "buff.ly", "tiny.cc", "rb.gy", "cutt.ly",
  "shorturl.at", "snip.ly", "bl.ink", "rebrand.ly",
]);

// ─── Helpers ───────────────────────────────────────────────────────────────

function safeDecodeUri(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function safeDecodeUriDouble(value) {
  // Double-decode: attacker encodes twice — %2525 decodes to %25 then to %
  try { return decodeURIComponent(decodeURIComponent(value)); } catch { return value; }
}

function getParsed(url) {
  try { return new URL(String(url || "")); } catch { return null; }
}

/**
 * True only if the base64 block is in a context that makes no legitimate sense:
 * long contiguous run (>=30 chars) of base64 alphabet in a path segment.
 * This avoids false positives from long random alphanumeric IDs.
 */
function hasDeepBase64InPath(path) {
  // Must be a very long, high-density base64 segment (>=30 chars, ends with = padding)
  return /(?:^|\/)[A-Za-z0-9+/]{30,}={1,2}(?:\/|$|&|\?)/.test(path);
}

function hasPunycode(hostname) {
  // xn-- prefix on any label = internationalized domain = potential homoglyph attack
  return hostname.split(".").some((label) => label.startsWith("xn--"));
}

function isKnownShortener(hostname) {
  return SHORTENER_DOMAINS.has(hostname) ||
    [...SHORTENER_DOMAINS].some((d) => hostname.endsWith(`.${d}`));
}

/**
 * Detects obfuscation techniques in a URL.
 *
 * Returns:
 *   flag        — true if any meaningful obfuscation detected
 *   isObfuscated
 *   techniques  — { encoding, doubleEncoding, base64, punycode, shortener }
 *   decodedUrl  — fully decoded version for downstream analysis
 *   reasons     — human-readable list
 *
 * @param {string} url
 */
export function detectObfuscation(url) {
  // Trusted and search-engine URLs bypass all checks.
  // (Google Maps, OAuth flows etc. legitimately use encoding in query strings.)
  if (isTrustedDomain(url) || isSearchEngineQuery(url)) {
    return {
      flag: false,
      isObfuscated: false,
      techniques: {},
      decodedUrl: url,
      reason: "Trusted or search-engine domain — obfuscation check suppressed.",
    };
  }

  const input = String(url || "");
  const parsed = getParsed(input);

  // If URL can't be parsed, we can't reliably detect obfuscation — treat as safe
  // (malformed URLs are caught by behavior.js "invalid URL" signal instead)
  if (!parsed) {
    return {
      flag: false,
      isObfuscated: false,
      techniques: {},
      decodedUrl: input,
      reason: "URL could not be parsed for obfuscation analysis.",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname;
  const query = parsed.search;
  const decodedUrl = safeDecodeUri(input);
  const doubleDecoded = safeDecodeUriDouble(input);

  const techniques = {};
  const reasons = [];

  // ── Technique 1: Percent-encoding in HOSTNAME or PATH ────────────────────
  // Query string encoding (?q=hello%20world) is NORMAL, so we check
  // hostname + path specifically to avoid false positives.
  const hostnameAndPath = hostname + path;
  if (/%[0-9a-f]{2}/i.test(hostnameAndPath)) {
    techniques.encoding = true;
    reasons.push("URL percent-encoding found in hostname or path (not just query)");
  }

  // ── Technique 2: Double-encoding ─────────────────────────────────────────
  // %2525 → %25 → % — a common bypass technique for WAFs and filters.
  if (doubleDecoded !== decodedUrl) {
    techniques.doubleEncoding = true;
    reasons.push("Double URL-encoding detected (potential WAF bypass attempt)");
  }

  // ── Technique 3: Deep base64 in path ─────────────────────────────────────
  // Long base64-padded segments in path are suspicious (not just random IDs).
  if (hasDeepBase64InPath(path)) {
    techniques.base64 = true;
    reasons.push("Base64-encoded segment found in URL path");
  }

  // ── Technique 4: Punycode internationalized domain ───────────────────────
  // Attackers register "xn--pple-43d.com" which renders as "аpple.com"
  if (hasPunycode(hostname)) {
    techniques.punycode = true;
    reasons.push(`Punycode internationalized domain detected (${hostname}) — possible homoglyph attack`);
  }

  // ── Technique 5: URL shortener ───────────────────────────────────────────
  if (isKnownShortener(hostname)) {
    techniques.shortener = true;
    reasons.push(`URL shortener service (${hostname}) — destination unknown`);
  }

  const triggered = Object.keys(techniques).length > 0;

  return {
    flag: triggered,
    isObfuscated: triggered,
    techniques,
    decodedUrl,
    reason: triggered
      ? reasons.join("; ") + "."
      : "No obfuscation techniques detected.",
  };
}

/** Async compatibility wrapper. */
export async function analyzeByObfuscation(url) {
  const result = detectObfuscation(url);
  return {
    source: "obfuscation",
    verdict: result.isObfuscated ? "suspicious" : "safe",
    reason: result.reason,
  };
}
