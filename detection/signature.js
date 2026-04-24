/**
 * signature.js — Sentinel Browse Extension
 *
 * Signature-based URL detection.
 * Uses root-domain whitelist and search-engine awareness to prevent
 * false positives on trusted sites (e.g. google.com/search?q=login).
 */

import { isTrustedDomain, isSearchEngineQuery, getRootDomain, getHostname } from "./domainWhitelist.js";

/**
 * Extended keyword list for phishing pattern matching.
 * Only applied when domain is NOT trusted and URL is NOT a search query.
 */
const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "update", "free", "bonus",
  "password", "credential", "signin", "account", "confirm",
  "wallet", "banking", "paypal", "appleid", "support-ticket",
];

/**
 * Blacklisted domains — immediate flag regardless of other checks.
 * These are known bad actors added to our local signature dataset.
 */
const BLACKLISTED_DOMAINS = [
  "malicious.com",
  "phishing-site.net",
  "paypal-login-secure.com",
  "facebook-verification.net",
  "amazon-update-account.xyz",
];

/**
 * Reverses common leet-speak character substitutions seen in phishing URLs.
 * e.g. "p4ypa1" → "paypal"
 */
function normalizeLeetspeak(text) {
  return text
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/\$/g, "s");
}

function isBlacklistedHost(hostname) {
  const root = getRootDomain(hostname);
  return BLACKLISTED_DOMAINS.some(
    (blocked) => root === blocked || hostname === blocked || hostname.endsWith(`.${blocked}`)
  );
}

/**
 * Performs signature-based URL analysis.
 *
 * Priority:
 *  1. Trusted domain + search query → always safe (no keyword scan)
 *  2. Trusted domain → skip keyword scan, still check blacklist
 *  3. Blacklisted host → immediate malicious flag
 *  4. Leet-speak normalized keyword scan
 *  5. Plain keyword scan
 *
 * @param {string} url
 * @returns {{ flag: boolean, isMalicious: boolean, reason: string, skippedKeywords?: boolean }}
 */
export function checkSignature(url) {
  const lowerUrl = String(url || "").toLowerCase();
  const hostname = getHostname(lowerUrl);

  if (!lowerUrl) {
    return { flag: false, isMalicious: false, reason: "URL is empty." };
  }

  // ── Context guards: prevent false positives ──────────────────────────────
  // Search engine result pages: google.com/search?q=login is NOT malicious
  if (isSearchEngineQuery(lowerUrl)) {
    return {
      flag: false,
      isMalicious: false,
      skippedKeywords: true,
      reason: "Search engine results page — keyword scan suppressed.",
    };
  }

  // Trusted domain: skip keyword scan entirely (but still check blacklist)
  const trusted = isTrustedDomain(lowerUrl);

  // ── Blacklist check (applies to all domains including trusted) ───────────
  if (hostname && isBlacklistedHost(hostname)) {
    return {
      flag: true,
      isMalicious: true,
      reason: `Domain is blacklisted (${getRootDomain(hostname)}).`,
    };
  }

  if (trusted) {
    return {
      flag: false,
      isMalicious: false,
      skippedKeywords: true,
      reason: `Trusted domain — keyword scan suppressed (${getRootDomain(hostname)}).`,
    };
  }

  // ── Keyword scan (untrusted, non-search domains only) ───────────────────
  const normalizedUrl = normalizeLeetspeak(lowerUrl);

  for (const keyword of SUSPICIOUS_KEYWORDS) {
    // Leet-speak obfuscated variant (e.g. "l0gin" → "login")
    if (!lowerUrl.includes(keyword) && normalizedUrl.includes(keyword)) {
      return {
        flag: true,
        isMalicious: true,
        reason: `Keyword "${keyword}" appears obfuscated with leet-speak substitution.`,
      };
    }

    // Plain match — only in hostname portion to reduce path false positives
    if (hostname.includes(keyword)) {
      return {
        flag: true,
        isMalicious: true,
        reason: `Suspicious keyword "${keyword}" found in domain name.`,
      };
    }
  }

  return {
    flag: false,
    isMalicious: false,
    reason: "No signature match found.",
  };
}

/** Async compatibility wrapper for the existing extension pipeline. */
export async function analyzeBySignature(url) {
  const result = checkSignature(url);
  return {
    source: "signature",
    verdict: result.isMalicious ? "malicious" : "safe",
    reason: result.reason,
  };
}
