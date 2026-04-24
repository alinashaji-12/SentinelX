/**
 * behavior.js — Sentinel Browse Extension
 *
 * Domain Intelligence module.
 * Detects suspicious domain structure signals:
 *   - High-risk TLDs (.xyz, .ru, .top, .tk, .pw, .cc…)
 *   - Hyphen-heavy domains (common in phishing)
 *   - Unusually long hostnames
 *   - Deep subdomain nesting
 *   - Excessive special characters in URL
 *
 * IMPORTANT: Trusted and search-engine domains bypass ALL checks.
 * Each signal is individually weighted; the module returns both a
 * flag and a per-signal breakdown for the multi-signal engine.
 */

import { isTrustedDomain, isSearchEngineQuery } from "./domainWhitelist.js";

// ─── High-risk TLDs ────────────────────────────────────────────────────────
// These TLDs are disproportionately abused in phishing because they are cheap,
// anonymous, or have historically weak abuse controls.
const HIGH_RISK_TLDS = new Set([
  "xyz", "tk", "ml", "ga", "cf", "gq", // free/near-free TLDs (Freenom etc.)
  "top", "club", "online", "site", "web",
  "ru", "cn", "pw", "cc", "ws",
  "info", "biz",
  "click", "link", "live", "stream",
  "zip", "mov",                          // Google-released but abused
]);

// ─── Benign long-URL domains (CDN, analytics, etc.) ───────────────────────
// These legitimately produce long URLs and should not trigger URL-length signal.
const LONG_URL_EXEMPTIONS = new Set([
  "youtube.com", "youtu.be", "docs.google.com", "drive.google.com",
  "accounts.google.com", "mail.google.com",
  "sharepoint.com", "office.com",
  "stackoverflow.com", "github.com",
]);

function getHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function getRootTLD(hostname) {
  const parts = hostname.split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : "";
}

function countHyphens(hostname) {
  return (hostname.match(/-/g) || []).length;
}

function countSpecialChars(value) {
  const matches = value.match(/[@\-_ %]/g);
  return matches ? matches.length : 0;
}

function isLongUrlExempt(hostname) {
  return [...LONG_URL_EXEMPTIONS].some((h) => hostname === h || hostname.endsWith(`.${h}`));
}

/**
 * Analyzes domain structure and URL anatomy for behavioral risk signals.
 *
 * Returns:
 *   flag          — true if any signal crossed threshold
 *   signals       — { tldRisk, hyphenRisk, longHostname, deepSubdomain, longUrl, specialChars }
 *   score         — raw integer count of triggered signals
 *   reasons       — human-readable explanations
 *
 * @param {string} url
 */
export function analyzeBehavior(url) {
  // Trusted and search-engine domains bypass all behavioral checks.
  if (isTrustedDomain(url) || isSearchEngineQuery(url)) {
    return {
      flag: false,
      isSuspicious: false,
      score: 0,
      signals: {},
      reason: "Trusted or search-engine domain — behavior check suppressed.",
    };
  }

  const input = String(url || "");
  let parsedUrl;

  try {
    parsedUrl = new URL(input);
  } catch {
    return {
      flag: true,
      isSuspicious: true,
      score: 4,
      signals: { invalidUrl: true },
      reason: "Invalid or malformed URL.",
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const tld = getRootTLD(hostname);
  const parts = hostname.split(".").filter(Boolean);
  const dotCount = parts.length - 1;
  const hyphenCount = countHyphens(hostname);
  const specialCharCount = countSpecialChars(input);

  const signals = {};
  let score = 0;
  const reasons = [];

  // ── Signal 1: Suspicious TLD ─────────────────────────────────────────────
  if (tld && HIGH_RISK_TLDS.has(tld)) {
    signals.tldRisk = true;
    score += 2;
    reasons.push(`High-risk TLD detected (.${tld})`);
  }

  // ── Signal 2: Hyphen-heavy domain ────────────────────────────────────────
  // Phishers use hyphens to simulate sub-brands: "paypal-secure-login.com"
  if (hyphenCount >= 3) {
    signals.hyphenRisk = true;
    score += 2;
    reasons.push(`Hyphen-heavy domain (${hyphenCount} hyphens) — common in brand impersonation`);
  } else if (hyphenCount >= 2) {
    signals.hyphenRisk = true;
    score += 1;
    reasons.push(`Multiple hyphens in domain (${hyphenCount})`);
  }

  // ── Signal 3: Unusually long hostname ────────────────────────────────────
  if (hostname.length > 40) {
    signals.longHostname = true;
    score += 1;
    reasons.push(`Unusually long hostname (${hostname.length} chars)`);
  }

  // ── Signal 4: Deep subdomain nesting ─────────────────────────────────────
  if (parts.length >= 5) {
    signals.deepSubdomain = true;
    score += 2;
    reasons.push(`Deep subdomain nesting (${parts.length} labels)`);
  } else if (parts.length === 4) {
    signals.deepSubdomain = true;
    score += 1;
    reasons.push("Elevated subdomain depth (4 labels)");
  }

  // ── Signal 5: Very long URL (exempt CDN/docs domains) ────────────────────
  if (input.length > 120 && !isLongUrlExempt(hostname)) {
    signals.longUrl = true;
    score += 1;
    reasons.push(`Unusually long URL (${input.length} chars)`);
  }

  // ── Signal 6: Excessive special characters ───────────────────────────────
  if (specialCharCount >= 6) {
    signals.specialChars = true;
    score += 1;
    reasons.push("Excessive special characters in URL");
  }

  return {
    flag: score >= 2,
    isSuspicious: score >= 2,
    score,
    signals,
    reason: reasons.length > 0
      ? reasons.join("; ") + "."
      : "No suspicious domain behavior detected.",
  };
}

/** Async compatibility wrapper for the existing extension pipeline. */
export async function analyzeByBehavior(url) {
  const result = analyzeBehavior(url);
  return {
    source: "behavior",
    verdict: result.isSuspicious ? "suspicious" : "safe",
    reason: `${result.reason} (score: ${result.score})`,
  };
}
