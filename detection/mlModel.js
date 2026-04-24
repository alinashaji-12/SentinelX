/**
 * mlModel.js — Sentinel Browse Extension
 *
 * Intent Detection module.
 *
 * CORE PRINCIPLE (Task 3):
 *   A URL is only flagged for phishing INTENT when BOTH conditions are true:
 *     1. Phishing KEYWORD found in hostname (login, verify, account…)
 *     AND
 *     2. URGENCY WORD found in hostname or path (urgent, now, alert, expire…)
 *
 *   Single keyword matches alone produce no flag.
 *   This eliminates false positives on legitimate pages that happen to
 *   contain words like "verify" or "account" (e.g. bank login pages).
 *
 * The module also computes a heuristic confidence score used by the
 * multi-signal engine in advancedEngine.js for orchestration decisions.
 */

import { getHostname, isSearchEngineQuery, isTrustedDomain } from "./domainWhitelist.js";

// ─── Phishing intent vocabulary ────────────────────────────────────────────

/** Words indicating the page is trying to collect credentials or personal data. */
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
  "paypal", "amazon", "netflix", "microsoft",
]);

/** Words expressing urgency — a hallmark of social engineering. */
const URGENCY_WORDS = new Set([
  "urgent", "urgently",
  "immediately", "immediate",
  "now", "asap",
  "alert", "warning", "critical",
  "expire", "expires", "expiring", "expiration",
  "limited", "action-required", "action",
  "locked", "lock", "blocked",
  "unusual", "activity",
  "deadline", "last-chance",
]);

const MALICIOUS_CONFIDENCE_THRESHOLD = 0.60;

// ─── Helpers ───────────────────────────────────────────────────────────────

function tokenize(text) {
  // Split on non-alphanumeric characters to get individual words
  return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function findMatches(tokens, wordSet) {
  return tokens.filter((t) => wordSet.has(t));
}

function countDots(hostname) {
  return (hostname.match(/\./g) || []).length;
}

/**
 * Computes phishing intent detection result.
 *
 * Intent = phishing keyword IN hostname + urgency word IN hostname OR path.
 * Confidence score is computed from 4 features and used by advancedEngine.js
 * as a supplementary signal (not independently sufficient for MALICIOUS verdict).
 *
 * @param {string} url
 * @returns {{
 *   flag: boolean,
 *   isMalicious: boolean,
 *   hasIntent: boolean,
 *   phishingKeywords: string[],
 *   urgencyWords: string[],
 *   confidence: number,
 *   model: string,
 *   reason: string
 * }}
 */
export function predictMalicious(url) {
  const input = String(url || "").toLowerCase();

  // Fast-path: trusted and search-engine domains always return clean
  if (isTrustedDomain(input) || isSearchEngineQuery(input)) {
    return {
      flag: false,
      isMalicious: false,
      hasIntent: false,
      phishingKeywords: [],
      urgencyWords: [],
      confidence: 0.02,
      model: "intent-ml",
      reason: "Trusted or search-engine domain — intent check suppressed.",
    };
  }

  let parsed;
  try { parsed = new URL(input); } catch {
    return {
      flag: false,
      isMalicious: false,
      hasIntent: false,
      phishingKeywords: [],
      urgencyWords: [],
      confidence: 0.1,
      model: "intent-ml",
      reason: "URL could not be parsed for intent analysis.",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname.toLowerCase();
  const urlLength = input.length;
  const dotCount = countDots(hostname);

  // Tokenize hostname and path separately
  const hostnameTokens = tokenize(hostname);
  const pathTokens = tokenize(path);
  const allTokens = [...hostnameTokens, ...pathTokens];

  // ── Intent detection: keyword + urgency combination ──────────────────────
  const foundKeywords = findMatches(hostnameTokens, PHISHING_KEYWORDS);
  // Urgency words can be in hostname OR path — phishers use both
  const foundUrgency = findMatches(allTokens, URGENCY_WORDS);

  // TRUE INTENT: both must be present
  const hasIntent = foundKeywords.length > 0 && foundUrgency.length > 0;

  // ── Confidence score (4 normalized features) ─────────────────────────────
  // Used by advancedEngine.js as a supplementary numeric signal,
  // NOT as a standalone malicious trigger.
  let score = 0;
  score += Math.min(urlLength / 150, 1) * 0.20;       // long URL
  score += Math.min(dotCount / 5, 1) * 0.20;           // dot density
  score += (foundKeywords.length > 0 ? 1 : 0) * 0.30; // has phishing keyword
  score += (foundUrgency.length > 0 ? 1 : 0) * 0.30;  // has urgency word

  const confidence = Number(Math.min(Math.max(score, 0), 1).toFixed(3));

  // ── Flag: only when INTENT is confirmed (keyword + urgency) ──────────────
  // High confidence alone is NOT sufficient for flag=true.
  const isMalicious = hasIntent && confidence >= MALICIOUS_CONFIDENCE_THRESHOLD;

  let reason;
  if (hasIntent) {
    reason = `Phishing intent detected: keywords=[${foundKeywords.join(",")}] + urgency=[${foundUrgency.join(",")}]. Confidence: ${confidence}.`;
  } else if (foundKeywords.length > 0) {
    reason = `Phishing keyword found (${foundKeywords.join(",")}) but no urgency words — insufficient for intent flag.`;
  } else if (foundUrgency.length > 0) {
    reason = `Urgency words found (${foundUrgency.join(",")}) but no phishing keywords — insufficient for intent flag.`;
  } else {
    reason = `No phishing intent signals detected. Confidence: ${confidence}.`;
  }

  return {
    flag: isMalicious,
    isMalicious,
    hasIntent,
    phishingKeywords: foundKeywords,
    urgencyWords: foundUrgency,
    confidence,
    model: "intent-ml",
    reason,
  };
}
