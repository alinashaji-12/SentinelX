/**
 * adaptiveProfile.js — Sentinel Browse Extension
 *
 * Domain reputation tracking and adaptive user profile derivation.
 *
 * Critical invariant (Steps 1 & 4):
 *   Trusted domains NEVER accumulate risk metrics.
 *   Storage updates for trusted domains are silently skipped.
 *   The snapshot for a trusted domain always returns protected=true,
 *   trustBoost=true, highRisk=false — regardless of stored history.
 */

import { isTrustedDomain, isSearchEngineQuery, getRootDomain, getHostname as getHostnameFromUrl } from "../detection/domainWhitelist.js";

const MAX_DOMAIN_PROFILES = 300;

export const DOMAIN_PROFILE_STORAGE_KEY = "domainProfiles";

/**
 * Extracts a lowercase hostname from any URL string.
 * Re-exported for callers in background.js that need it.
 */
export function getHostname(url) {
  try {
    return new URL(String(url || "")).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function toNumber(value) {
  return Number(value || 0);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

/**
 * Returns true if this URL belongs to a trusted or search-engine domain.
 * These domains must NEVER receive risk penalties.
 */
function isProtectedUrl(url) {
  return isTrustedDomain(url) || isSearchEngineQuery(url);
}

/**
 * Builds the "protected" profile snapshot returned for all trusted domains.
 * Regardless of any corrupted stored history, trusted domains are always safe.
 *
 * Step 1: NEVER mark trusted domains as highRisk.
 * Step 6: Remove contradictory signals — protected=true means no negative flags.
 */
function buildProtectedProfile(hostname) {
  const root = getRootDomain(hostname);
  return {
    hostname,
    rootDomain: root,
    safeVisits: 0,
    suspiciousDetections: 0,
    maliciousDetections: 0,
    bypassCount: 0,
    totalVisits: 0,
    riskVisits: 0,
    riskRatio: 0,
    reputationScore: 100,
    trustBoost: true,   // always boost trusted domains
    highRisk: false,    // NEVER high-risk for trusted domains
    isReputable: true,
    protected: true,    // flag consumed by advancedEngine.js for hard override
  };
}

/**
 * Builds the reputation snapshot for a given domain from stored profiles.
 *
 * For trusted or search-engine domains: returns buildProtectedProfile() immediately
 * (Step 1 & 4 — no risk metrics, no highRisk, protected=true).
 *
 * For untrusted domains: derives trustBoost and highRisk from visit history.
 */
export function getDomainProfileSnapshot(domainProfiles = {}, url) {
  const hostname = getHostname(url);

  // ── STEP 1 & 4: Hard guard for trusted/search domains ──────────────────
  if (!hostname || isProtectedUrl(url)) {
    return buildProtectedProfile(hostname || "");
  }

  const stored = domainProfiles[hostname] || {};
  const safeVisits = toNumber(stored.safeVisits);
  const suspiciousDetections = toNumber(stored.suspiciousDetections);
  const maliciousDetections = toNumber(stored.maliciousDetections);
  const bypassCount = toNumber(stored.bypassCount);
  const totalVisits = safeVisits + suspiciousDetections + maliciousDetections;
  const riskVisits = suspiciousDetections + maliciousDetections;
  const riskRatio = totalVisits > 0 ? riskVisits / totalVisits : 0;
  const reputationScore = clamp(
    50 + safeVisits * 8 - suspiciousDetections * 7 - maliciousDetections * 12 - bypassCount * 4,
    0,
    100
  );

  // trustBoost: domain has a solidly safe visit history
  const trustBoost = safeVisits >= 5 && maliciousDetections === 0 && riskRatio <= 0.2;
  // highRisk: domain has accumulated meaningful danger signals
  const highRisk = maliciousDetections >= 3 || riskRatio >= 0.6;

  return {
    hostname,
    rootDomain: getRootDomain(hostname),
    safeVisits,
    suspiciousDetections,
    maliciousDetections,
    bypassCount,
    totalVisits,
    riskVisits,
    riskRatio,
    reputationScore,
    trustBoost,
    highRisk,
    isReputable: safeVisits >= 3 && maliciousDetections === 0 && riskRatio <= 0.25,
    protected: false,
  };
}

export function deriveUserTrustProfile(threatHistory = [], bypassHistory = []) {
  const scans = Array.isArray(threatHistory) ? threatHistory : [];
  const bypasses = Array.isArray(bypassHistory) ? bypassHistory : [];
  const totalScans = scans.length;
  const safeVisits = scans.filter((item) => String(item?.status || "").toLowerCase() === "safe").length;
  const riskyVisits = scans.filter((item) => {
    const status = String(item?.status || "").toLowerCase();
    return status === "suspicious" || status === "malicious";
  }).length;
  const bypassRate = riskyVisits > 0 ? bypasses.length / riskyVisits : 0;
  const safeRate = totalScans > 0 ? safeVisits / totalScans : 0;
  const cautiousMode = totalScans >= 5 && bypassRate <= 0.1 && safeRate >= 0.65;
  const relaxedMode = riskyVisits >= 3 && bypassRate >= 0.35;

  return {
    totalScans,
    safeVisits,
    riskyVisits,
    bypassCount: bypasses.length,
    bypassRate: Number(bypassRate.toFixed(2)),
    safeRate: Number(safeRate.toFixed(2)),
    cautiousMode,
    relaxedMode,
    tuningLabel: cautiousMode ? "strict" : relaxedMode ? "relaxed" : "balanced",
  };
}

/**
 * Updates the stored domain profile map with the result of a scan.
 *
 * Step 4: Trusted and search-engine domains are SKIPPED entirely.
 * This prevents false "malicious" history from corrupting future scores.
 */
export function updateDomainProfileMap(domainProfiles = {}, url, finalResult = {}, wasBypassed = false) {
  const hostname = getHostname(url);
  if (!hostname) return domainProfiles;

  // ── STEP 4: Never store history for protected domains ──────────────────
  if (isProtectedUrl(url)) {
    console.info(`[Sentinel] Skipping profile update for protected domain: ${hostname}`);
    return domainProfiles;
  }

  const nextProfiles = { ...domainProfiles };
  const previous = nextProfiles[hostname] || {};
  const nextEntry = {
    safeVisits: toNumber(previous.safeVisits),
    suspiciousDetections: toNumber(previous.suspiciousDetections),
    maliciousDetections: toNumber(previous.maliciousDetections),
    bypassCount: toNumber(previous.bypassCount),
    lastSeenAt: new Date().toISOString(),
  };
  const status = String(finalResult.status || "").toLowerCase();

  if (status === "safe") {
    nextEntry.safeVisits += 1;
  } else if (status === "suspicious") {
    nextEntry.suspiciousDetections += 1;
  } else if (status === "malicious") {
    nextEntry.maliciousDetections += 1;
  }

  if (wasBypassed) {
    nextEntry.bypassCount += 1;
  }

  nextProfiles[hostname] = nextEntry;

  const entries = Object.entries(nextProfiles)
    .sort((a, b) => {
      const aSeen = new Date(a[1]?.lastSeenAt || 0).getTime() || 0;
      const bSeen = new Date(b[1]?.lastSeenAt || 0).getTime() || 0;
      return bSeen - aSeen;
    })
    .slice(0, MAX_DOMAIN_PROFILES);

  return Object.fromEntries(entries);
}

/**
 * Step 7: Resets corrupt profile entries for trusted/protected domains.
 *
 * Iterates over all stored profiles and removes any entries whose
 * hostname belongs to a trusted domain (these should never have been stored).
 * Call this once on extension startup or via a dashboard reset button.
 *
 * @param {object} domainProfiles — current stored profiles map
 * @returns {object} cleaned profiles map
 */
export function resetCorruptedProfiles(domainProfiles = {}) {
  const cleaned = {};
  let removedCount = 0;

  for (const [hostname, entry] of Object.entries(domainProfiles)) {
    // Build a fake URL to run the trusted check against the hostname
    const testUrl = `https://${hostname}/`;
    if (isProtectedUrl(testUrl)) {
      removedCount += 1;
      console.info(`[Sentinel] resetCorruptedProfiles: removed trusted domain profile "${hostname}"`);
    } else {
      cleaned[hostname] = entry;
    }
  }

  if (removedCount > 0) {
    console.info(`[Sentinel] resetCorruptedProfiles: cleared ${removedCount} protected domain profile(s)`);
  }

  return cleaned;
}
