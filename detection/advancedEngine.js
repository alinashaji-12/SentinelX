/**
 * advancedEngine.js — Sentinel Browse Extension
 *
 * Multi-Signal Intelligence Orchestration Engine.
 *
 * UNIFIED OUTPUT FORMAT (CRITICAL — Single Source of Truth):
 *
 * ALL returns have this exact structure:
 * {
 *   status: "safe" | "suspicious" | "malicious",
 *   trustScore: number (0-100),
 *   attackType: string (PHISHING | MALWARE | SOCIAL_ENGINEERING | OBFUSCATED_URL | SAFE),
 *   explanation: string (human-readable analysis),
 *   signals: string[] (list of detected signals),
 *   confidence: number (0-100),
 *   reason: string (concatenated reasons),
 *   reasons: string[] (array of reasons),
 *   score: number (internal scoring),
 *   sources: object[] (breakdown of each detection module),
 *   signalGroups: object (hasIntent, hasDomain, hasObfuscation, etc.),
 *   keywordMatches: string[],
 *   domainProfile: object,
 *   flag: boolean (status !== "safe"),
 *   fastPath: boolean
 * }
 *
 * CLASSIFICATION LOGIC:
 *   MALICIOUS if: Safe Browsing OR Dataset OR (intent + domain + obfuscation) OR (intent + domain, score > 6)
 *   SUSPICIOUS if: 1-2 weak signals
 *   SAFE if: Trusted domain OR no meaningful signals
 */

import { buildTrustResult } from "../utils/trustScore.js";
import {
  getRootDomain,
  getHostname,
  isTrustedDomain,
  isSearchEngineQuery,
  TRUSTED_ROOT_DOMAINS,
} from "./domainWhitelist.js";

// ─── Helpers ───────────────────────────────────────────────────────────────

function usesIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function toSource(name, verdict, triggered, detail) {
  return {
    name,
    verdict,
    triggered,
    detail: String(detail || "").trim() || "No notable signal.",
  };
}

/**
 * Classifies attack type based on signal groups.
 * Returns type for consistent handling.
 *
 * @param {object} signals
 * @returns {string} PHISHING | MALWARE | SOCIAL_ENGINEERING | OBFUSCATED_URL | SAFE
 */
function classifyAttackType(signals = {}) {
  const {
    hasIntent = false,
    hasDomainAnomaly = false,
    hasObfuscation = false,
    hasSignature = false,
    hasDataset = false,
    hasSafeBrowsing = false,
    hasIpAddress = false,
  } = signals;

  // Hard signals: always MALWARE
  if (hasSafeBrowsing || hasDataset) {
    return "MALWARE";
  }

  // Intent + domain = PHISHING
  if (hasIntent && hasDomainAnomaly) {
    return "PHISHING";
  }

  // Intent + obfuscation = SOCIAL_ENGINEERING
  if (hasIntent && hasObfuscation && !hasDomainAnomaly) {
    return "SOCIAL_ENGINEERING";
  }

  // Pure obfuscation = OBFUSCATED_URL
  if (hasObfuscation && !hasIntent && !hasDataset) {
    return "OBFUSCATED_URL";
  }

  // Domain anomaly alone = PHISHING
  if (hasDomainAnomaly && !hasIntent) {
    return "PHISHING";
  }

  // IP address = PHISHING
  if (hasIpAddress) {
    return "PHISHING";
  }

  // Signature + other = depends on other signal
  if (hasSignature && (hasDomainAnomaly || hasObfuscation)) {
    return hasObfuscation ? "MALWARE" : "PHISHING";
  }

  return "SAFE";
}

/**
 * Generates a human-readable explanation for the detection verdict.
 * Translates technical signals into understandable narratives.
 *
 * @param {object} result
 * @returns {object} { explanation, signals }
 */
function generateExplanation(result = {}) {
  const {
    status = "safe",
    signalGroups = {},
    reasons = [],
    keywordMatches = [],
    confidence = 0,
    score = 0,
  } = result;

  let explanation = "";
  const signals = [];
  const narrativeParts = [];

  if (status === "malicious") {
    explanation = "⚠️ MALICIOUS: This URL exhibits multiple strong indicators of malicious intent.";

    if (signalGroups.hasSafeBrowsing) {
      narrativeParts.push("Google Safe Browsing flagged this as a known malicious site");
      signals.push("Safe Browsing match");
    }
    if (signalGroups.hasDataset) {
      narrativeParts.push("Domain matched known phishing/malware database");
      signals.push("Phishing/Malware dataset match");
    }
    if (signalGroups.hasIntent && signalGroups.hasDomainAnomaly) {
      narrativeParts.push(
        `Phishing keywords (${keywordMatches.slice(0, 2).join(", ")}) combined with suspicious domain structure`
      );
      signals.push("Phishing intent detected");
      signals.push("Suspicious domain structure");
    }
    if (signalGroups.hasObfuscation) {
      narrativeParts.push("URL uses obfuscation techniques common in attack delivery");
      signals.push("URL obfuscation detected");
    }
    if (signalGroups.hasIpAddress) {
      narrativeParts.push("Uses raw IP address instead of domain name");
      signals.push("IP address usage");
    }

    if (narrativeParts.length === 0) {
      narrativeParts.push("Multiple attack indicators present");
    }

    explanation += " " + narrativeParts.join(". ") + ".";

  } else if (status === "suspicious") {
    explanation = "⚠️ SUSPICIOUS: This URL has some characteristics that warrant caution.";

    if (signalGroups.hasDomainAnomaly) {
      narrativeParts.push("Domain has unusual structural patterns typical of phishing sites");
      signals.push("Domain anomalies");
    }
    if (signalGroups.hasIntent) {
      narrativeParts.push(`Contains phishing-related keywords: ${keywordMatches.slice(0, 2).join(", ")}`);
      signals.push("Phishing keywords present");
    }
    if (signalGroups.hasObfuscation) {
      narrativeParts.push("URL contains obfuscation techniques");
      signals.push("URL obfuscation");
    }
    if (signalGroups.hasIpAddress) {
      narrativeParts.push("Uses IP address instead of domain");
      signals.push("IP address usage");
    }

    if (narrativeParts.length === 0) {
      narrativeParts.push("One or more weak risk signals detected");
    }

    explanation += " " + narrativeParts.join(". ") + ". Proceed with caution.";

  } else {
    explanation = "✓ SAFE: No significant malicious indicators detected.";
    signals.push("No threats identified");
  }

  return {
    explanation,
    signals: signals.length > 0 ? signals : ["No notable signals"],
  };
}

/**
 * Builds the immediate safe-override result for trusted/protected domains.
 */
function buildTrustedOverrideResult(hostname, rootDomain, isSearch) {
  const reason = isSearch
    ? "Search engine query — all scoring bypassed"
    : `Trusted domain (${rootDomain}) — all scoring bypassed`;

  const explData = generateExplanation({
    status: "safe",
    signalGroups: {},
    reasons: [reason],
    keywordMatches: [],
    confidence: 0,
    score: -5,
  });

  return {
    flag: false,
    fastPath: false,
    status: "safe",
    trustScore: 95,
    score: -5,
    confidence: 0,
    reason,
    reasons: [reason],
    attackType: "SAFE",
    explanation: explData.explanation,
    signals: explData.signals,
    sources: [],
    signalCount: 0,
    strongSignalCount: 0,
    suspiciousSignalCount: 0,
    appliedRules: [isSearch ? "HARD_OVERRIDE: SEARCH_ENGINE" : "HARD_OVERRIDE: TRUSTED_DOMAIN"],
    signalGroups: {
      hasIntent: false,
      hasDomainAnomaly: false,
      hasObfuscation: false,
      hasSignature: false,
      hasDataset: false,
      hasSafeBrowsing: false,
      hasIpAddress: false,
    },
    keywordMatches: [],
    domainProfile: {
      hostname,
      rootDomain,
      isTrusted: true,
      isSearchQuery: isSearch,
      protected: true,
    },
  };
}

/**
 * Counts obfuscation techniques.
 */
function countObfuscationTechniques(obfuscationResult) {
  const t = obfuscationResult?.techniques || {};
  return Object.values(t).filter(Boolean).length;
}

/**
 * Counts behavior signals.
 */
function countBehaviorSignals(behaviorResult) {
  const s = behaviorResult?.signals || {};
  return Object.values(s).filter(Boolean).length;
}

/**
 * Main analysis engine — orchestrates all detection modules.
 *
 * @param {string} url
 * @param {object} results — module results (mlResult, behaviorResult, etc.)
 * @param {object} context — domain/user profile context
 * @returns {object} unified result object
 */
export function analyzeUrlAdvanced(url, results = {}, context = {}) {
  const input = String(url || "");
  const lowerUrl = input.toLowerCase();
  const hostname = getHostname(lowerUrl);
  const rootDomain = getRootDomain(hostname);
  const isSearch = isSearchEngineQuery(lowerUrl);
  const trusted = isTrustedDomain(lowerUrl);

  // ── HARD OVERRIDE: trusted / search-engine domains ──────────────────
  if (trusted || isSearch) {
    return buildTrustedOverrideResult(hostname, rootDomain, isSearch);
  }

  // ── Unpack module results ─────────────────────────────────────────────
  const domainProfile = context.domainProfile || {};
  const intentResult = results.mlResult || {};
  const domainResult = results.behaviorResult || {};
  const obfuscResult = results.obfuscationResult || {};

  // ── Signal-group presence ─────────────────────────────────────────────
  const hasIntent = Boolean(intentResult.hasIntent);
  const hasDomainAnomaly = Boolean(domainResult.flag);
  const hasObfuscation = Boolean(obfuscResult.isObfuscated);
  const hasSignature = Boolean(results.signatureResult?.flag);
  const hasDataset = Boolean(results.datasetResult?.flag);
  const hasSafeBrowsing = Boolean(results.safeBrowsingResult?.isMalicious);
  const hasIpAddress = usesIpAddress(hostname);

  // ── Count sub-signals ────────────────────────────────────────────────
  const obfuscTechCount = countObfuscationTechniques(obfuscResult);
  const domainSignalCount = countBehaviorSignals(domainResult);

  const reasons = [];
  let score = 0;
  let strongSignalCount = 0;
  let suspiciousSignalCount = 0;
  const appliedRules = [];

  // ── Adaptive reputation ──────────────────────────────────────────────
  if (!domainProfile.protected) {
    if (domainProfile.trustBoost) {
      score -= 2;
      reasons.push(`Domain has established safe history`);
      appliedRules.push("ADAPTIVE_TRUST_BOOST: score-2");
    }
    if (domainProfile.highRisk) {
      score += 2;
      strongSignalCount += 1;
      reasons.push("Domain previously flagged as high-risk");
      appliedRules.push("ADAPTIVE_HIGH_RISK: score+2");
    }
  }

  // ── Hard signals ──────────────────────────────────────────────────────
  if (hasSafeBrowsing) {
    score += 6;
    strongSignalCount += 1;
    reasons.push("Google Safe Browsing flagged this URL");
    appliedRules.push("SAFE_BROWSING_HIT: score+6");
  }

  if (hasDataset) {
    score += 5;
    strongSignalCount += 1;
    reasons.push("URL matched phishing/malware database");
    appliedRules.push("DATASET_MATCH: score+5");
  }

  if (hasSignature) {
    score += 3;
    strongSignalCount += 1;
    reasons.push("Signature analysis: known phishing pattern");
    appliedRules.push("SIGNATURE_HIT: score+3");
  }

  // ── INTENT signal group ───────────────────────────────────────────────
  if (hasIntent) {
    score += 3;
    strongSignalCount += 1;
    const kw = intentResult.phishingKeywords?.join(", ") || "";
    const uw = intentResult.urgencyWords?.join(", ") || "";
    reasons.push(`Phishing intent: keywords [${kw}] + urgency [${uw}]`);
    appliedRules.push(`INTENT_DETECTED: score+3`);
  } else if ((intentResult.phishingKeywords?.length ?? 0) > 0) {
    score += 1;
    suspiciousSignalCount += 1;
    reasons.push(`Phishing keyword (weak signal): ${intentResult.phishingKeywords?.join(", ")}`);
    appliedRules.push("KEYWORD_ONLY_WEAK: score+1");
  }

  // ── DOMAIN signal group ───────────────────────────────────────────────
  if (hasDomainAnomaly) {
    const domScore = Math.min(domainSignalCount * 1.5, 4);
    score += domScore;
    domainSignalCount >= 3 ? strongSignalCount++ : suspiciousSignalCount++;
    if (domainResult.reason) {
      reasons.push(`Domain anomaly: ${domainResult.reason}`);
    }
    appliedRules.push(`DOMAIN_ANOMALY: score+${domScore}`);
  }

  // ── OBFUSCATION signal group ──────────────────────────────────────────
  if (hasObfuscation) {
    const obScore = Math.min(obfuscTechCount * 1.5, 4);
    score += obScore;
    obfuscTechCount >= 2 ? strongSignalCount++ : suspiciousSignalCount++;
    if (obfuscResult.reason) {
      reasons.push(`Obfuscation: ${obfuscResult.reason}`);
    }
    appliedRules.push(`OBFUSCATION: score+${obScore}`);
  }

  // ── IP address ────────────────────────────────────────────────────────
  if (hasIpAddress) {
    score += 2;
    suspiciousSignalCount += 1;
    reasons.push("Raw IP address used instead of domain");
    appliedRules.push("IP_ADDRESS: score+2");
  }

  // ─── DECISION LOGIC ────────────────────────────────────────────────────
  const totalSignals = strongSignalCount + suspiciousSignalCount;
  let status;

  if (hasSafeBrowsing || hasDataset) {
    status = "malicious";
    appliedRules.push("DECISION: MALICIOUS (hard external verdict)");
  } else if (hasIntent && hasDomainAnomaly && hasObfuscation) {
    status = "malicious";
    appliedRules.push("DECISION: MALICIOUS (intent + domain + obfuscation)");
  } else if (hasIntent && hasDomainAnomaly && score > 6) {
    status = "malicious";
    appliedRules.push(`DECISION: MALICIOUS (intent + domain, score=${score})`);
  } else if (hasSignature && (hasDomainAnomaly || hasObfuscation)) {
    status = "malicious";
    appliedRules.push("DECISION: MALICIOUS (signature + corroborating signal)");
  } else if (hasIpAddress && (hasIntent || hasObfuscation)) {
    status = "malicious";
    appliedRules.push("DECISION: MALICIOUS (IP + intent/obfuscation)");
  } else if (totalSignals >= 1 || score > 2) {
    status = "suspicious";
    appliedRules.push(`DECISION: SUSPICIOUS (signals=${totalSignals}, score=${score})`);
  } else {
    status = "safe";
    appliedRules.push(`DECISION: SAFE (score=${score})`);
  }

  // ── Trust score & confidence ──────────────────────────────────────────
  const trustScore = Math.max(0, Math.min(100, 100 - score * 10));
  const confidence = clamp(
    0.15 + score * 0.06 + totalSignals * 0.07 + strongSignalCount * 0.10,
    0.02,
    0.99
  );
  const confidencePercent = Math.round(confidence * 100);

  // ── Attack type classification ────────────────────────────────────────
  const signalGroups = {
    hasIntent,
    hasDomainAnomaly,
    hasObfuscation,
    hasSignature,
    hasDataset,
    hasSafeBrowsing,
    hasIpAddress,
  };
  const attackType = classifyAttackType(signalGroups);

  // ── Sources breakdown ─────────────────────────────────────────────────
  const sources = [
    toSource("Signature Analysis", hasSignature ? "malicious" : "safe", hasSignature, results.signatureResult?.reason),
    toSource("Domain Intelligence", hasDomainAnomaly ? "suspicious" : "safe", hasDomainAnomaly, domainResult.reason),
    toSource("Obfuscation Analysis", hasObfuscation ? "suspicious" : "safe", hasObfuscation, obfuscResult.reason),
    toSource("Google Safe Browsing", hasSafeBrowsing ? "malicious" : "safe", hasSafeBrowsing, results.safeBrowsingResult?.reason),
    toSource("Phishing Dataset", hasDataset ? "malicious" : "safe", hasDataset, results.datasetResult?.reason),
    toSource("Intent Detection", intentResult.hasIntent ? "malicious" : "safe", Boolean(intentResult.hasIntent), intentResult.reason),
  ];

  if (reasons.length === 0) {
    reasons.push("No significant risk signals detected");
  }

  // ── Generate explanation ──────────────────────────────────────────────
  const preliminaryResult = {
    status,
    signalGroups,
    keywordMatches: intentResult.phishingKeywords || [],
    reasons,
    confidence: Number(confidence.toFixed(2)),
    score,
  };

  const explData = generateExplanation(preliminaryResult);

  // ═════════════════════════════════════════════════════════════════════
  // UNIFIED RESULT OBJECT
  // ═════════════════════════════════════════════════════════════════════

  return {
    status,
    trustScore: Math.round(trustScore),
    attackType,
    explanation: explData.explanation,
    signals: explData.signals,
    confidence: confidencePercent,
    reason: reasons.join("; "),
    reasons,
    score: Number(score.toFixed(1)),
    sources,
    signalCount: totalSignals,
    strongSignalCount,
    suspiciousSignalCount,
    appliedRules,
    signalGroups,
    keywordMatches: intentResult.phishingKeywords || [],
    domainProfile: {
      hostname,
      rootDomain,
      isTrusted: false,
      isSearchQuery: false,
      protected: false,
      ...domainProfile,
    },
    flag: status !== "safe",
    fastPath: false,
  };
}

/**
 * Synchronous pre-navigation URL analysis.
 * All detection is 100% local (no network). Safe Browsing is skipped.
 *
 * @param {string} url
 * @param {object} context — domain/user profile
 * @returns {object} unified result object
 */
export function fastAnalyzeUrl(url, context = {}) {
  try {
    // Modules called by background.js before invoking this
    // For now, return safe as fallback
    const safeResult = {
      status: "safe",
      trustScore: 100,
      attackType: "SAFE",
      explanation: "✓ SAFE: No significant malicious indicators detected.",
      signals: ["No threats identified"],
      confidence: 0,
      reason: "Fast-check unavailable",
      reasons: ["Fast-check unavailable"],
      score: 0,
      sources: [],
      signalCount: 0,
      strongSignalCount: 0,
      suspiciousSignalCount: 0,
      appliedRules: ["FAST_CHECK_FALLBACK"],
      signalGroups: {
        hasIntent: false,
        hasDomainAnomaly: false,
        hasObfuscation: false,
        hasSignature: false,
        hasDataset: false,
        hasSafeBrowsing: false,
        hasIpAddress: false,
      },
      keywordMatches: [],
      domainProfile: {},
      flag: false,
      fastPath: true,
    };

    try {
      // In production, this would call local modules
      // For now, return safe
      return safeResult;
    } catch (err) {
      console.warn("[Sentinel] fastAnalyzeUrl error:", err);
      safeResult.reason = "Fast-check error — fail-open";
      safeResult.appliedRules = ["FAST_CHECK_ERROR: fail-open"];
      return safeResult;
    }
  } catch (err) {
    console.warn("[Sentinel] fastAnalyzeUrl outer error:", err);
    return {
      status: "safe",
      trustScore: 100,
      attackType: "SAFE",
      explanation: "✓ SAFE: Fast-check error — defaulted to safe.",
      signals: ["No threats identified"],
      confidence: 0,
      reason: "Fast-check error",
      reasons: ["Fast-check error — fail-open"],
      score: 0,
      sources: [],
      signalCount: 0,
      strongSignalCount: 0,
      suspiciousSignalCount: 0,
      appliedRules: ["FAST_CHECK_ERROR: fail-open"],
      signalGroups: {},
      keywordMatches: [],
      domainProfile: {},
      flag: false,
      fastPath: true,
    };
  }
}
