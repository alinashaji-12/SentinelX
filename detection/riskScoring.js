/**
 * riskScoring.js — Sentinel Browse Extension v2.0
 *
 * WEIGHTED COMPOSITE SCORING ENGINE WITH CONFIDENCE SYSTEM
 *
 * NEW ARCHITECTURE (v2.0):
 *   Replaces additive scoring with weighted composite formula:
 *
 *   finalRiskScore = (domainScore × 0.3) +
 *                    (behaviorScore × 0.3) +
 *                    (contentScore × 0.2) +
 *                    (aiScore × 0.2)
 *
 *   Each component is 0-100, weighted by component type and signal confidence.
 *   Confidence weighting:
 *     - LOW confidence signals → 0.2x weight
 *     - MEDIUM confidence signals → 0.6x weight
 *     - HIGH confidence signals → 1.0x weight
 *   
 *   Single signal cap: No signal > 60-point contribution to final score
 *   Scoring tiers:
 *     0-30:  SAFE (no alert)
 *     30-60: SUSPICIOUS (overlay only)
 *     60+:   MALICIOUS (full warning)
 *
 * INPUTS:
 *   - domainSignals: { score (0-100), hasSafeBrowsing, hasDataset, etc. }
 *   - behaviorSignals: [{ event, confidence, severity, userInitiated }, ...]
 *   - contentSignals: { score (0-100), keywords, obfuscation, etc. }
 *   - aiSignals: { score (0-100), reasoning, confidence }
 *
 * OUTPUTS:
 *   { finalScore, domainScore, behaviorScore, contentScore, aiScore,
 *     verdict, confidence, explanation, breakdown }
 */

/**
 * Applies confidence-based weight multiplier to a signal.
 * Controls how much a signal affects final score based on reliability.
 *
 * @param {string} confidence - "LOW" | "MEDIUM" | "HIGH"
 * @returns {number} Weight multiplier (0.2, 0.6, or 1.0)
 */
function getConfidenceWeight(confidence) {
  const weights = {
    "LOW": 0.2,
    "MEDIUM": 0.6,
    "HIGH": 1.0,
  };
  return weights[confidence] || 0.6;
}

/**
 * Calculates behavioral risk score from detected behavior events.
 *
 * Aggregates all behavior signals with confidence weighting.
 * Prevents single signals from dominating via MAX_SIGNAL_CAP.
 *
 * @param {Array} behaviorSignals - Array of { event, confidence, severity, userInitiated }
 * @returns {number} Behavior risk score (0-100)
 */
export function calculateBehaviorScore(behaviorSignals = []) {
  if (!Array.isArray(behaviorSignals) || behaviorSignals.length === 0) {
    return 0;
  }

  const SIGNAL_WEIGHTS = {
    // HIGH severity (dangerous behaviors)
    "blob_download": 8,          // Automated download
    "hidden_download_anchor": 8, // Hidden download trigger
    "hidden_iframe": 7,          // Invisible iframe
    "meta_refresh": 7,           // Automatic redirect
    "clipboard_write": 6,        // Clipboard access (context-dependent)
    
    // MEDIUM severity (suspicious patterns)
    "suspicious_redirect": 5,    // Navigation hijacking
    "pushstate_abuse": 5,        // Aggressive history manipulation
    "programmatic_copy": 4,      // Automated clipboard copy
    "download_click": 3,         // User-initiated download (lower weight)
  };

  let totalScore = 0;
  let signalCount = 0;

  for (const signal of behaviorSignals) {
    // Native browser prompts are not inherently malicious
    if (signal.type === "permission_prompt" && signal.source === "browser_native") {
      continue;
    }

    const baseWeight = SIGNAL_WEIGHTS[signal.event] || 5;
    const confidenceMultiplier = getConfidenceWeight(signal.confidence);
    const signalScore = baseWeight * confidenceMultiplier;

    // Cap individual signal contribution at 60% of final score
    const cappedSignal = Math.min(signalScore, 60);
    totalScore += cappedSignal;
    signalCount++;
  }

  // Normalize to 0-100 scale (prevent unbounded accumulation)
  // With 5 average signals at confidence MEDIUM (3 points each) = 15 points
  // Scale to 0-100: divide by signal count and multiply to reach reasonable scale
  if (signalCount > 0) {
    // Average signal strength, scaled to 0-100
    return Math.min((totalScore / signalCount) * 8, 100);
  }

  return 0;
}

/**
 * Calculates domain risk score from URL structure and reputation.
 *
 * @param {object} domainSignals - Domain analysis signals
 * @param {boolean} domainSignals.hasSafeBrowsing - Google Safe Browsing hit
 * @param {boolean} domainSignals.hasDataset - Known malicious dataset hit
 * @param {boolean} domainSignals.hasIP - Uses raw IP address
 * @param {boolean} domainSignals.hasObfuscation - Encoded/obfuscated domain
 * @param {boolean} domainSignals.hasDomainAnomaly - Structure anomalies
 * @param {boolean} domainSignals.hasSuspiciousTLD - High-risk TLD
 * @returns {number} Domain risk score (0-100)
 */
export function calculateDomainScore(domainSignals = {}) {
  let score = 0;

  // CRITICAL signals (high confidence)
  if (domainSignals.hasSafeBrowsing) score += 45;   // 45% of domain score
  if (domainSignals.hasDataset) score += 40;        // 40% of domain score

  // STRONG signals (multiple overlapping anomalies)
  if (domainSignals.hasIP) score += 30;
  if (domainSignals.hasObfuscation) score += 25;
  if (domainSignals.hasDomainAnomaly) score += 20;

  // WEAK signals (isolated indicators)
  if (domainSignals.hasSuspiciousTLD) score += 10;

  // Cap at 100
  return Math.min(score, 100);
}

/**
 * Calculates content risk score from page content analysis.
 *
 * @param {object} contentSignals
 * @param {boolean} contentSignals.hasPhishingKeywords
 * @param {boolean} contentSignals.hasBrandImpersonation
 * @param {boolean} contentSignals.hasUrencyLanguage
 * @returns {number} Content risk score (0-100)
 */
export function calculateContentScore(contentSignals = {}) {
  let score = 0;

  if (contentSignals.hasPhishingKeywords) score += 35;
  if (contentSignals.hasBrandImpersonation) score += 30;
  if (contentSignals.hasUrgencyLanguage) score += 25;

  return Math.min(score, 100);
}

/**
 * Calculates AI/ML analysis risk score.
 *
 * @param {object} aiSignals
 * @param {number} aiSignals.score - AI model risk score (0-100)
 * @param {string} aiSignals.confidence - "LOW" | "MEDIUM" | "HIGH"
 * @returns {number} AI risk score (0-100) with confidence weighting
 */
export function calculateAIScore(aiSignals = {}) {
  if (!aiSignals.score) return 0;

  const confidenceWeight = getConfidenceWeight(aiSignals.confidence);
  return Math.min(aiSignals.score * confidenceWeight, 100);
}

/**
 * MAIN SCORING FUNCTION: Weighted composite risk calculation.
 *
 * Combines all signal sources into final 0-100 risk score using weights.
 * Accounts for signal confidence to reduce false positives.
 *
 * @param {object} allSignals - { domain, behavior, content, ai }
 * @returns {object} Complete risk analysis
 */
export function calculateWeightedRiskScore(allSignals = {}) {
  const {
    domain = {},
    behavior = [],
    content = {},
    ai = {},
  } = allSignals;

  // Calculate component scores
  const domainScore = calculateDomainScore(domain);
  const behaviorScore = calculateBehaviorScore(behavior);
  const contentScore = calculateContentScore(content);
  const aiScore = calculateAIScore(ai);

  // Apply weights and combine
  const finalScore = (domainScore * 0.3) +
                     (behaviorScore * 0.3) +
                     (contentScore * 0.2) +
                     (aiScore * 0.2);

  // Determine verdict and confidence
  let verdict = "SAFE";
  let confidence = 0;

  if (finalScore >= 60) {
    verdict = "MALICIOUS";
    confidence = Math.min(90 + (finalScore - 60) / 8, 99);
  } else if (finalScore >= 30) {
    verdict = "SUSPICIOUS";
    confidence = Math.min(55 + (finalScore - 30) / 3, 95);
  } else {
    verdict = "SAFE";
    confidence = Math.max(25 - finalScore / 2, 5);
  }

  return {
    finalScore: Math.round(finalScore),
    domainScore: Math.round(domainScore),
    behaviorScore: Math.round(behaviorScore),
    contentScore: Math.round(contentScore),
    aiScore: Math.round(aiScore),
    verdict,
    confidence: Math.round(confidence),
    breakdown: {
      domainWeight: "30%",
      behaviorWeight: "30%",
      contentWeight: "20%",
      aiWeight: "20%",
    },
  };
}

/**
 * Classifies attack type based on dominant signal source.
 *
 * @param {object} allSignals
 * @returns {string} MALWARE | PHISHING | OBFUSCATED_URL | SOCIAL_ENGINEERING | SAFE
 */
export function classifyAttack(allSignals = {}) {
  const { domain = {}, behavior = [], content = {} } = allSignals;

  // MALWARE: Database/SafeBrowsing hit
  if (domain.hasSafeBrowsing || domain.hasDataset) return "MALWARE";

  // PHISHING: Behavior + domain anomalies
  if (behavior.length >= 2 && domain.hasDomainAnomaly) return "PHISHING";
  if (behavior.some(b => b.event === "clipboard_write") && domain.hasIP) return "PHISHING";

  // SOCIAL_ENGINEERING: Content + behavior
  if (content.hasPhishingKeywords && behavior.length > 0) return "SOCIAL_ENGINEERING";

  // OBFUSCATED_URL: Encoding/obfuscation
  if (domain.hasObfuscation) return "OBFUSCATED_URL";

  return "SAFE";
}

/**
 * Generates human-readable explanation with decision transparency.
 *
 * @param {object} result - Result from calculateWeightedRiskScore
 * @param {object} allSignals - Original signal data
 * @returns {string} Human-readable explanation
 */
export function generateExplanation(result, allSignals = {}) {
  const { verdict, finalScore, confidence } = result;
  const { domain = {}, behavior = [] } = allSignals;

  // Build reason list
  const reasons = [];

  if (domain.hasSafeBrowsing) {
    reasons.push("Google Safe Browsing identified as malicious");
  }
  if (domain.hasDataset) {
    reasons.push("Matched known phishing/malware database");
  }
  if (domain.hasDomainAnomaly) {
    reasons.push("Domain structure appears deceptive");
  }
  if (behavior.length > 0) {
    const confidence_high = behavior.filter(b => b.confidence === "HIGH").length;
    if (confidence_high > 0) {
      reasons.push(`${confidence_high} suspicious behavior(s) detected`);
    }
  }

  // Format message by verdict
  let message = "";
  if (verdict === "MALICIOUS") {
    message = `⚠️ HIGH-RISK THREAT (${finalScore}/100, ${confidence}% confidence): ${reasons.join(" • ")}`;
  } else if (verdict === "SUSPICIOUS") {
    message = `⚠️ SUSPICIOUS ACTIVITY (${finalScore}/100, ${confidence}% confidence): ${reasons.join(" • ")}`;
  } else {
    message = `✓ No major security concerns detected (${finalScore}/100)`;
  }

  return message;
}

/**
 * Orchestrates complete risk analysis with all scoring components.
 *
 * @param {object} allSignals
 * @returns {object} Complete analysis result
 */
export function analyzeRisk(allSignals = {}) {
  const result = calculateWeightedRiskScore(allSignals);
  result.attackType = classifyAttack(allSignals);
  result.explanation = generateExplanation(result, allSignals);

  return result;
}

