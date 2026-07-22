/**
 * threatEvaluator.js — Centralized Threat Decision Engine
 *
 * PRODUCTION-GRADE ALERT DECISION SYSTEM
 * ══════════════════════════════════════════════════════════════════════
 *
 * PURPOSE:
 *   Provide a single function for all threat alert decisions:
 *   - Weighted signal correlation
 *   - Confidence weighting
 *   - Trust-aware risk moderation
 *   - Alert hysteresis (anti-flicker)
 *   - Cooldown enforcement
 *   - Explainable reasoning
 *   - Hard safety overrides
 *
 * CONTRACT:
 *   evaluateThreat(result, context) → {
 *     shouldAlert: boolean,
 *     severity: "safe" | "suspicious" | "malicious",
 *     finalRisk: number,     // 0–100
 *     reasoning: string[],
 *     cooldownRequired: boolean,
 *     cooldownDuration: number  // ms
 *   }
 *
 * INTEGRATION POINTS:
 *   • Called from background.js BEFORE sending chrome.tabs.sendMessage
 *   • Called from content.js (if needed) for overlay display
 *   • Maintains state for hysteresis (lastSeverity per URL)
 *   • Enforces cooldown via timing checks
 */

"use strict";

// ══════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════════════

/**
 * Signal type weights for correlation scoring.
 * Signals with higher weights indicate stronger threat indicators.
 */
const SIGNAL_WEIGHTS = {
  // Critical: Hard malware/phishing indicators
  "phishing_form": 3.5,
  "clipboard_hijack": 3.0,
  "keylogger_detected": 3.5,
  "malware_signature": 4.0,
  "ransomware_pattern": 4.0,
  "hardBlockStrategy": 3.5,

  // High: Credential harvesting patterns
  "credential_harvesting": 3.0,
  "login_form_on_suspicious": 2.5,
  "fake_login_page": 3.0,
  "phishing_keyword": 2.0,

  // Medium: Behavioral anomalies
  "behavioral_anomaly": 2.0,
  "hidden_iframe": 1.5,
  "suspicious_redirect": 2.5,
  "obfuscated_url": 2.0,
  "scamContentDetected": 2.0,
  "scamAdvanced": 2.0,
  "typosquatting": 2.5,

  // Medium: Domain reputation issues
  "brand_impersonation": 2.5,
  "high_risk_tld": 1.5,
  "homoglyph_detected": 2.0,
  "long_hostname": 1.0,
  "entropy_anomaly": 1.5,
  "url_shortener": 1.0,

  // Low: Encoding tricks
  "URL_encoding": 0.5,
  "double_encoding": 1.0,
  "decodedSuspiciousContent": 1.5,
  "punycode": 1.0,

  // Informational
  "ip_address": 0.5,
  "redirectLoop": 1.5,

  // ── SSL / TLS signals (Phase 1) ────────────────────────────────────────
  // These map directly to certificate issues detected via webRequest API.
  // Weights are calibrated relative to behavioral signals:
  //   • insecure_http alone ≈ low risk (many legacy CDNs still use HTTP)
  //   • invalid/expired cert = strong risk (clear user deception signal)
  //   • self_signed_cert + any other signal = suspicious at minimum
  //   • weak_encryption = medium (SHA1/MD5 deprecated but not always attack)
  //   • mixed_content = low (often third-party ads on otherwise safe pages)
  "insecure_http":      1.5,   // Plain HTTP navigation (no HTTPS)
  "invalid_ssl":        3.5,   // Cert validation failed / untrusted CA
  "expired_cert":       3.0,   // Certificate past validTo date
  "self_signed_cert":   2.5,   // Issuer == Subject (no trusted CA chain)
  "domain_mismatch":    3.5,   // SAN/CN does not match the hostname
  "weak_encryption":    1.5,   // SHA-1, MD5, RC4, DES detected
  "mixed_content":      1.0,   // HTTPS page loads HTTP sub-resources

  // Default weight for unknown signals
  "default": 1.0,
};

/**
 * Signal strength threshold rules
 */
const SIGNAL_THRESHOLDS = {
  ignore: 2,        // strength < 2 → ignore
  suspicious: 4,    // strength 2–4 → suspicious
  highRisk: 100,    // strength > 4 → high risk
};

/**
 * Risk score decision thresholds for severity classification
 */
const RISK_THRESHOLDS = {
  malicious: 80,    // finalRisk >= 80 → malicious
  suspicious: 40,   // finalRisk >= 40 → suspicious
  safe: 0,          // finalRisk < 40 → safe
};

/**
 * Hard safety override signals.
 * If BOTH signal is present AND confidence > 0.7, force malicious.
 *
 * NOTE: clipboard_hijack is intentionally excluded — it is too frequently
 * triggered by legitimate sites (copy buttons, editors) and must not alone
 * force a malicious verdict. It is still scored normally by SIGNAL_WEIGHTS.
 */
const HARD_SAFETY_OVERRIDES = new Set([
  "phishing_form",
  "keylogger_detected",
  "malware_signature",
  "ransomware_pattern",
]);

/**
 * Signal decay rules: reduce weights for high-trust contexts
 */
const SIGNAL_DECAY_RULES = {
  "clipboard_hijack": {
    decayOnHighTrust: 0.3,    // Reduce weight by 70% on high-trust domains
    minWeight: 0.5,            // Don't decay below this
  },
  "hidden_iframe": {
    decayOnHighTrust: 0.4,
    minWeight: 0.5,
  },
  "URL_encoding": {
    decayOnHighTrust: 0.2,
    minWeight: 0,
  },
};

/**
 * Cooldown configuration by severity
 */
const COOLDOWN_CONFIG = {
  "malicious": {
    enabled: false,      // Never cooldown critical alerts
    duration: 0,
  },
  "suspicious": {
    enabled: true,
    duration: 60000,      // FIX 7: 60 seconds (not 5s) — suppress duplicate suspicious on same domain only
  },
  "safe": {
    enabled: false,      // Don't alert on safe
    duration: 0,
  },
};

/**
 * Trust tier risk modifiers
 */
const TRUST_MODIFIERS = {
  "high": 0.6,         // Reduce risk by 40% on high-trust domains
  "medium": 1.0,       // No modifier on medium-trust domains
  "low": 1.2,          // Increase risk by 20% on low-trust domains
};

/**
 * Confidence weighting formula
 * If confidence < 50%, further reduce finalRisk by 30%
 */
const CONFIDENCE_REDUCTION = {
  threshold: 0.5,      // confidence < 50%
  reduction: 0.7,      // multiply risk by 70%
};

/**
 * Hysteresis rules: prevent rapid severity transitions
 */
const HYSTERESIS_RULES = {
  "malicious": {
    canDowngradeTo: ["malicious"],    // Malicious stays malicious
  },
  "suspicious": {
    canDowngradeTo: ["suspicious", "safe"],
  },
  "safe": {
    canDowngradeTo: ["safe", "suspicious", "malicious"],
  },
};

// ══════════════════════════════════════════════════════════════════════
// STATE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════

/**
 * In-memory state for per-URL hysteresis tracking.
 * Map: normalized URL → { lastSeverity, lastUpdateTime }
 *
 * NOTE: This is in-memory and persists for the lifetime of the service worker.
 * On service worker restart, state is reset (acceptable — hysteresis is a
 * short-term feature to prevent flicker during a single browsing session).
 */
const hysteresisState = new Map();

/**
 * Cooldown tracker: tracks when the last alert of each severity was shown.
 * Map: URL → { severity, timestamp }
 */
const cooldownState = new Map();

// ══════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════

/**
 * Compute the total weighted signal strength from a list of signal types.
 *
 * @param {string[]|object[]} signals - Array of signal type strings or objects with .type
 * @returns {number} Total weighted strength
 */
function computeSignalStrength(signals) {
  if (!Array.isArray(signals)) return 0;

  return signals.reduce((sum, signal) => {
    // Handle both string and object signal formats
    const signalType = typeof signal === "string" ? signal : signal.type || signal;
    const weight = SIGNAL_WEIGHTS[signalType] || SIGNAL_WEIGHTS.default;
    return sum + weight;
  }, 0);
}

/**
 * Apply signal decay for high-trust domains.
 * Reduces weights for certain signals when domain is explicitly trusted.
 *
 * @param {string[]} signals
 * @param {string} trustTier - "high" | "medium" | "low"
 * @returns {number} Adjusted total weight
 */
function applySignalDecayByTrust(signals, trustTier) {
  if (trustTier !== "high" || !Array.isArray(signals)) {
    return computeSignalStrength(signals);
  }

  let totalWeight = 0;
  for (const signal of signals) {
    const signalType = typeof signal === "string" ? signal : signal.type || signal;
    let weight = SIGNAL_WEIGHTS[signalType] || SIGNAL_WEIGHTS.default;

    // Apply decay rule if exists
    if (SIGNAL_DECAY_RULES[signalType]) {
      const rule = SIGNAL_DECAY_RULES[signalType];
      const decayedWeight = weight * rule.decayOnHighTrust;
      weight = Math.max(rule.minWeight, decayedWeight);
    }

    totalWeight += weight;
  }

  return totalWeight;
}

/**
 * Classify threat level based on signal strength.
 *
 * @param {number} strength
 * @returns {"ignore" | "suspicious" | "malicious"}
 */
function classifyBySignalStrength(strength) {
  if (strength < SIGNAL_THRESHOLDS.ignore) return "ignore";
  if (strength < SIGNAL_THRESHOLDS.suspicious) return "suspicious";
  return "malicious";
}

/**
 * Apply confidence weighting to final risk score.
 *
 * @param {number} baseRisk
 * @param {number} confidence - 0–100
 * @returns {number} Adjusted risk
 */
function applyConfidenceWeighting(baseRisk, confidence) {
  let finalRisk = baseRisk;

  // Normalize confidence to 0–1
  const normalizedConfidence = Math.max(0, Math.min(100, confidence)) / 100;

  // Multiply by confidence
  finalRisk = finalRisk * normalizedConfidence;

  // Further reduce if confidence is low (< 50%)
  if (normalizedConfidence < CONFIDENCE_REDUCTION.threshold) {
    finalRisk = finalRisk * CONFIDENCE_REDUCTION.reduction;
  }

  return finalRisk;
}

/**
 * Apply trust-aware risk moderation.
 *
 * @param {number} risk
 * @param {string} trustTier - "high" | "medium" | "low"
 * @returns {number} Adjusted risk
 */
function applyTrustModeration(risk, trustTier) {
  const modifier = TRUST_MODIFIERS[trustTier] || TRUST_MODIFIERS.medium;
  return risk * modifier;
}

/**
 * Check if a hard safety override is triggered.
 * Both signal presence AND confidence > 0.7 required.
 *
 * @param {string[]} signals
 * @param {number} confidence - 0–100
 * @returns {boolean}
 */
function isHardSafetyOverride(signals, confidence) {
  if (!Array.isArray(signals) || confidence <= 70) {
    return false;
  }

  return signals.some((sig) => {
    const signalType = typeof sig === "string" ? sig : sig.type || sig;
    return HARD_SAFETY_OVERRIDES.has(signalType);
  });
}

/**
 * Apply hysteresis to prevent severity downgrade (anti-flicker).
 *
 * @param {string} normalizedUrl
 * @param {string} newSeverity
 * @returns {string} Final severity after hysteresis rules
 */
function applyHysteresis(normalizedUrl, newSeverity) {
  const state = hysteresisState.get(normalizedUrl);

  // No prior state — use new severity
  if (!state) {
    hysteresisState.set(normalizedUrl, {
      lastSeverity: newSeverity,
      lastUpdateTime: Date.now(),
    });
    return newSeverity;
  }

  const lastSeverity = state.lastSeverity;

  // Check if downgrade is allowed by hysteresis rules
  const rules = HYSTERESIS_RULES[lastSeverity];
  if (!rules || !rules.canDowngradeTo.includes(newSeverity)) {
    // Downgrade not allowed — keep last severity
    console.log(
      `[Sentinel-Hysteresis] Preventing downgrade: ${lastSeverity} → ${newSeverity}`
    );
    return lastSeverity;
  }

  // Allowed transition — update state
  hysteresisState.set(normalizedUrl, {
    lastSeverity: newSeverity,
    lastUpdateTime: Date.now(),
  });

  return newSeverity;
}

/**
 * Check if alert is within cooldown period.
 *
 * @param {string} normalizedUrl
 * @param {string} severity
 * @returns {boolean} true if alert is in cooldown (should skip)
 */
function isCoolingDown(normalizedUrl, severity) {
  const config = COOLDOWN_CONFIG[severity];

  if (!config || !config.enabled) {
    return false;
  }

  const state = cooldownState.get(normalizedUrl);
  if (!state) {
    return false;
  }

  const elapsed = Date.now() - state.timestamp;
  if (elapsed < config.duration) {
    return true;  // In cooldown
  }

  // Cooldown expired — clean up
  cooldownState.delete(normalizedUrl);
  return false;
}

/**
 * Record alert in cooldown tracker.
 *
 * @param {string} normalizedUrl
 * @param {string} severity
 */
function recordCooldown(normalizedUrl, severity) {
  cooldownState.set(normalizedUrl, {
    severity,
    timestamp: Date.now(),
  });
}

/**
 * Build reasoning explanation from decision factors.
 *
 * @param {object} params
 * @returns {string[]} Array of human-readable reasons
 */
function buildReasoning(params) {
  const {
    signals,
    signalStrength,
    confidence,
    trustTier,
    finalRisk,
    baseReasons,
    isHardOverride,
  } = params;

  const reasoning = [];

  if (isHardOverride) {
    reasoning.push("🚨 CRITICAL: Hard safety override triggered");
    if (Array.isArray(signals)) {
      const criticalSignals = signals.filter((s) =>
        HARD_SAFETY_OVERRIDES.has(typeof s === "string" ? s : s.type || s)
      );
      if (criticalSignals.length > 0) {
        reasoning.push(`Critical signals detected: ${criticalSignals.join(", ")}`);
      }
    }
  }

  // Add original reasons from detection engine
  if (Array.isArray(baseReasons)) {
    reasoning.push(...baseReasons.slice(0, 2));  // Limit to 2 for conciseness
  }

  // Signal correlation
  if (signals && signals.length > 0) {
    reasoning.push(`${signals.length} threat signals correlated`);
    if (signalStrength >= 4) {
      reasoning.push("Multiple strong indicators detected");
    }
  }

  // Confidence assessment
  if (confidence < 50) {
    reasoning.push("⚠ Low confidence — may be false positive");
  } else if (confidence >= 90) {
    reasoning.push("✓ High confidence threat assessment");
  }

  // Trust tier
  if (trustTier === "low") {
    reasoning.push("Domain has low reputation");
  }

  // Risk score
  if (finalRisk >= 80) {
    reasoning.push("Risk score exceeds malicious threshold");
  } else if (finalRisk >= 40) {
    reasoning.push("Risk score indicates suspicious activity");
  }

  return reasoning;
}

/**
 * MAIN FUNCTION: Centralized threat evaluation engine.
 *
 * Orchestrates all decision factors:
 *   1. Signal correlation with weighting
 *   2. Confidence weighting
 *   3. Trust-aware moderation
 *   4. Hard safety overrides
 *   5. Hysteresis (anti-flicker)
 *   6. Cooldown enforcement
 *   7. Reasoning generation
 *
 * @param {object} result - Detection engine result from analyzeUrl()
 * @param {object} context - Additional context (optional)
 *   - trustTier: "high" | "medium" | "low"
 *   - userProfile: { sensitivityLevel, recentlyBypassed }
 *   - previousSeverity: string (for hysteresis)
 *
 * @returns {object} {
 *   shouldAlert: boolean,
 *   severity: "safe" | "suspicious" | "malicious",
 *   finalRisk: number,
 *   reasoning: string[],
 *   cooldownRequired: boolean,
 *   cooldownDuration: number,
 *   debugInfo: object  // For dev_mode
 * }
 */
function evaluateThreat(result, context = {}) {
  // ── Input validation ──────────────────────────────────────────────
  if (!result || typeof result !== "object") {
    return {
      shouldAlert: false,
      severity: "safe",
      finalRisk: 0,
      reasoning: ["Invalid input to threat evaluator"],
      cooldownRequired: false,
      cooldownDuration: 0,
    };
  }

  const normalizedUrl = context.url || "unknown";
  const trustTier = context.trustTier || "medium";
  const signals = result.signals || [];
  const baseConfidence = result.confidence || 50;
  const baseRiskScore = result.score || 0;
  const baseStatus = result.status || "safe";
  const baseReasons = result.reasons || [];

  // ── Structured logging ─────────────────────────────────────────
  const debugInfo = {
    signals,
    baseStatus,
    baseRiskScore,
    confidence: baseConfidence,
    trustTier,
  };

  try {
    // ───────────────────────────────────────────────────────────────
    // STEP 0: HIGH-TRUST HARD OVERRIDE (Rule 5)
    // ───────────────────────────────────────────────────────────────
    // High-trust domains get an immediate safe verdict BEFORE any signal
    // scoring.  This eliminates false positives on google.com, university
    // sites, etc., where behavioral signals are almost always benign.
    if (trustTier === "high") {
      debugInfo.trustHardOverride = true;
      console.debug("[Sentinel FIX] 🏆 High-trust domain — all signals suppressed", { trustTier, signals, url: normalizedUrl });
      return {
        shouldAlert: false,
        severity: "safe",
        finalRisk: 5,
        reasoning: ["Trusted domain — behavior signals ignored"],
        cooldownRequired: false,
        cooldownDuration: 0,
        debugInfo,
      };
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 1: HARD SAFETY OVERRIDE
    // ───────────────────────────────────────────────────────────────
    const hasHardOverride = isHardSafetyOverride(signals, baseConfidence);
    if (hasHardOverride) {
      debugInfo.hardOverride = true;
      const reasoning = buildReasoning({
        signals,
        confidence: baseConfidence,
        trustTier,
        finalRisk: 100,
        baseReasons,
        isHardOverride: true,
      });

      return {
        shouldAlert: true,
        severity: "malicious",
        finalRisk: 100,
        reasoning,
        cooldownRequired: false,  // Malicious always shows
        cooldownDuration: 0,
        debugInfo,
      };
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 2: SIGNAL CORRELATION WITH WEIGHTING
    // ───────────────────────────────────────────────────────────────
    const signalStrength = applySignalDecayByTrust(signals, trustTier);
    debugInfo.signalStrength = signalStrength;

    // Classify by signal strength
    const strengthClassification = classifyBySignalStrength(signalStrength);

    // ── RULE 4: Single weak signal — never alert ────────────────────────
    // A single behavioral signal (e.g. one redirect, one clipboard event)
    // without corroboration is almost always a false positive.
    // Hard-override signals (phishing_form, malware_signature) are exempt
    // because they already returned above.  This only suppresses weak
    // signals that didn't trigger the hard-override path.
    if (signals.length === 1) {
      debugInfo.singleSignalSuppressed = true;
      console.debug("[Sentinel FIX] 🚫 Single weak signal ignored — no corroboration", { signal: signals[0], url: normalizedUrl });
      return {
        shouldAlert: false,
        severity: "safe",
        finalRisk: 10,
        reasoning: ["Single weak signal ignored — requires corroboration"],
        cooldownRequired: false,
        cooldownDuration: 0,
        debugInfo,
      };
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 3: CONFIDENCE WEIGHTING
    // ───────────────────────────────────────────────────────────────
    let baseRisk = baseRiskScore;

    // If signal strength says "malicious" but base score is low, use signal
    if (strengthClassification === "malicious" && baseRisk < 60) {
      baseRisk = 70;
      debugInfo.riskAdjustedBySignals = true;
    }

    // Apply confidence weighting
    let finalRisk = applyConfidenceWeighting(baseRisk, baseConfidence);
    debugInfo.afterConfidenceWeighting = finalRisk;

    // ───────────────────────────────────────────────────────────────
    // STEP 4: TRUST-AWARE MODERATION
    // ───────────────────────────────────────────────────────────────
    finalRisk = applyTrustModeration(finalRisk, trustTier);
    debugInfo.afterTrustModeration = finalRisk;

    // ── RULE 6: Clipboard risk cap ────────────────────────────────────
    // clipboard_hijack alone must never push finalRisk above the suspicious
    // band (40–79).  If it is present as a signal, cap at 40 to prevent a
    // single behavioural event from triggering a malicious verdict.
    if (Array.isArray(signals) && signals.includes("clipboard_hijack")) {
      if (finalRisk > 40) {
        console.debug(`[Sentinel FIX] ✂️ clipboard_hijack risk capped: ${finalRisk.toFixed(1)} → 40`);
        finalRisk = 40;
        debugInfo.clipboardRiskCapped = true;
      }
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 5: DETERMINE SEVERITY BY RISK THRESHOLDS
    // ───────────────────────────────────────────────────────────────
    let severity = "safe";
    if (finalRisk >= RISK_THRESHOLDS.malicious) {
      severity = "malicious";
    } else if (finalRisk >= RISK_THRESHOLDS.suspicious) {
      severity = "suspicious";
    }

    // FIX 7 — Respect SUSPICIOUS from detectionEngine as first-class state
    // If detectionEngine already classified as suspicious, ensure we don't downgrade it
    if (baseStatus === "suspicious" && severity === "safe") {
      severity = "suspicious";
      debugInfo.suspiciousFromDetectionEngine = true;
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 6: APPLY HYSTERESIS (ANTI-FLICKER)
    // ───────────────────────────────────────────────────────────────
    severity = applyHysteresis(normalizedUrl, severity);
    debugInfo.afterHysteresis = severity;

    // ───────────────────────────────────────────────────────────────
    // STEP 7: COOLDOWN ENFORCEMENT
    // ───────────────────────────────────────────────────────────────
    let shouldAlert = severity !== "safe";
    let cooldownRequired = false;
    let cooldownDuration = 0;

    if (shouldAlert && isCoolingDown(normalizedUrl, severity)) {
      shouldAlert = false;
      cooldownRequired = true;
      cooldownDuration = COOLDOWN_CONFIG[severity].duration;
      debugInfo.coolingDown = true;
    }

    // Record cooldown if alert will be shown
    if (shouldAlert && severity !== "safe") {
      recordCooldown(normalizedUrl, severity);
      const config = COOLDOWN_CONFIG[severity];
      if (config && config.enabled) {
        cooldownDuration = config.duration;
      }
    }

    // ───────────────────────────────────────────────────────────────
    // STEP 8: BUILD REASONING
    // ───────────────────────────────────────────────────────────────
    const reasoning = buildReasoning({
      signals,
      signalStrength,
      confidence: baseConfidence,
      trustTier,
      finalRisk,
      baseReasons,
      isHardOverride: false,
    });

    // ───────────────────────────────────────────────────────────────
    // RETURN DECISION
    // ───────────────────────────────────────────────────────────────
    return {
      shouldAlert,
      severity,
      finalRisk: Math.round(finalRisk * 10) / 10,  // Round to 1 decimal
      reasoning,
      cooldownRequired,
      cooldownDuration,
      debugInfo,
    };
  } catch (error) {
    // Fail-open: on any error, return safe
    console.error("[Sentinel-ThreatEvaluator] Error:", error);
    return {
      shouldAlert: false,
      severity: "safe",
      finalRisk: 0,
      reasoning: ["Evaluator error — defaulting to safe"],
      cooldownRequired: false,
      cooldownDuration: 0,
      debugInfo: { error: error.message },
    };
  }
}

/**
 * STRUCTURED DEBUG LOGGING
 * Call this to log full evaluation details (use in dev_mode)
 *
 * @param {string} url
 * @param {object} decision - Return value from evaluateThreat
 */
function logEvaluation(url, decision) {
  console.group("[Sentinel Threat Evaluation]");
  console.log("URL:", url);
  console.log("Signals:", decision.debugInfo?.signals || []);
  console.log("Signal Strength:", decision.debugInfo?.signalStrength);
  console.log("Base Risk Score:", decision.debugInfo?.baseRiskScore);
  console.log("Confidence:", decision.debugInfo?.confidence);
  console.log("Trust Tier:", decision.debugInfo?.trustTier);
  console.log("After Confidence Weighting:", decision.debugInfo?.afterConfidenceWeighting);
  console.log("After Trust Moderation:", decision.debugInfo?.afterTrustModeration);
  console.log("Final Risk:", decision.finalRisk);
  console.log("Severity:", decision.severity);
  console.log("Should Alert:", decision.shouldAlert);
  console.log("Reasoning:", decision.reasoning);
  console.log("Cooldown Required:", decision.cooldownRequired);
  if (decision.debugInfo?.hardOverride) {
    console.warn("🚨 HARD SAFETY OVERRIDE TRIGGERED");
  }
  console.groupEnd();
}

// ══════════════════════════════════════════════════════════════════════
// EXPORT (MV3 compatible — no module syntax)
// ══════════════════════════════════════════════════════════════════════

if (typeof globalThis !== "undefined") {
  globalThis.SentinelThreatEvaluator = {
    evaluateThreat,
    logEvaluation,
    computeSignalStrength,
    applyHysteresis,
    clearHysteresisState: () => hysteresisState.clear(),
    clearCooldownState: () => cooldownState.clear(),
  };
}
