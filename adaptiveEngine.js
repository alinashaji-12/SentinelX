/**
 * adaptiveEngine.js — Sentinel Browse Extension v3.0
 *
 * ADAPTIVE INTELLIGENCE LAYER
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * ARCHITECTURE:
 *   This module runs AFTER detectionEngine.js produces its base result.
 *   It reads persisted data (reputation, user profile) from chrome.storage.local
 *   and applies a multi-factor adjustment to produce the FINAL verdict.
 *
 * PIPELINE:
 *   baseResult (from detectionEngine.js)
 *     → computeReputationWeight()    reads sentinel_reputation
 *     → computeBehaviorAdjustment()  reads sentinel_user_profile
 *     → computeFinalScore()          multi-factor formula
 *     → classifyAdaptive()           dynamic thresholds per sensitivity level
 *     → return AdaptiveResult         augmented output object
 *
 * KEY DESIGN DECISIONS:
 *   • Reputation score uses exponential time decay (half-life = 15 days).
 *     Old data becomes irrelevant; fresh data is weighted heavily.
 *   • Behavior adjustment NEVER promotes status (safe → malicious is impossible
 *     from behavior alone). It can only suppress (suspicious → safe).
 *   • User-trusted domains bypass scoring entirely (explicit trust grant).
 *   • Auto-escalation from reputation to malicious requires the engine to
 *     independently flag the URL as at least suspicious. Reputation alone
 *     cannot block — prevents false positives from reputation poisoning.
 *   • All reads are async (storage). All computes are sync (<1ms).
 *   • Fail-open: any storage error returns the original base result unchanged.
 *
 * STORAGE CONTRACTS:
 *
 *   sentinel_reputation  (written by updateDomainReputation in background.js)
 *   {
 *     "evil.com": {
 *       suspiciousHits: number,   // Engine flagged as suspicious
 *       maliciousHits: number,    // Engine flagged as malicious
 *       bypassCount: number,      // User clicked "Proceed" on this domain
 *       firstSeen: timestamp,
 *       lastSeen: timestamp,
 *       autoEscalated: boolean,   // System promoted suspicious→malicious
 *     }
 *   }
 *
 *   sentinel_user_profile  (written by updateUserProfile in this file)
 *   {
 *     totalBypasses: number,
 *     totalBlocked: number,
 *     totalWarned: number,
 *     sensitivityLevel: "high" | "normal" | "low",
 *     domains: {
 *       "evil.com": {
 *         bypassCount: number,
 *         firstBypass: timestamp,
 *         lastBypass: timestamp,
 *         userTrusted: boolean,    // true after TRUST_BYPASS_THRESHOLD bypasses
 *         trustGrantedAt: timestamp | null,
 *       }
 *     },
 *     lastUpdated: timestamp,
 *   }
 *
 * STRICT DESIGN RULES (same as detectionEngine.js):
 *   ✓ ZERO imports — loaded via importScripts()
 *   ✓ ZERO synchronous network calls
 *   ✓ Fail-open on any error
 *   ✓ Self-contained (no shared globals with detectionEngine.js assumed beyond globalThis)
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const ADAPTIVE_CONFIG = {
  /**
   * Reputation decay half-life.
   * Hits older than this many days contribute 50% of their original weight.
   * Set to 15 days: a domain flagged once 15 days ago = 0.5× weight.
   */
  DECAY_HALF_LIFE_DAYS: 15,

  /**
   * Maximum reputation weight contribution to finalScore.
   * Caps at +5 to prevent reputation alone from blocking legitimately safe URLs.
   */
  MAX_REPUTATION_WEIGHT: 5.0,

  /**
   * Auto-escalation threshold.
   * If (maliciousHits × 2 + suspiciousHits × 0.5) × decayFactor ≥ this value,
   * the domain is auto-escalated: a suspicious verdict becomes malicious.
   * Requires the base engine to produce at least "suspicious" — never overrides "safe".
   */
  AUTO_ESCALATE_THRESHOLD: 6.0,

  /**
   * Number of bypasses on the same domain to grant "user-trusted" status.
   * User-trusted domains get a -5 score adjustment (effectively safe).
   */
  TRUST_BYPASS_THRESHOLD: 5,

  /**
   * Trusted status expiry (days of inactivity before trust lapses).
   * If trust was granted AND last bypass was both >30 days ago, trust expires.
   * Expired trust degrades to MILD_SUPPRESS_3_BYPASSES (-2.5).
   */
  TRUST_EXPIRY_DAYS: 30,

  /**
   * Bypasses on the same domain (below trust threshold) for mild suppression.
   * 2 bypasses on the same domain → -1.5 adjustment.
   * 3+ bypasses → -2.5 adjustment.
   */
  MILD_SUPPRESS_2_BYPASSES: -1.5,
  MILD_SUPPRESS_3_BYPASSES: -2.5,

  /**
   * Global bypass rate threshold for sensitivity adjustment.
   * bypass% = totalBypasses / (totalBypasses + totalBlocked)
   * > 50% → user is blocking-averse → reduce sensitivity (raise thresholds).
   * < 10% → user respects alerts → increase sensitivity (lower thresholds).
   */
  HIGH_BYPASS_RATE: 0.50,
  LOW_BYPASS_RATE: 0.10,

  /**
   * Signal combination boost multiplier.
   * When the base engine finds BOTH a structural attack (typosquat / brand) AND
   * behavioral intent (keyword+urgency), the domain's reputation weight is
   * multiplied by this factor — amplifying known-bad reputations for multi-signal
   * threats while leaving single-signal detections unaffected.
   */
  SIGNAL_COMBINATION_BOOST: 1.5,

  /**
   * Reputation entry pruning cutoff (days).
   * Entries not seen for this long are removed from sentinel_reputation.
   * Increased from 7 to 30 days: exponential decay already handles staleness;
   * we keep longer history so the system can recognize returning threats.
   */
  REPUTATION_PRUNE_DAYS: 30,

  /**
   * Classification thresholds per sensitivity level.
   * finalScore >= maliciousThreshold → malicious
   * finalScore >= suspiciousThreshold → suspicious
   * else → safe
   */
  THRESHOLDS: {
    high:   { suspicious: 35, malicious: 75 },
    normal: { suspicious: 40, malicious: 80 },
    low:    { suspicious: 50, malicious: 85 },
  },

  /** Storage key names — must match background.js CONFIG.KEYS */
  KEYS: {
    REPUTATION:   "sentinel_reputation",
    USER_PROFILE: "sentinel_user_profile",
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — STORAGE HELPERS (minimal, self-contained)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Promisified chrome.storage.local.get — scoped to this module.
 * @param {string[]} keys
 * @returns {Promise<object>}
 */
function adaptiveStorageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(Array.isArray(keys) ? keys : [keys], (result) => {
      resolve(result || {});
    });
  });
}

/**
 * Promisified chrome.storage.local.set — scoped to this module.
 * @param {object} data
 * @returns {Promise<void>}
 */
function adaptiveStorageSet(data) {
  return new Promise((resolve) => {
    chrome.storage.local.set(data, resolve);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — REPUTATION WEIGHT COMPUTATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Computes a time-decayed reputation weight for a given domain entry.
 *
 * Formula:
 *   rawScore = (maliciousHits × 2) + (suspiciousHits × 0.5)
 *   daysSinceLastSeen = (now - lastSeen) / MS_PER_DAY
 *   decayFactor = 0.5 ^ (daysSinceLastSeen / DECAY_HALF_LIFE_DAYS)
 *   weight = rawScore × decayFactor  [capped at MAX_REPUTATION_WEIGHT]
 *
 * Why this formula?
 *   Raw score: malicious hits counted 4× more than suspicious (they represent
 *   confirmed threats, not just heuristic flags). This prevents aggressive
 *   domains from hiding behind low suspicious counts.
 *   Decay: Half-life of 15 days means a domain that went quiet for 30 days
 *   has only 25% reputation weight. Attackers often rotate infrastructure
 *   quickly — we shouldn't permanently block domains that may be reclaimed.
 *
 * @param {object|null} repEntry — Entry from sentinel_reputation for this domain
 * @returns {{ weight: number, reputationScore: number, autoEscalate: boolean }}
 */
/**
 * @param {object|null} repEntry — Entry from sentinel_reputation for this domain
 * @param {object} [signalFlags={}] — Signal flags from detectionEngine result (signalFlags field).
 *   Used for signal combination boost: if the base engine independently detected
 *   both a structural attack (typosquat/brand) AND behavioral intent (keyword+urgency),
 *   the existing reputation is considered a stronger indicator and its weight is amplified.
 * @returns {{ weight: number, reputationScore: number, autoEscalate: boolean, combinationBoosted: boolean }}
 */
function computeReputationWeight(repEntry, signalFlags = {}) {
  if (!repEntry) {
    return { weight: 0, reputationScore: 0, autoEscalate: false, combinationBoosted: false };
  }

  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const now = Date.now();

  const maliciousHits = Number(repEntry.maliciousHits || 0);
  const suspiciousHits = Number(repEntry.suspiciousHits || 0);
  const lastSeen = Number(repEntry.lastSeen || now);

  // Raw reputation score (unweighted by time)
  const rawScore = (maliciousHits * 2) + (suspiciousHits * 0.5);

  // Time decay: exponential half-life
  const daysSince = Math.max(0, (now - lastSeen) / MS_PER_DAY);
  const decayFactor = Math.pow(0.5, daysSince / ADAPTIVE_CONFIG.DECAY_HALF_LIFE_DAYS);

  // Signal combination boost:
  //   Applied when the CURRENT request triggers BOTH a structural signal (typosquat or brand
  //   impersonation) AND an intent signal (phishing keyword + urgency). This means the attacker
  //   is using a multi-vector approach — known-bad reputation on such domains is more reliable.
  const hasStructuralSignal  = Boolean(signalFlags.hasTyposquat || signalFlags.hasBrandPlacement);
  const hasIntentSignal      = Boolean(signalFlags.hasIntent);
  const combinationBoosted   = hasStructuralSignal && hasIntentSignal && rawScore > 0;
  const combinationMultiplier = combinationBoosted ? ADAPTIVE_CONFIG.SIGNAL_COMBINATION_BOOST : 1.0;

  const reputationScore = rawScore * decayFactor * combinationMultiplier;

  // Auto-escalation: reputation alone cannot block, but it can promote
  // suspicious → malicious if the domain has a strong track record of threats
  const autoEscalate = reputationScore >= ADAPTIVE_CONFIG.AUTO_ESCALATE_THRESHOLD;

  // Weight = capped reputation contribution to finalScore
  const weight = Math.min(reputationScore, ADAPTIVE_CONFIG.MAX_REPUTATION_WEIGHT);

  return { weight, reputationScore, autoEscalate, combinationBoosted };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — BEHAVIOR ADJUSTMENT COMPUTATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Computes the behavior-based score adjustment for a domain.
 *
 * Adjustment rules (negative = reduce severity, positive = increase):
 *   userTrusted == true     → -5   (user explicitly trusts domain, near-safe)
 *   domainBypasses >= 3     → -2.5 (user ignored 3+ warnings for this domain)
 *   domainBypasses == 2     → -1.5 (user ignored 2 warnings for this domain)
 *   domainBypasses == 1     → -0.5 (first bypass — could be a mistake, minor reduction)
 *   no bypass history       →  0
 *
 * Why behavior can SUPPRESS but not ESCALATE:
 *   Behavioral escalation (e.g. "user visited malicious domain → increase score")
 *   would create feedback loops and could punish users exploring suspicious links
 *   in a sandboxed context. We trust the engine for escalation; behavior only suppresses.
 *
 * @param {object|null} profileDomainEntry — Entry from sentinel_user_profile.domains[hostname]
 * @returns {{ adjustment: number, userTrusted: boolean, reason: string }}
 */
function computeBehaviorAdjustment(profileDomainEntry) {
  if (!profileDomainEntry) {
    return { adjustment: 0, userTrusted: false, reason: "no_history" };
  }

  // User explicitly trusted this domain (accumulated TRUST_BYPASS_THRESHOLD bypasses)
  if (profileDomainEntry.userTrusted === true) {
    // ── Trust expiry check ────────────────────────────────────────────────
    // Trust granted long ago with no recent re-confirmation can expire.
    // Conditions for expiry (both must be true):
    //   • The trust grant itself is older than TRUST_EXPIRY_DAYS
    //   • The last bypass on this domain is also older than TRUST_EXPIRY_DAYS
    // This prevents permanently whitelisting domains the user has simply forgotten.
    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const now = Date.now();
    const trustAge = profileDomainEntry.trustGrantedAt
      ? (now - Number(profileDomainEntry.trustGrantedAt)) / MS_PER_DAY
      : 0;
    const lastBypassAge = profileDomainEntry.lastBypass
      ? (now - Number(profileDomainEntry.lastBypass)) / MS_PER_DAY
      : 999;

    if (trustAge > ADAPTIVE_CONFIG.TRUST_EXPIRY_DAYS && lastBypassAge > ADAPTIVE_CONFIG.TRUST_EXPIRY_DAYS) {
      // Trust lapsed — degrade gracefully to mild suppression (not zero)
      // The user did explicitly bypass multiple times; we remember that but warn again.
      return {
        adjustment: ADAPTIVE_CONFIG.MILD_SUPPRESS_3_BYPASSES,
        userTrusted: false,
        reason: "trust_expired",
      };
    }

    return {
      adjustment: -5,
      userTrusted: true,
      reason: "user_trusted",
    };
  }

  const bypasses = Number(profileDomainEntry.bypassCount || 0);

  if (bypasses >= 3) {
    return { adjustment: ADAPTIVE_CONFIG.MILD_SUPPRESS_3_BYPASSES, userTrusted: false, reason: `${bypasses}_bypasses` };
  }
  if (bypasses === 2) {
    return { adjustment: ADAPTIVE_CONFIG.MILD_SUPPRESS_2_BYPASSES, userTrusted: false, reason: "2_bypasses" };
  }
  if (bypasses === 1) {
    return { adjustment: -0.5, userTrusted: false, reason: "1_bypass" };
  }

  return { adjustment: 0, userTrusted: false, reason: "no_bypasses" };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — GLOBAL SENSITIVITY COMPUTATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Determines the user's global sensitivity level based on bypass behavior.
 *
 * Sensitivity level affects the scoring thresholds:
 *   high   → blocks at lower finalScore (more aggressive)
 *   normal → default thresholds
 *   low    → blocks at higher finalScore (more permissive)
 *
 * Auto-adjusts from declared setting in profile based on actual bypass rate.
 * This prevents the system from being over-sensitive for users who routinely
 * bypass (security researchers, developers) or under-sensitive for cautious users.
 *
 * @param {object|null} userProfile — The sentinel_user_profile object
 * @returns {"high" | "normal" | "low"}
 */
function computeSensitivityLevel(userProfile) {
  if (!userProfile) return "normal";

  const declaredLevel = userProfile.sensitivityLevel || "normal";

  const totalBypasses = Number(userProfile.totalBypasses || 0);
  const totalBlocked = Number(userProfile.totalBlocked || 0);
  const totalDecisions = totalBypasses + totalBlocked;

  // Not enough decisions to compute a meaningful rate
  if (totalDecisions < 10) return declaredLevel;

  const bypassRate = totalBypasses / totalDecisions;

  // User bypasses >50% of blocks → they're annoyed by alerts → lower sensitivity
  if (bypassRate > ADAPTIVE_CONFIG.HIGH_BYPASS_RATE) return "low";

  // User bypasses <10% of blocks → they're cautious → higher sensitivity
  if (bypassRate < ADAPTIVE_CONFIG.LOW_BYPASS_RATE) return "high";

  return declaredLevel;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — FINAL SCORE & CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Computes the final adaptive score from base + reputation + behavior.
 *
 * Formula:
 *   finalScore = baseScore + reputationWeight + behaviorAdjustment
 *
 * Clamping:
 *   - Min: -5 (user-trusted domain)
 *   - Max: 15 (strong multi-signal threat with established reputation)
 *
 * @param {number} baseScore — From detectionEngine.js result.score
 * @param {number} reputationWeight — From computeReputationWeight()
 * @param {number} behaviorAdjustment — From computeBehaviorAdjustment()
 * @returns {number}
 */
function computeFinalScore(baseScore, reputationWeight, behaviorAdjustment) {
  const raw = (Number(baseScore) || 0) + reputationWeight + behaviorAdjustment;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

/**
 * Classifies the final verdict based on finalScore and the user's sensitivity.
 *
 * Classification logic:
 *   1. If baseResult is "safe" AND behavior marks this as userTrusted → stays safe
 *   2. If baseResult is "safe" AND finalScore < suspiciousThreshold → stays safe
 *      (reputation alone cannot block — at minimum the engine must detect something)
 *   3. If baseResult is "malicious" AND userTrusted → downgrade to suspicious
 *      (user-trusted domains get benefit of the doubt, but are still warned)
 *   4. If autoEscalate AND baseResult is "suspicious" → promote to malicious
 *   5. Otherwise: threshold-based classification from finalScore
 *
 * @param {string} baseStatus — "safe" | "suspicious" | "malicious"
 * @param {number} finalScore
 * @param {"high"|"normal"|"low"} sensitivityLevel
 * @param {boolean} autoEscalate — From computeReputationWeight()
 * @param {boolean} userTrusted — From computeBehaviorAdjustment()
 * @returns {{ status: string, appliedRule: string }}
 */
function classifyAdaptive(baseStatus, finalScore, sensitivityLevel, autoEscalate, userTrusted) {
  const thresholds = ADAPTIVE_CONFIG.THRESHOLDS[sensitivityLevel] || ADAPTIVE_CONFIG.THRESHOLDS.normal;

  // Rule 1: User-trusted malicious → downgrade to suspicious warning
  // User has explicitly bypassed this domain multiple times; respect their decision
  // but still warn them since the engine independently flagged it.
  if (userTrusted && baseStatus === "malicious") {
    return { status: "suspicious", appliedRule: "USER_TRUSTED_DOWNGRADE" };
  }

  // Rule 2: User-trusted + engine says safe → hard safe exit
  if (userTrusted && baseStatus === "safe") {
    return { status: "safe", appliedRule: "USER_TRUSTED_SAFE" };
  }

  // Rule 3: Auto-escalation — established bad reputation + engine suspicious
  // Requires engine confirmation (base !== safe) to prevent reputation poisoning FPs
  if (autoEscalate && baseStatus !== "safe") {
    return { status: "malicious", appliedRule: "REPUTATION_AUTO_ESCALATE" };
  }

  // Rule 4: Engine said malicious — reputation/behavior cannot unlock it
  // Behavior can only take malicious → suspicious (Rule 1), not → safe.
  if (baseStatus === "malicious") {
    return { status: "malicious", appliedRule: "ENGINE_MALICIOUS_CONFIRMED" };
  }

  // Rule 5: Threshold-based dynamic classification
  if (finalScore >= thresholds.malicious) {
    return { status: "malicious", appliedRule: `ADAPTIVE_MALICIOUS_${sensitivityLevel.toUpperCase()}` };
  }
  if (finalScore >= thresholds.suspicious) {
    return { status: "suspicious", appliedRule: `ADAPTIVE_SUSPICIOUS_${sensitivityLevel.toUpperCase()}` };
  }

  return { status: "safe", appliedRule: `ADAPTIVE_SAFE_${sensitivityLevel.toUpperCase()}` };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — MAIN ADAPTIVE ANALYSIS FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * applyAdaptiveScoring — Main entry point for the adaptive layer.
 *
 * Called AFTER detectionEngine.analyzeUrl() produces its base result.
 * Reads reputation and user profile from storage, computes adjustments,
 * and returns an augmented result object.
 *
 * The returned object EXTENDS the base result with:
 *   - finalScore:          number — the multi-factor score
 *   - reputationWeight:    number — reputation contribution
 *   - behaviorAdjustment:  number — user behavior contribution
 *   - sensitivityLevel:    "high" | "normal" | "low"
 *   - adaptiveAppliedRule: string — which adaptive rule determined the verdict
 *   - wasAdaptivelyChanged: boolean — whether the verdict changed from base
 *   - userTrusted:         boolean — whether domain is user-trusted
 *   - autoEscalated:       boolean — whether reputation escalated the verdict
 *
 * @param {object} baseResult — Return value from detectionEngine.analyzeUrl()
 * @param {string} hostname — The root hostname of the analyzed URL
 * @returns {Promise<object>} Augmented result
 */
async function applyAdaptiveScoring(baseResult, hostname) {
  // Hard-safe guard: if base result is a hard-override trusted/safe domain,
  // skip ALL adaptive processing. These domains have score = -5 and we
  // never want to re-classify trusted domains as suspicious.
  if (baseResult.appliedRule === "HARD_OVERRIDE_TRUSTED") {
    return {
      ...baseResult,
      finalScore: Math.max(0, Math.min(100, Math.round(Number(baseResult.score) || 0))),
      reputationWeight: 0,
      behaviorAdjustment: 0,
      sensitivityLevel: "normal",
      adaptiveAppliedRule: "ADAPTIVE_SKIP_TRUSTED",
      wasAdaptivelyChanged: false,
      userTrusted: false,
      autoEscalated: false,
    };
  }

  try {
    // ── Read both storage keys in a single batch call (1 I/O operation) ────
    const data = await adaptiveStorageGet([
      ADAPTIVE_CONFIG.KEYS.REPUTATION,
      ADAPTIVE_CONFIG.KEYS.USER_PROFILE,
    ]);

    const reputation   = data[ADAPTIVE_CONFIG.KEYS.REPUTATION]   || {};
    const userProfile  = data[ADAPTIVE_CONFIG.KEYS.USER_PROFILE]  || null;

    // Extract domain-specific entries
    const repEntry     = reputation[hostname]                         || null;
    const profileEntry = userProfile?.domains?.[hostname]             || null;

    // ── Compute all three factors ────────────────────────────────────────
    // Pass signal flags from base result to enable the signal combination boost:
    // a domain with history PLUS current multi-vector attack = higher weight.
    const signalFlags = baseResult.signalFlags || {};
    const { weight: reputationWeight, reputationScore, autoEscalate, combinationBoosted } = computeReputationWeight(repEntry, signalFlags);
    const { adjustment: behaviorAdjustment, userTrusted, reason: behaviorReason } = computeBehaviorAdjustment(profileEntry);
    const sensitivityLevel = computeSensitivityLevel(userProfile);

    // ── Multi-factor final score ─────────────────────────────────────────
    const finalScore = computeFinalScore(baseResult.score, reputationWeight, behaviorAdjustment);

    // ── Classify based on adaptive rules ────────────────────────────────
    const { status: adaptiveStatus, appliedRule: adaptiveAppliedRule } = classifyAdaptive(
      baseResult.status,
      finalScore,
      sensitivityLevel,
      autoEscalate,
      userTrusted,
    );

    const wasAdaptivelyChanged = adaptiveStatus !== baseResult.status;

    // ── Build reason annotations for changed verdicts ────────────────────
    const adaptiveReasons = [...(baseResult.reasons || [])];
    const adaptiveSignals = [...(baseResult.signals || [])];

    if (reputationWeight > 0) {
      adaptiveReasons.push(
        `Domain reputation: ${repEntry?.maliciousHits || 0} malicious, ` +
        `${repEntry?.suspiciousHits || 0} suspicious hits (decayed score: ${reputationScore.toFixed(2)})`
      );
      adaptiveSignals.push("Domain reputation");
    }

    if (userTrusted) {
      adaptiveReasons.push("Domain is user-trusted (bypassed multiple times — verdict softened)");
      adaptiveSignals.push("User-trusted domain");
    } else if (behaviorAdjustment < 0) {
      adaptiveReasons.push(`Behavior adjustment: user bypassed this domain ${profileEntry?.bypassCount} time(s)`);
    }

    if (combinationBoosted) {
      adaptiveReasons.push(
        `Signal combination boost applied: multi-vector attack (structural + intent) ` +
        `on domain with existing reputation history`
      );
      adaptiveSignals.push("Signal combination boost");
    }

    if (autoEscalate) {
      adaptiveReasons.push(
        `Auto-escalated: domain reputation score (${reputationScore.toFixed(2)}) ` +
        `exceeds escalation threshold (${ADAPTIVE_CONFIG.AUTO_ESCALATE_THRESHOLD})`
      );
      adaptiveSignals.push("Auto-escalated threat");
    }

    if (wasAdaptivelyChanged) {
      console.log(
        `[Sentinel Adaptive] Verdict changed: ${baseResult.status} → ${adaptiveStatus}` +
        ` | Rule: ${adaptiveAppliedRule} | finalScore: ${finalScore.toFixed(2)}`
      );
    }

    return {
      ...baseResult,
      // Override status with adaptive decision
      status: adaptiveStatus,
      // Augment reasons and signals with adaptive context
      reasons: adaptiveReasons,
      signals: adaptiveSignals,
      reason: adaptiveReasons.join("; "),
      // Adaptive metadata
      finalScore: Number(finalScore.toFixed(2)),
      reputationWeight: Number(reputationWeight.toFixed(2)),
      behaviorAdjustment: Number(behaviorAdjustment.toFixed(2)),
      sensitivityLevel,
      adaptiveAppliedRule,
      wasAdaptivelyChanged,
      userTrusted,
      autoEscalated: autoEscalate,
      combinationBoosted,
      behaviorReason,
      // Reputation snapshot for warning page rendering
      reputationSnapshot: repEntry ? {
        maliciousHits: repEntry.maliciousHits || 0,
        suspiciousHits: repEntry.suspiciousHits || 0,
        bypassCount: repEntry.bypassCount || 0,
        lastSeen: repEntry.lastSeen || null,
      } : null,
    };

  } catch (err) {
    // FAIL-OPEN: any storage/compute error returns base result unchanged
    console.warn("[Sentinel Adaptive] applyAdaptiveScoring error — returning base result:", err?.message);
    return {
      ...baseResult,
      finalScore: baseResult.score,
      reputationWeight: 0,
      behaviorAdjustment: 0,
      sensitivityLevel: "normal",
      adaptiveAppliedRule: "ADAPTIVE_ERROR_FALLBACK",
      wasAdaptivelyChanged: false,
      userTrusted: false,
      autoEscalated: false,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — USER PROFILE UPDATE (called from background.js on bypass)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Updates sentinel_user_profile when a user performs an action.
 *
 * Actions:
 *   "bypass"    — User clicked "Proceed Anyway" on warning page
 *   "blocked"   — URL was blocked (user did NOT bypass)
 *   "warned"    — URL was flagged as suspicious (overlay shown)
 *
 * Auto-trust logic:
 *   After TRUST_BYPASS_THRESHOLD bypasses on the same domain, the domain is
 *   marked as userTrusted = true. The system continues to warn but cannot
 *   block a user-trusted domain outright.
 *
 * Sensitivity recalculation:
 *   After every update, we recompute sensitivityLevel from the bypass rate.
 *   This persists the computed level so the adaptive engine can read it
 *   without recomputing from raw counts.
 *
 * @param {string} hostname — Root hostname
 * @param {"bypass" | "blocked" | "warned"} action
 * @returns {Promise<void>}
 */
async function updateUserProfile(hostname, action) {
  try {
    const data = await adaptiveStorageGet([ADAPTIVE_CONFIG.KEYS.USER_PROFILE]);
    const profile = data[ADAPTIVE_CONFIG.KEYS.USER_PROFILE] || {
      totalBypasses: 0,
      totalBlocked: 0,
      totalWarned: 0,
      sensitivityLevel: "normal",
      domains: {},
      lastUpdated: Date.now(),
    };

    // ── Update global counters ───────────────────────────────────────────
    if (action === "bypass")  profile.totalBypasses = (profile.totalBypasses || 0) + 1;
    if (action === "blocked") profile.totalBlocked  = (profile.totalBlocked  || 0) + 1;
    if (action === "warned")  profile.totalWarned   = (profile.totalWarned   || 0) + 1;

    // ── Update domain-specific entry ─────────────────────────────────────
    if (action === "bypass" && hostname) {
      if (!profile.domains) profile.domains = {};

      const domainEntry = profile.domains[hostname] || {
        bypassCount: 0,
        firstBypass: Date.now(),
        lastBypass: Date.now(),
        userTrusted: false,
        trustGrantedAt: null,
      };

      domainEntry.bypassCount = (domainEntry.bypassCount || 0) + 1;
      domainEntry.lastBypass = Date.now();

      // Auto-trust after threshold bypasses
      if (!domainEntry.userTrusted && domainEntry.bypassCount >= ADAPTIVE_CONFIG.TRUST_BYPASS_THRESHOLD) {
        domainEntry.userTrusted = true;
        domainEntry.trustGrantedAt = Date.now();
        console.log(`[Sentinel Adaptive] Domain auto-trusted after ${domainEntry.bypassCount} bypasses: ${hostname}`);
      }

      profile.domains[hostname] = domainEntry;

      // ── Time-pattern tracking ───────────────────────────────────────────
      // Track which hours + days the user tends to bypass warnings.
      // Used for future analytics (e.g. flagging out-of-pattern bypass bursts).
      // Data is stored compactly as { hourly: {0..23: count}, daily: {0..6: count} }.
      // This is PURELY analytical — it does not affect scoring.
      if (!profile.timePatterns) {
        profile.timePatterns = { hourly: {}, daily: {} };
      }
      const hour = String(new Date().getHours());
      const day  = String(new Date().getDay());  // 0 = Sunday
      profile.timePatterns.hourly[hour] = (profile.timePatterns.hourly[hour] || 0) + 1;
      profile.timePatterns.daily[day]   = (profile.timePatterns.daily[day]   || 0) + 1;
    }

    // ── Recompute and persist sensitivity level ──────────────────────────
    profile.sensitivityLevel = computeSensitivityLevel(profile);
    profile.lastUpdated = Date.now();

    // Enforce domain history cap (prevent unbounded storage growth)
    // Keep only the 200 most recently bypassed domains
    const domainKeys = Object.keys(profile.domains || {});
    if (domainKeys.length > 200) {
      const sorted = domainKeys.sort(
        (a, b) => (profile.domains[b].lastBypass || 0) - (profile.domains[a].lastBypass || 0)
      );
      const pruned = {};
      sorted.slice(0, 200).forEach(k => { pruned[k] = profile.domains[k]; });
      profile.domains = pruned;
    }

    await adaptiveStorageSet({ [ADAPTIVE_CONFIG.KEYS.USER_PROFILE]: profile });

  } catch (e) {
    console.warn("[Sentinel Adaptive] updateUserProfile error:", e);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9 — REPUTATION SCHEMA UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Upgrades the existing reputation record written by background.js
 * (which uses { suspicious, malicious } keys) to the v3.0 schema
 * (which uses { suspiciousHits, maliciousHits, bypassCount } keys).
 *
 * Called once on first adaptive analysis for a domain. Idempotent.
 * Background.js continues writing the v2.1 schema; adaptive engine
 * normalizes on read so both schemas coexist without migration risk.
 *
 * @param {object|null} rawRepEntry — Raw entry from sentinel_reputation
 * @returns {object} Normalized v3.0 entry
 */
function normalizeRepEntry(rawRepEntry) {
  if (!rawRepEntry) return null;

  return {
    // Support both v2.1 (suspicious/malicious) and v3.0 (suspiciousHits/maliciousHits) schemas
    suspiciousHits: rawRepEntry.suspiciousHits ?? rawRepEntry.suspicious ?? 0,
    maliciousHits:  rawRepEntry.maliciousHits  ?? rawRepEntry.malicious  ?? 0,
    bypassCount:    rawRepEntry.bypassCount    ?? 0,
    firstSeen:      rawRepEntry.firstSeen      ?? Date.now(),
    lastSeen:       rawRepEntry.lastSeen       ?? Date.now(),
    autoEscalated:  rawRepEntry.autoEscalated  ?? false,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 10 — REPUTATION UPDATE (upgraded from background.js version)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Updates the domain reputation entry in sentinel_reputation.
 * This is the v3.0 upgrade of updateDomainReputation() in background.js.
 * background.js should call this instead of its own version.
 *
 * New in v3.0:
 *   - Uses v3.0 schema (suspiciousHits, maliciousHits, bypassCount)
 *   - Sets autoEscalated flag when reputation threshold is crossed
 *   - Updates bypassCount when action is "bypass"
 *   - 7-day pruning retained from v2.1
 *
 * @param {string} hostname
 * @param {"suspicious" | "malicious" | "bypass"} action
 * @returns {Promise<void>}
 */
async function updateDomainReputationV3(hostname, action) {
  try {
    if (!hostname) return;

    const data = await adaptiveStorageGet([ADAPTIVE_CONFIG.KEYS.REPUTATION]);
    const rep = data[ADAPTIVE_CONFIG.KEYS.REPUTATION] || {};

    // Normalize existing entry (handles v2.1 schema migration)
    const existing = normalizeRepEntry(rep[hostname]);

    const entry = existing || {
      suspiciousHits: 0,
      maliciousHits: 0,
      bypassCount: 0,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      autoEscalated: false,
    };

    entry.lastSeen = Date.now();

    if (action === "malicious")  entry.maliciousHits  = (entry.maliciousHits  || 0) + 1;
    if (action === "suspicious") entry.suspiciousHits = (entry.suspiciousHits || 0) + 1;
    if (action === "bypass")     entry.bypassCount    = (entry.bypassCount    || 0) + 1;

    // Check and set auto-escalation flag
    const { autoEscalate } = computeReputationWeight(entry);
    entry.autoEscalated = autoEscalate;

    rep[hostname] = entry;

    // Prune entries older than REPUTATION_PRUNE_DAYS.
    // NOTE: 30 days (not 7) — exponential decay already handles staleness.
    // Longer history lets the system recognise returning threats (attackers
    // often reuse infrastructure after short quiet periods).
    const cutoff = Date.now() - (ADAPTIVE_CONFIG.REPUTATION_PRUNE_DAYS * 24 * 60 * 60 * 1000);
    for (const [host, e] of Object.entries(rep)) {
      if ((e.lastSeen || 0) < cutoff) delete rep[host];
    }

    await adaptiveStorageSet({ [ADAPTIVE_CONFIG.KEYS.REPUTATION]: rep });

  } catch (e) {
    console.warn("[Sentinel Adaptive] updateDomainReputationV3 error:", e);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 11b — ANALYTICS & TRUST MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * getAdaptiveStats — Returns a combined snapshot of reputation + user profile.
 *
 * Called by:
 *   • dashboard.js for the stats panel
 *   • background.js message handler (sentinel:get-adaptive-stats)
 *
 * @returns {Promise<object>} Snapshot object
 */
async function getAdaptiveStats() {
  try {
    const data = await adaptiveStorageGet([
      ADAPTIVE_CONFIG.KEYS.REPUTATION,
      ADAPTIVE_CONFIG.KEYS.USER_PROFILE,
    ]);
    const reputation  = data[ADAPTIVE_CONFIG.KEYS.REPUTATION]  || {};
    const profile     = data[ADAPTIVE_CONFIG.KEYS.USER_PROFILE] || {};

    const repEntries = Object.entries(reputation);

    // Top threat domains by weighted score
    const topThreats = repEntries
      .map(([host, e]) => ({
        host,
        maliciousHits:  e.maliciousHits  || 0,
        suspiciousHits: e.suspiciousHits || 0,
        bypassCount:    e.bypassCount    || 0,
        autoEscalated:  e.autoEscalated  || false,
        lastSeen:       e.lastSeen       || null,
        rawScore: (e.maliciousHits || 0) * 2 + (e.suspiciousHits || 0) * 0.5,
      }))
      .sort((a, b) => b.rawScore - a.rawScore)
      .slice(0, 10);

    const domainEntries = Object.entries(profile.domains || {});
    const userTrustedDomains = domainEntries
      .filter(([, d]) => d.userTrusted)
      .map(([k, d]) => ({
        host: k,
        bypassCount:    d.bypassCount    || 0,
        trustGrantedAt: d.trustGrantedAt || null,
        lastBypass:     d.lastBypass     || null,
      }));

    const totalDecisions = (profile.totalBypasses || 0) + (profile.totalBlocked || 0);

    return {
      reputation: {
        totalTrackedDomains:  repEntries.length,
        autoEscalatedDomains: repEntries.filter(([, e]) => e.autoEscalated).length,
        topThreats,
      },
      userProfile: {
        totalBypasses:       profile.totalBypasses  || 0,
        totalBlocked:        profile.totalBlocked   || 0,
        totalWarned:         profile.totalWarned    || 0,
        sensitivityLevel:    profile.sensitivityLevel || "normal",
        bypassRate:          totalDecisions > 0
          ? Number(((profile.totalBypasses || 0) / totalDecisions).toFixed(3))
          : 0,
        userTrustedCount:    userTrustedDomains.length,
        userTrustedDomains,
        timePatterns:        profile.timePatterns || { hourly: {}, daily: {} },
        lastUpdated:         profile.lastUpdated  || null,
      },
    };
  } catch (e) {
    console.warn("[Sentinel Adaptive] getAdaptiveStats error:", e);
    return { reputation: { totalTrackedDomains: 0, autoEscalatedDomains: 0, topThreats: [] }, userProfile: {} };
  }
}

/**
 * revokeTrust — Explicitly removes user-trusted status from a domain.
 *
 * After revocation the domain is treated as a normal high-bypass domain
 * (MILD_SUPPRESS_3_BYPASSES adjustment) rather than fully trusted.
 * The bypassCount is preserved so the user's history is not erased.
 *
 * Called by:
 *   • dashboard.js "Revoke Trust" control
 *   • background.js message handler (sentinel:revoke-trust)
 *
 * @param {string} hostname — Root hostname to revoke trust for
 * @returns {Promise<boolean>} true if revoked, false if not found/already untrusted
 */
async function revokeTrust(hostname) {
  try {
    if (!hostname) return false;

    const data = await adaptiveStorageGet([ADAPTIVE_CONFIG.KEYS.USER_PROFILE]);
    const profile = data[ADAPTIVE_CONFIG.KEYS.USER_PROFILE];
    if (!profile?.domains?.[hostname]) return false;

    const entry = profile.domains[hostname];
    if (!entry.userTrusted) return false;

    // Revoke but preserve history
    entry.userTrusted    = false;
    entry.trustGrantedAt = null;
    entry.trustRevokedAt = Date.now();
    profile.lastUpdated  = Date.now();

    await adaptiveStorageSet({ [ADAPTIVE_CONFIG.KEYS.USER_PROFILE]: profile });
    console.log(`[Sentinel Adaptive] Trust revoked for: ${hostname}`);
    return true;

  } catch (e) {
    console.warn("[Sentinel Adaptive] revokeTrust error:", e);
    return false;
  }
}

/**
 * grantTrust — Manually marks a domain as user-trusted (dashboard shortcut).
 * Equivalent to the user having bypassed TRUST_BYPASS_THRESHOLD times.
 *
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
async function grantTrust(hostname) {
  try {
    if (!hostname) return false;

    const data = await adaptiveStorageGet([ADAPTIVE_CONFIG.KEYS.USER_PROFILE]);
    const profile = data[ADAPTIVE_CONFIG.KEYS.USER_PROFILE] || {
      totalBypasses: 0, totalBlocked: 0, totalWarned: 0,
      sensitivityLevel: "normal", domains: {}, lastUpdated: Date.now(),
    };

    if (!profile.domains) profile.domains = {};
    const entry = profile.domains[hostname] || {
      bypassCount: 0, firstBypass: Date.now(), lastBypass: Date.now(),
      userTrusted: false, trustGrantedAt: null,
    };

    entry.userTrusted    = true;
    entry.trustGrantedAt = Date.now();
    entry.lastBypass     = Date.now();
    profile.domains[hostname] = entry;
    profile.lastUpdated = Date.now();

    await adaptiveStorageSet({ [ADAPTIVE_CONFIG.KEYS.USER_PROFILE]: profile });
    console.log(`[Sentinel Adaptive] Trust manually granted for: ${hostname}`);
    return true;

  } catch (e) {
    console.warn("[Sentinel Adaptive] grantTrust error:", e);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 11 — MODULE EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

if (typeof globalThis !== "undefined") {
  globalThis.SentinelAdaptiveEngine = {
    // Core pipeline
    applyAdaptiveScoring,
    // Profile + reputation writers
    updateUserProfile,
    updateDomainReputationV3,
    // Trust management
    revokeTrust,
    grantTrust,
    // Analytics
    getAdaptiveStats,
    // Schema utility
    normalizeRepEntry,
    // Expose config for background.js
    KEYS: ADAPTIVE_CONFIG.KEYS,
    CONFIG: ADAPTIVE_CONFIG,
  };
}
