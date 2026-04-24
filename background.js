/**
 * background.js â€” Sentinel Browse Extension v2.0 (MV3 Service Worker)
 *
 * PRODUCTION-GRADE ARCHITECTURE
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 *
 * CRITICAL MV3 CONSTRAINTS THIS FILE HANDLES:
 *   â€¢ Service workers restart after ~30s of inactivity â€” any in-memory
 *     state (Maps, Sets, variables) is DESTROYED. Bypass must use storage.
 *   â€¢ webNavigation.onBeforeNavigate fires for redirects and history
 *     navigation â€” deduplication prevents re-analysis of the same tab.
 *   â€¢ chrome.tabs.update is async â€” the navigation may complete before
 *     the callback fires. We use immediate redirect to warning.html to
 *     preempt the navigation as early as possible.
 *   â€¢ importScripts() is the only safe module loading mechanism in a
 *     non-module service worker. No ES `import` syntax.
 *
 * EXECUTION ORDER (per navigation event):
 *   1. frameId === 0 guard (main frame only)
 *   2. Scheme guard (http/https only)
 *   3. Dedup guard (pendingAnalysis Set â€” same tab, 2s window)
 *   4. Bypass check FIRST (chrome.storage.local, TTL validated)
 *   5. LRU cache check (in-memory, 500 entries, 10-min TTL)
 *   6. Detection engine (analyzeUrl â€” synchronous, <5ms)
 *   7. Result routing:
 *      MALICIOUS â†’ chrome.tabs.update â†’ warning.html (with all data)
 *      SUSPICIOUS â†’ chrome.tabs.sendMessage â†’ content.js overlay
 *      SAFE      â†’ async history log only
 *   8. Cache store + history save (non-blocking async)
 */

"use strict";

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 1 â€” LOAD DETECTION ENGINE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// importScripts is the only valid way to load external scripts in a
// non-module MV3 service worker.
try {
  importScripts("detectionEngine.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load detectionEngine.js:", e);
}

// Load v3.0 adaptive intelligence layer
try {
  importScripts("adaptiveEngine.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load adaptiveEngine.js:", e);
}

// Load threat intelligence enrichment module
try {
  importScripts("threatIntelService.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load threatIntelService.js:", e);
}

// Load production-grade threat evaluator (centralized alert decisions)
try {
  importScripts("threatEvaluator.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load threatEvaluator.js:", e);
}

async function callAIAnalysis(data) {
  try {
    console.log("ðŸ§  Calling AI with:", data);

    const response = await fetch("http://localhost:3000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    const result = await response.json();
    console.log("ðŸ§  AI Response:", result);

    return result;
  } catch (error) {
    console.error("âŒ AI ERROR:", error);
    return null;
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 2 â€” CONSTANTS & CONFIGURATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const CONFIG = {
  /** LRU cache: max entries before eviction of oldest. */
  CACHE_MAX_SIZE: 500,
  /** LRU cache: result valid for 10 minutes. */
  CACHE_TTL_MS: 10 * 60 * 1000,
  /** Bypass TTL: 5 minutes. Stored in chrome.storage.local. */
  BYPASS_TTL_MS: 5 * 60 * 1000,
  /** Dedup window: ignore duplicate events for same tab within 2 seconds. */
  DEDUP_WINDOW_MS: 2000,
  /** Maximum threat history entries in storage. */
  MAX_HISTORY: 500,
  // VULN-08 FIX: Cap pendingAnalysis Map to prevent memory leak.
  // Without this, heavy browsing (500 tabs/30s) fills the Map unboundedly.
  DEDUP_MAX_SIZE: 200,
  /** Redirect chain TTL: forget origin after 10 seconds. */
  REDIRECT_CHAIN_TTL_MS: 10000,
  /** Domain reputation: flag as malicious after this many suspicious visits. */
  REPUTATION_PROMOTE_THRESHOLD: 3,
  /** Storage keys. */
  KEYS: {
    BYPASSES: "sentinel_bypasses",
    HISTORY: "sentinel_history",
    LAST_ANALYSIS: "sentinel_last_analysis",
    SETTINGS: "sentinel_settings",
    REPUTATION:   "sentinel_reputation",
    USER_PROFILE: "sentinel_user_profile",
    REPORTS: "sentinel_reports",
    SAFE_MARKS: "sentinel_safe_marks",
  },
};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// GLOBAL STATE & DEV MODE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

let _devModeEnabled = false;

// Keep dev_mode in sync with storage (lightweight)
try {
  chrome.storage.local.get(["dev_mode"], (d) => {
    _devModeEnabled = Boolean(d && d.dev_mode);
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.dev_mode) _devModeEnabled = Boolean(changes.dev_mode.newValue);
  });
} catch (e) {
  console.warn("[Sentinel] Failed to sync dev_mode:", e);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 3 â€” LRU CACHE (IN-MEMORY, <5ms/operation)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Minimal LRU (Least Recently Used) cache for URL analysis results.
 *
 * Implementation uses a Map (insertion-order iteration) to approximate LRU:
 *   - On hit: delete + re-insert moves entry to end (most recent)
 *   - On eviction: delete first entry (least recently used)
 *
 * Key: normalized URL string
 * Value: { result: object, expires: timestamp }
 *
 * NOTE: This cache is in-memory and is destroyed when the service worker
 * restarts. That is ACCEPTABLE â€” the cache is only a performance optimization.
 * Bypass state uses chrome.storage.local for persistence.
 */
class LRUCache {
  constructor(maxSize, ttlMs) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.map = new Map();
  }

  /**
   * Get a cached result. Returns null if missing or expired.
   * @param {string} key
   * @returns {object|null}
   */
  get(key) {
    if (!this.map.has(key)) return null;

    const entry = this.map.get(key);

    // Expired?
    if (Date.now() > entry.expires) {
      this.map.delete(key);
      return null;
    }

    // Move to end (most recently used)
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.result;
  }

  /**
   * Store a result. Evicts LRU entry if at capacity.
   * @param {string} key
   * @param {object} result
   */
  set(key, result) {
    // If key exists, remove it first (will be re-added at end)
    if (this.map.has(key)) {
      this.map.delete(key);
    }

    // Evict LRU (first entry) if at capacity
    if (this.map.size >= this.maxSize) {
      const lruKey = this.map.keys().next().value;
      this.map.delete(lruKey);
    }

    this.map.set(key, {
      result,
      expires: Date.now() + this.ttlMs,
    });
  }

  /**
   * Remove a specific key from cache (used when a bypass is granted).
   * @param {string} key
   */
  delete(key) {
    this.map.delete(key);
  }

  /** Current cache size. */
  get size() {
    return this.map.size;
  }
}

// Singleton cache â€” persists as long as the service worker is alive
const urlCache = new LRUCache(CONFIG.CACHE_MAX_SIZE, CONFIG.CACHE_TTL_MS);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 4 â€” DEDUPLICATION GUARD
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Tracks recently-analyzed tabs to prevent duplicate analysis.
 *
 * Key: tabId (number)
 * Value: { url: string, timestamp: number }
 *
 * Without this guard, chrome.webNavigation.onBeforeNavigate fires for:
 *   1. The initial navigation
 *   2. Server-side redirects (302, 301)
 *   3. Client-side meta-refresh redirects
 *   4. History API navigation (pushState)
 *
 * We deduplicate by (tabId + normalizedUrl + 2s window).
 */
// VULN-08 FIX: Map is now BOUNDED to CONFIG.DEDUP_MAX_SIZE via FIFO insertion-order
// eviction. Previously grew unboundedly during heavy browsing sessions.
const pendingAnalysis = new Map();

// VULN-10: Redirect chain tracker.
// Tracks {tabId â†’ { originUrl, timestamp }} to detect when a "clean"
// page immediately redirects to a suspicious destination.
// Cleared after CONFIG.REDIRECT_CHAIN_TTL_MS (10s).
const redirectChain = new Map();
const redirectLoopTracker = new Map();

/**
 * Checks and sets the dedup guard for a tab+url combination.
 * Returns true if this analysis should be SKIPPED (duplicate).
 *
 * VULN-08 FIX: Map is capped at DEDUP_MAX_SIZE. When full, the oldest
 * entry (first key in insertion order) is evicted before inserting the new one.
 *
 * @param {number} tabId
 * @param {string} normalizedUrl
 * @returns {boolean} true = skip (duplicate)
 */
function isDuplicate(tabId, normalizedUrl) {
  const now = Date.now();
  const entry = pendingAnalysis.get(tabId);

  if (entry && entry.url === normalizedUrl && now - entry.timestamp < CONFIG.DEDUP_WINDOW_MS) {
    return true; // Same tab, same URL, within dedup window
  }

  // Enforce size cap before inserting (FIFO eviction)
  if (pendingAnalysis.size >= CONFIG.DEDUP_MAX_SIZE) {
    const oldestKey = pendingAnalysis.keys().next().value;
    pendingAnalysis.delete(oldestKey);
  }

  // Register this analysis
  pendingAnalysis.set(tabId, { url: normalizedUrl, timestamp: now });

  // Also clean up stale entries older than 30s to keep Map lean
  for (const [tid, data] of pendingAnalysis) {
    if (now - data.timestamp > 30000) pendingAnalysis.delete(tid);
  }

  return false;
}

/**
 * Records a navigation event for redirect chain tracking. (VULN-10)
 *
 * When a navigation fires, we store the tab's previous URL as the
 * "origin" of a potential redirect chain. If the NEXT navigation on
 * the same tab is to a malicious URL, we can attribute it as a
 * redirect-chain attack and flag the origin URL too.
 *
 * @param {number} tabId
 * @param {string} normalizedUrl
 */
function recordRedirectOrigin(tabId, normalizedUrl) {
  const now = Date.now();
  const existing = redirectChain.get(tabId);

  // Purge expired entries to prevent memory growth
  for (const [tid, data] of redirectChain) {
    if (now - data.timestamp > CONFIG.REDIRECT_CHAIN_TTL_MS) redirectChain.delete(tid);
  }

  // Store previous URL as origin of possible redirect
  redirectChain.set(tabId, { originUrl: normalizedUrl, timestamp: now });
}

/**
 * Tracks rapid consecutive navigations to detect redirect loops.
 * @param {number} tabId
 * @returns {{loopDetected:boolean,count:number}}
 */
function updateRedirectLoopTelemetry(tabId) {
  const now = Date.now();
  const windowMs = 8000;
  const threshold = 5;
  const entry = redirectLoopTracker.get(tabId) || { count: 0, firstSeen: now };
  if (now - entry.firstSeen > windowMs) {
    entry.count = 0;
    entry.firstSeen = now;
  }
  entry.count += 1;
  redirectLoopTracker.set(tabId, entry);
  return { loopDetected: entry.count >= threshold, count: entry.count };
}

/**
 * Retrieves and clears the redirect origin for a tab.
 * Returns null if no origin recorded or entry is expired.
 *
 * @param {number} tabId
 * @returns {string|null}
 */
function consumeRedirectOrigin(tabId) {
  const entry = redirectChain.get(tabId);
  redirectChain.delete(tabId);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CONFIG.REDIRECT_CHAIN_TTL_MS) return null;
  return entry.originUrl;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 5 â€” STORAGE HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Promisified chrome.storage.local.get
 * NOTE: Keys MUST be an array â€” passing a string is documented to work
 * but has inconsistent behavior across Chrome versions.
 *
 * @param {string[]} keys
 * @returns {Promise<object>}
 */
function storageGet(keys) {
  return new Promise(resolve => {
    chrome.storage.local.get(Array.isArray(keys) ? keys : [keys], result => {
      resolve(result || {});
    });
  });
}

/**
 * Promisified chrome.storage.local.set
 * @param {object} data
 * @returns {Promise<void>}
 */
function storageSet(data) {
  return new Promise(resolve => {
    chrome.storage.local.set(data, resolve);
  });
}

const TRUSTED_DOMAINS = [
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "edu",
  "gov",
];

function isTrustedDomainHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  if (!host) return false;
  return TRUSTED_DOMAINS.some(domain => (
    domain === "edu" || domain === "gov"
      ? host.endsWith(`.${domain}`)
      : host === domain || host.endsWith(`.${domain}`)
  ));
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 5.4 â€” CLIPBOARD HIJACK CONTEXT VALIDATOR (v3.0)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * STRICT CLIPBOARD VALIDATION
 * 
 * Clipboard hijack alone is NOT suspicious. Must have:
 *   1. Multiple clipboard events detected (already handled in behaviorMonitor)
 *   2. Supporting malicious signals (phishing_form, hidden_iframe, redirect)
 *   3. OR low-trust domain context
 * 
 * Suppressions:
 *   - High-trust domains: ALWAYS suppress clipboard_hijack signal
 *   - Single signal: Only flag if it's truly isolated + contextual proof
 *
 * @param {Array<string>} signals - All detected signals for this tab
 * @param {string} trustTier - "high" | "medium" | "low" (domain trust level)
 * @param {string} domain - Current domain being evaluated
 * @returns {object} { isRealAttack: boolean, suppression: string|null }
 */
function isRealClipboardAttack(signals, trustTier, domain) {
  const hasClipboard = signals.includes("clipboard_hijack");
  if (!hasClipboard) {
    return { isRealAttack: false, suppression: null };
  }

  // RULE: High-trust domain (Google, university sites, gov) â†’ suppress clipboard_hijack
  if (trustTier === "high") {
    return {
      isRealAttack: false,
      suppression: "Clipboard access detected but considered benign due to trusted domain"
    };
  }

  // RULE: Low-trust + clipboard alone â†’ suppress
  const supportingSignals = [
    "phishing_form",
    "hidden_iframe", 
    "redirect_loop",
    "phishing_detected",
    "sensitive_data_entry",
    "hidden_download_anchor",
    "auto_download"
  ];
  const hasSupporting = supportingSignals.some(s => signals.includes(s));

  if (trustTier === "low" && !hasSupporting) {
    return {
      isRealAttack: false,
      suppression: "Clipboard access detected but no supporting malicious signals found"
    };
  }

  // Real attack: has clipboard + supporting signals OR low-trust domain
  return {
    isRealAttack: true,
    suppression: null
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 5.5 â€” FALSE POSITIVE FILTER (v2.0 Confidence-Based)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Checks if detected signals warrant an alert based on aggregation rules.
 *
 * Rules:
 *   - Single LOW-confidence signal â†’ suppress
 *   - Single MEDIUM-confidence signal with trusted domain â†’ suppress
 *   - 2+ signals with MEDIUM+ confidence â†’ alert
 *   - 1+ signals with HIGH confidence â†’ alert
 *
 * @param {Array} behaviorSignals - Array of { confidence, severity, event }
 * @param {object} domainSignals - Domain-level signal flags
 * @returns {object} { shouldAlert: boolean, reason: string }
 */
function checkSignalAggregation(behaviorSignals, domainSignals) {
  if (!Array.isArray(behaviorSignals)) {
    behaviorSignals = [];
  }

  // Count signals by confidence level
  const highConfidenceSignals = behaviorSignals.filter(s => s.confidence === "HIGH");
  const mediumConfidenceSignals = behaviorSignals.filter(s => s.confidence === "MEDIUM");
  const lowConfidenceSignals = behaviorSignals.filter(s => s.confidence === "LOW");

  const highDomainSignals = (domainSignals.hasSafeBrowsing || domainSignals.hasDataset) ? 1 : 0;

  const totalHigh = highConfidenceSignals.length + highDomainSignals;
  const totalMedium = mediumConfidenceSignals.length;
  const totalMediumOrHigher = totalHigh + totalMedium;

  const isMalicious = (signals) => (
    Number(signals.highConfidence || 0) >= 1 ||
    Number(signals.mediumConfidence || 0) >= 2
  );

  if (isMalicious({ highConfidence: totalHigh, mediumConfidence: totalMedium })) {
    return {
      shouldAlert: true,
      reason: totalHigh >= 1
        ? `high_confidence_signal (domain: ${highDomainSignals}, behavior: ${highConfidenceSignals.length})`
        : `multiple_medium_signals (count: ${totalMediumOrHigher})`
    };
  }

  // Rule 3: Single signal scenarios
  if (behaviorSignals.length === 1) {
    const signal = behaviorSignals[0];

    // Single LOW â†’ suppress
    if (signal.confidence === "LOW") {
      return {
        shouldAlert: false,
        reason: `single_low_confidence_signal (event: ${signal.event})`
      };
    }
  }

  // Rule 4: Only LOW signals â†’ suppress
  if (lowConfidenceSignals.length > 0 && totalMediumOrHigher === 0) {
    return {
      shouldAlert: false,
      reason: `only_low_confidence_signals (count: ${lowConfidenceSignals.length})`
    };
  }

  // Default: no signals â†’ don't alert
  return {
    shouldAlert: false,
    reason: "no_signals"
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 5.6 â€” ADAPTIVE ALERT GATING (v3.1 â€” Low-Noise, Future-Proof)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Signal weight mapping (v3.1).
 * Higher weight = more significant threat indicator.
 * 
 * @type {object<string, number>}
 */
const SIGNAL_WEIGHTS = {
  // High-confidence signals (>0.8 weight)
  phishing_detected: 1.0,
  malware_signature: 1.0,
  threatIntelMatch: 1.0,
  
  // Medium-high signals (0.6â€“0.8 weight)
  phishing_form: 0.75,
  credential_theft: 0.75,
  redirect_loop: 0.75,
  
  // Medium signals (0.4â€“0.6 weight)
  hidden_iframe: 0.65,
  auto_download: 0.65,
  sensitive_data_entry: 0.6,
  hidden_download_anchor: 0.55,
  obfuscation_detected: 0.5,
  
  // Low-medium signals (0.3â€“0.4 weight)
  clipboard_hijack: 0.4,
  suspicious_regex: 0.35,
  reputationRiskElevated: 0.35,
  
  // Default for unknown signals
  _default: 0.2,
};

/**
 * Signal decay multiplier (v3.1).
 * Reduces weight for noisy/common-false-positive signals.
 * Applied AFTER base weight, not instead of it.
 * 
 * @type {object<string, number>}
 */
const SIGNAL_DECAY = {
  // Clipboard hijack is ~50% false positive on high-trust domains
  clipboard_hijack: 0.5,
  
  // Hidden iframe is common in ads/analytics
  hidden_iframe: 0.7,
  
  // Suspicious regex can be overly broad
  suspicious_regex: 0.6,
  
  // Default: no decay
  _default: 1.0,
};

/**
 * Applies signal decay to reduce noisy signal weights.
 * Maps each signal to its weighted and decayed value.
 * 
 * @param {Array<{type: string, ...}>} signals - Array of signal objects with type field
 * @returns {Array<{type: string, weight: number, ...}>} Signals with computed weights
 */
function applySignalDecay(signals) {
  if (!Array.isArray(signals)) return [];
  
  return signals.map(signal => {
    const baseWeight = SIGNAL_WEIGHTS[signal.type] || SIGNAL_WEIGHTS._default;
    const decayMultiplier = SIGNAL_DECAY[signal.type] || SIGNAL_DECAY._default;
    const finalWeight = baseWeight * decayMultiplier;
    
    return {
      ...signal,
      weight: finalWeight,
    };
  });
}

/**
 * Checks if signals have sufficient correlation/overlap.
 * Prevents single-signal false positives by requiring either:
 *   - 2+ signals (any type)
 *   - 1 signal with high base weight (>0.7)
 * 
 * @param {Array<{type: string, ...}>} signals
 * @returns {boolean} true if signals are sufficiently correlated
 */
function hasCorrelation(signals) {
  if (!Array.isArray(signals) || signals.length === 0) {
    return false; // No signals = no correlation
  }
  
  if (signals.length >= 2) {
    return true; // Multiple signals = inherent correlation
  }
  
  // Single signal: check if it's high-confidence enough
  const signal = signals[0];
  const baseWeight = SIGNAL_WEIGHTS[signal.type] || SIGNAL_WEIGHTS._default;
  return baseWeight >= 0.7;
}

/**
 * Determines if an alert should be triggered based on risk scoring rules.
 * 
 * Alert rules (v3.1):
 *   1. High risk (â‰¥70) â†’ always alert
 *   2. Medium risk (â‰¥40) + strong signals (â‰¥2) + high confidence (â‰¥0.7) â†’ alert
 *   3. Otherwise â†’ don't alert
 * 
 * @param {object} result - Detection result with risk, signals, confidence
 * @returns {boolean}
 */
function shouldTriggerAlert(result) {
  if (!result) return false;
  
  const highRisk = (result.finalRiskScore || result.risk || 0) >= 70;
  const mediumRisk = (result.finalRiskScore || result.risk || 0) >= 40;
  const strongSignals = Array.isArray(result.signals) && result.signals.length >= 2;
  const highConfidence = (result.aiConfidence || result.confidence || 0) >= 0.7;
  
  return (
    highRisk ||
    (mediumRisk && strongSignals && highConfidence)
  );
}

/**
 * Checks if a domain has sufficient trust to suppress medium-risk alerts.
 * Trust-aware suppression rules:
 *   - High trust + risk < 60 â†’ suppress alert
 *   - Low trust â†’ never suppress (alert normally)
 * 
 * @param {object} result - Detection result
 * @returns {boolean} true if alert should be suppressed due to trust
 */
function isTrustAwareSuppressed(result) {
  if (!result) return false;
  
  const trustTier = result.trustTier || "medium";
  const riskScore = result.finalRiskScore || result.risk || 0;
  
  return (trustTier === "high" && riskScore < 60);
}

/**
 * Cooldown system state: { lastAlertTime: number }
 * Prevents alert spam within 5-second windows.
 * 
 * @type {object}
 */
const ALERT_COOLDOWN = {
  lastAlertTime: 0,
  COOLDOWN_MS: 5000,
};

/**
 * Checks if alert cooldown is active.
 * Returns true if an alert was triggered within the last 5 seconds.
 * 
 * @returns {boolean}
 */
function isCooldownActive() {
  return Date.now() - ALERT_COOLDOWN.lastAlertTime < ALERT_COOLDOWN.COOLDOWN_MS;
}

/**
 * MASTER ALERT DECISION FUNCTION (v3.1)
 * 
 * Combines all adaptive gating rules:
 *   1. Cooldown check â†’ suppress if too recent
 *   2. Trigger evaluation (risk + signals + confidence)
 *   3. Trust-aware suppression check
 *   4. Correlation requirement (no isolated low-weight signals)
 *   5. Update cooldown on successful alert
 * 
 * @param {object} result - Detection result
 * @returns {boolean} true if alert should be shown
 */
function shouldShowAlert(result) {
  if (!result) return false;
  
  // Rule 1: Cooldown check
  if (isCooldownActive()) {
    console.log("[Sentinel-AdaptiveGating] â± Alert suppressed: cooldown active");
    return false;
  }
  
  // Rule 2: Trigger evaluation
  const shouldTrigger = shouldTriggerAlert(result);
  if (!shouldTrigger) {
    console.log("[Sentinel-AdaptiveGating] ðŸ“Š Alert not triggered: insufficient risk/signals");
    return false;
  }
  
  // Rule 3: Trust-aware suppression
  if (isTrustAwareSuppressed(result)) {
    console.log("[Sentinel-AdaptiveGating] ðŸ† Alert suppressed: high trust domain");
    return false;
  }
  
  // Rule 4: Correlation requirement
  if (!hasCorrelation(result.signals)) {
    console.log("[Sentinel-AdaptiveGating] ðŸ”— Alert suppressed: isolated signal (low correlation)");
    return false;
  }
  
  // Rule 5: All checks passed â†’ show alert and record time
  ALERT_COOLDOWN.lastAlertTime = Date.now();
  console.log("[Sentinel-AdaptiveGating] âœ… Alert APPROVED");
  return true;
}

function checkFalsePositiveFilter(result, normalizedUrl) {
  if (!result || result.status === "malicious") {
    // Never suppress MALICIOUS verdicts
    return { shouldSuppress: false, reason: "malicious verdict" };
  }

  if (result.status !== "suspicious") {
    // Only filter SUSPICIOUS verdicts
    return { shouldSuppress: false, reason: "safe verdict" };
  }

  // Extract hostname for trust check
  let hostname = "";
  try {
    hostname = new URL(normalizedUrl).hostname.toLowerCase();
  } catch {
    return { shouldSuppress: false, reason: "url parse failed" };
  }

  // Check if domain is trusted
  const TRUSTED_DOMAINS = new Set([
    "google.com", "googleapis.com", "googlevideo.com", "gstatic.com",
    "youtube.com", "youtu.be",
    "bing.com", "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "amazon.com", "amazonaws.com",
    "facebook.com", "instagram.com", "meta.com",
    "twitter.com", "x.com",
    "github.com", "githubusercontent.com",
    "linkedin.com", "licdn.com",
    "wikipedia.org", "wikimedia.org",
    "stackoverflow.com", "stackexchange.com",
    "medium.com", "wordpress.org",
  ]);

  // Check if root domain is trusted
  const rootDomain = getRootDomain(hostname);
  const isTrusted = TRUSTED_DOMAINS.has(rootDomain) || 
                    /\.edu$|\.gov$|\.org$/.test(rootDomain) ||
                    hostname.endsWith(rootDomain) && TRUSTED_DOMAINS.has(rootDomain);

  if (!isTrusted) {
    // Unknown domain â€” don't suppress
    return { shouldSuppress: false, reason: "untrusted domain" };
  }

  // Check for HIGH-confidence signals
  let hasHighConfidenceSignal = false;

  // Check direct signal flags
  if (result.hasSafeBrowsing || result.hasDataset) {
    hasHighConfidenceSignal = true;
  }

  // Check behavioral signals array (if present)
  if (Array.isArray(result.behaviorSignals)) {
    hasHighConfidenceSignal = result.behaviorSignals.some(sig => sig.confidence === "HIGH");
  }

  if (hasHighConfidenceSignal) {
    // High-confidence signal found â€” don't suppress
    return { shouldSuppress: false, reason: "high-confidence signal detected" };
  }

  // Trusted domain + SUSPICIOUS + no HIGH-confidence signals = suppress
  return {
    shouldSuppress: true,
    reason: "trusted domain with low/medium confidence signals only"
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 6 â€” BYPASS SYSTEM (STORAGE-PERSISTENT)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Normalizes a URL to a bypass key.
 * Strips fragment and normalizes to prevent key mismatches.
 *
 * @param {string} url
 * @returns {string}
 */
// VULN-04 FIX: toBypassKey() previously skipped multi-pass decode,
// causing key mismatches with normalizeCacheKey() for double-encoded URLs.
// e.g. toBypassKey("https://pay%2570al.com/") â†’ "paypal.com" (via URL constructor)
//      normalizeCacheKey same input â†’ "paypal.com" (via decode first)
// For standard encoding these matched, but for double-encoding they diverged.
// Now BOTH functions perform the same 4-pass decode before URL construction.
function toBypassKey(url) {
  // Must perform same multi-pass decode as normalizeCacheKey() to guarantee
  // that bypass keys and cache keys are always identical for the same URL.
  let rawUrl = String(url || "").trim();
  const MAX_PASSES = 4;
  for (let i = 0; i < MAX_PASSES; i++) {
    try {
      const decoded = decodeURIComponent(rawUrl);
      if (decoded === rawUrl) break;
      rawUrl = decoded;
    } catch {
      break;
    }
  }
  rawUrl = rawUrl.replace(/\x00/g, "");
  try {
    const p = new URL(rawUrl);
    p.hash = "";
    return p.protocol.toLowerCase() + "//" + p.host.toLowerCase() + p.pathname + p.search;
  } catch {
    return rawUrl.toLowerCase();
  }
}

/**
 * Checks if a URL has an active (non-expired) bypass.
 * Reads from chrome.storage.local â€” survives service worker restarts.
 *
 * @param {string} url
 * @returns {Promise<boolean>}
 */
async function isBypassed(url) {
  const key = toBypassKey(url);
  if (!key) return false;

  try {
    const data = await storageGet([CONFIG.KEYS.BYPASSES]);
    const bypasses = data[CONFIG.KEYS.BYPASSES] || {};
    const entry = bypasses[key];

    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      // Expired â€” clean up
      delete bypasses[key];
      await storageSet({ [CONFIG.KEYS.BYPASSES]: bypasses });
      return false;
    }
    return true;
  } catch (e) {
    console.warn("[Sentinel] Bypass check error:", e);
    return false; // Fail-open: don't block on storage error
  }
}

/**
 * Registers a bypass for a URL in chrome.storage.local.
 * Called when the user clicks "Proceed Anyway" on the warning page.
 *
 * @param {string} url
 * @returns {Promise<void>}
 */
async function registerBypass(url) {
  const key = toBypassKey(url);
  if (!key) return;

  try {
    const data = await storageGet([CONFIG.KEYS.BYPASSES]);
    const bypasses = data[CONFIG.KEYS.BYPASSES] || {};

    bypasses[key] = {
      url,
      registeredAt: Date.now(),
      expiresAt: Date.now() + CONFIG.BYPASS_TTL_MS,
    };

    // Prune expired bypasses on every write to prevent storage bloat
    const now = Date.now();
    for (const [k, v] of Object.entries(bypasses)) {
      if (now > v.expiresAt) delete bypasses[k];
    }

    await storageSet({ [CONFIG.KEYS.BYPASSES]: bypasses });

    // Also evict from LRU cache so next navigation re-evaluates
    urlCache.delete(key);

    console.log("[Sentinel] Bypass registered:", key);
  } catch (e) {
    console.warn("[Sentinel] Failed to register bypass:", e);
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 7 â€” URL NORMALIZATION (matches detectionEngine.js)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Normalizes a URL for use as a cache/bypass key.
 * Must produce the same output as detectionEngine.js normalizeUrl().
 *
 * @param {string} rawUrl
 * @returns {string}
 */
function normalizeCacheKey(rawUrl) {
  let url = String(rawUrl || "").trim();
  const MAX_PASSES = 4;
  for (let i = 0; i < MAX_PASSES; i++) {
    try {
      const decoded = decodeURIComponent(url);
      if (decoded === url) break;
      url = decoded;
    } catch {
      break;
    }
  }
  url = url.replace(/\x00/g, "");
  try {
    const p = new URL(url);
    p.hash = "";
    return p.protocol.toLowerCase() + "//" + p.host.toLowerCase() + p.pathname + p.search;
  } catch {
    return url.toLowerCase();
  }
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function getRootDomain(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^www\./, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  const doubleTlds = new Set([
    "co.uk", "co.in", "co.nz", "co.jp", "co.za",
    "com.au", "com.br", "com.sg", "com.my", "com.hk",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  return doubleTlds.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

function normalizeReasonList(result) {
  const list = [];
  if (Array.isArray(result?.reasons)) list.push(...result.reasons);
  if (result?.reason) list.push(result.reason);
  return [...new Set(
    list.map(r => String(r || "").trim()).filter(Boolean)
  )];
}

function computeRiskSteps(result, context) {
  const baseRaw     = typeof result?.score === "number" ? clamp(result.score * 10, 0, 100) : 0;
  const aiRaw       = typeof result?.aiScore === "number"
    ? clamp(result.aiScore, 0, 100)
    : clamp(result?.confidence || 0, 0, 100);
  const behaviorRaw = clamp(context?.behaviorRisk || 0, 0, 100);
  const intelRaw    = clamp(context?.intel?.confidence || 0, 0, 100);

  // â”€â”€ ML heuristic component (Section 5c of detectionEngine.js) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // mlRiskScore is injected by enrichWithML() which wraps analyzeUrl().
  // Defaults to 0 so legacy cached results without the field are unaffected.
  const mlRaw = clamp(typeof result?.mlRiskScore === "number" ? result.mlRiskScore : 0, 0, 100);

  // Weighted combination â€” weights sum to 1.0:
  //   base 40%  |  AI 25%  |  behavior 20%  |  intel 5%  |  ML 10%
  // (Previously: base 45%, AI 30%, behavior 20%, intel 5% â€” ML replaces 10pp
  //  taken equally from base and AI to preserve relative priority order.)
  let weighted = (baseRaw * 0.40) + (aiRaw * 0.25) + (behaviorRaw * 0.20) + (intelRaw * 0.05) + (mlRaw * 0.10);

  // Hard floor overrides (status-driven â€” must stay above threshold)
  if (result?.status === "malicious")      weighted = Math.max(weighted, 86);
  if (result?.status === "suspicious")     weighted = Math.max(weighted, 52);
  if (context?.intel?.isMalicious)         weighted = Math.max(weighted, 90);

  // Combine with mlRaw directly: final score is the max of the weighted
  // composite and the raw ML score so the ML model can never be down-voted
  // by a low AI/behavioral reading when it is highly confident.
  weighted = Math.max(weighted, mlRaw * 0.85);  // ML ceiling: 85% influence max

  const finalRiskScore = Math.round(clamp(weighted, 0, 100));
  const riskSteps = [
    `Base detection: ${Math.round(baseRaw)}/100`,
    `AI model: ${Math.round(aiRaw)}/100`,
    `Behavioral telemetry: ${Math.round(behaviorRaw)}/100`,
    `Threat intel confidence: ${Math.round(intelRaw)}/100`,
    `ML heuristic score: ${Math.round(mlRaw)}/100`,
    `Final risk score: ${finalRiskScore}/100`,
  ];

  return { finalRiskScore, baseRaw, aiRaw, behaviorRaw, intelRaw, mlRaw, riskSteps };
}

async function getThreatIntelContext(hostname) {
  const host = String(hostname || "").toLowerCase();
  if (!host) return { isMalicious: false, reports: 0, confidence: 0, source: "none" };

  const threatIntel = globalThis.SentinelThreatIntelService;
  const intel = threatIntel?.checkDomainReputation
    ? threatIntel.checkDomainReputation(host)
    : { isMalicious: false, reports: 0, confidence: 0, source: "none" };

  let reportCount = 0;
  let safeMarks = 0;
  try {
    const data = await storageGet([CONFIG.KEYS.REPORTS, CONFIG.KEYS.SAFE_MARKS]);
    const reports = Array.isArray(data[CONFIG.KEYS.REPORTS]) ? data[CONFIG.KEYS.REPORTS] : [];
    const marks = Array.isArray(data[CONFIG.KEYS.SAFE_MARKS]) ? data[CONFIG.KEYS.SAFE_MARKS] : [];
    const root = getRootDomain(host);

    reportCount = reports.filter(r => getRootDomain(r?.domain) === root).length;
    safeMarks = marks.filter(m => getRootDomain(m?.domain) === root).length;
  } catch {}

  const profile = threatIntel?.getMockDomainProfile
    ? threatIntel.getMockDomainProfile(host)
    : { domainAgeDays: undefined, serverLocation: undefined };

  const communityWeightedConfidence = clamp(
    (intel.confidence || 0) + (reportCount * 7) - (safeMarks * 6),
    0,
    100
  );

  return {
    ...intel,
    confidence: communityWeightedConfidence,
    reports: (intel.reports || 0) + reportCount,
    communityReports: reportCount,
    communitySafeMarks: safeMarks,
    domainAgeDays: profile.domainAgeDays,
    serverLocation: profile.serverLocation,
  };
}

async function applyAdvancedScoring(result, normalizedUrl, tabId) {
  const out = result && typeof result === "object" ? result : { status: "safe" };

  let hostname = "";
  try { hostname = new URL(normalizedUrl).hostname.toLowerCase(); } catch {}

  const behaviorRisk = TAB_BEHAVIOR_RISK.get(tabId) ?? 0;
  const intel = await getThreatIntelContext(hostname);

  if (intel.isMalicious) {
    out.status = "malicious";
    out.attackType = out.attackType && out.attackType !== "SAFE" ? out.attackType : "THREAT_INTEL_MATCH";
    out.signals = [...new Set([...(out.signals || []), "threatIntelMatch"])];
    out.sources = [
      ...(Array.isArray(out.sources) ? out.sources : []),
      {
        name: "Threat Intelligence",
        verdict: "malicious",
        triggered: true,
        detail: `Matched ${intel.source} (${intel.matchedDomain || hostname})`
      }
    ];
  } else if (intel.confidence >= 72 && out.status === "safe") {
    out.status = "suspicious";
    out.attackType = out.attackType && out.attackType !== "SAFE" ? out.attackType : "REPUTATION_RISK";
    out.signals = [...new Set([...(out.signals || []), "reputationRiskElevated"])];
  }

  const reasonSeed = normalizeReasonList(out);
  if (intel.isMalicious) reasonSeed.unshift("Threat intelligence lists this domain as malicious");
  if (intel.communityReports > 0) reasonSeed.push(`Community reports: ${intel.communityReports}`);
  if (behaviorRisk >= 30) reasonSeed.push(`Behavioral risk observed: ${behaviorRisk}/100`);
  if (!reasonSeed.length) reasonSeed.push("No critical threats detected by current models");

  const topReasons = [...new Set(reasonSeed)].slice(0, 3);
  const aiReasoning = String(out.aiReasoning || "").trim() || "AI model did not provide additional reasoning";
  const trustScore = typeof out.trustScore === "number" ? clamp(out.trustScore, 0, 100) : null;
  const domainTrust = trustScore !== null
    ? `${trustScore}/100 trust score`
    : intel.isMalicious
    ? "Threat intel flagged"
    : "Trust score unavailable";

  const { finalRiskScore, baseRaw, aiRaw, behaviorRaw, intelRaw, riskSteps } =
    computeRiskSteps(out, { behaviorRisk, intel });

  out.topReasons = topReasons;
  out.reasons = topReasons;
  out.explanation = `${out.status.toUpperCase()} verdict: ${topReasons.join("; ")}`;
  out.finalRiskScore = finalRiskScore;
  out.baseRiskScore = Math.round(baseRaw);
  out.aiRiskScore = Math.round(aiRaw);
  out.aiConfidence = Math.round(aiRaw);
  out.behaviorRiskScore = Math.round(behaviorRaw);
  out.intelConfidence = Math.round(intelRaw);
  out.aiReasoning = aiReasoning;
  out.domainAgeDays = intel.domainAgeDays;
  out.serverLocation = intel.serverLocation;
  out.riskSteps = riskSteps;

  out.breakdown = {
    ...(out.breakdown && typeof out.breakdown === "object" ? out.breakdown : {}),
    domainTrust,
    behavior: behaviorRaw >= 40 ? `High behavioral risk (${Math.round(behaviorRaw)}/100)` : `Behavioral risk ${Math.round(behaviorRaw)}/100`,
    content: out.attackType ? `Content classifier: ${String(out.attackType).replace(/_/g, " ")}` : "No content classifier hit",
    technical: intel.isMalicious
      ? `Threat intel confidence ${Math.round(intelRaw)}%`
      : `Technical confidence ${Math.round(baseRaw)}%`,
    aiReasoning,
  };

  if (out.status === "safe" && finalRiskScore >= 75) out.status = "malicious";
  else if (out.status === "safe" && finalRiskScore >= 45) out.status = "suspicious";

  return out;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 8 â€” HISTORY & ANALYTICS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Saves a detection result to the threat history log.
 * This is fire-and-forget â€” we do NOT await it in the navigation handler.
 *
 * @param {string} url
 * @param {object} result
 * @returns {Promise<void>}
 */
async function saveThreatHistory(url, result) {
  try {
    const data = await storageGet([CONFIG.KEYS.HISTORY]);
    const history = Array.isArray(data[CONFIG.KEYS.HISTORY]) ? data[CONFIG.KEYS.HISTORY] : [];

    const entry = {
      url: String(url || ""),
      domain: (() => { try { return new URL(url).hostname; } catch { return url; } })(),
      status: String(result.status || "safe"),
      score: Number(result.score || 0),
      finalRiskScore: Number(result.finalRiskScore || 0),
      trustScore: Number(result.trustScore || 100),
      confidence: Number(result.confidence || 0),
      aiReasoning: result.aiReasoning || null,
      aiScore: result.aiScore || null,
      explanation: String(result.explanation || ""),
      topReasons: Array.isArray(result.topReasons) ? result.topReasons.slice(0, 3) : [],
      behaviorRiskScore: Number(result.behaviorRiskScore || 0),
      domainAgeDays: result.domainAgeDays ?? null,
      serverLocation: result.serverLocation || null,
      attackType: String(result.attackType || "SAFE"),
      reason: String(result.reason || ""),
      reasons: Array.isArray(result.reasons) ? result.reasons : [],
      signals: Array.isArray(result.signals) ? result.signals : [],
      sources: Array.isArray(result.sources) ? result.sources : [],
      appliedRule: String(result.appliedRule || ""),
      action: result.status === "malicious" ? "blocked" : result.status === "suspicious" ? "warned" : "allowed",
      timestamp: new Date().toISOString(),
    };

    history.unshift(entry);

    await storageSet({
      [CONFIG.KEYS.HISTORY]: history.slice(0, CONFIG.MAX_HISTORY),
      [CONFIG.KEYS.LAST_ANALYSIS]: entry,
    });
  } catch (e) {
    console.warn("[Sentinel] History save error:", e);
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 9 â€” BLOCKING LOGIC
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Redirects a tab to the warning page with all detection data encoded
 * in URL parameters.
 *
 * Data strategy:
 *   Primary:  URL query parameters (instant, no storage read required)
 *   Fallback: chrome.storage.local[LAST_ANALYSIS] (warning.js reads this
 *             if URL params are missing â€” e.g. DNR-triggered redirects)
 *
 * URL length management:
 *   We limit individual params to 400 chars to stay well under the 2KB
 *   query string limit enforced by some Chromium builds.
 *
 * @param {number} tabId
 * @param {string} blockedUrl
 * @param {object} result
 */
function redirectToWarningPage(tabId, blockedUrl, result) {
  const warningBase = chrome.runtime.getURL("warning.html");

  // Safely encode each param with length limits
  const safeEncode = (val, maxLen = 400) =>
    encodeURIComponent(String(val || "").substring(0, maxLen));

  const reasonStr = Array.isArray(result.reasons)
    ? result.reasons.join("; ").substring(0, 800)
    : String(result.reason || "").substring(0, 800);

  const signalsJson = JSON.stringify(
    Array.isArray(result.signals) ? result.signals.slice(0, 10) : []
  );

  const sourcesJson = JSON.stringify(
    Array.isArray(result.sources) ? result.sources.slice(0, 6) : []
  );

  const breakdownJson = JSON.stringify(
    result && typeof result.breakdown === "object" && result.breakdown
      ? result.breakdown
      : {}
  );

  // Core detection params
  const params = [
    `url=${safeEncode(blockedUrl, 500)}`,
    `attackType=${safeEncode(result.attackType)}`,
    `confidence=${safeEncode(result.confidence)}`,
    `trustScore=${safeEncode(result.trustScore)}`,
    `score=${safeEncode(result.score)}`,
    `finalRiskScore=${safeEncode(result.finalRiskScore)}`,
    `explanation=${safeEncode(result.explanation || "", 500)}`,
    `aiReasoning=${safeEncode(result.aiReasoning || "", 400)}`,
    `domainAgeDays=${safeEncode(result.domainAgeDays)}`,
    `serverLocation=${safeEncode(result.serverLocation || "")}`,
    `reason=${safeEncode(reasonStr, 800)}`,
    `signals=${safeEncode(signalsJson, 400)}`,
    `sources=${safeEncode(sourcesJson, 400)}`,
    `breakdown=${safeEncode(breakdownJson, 600)}`,
    `source=sw`,
  ];

  // Adaptive metadata â€” present only when adaptive engine has run.
  // Allows warning.js to display reputation/behavior context without
  // an extra storage round-trip.
  if (result.finalScore !== undefined) {
    params.push(`finalScore=${safeEncode(Number(result.finalScore).toFixed(2))}`);
  }
  if (result.reputationWeight !== undefined && result.reputationWeight > 0) {
    params.push(`repWeight=${safeEncode(Number(result.reputationWeight).toFixed(2))}`);
  }
  if (result.userTrusted) {
    params.push(`userTrusted=1`);
  }
  if (result.autoEscalated) {
    params.push(`autoEscalated=1`);
  }
  if (result.adaptiveAppliedRule) {
    params.push(`adaptiveRule=${safeEncode(result.adaptiveAppliedRule)}`);
  }
  if (result.sensitivityLevel) {
    params.push(`sensitivity=${safeEncode(result.sensitivityLevel)}`);
  }
  if (result.reputationSnapshot) {
    params.push(`repSnap=${safeEncode(JSON.stringify(result.reputationSnapshot), 200)}`);
  }

  const redirectUrl = `${warningBase}?${params.join("&")}`;

  chrome.tabs.update(tabId, { url: redirectUrl }, () => {
    if (chrome.runtime.lastError) {
      console.error("[Sentinel] Tab update failed:", chrome.runtime.lastError.message);
    } else {
      console.log("[Sentinel] â›” Warning page shown for:", blockedUrl);
    }
  });
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 9b â€” SSL / TLS CERTIFICATE ANALYSIS ENGINE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//
// Detects 7 SSL/TLS threat categories using Chrome's webRequest API:
//   1. insecure_http      â€” plain HTTP navigation (no TLS at all)
//   2. invalid_ssl        â€” certificate validation failed / untrusted CA
//   3. expired_cert       â€” validTo timestamp in the past
//   4. self_signed_cert   â€” issuer == subject (no trusted CA chain)
//   5. domain_mismatch    â€” SAN/CN does not match the visited hostname
//   6. weak_encryption    â€” SHA-1, MD5, RC4, or DES cipher detected
//   7. mixed_content      â€” HTTPS page loads plain HTTP sub-resources
//
// Architecture:
//   â€¢ onHeadersReceived captures securityDetails per main-frame URL.
//   â€¢ onBeforeRequest tracks HTTP sub-resource requests on HTTPS pages.
//   â€¢ Both caches keyed by normalized URL / tabId.
//   â€¢ consumeSSLSignals(url, tabId) drains both and returns typed signals.
//   â€¢ Signals are merged into result.signals at Step 5.5 of the analysis
//     flow (onBeforeNavigate), before adaptive scoring and ML enrichment.
//
// False-positive guards:
//   â€¢ localhost / 127.0.0.1 excluded from HTTP-only check.
//   â€¢ securityDetails only trusted when it is a non-null object.
//   â€¢ Weak cipher detection uses explicit deprecated algorithm strings.

/** Per-URL SSL metadata cache populated by webRequest.onHeadersReceived. */
const _SSL_CACHE = new Map();

/** Per-tab HTTP sub-resource tracker for mixed-content detection. */
const _MIXED_CONTENT_CACHE = new Map();

/** Hostnames excluded from the plain-HTTP signal. */
const _SSL_SAFE_HTTP_DOMAINS = new Set(["localhost", "127.0.0.1", "::1"]);

/** Deprecated cipher / protocol substrings that indicate weak encryption. */
const _WEAK_CIPHER_PATTERNS = [
  "SHA1", "SHA-1", "MD5", "RC4", "DES", "EXPORT", "NULL",
  "TLS 1.0", "TLS 1.1",
];

/**
 * Converts raw webRequest securityDetails + URL into Sentinel signal strings.
 *
 * @param {string}      url        - request URL being analyzed
 * @param {object|null} secDetails - chrome.webRequest securityDetails object
 * @param {number}      tabId      - tab making the request
 * @returns {string[]} Array of signal strings (may be empty)
 */
function analyzeSSL(url, secDetails, tabId) {
  const signals = [];

  // 1. HTTP (no TLS) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const isHTTPS = url.startsWith("https://");
  if (!isHTTPS) {
    let hostname = "";
    try { hostname = new URL(url).hostname; } catch {}
    if (!_SSL_SAFE_HTTP_DOMAINS.has(hostname)) {
      signals.push("insecure_http");
    }
    return signals;   // HTTP pages cannot have cert signals
  }

  // 2â€“7. Certificate-level checks require securityDetails â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!secDetails || typeof secDetails !== "object") {
    return signals;   // absence of data â‰  presence of problem
  }

  // 2. Invalid / untrusted certificate
  if (secDetails.certificateId === 0) {
    signals.push("invalid_ssl");
  }

  // 3. Expired certificate
  const validTo = typeof secDetails.validTo === "number" ? secDetails.validTo : null;
  if (validTo !== null && validTo < Date.now() / 1000) {
    signals.push("expired_cert");
  }

  // 4. Self-signed certificate (issuer == subject, no trusted CA chain)
  const issuer  = String(secDetails.issuer      || "").trim().toLowerCase();
  const subject = String(secDetails.subjectName || "").trim().toLowerCase();
  if (issuer && subject && issuer === subject) {
    signals.push("self_signed_cert");
  }

  // 5. Domain mismatch (SAN / CN does not match request hostname)
  try {
    const requestHost = new URL(url).hostname.toLowerCase();
    const sanList = Array.isArray(secDetails.sanList) ? secDetails.sanList : [];
    const commonName = String(secDetails.subjectName || "").toLowerCase();

    const matchesSAN = sanList.some(san => {
      const s = String(san).toLowerCase();
      if (s === requestHost) return true;
      if (s.startsWith("*.")) {
        const base = s.slice(2);
        return requestHost.endsWith("." + base) || requestHost === base;
      }
      return false;
    });
    const matchesCN = commonName && (
      commonName === requestHost ||
      (commonName.startsWith("*.") && requestHost.endsWith("." + commonName.slice(2)))
    );

    if (!matchesSAN && !matchesCN && (sanList.length > 0 || commonName)) {
      signals.push("domain_mismatch");
    }
  } catch {}

  // 6. Weak encryption (deprecated cipher / protocol)
  const cryptoStr = [
    secDetails.cipher || "",
    secDetails.keyExchangeGroup || "",
    secDetails.protocol || "",
  ].join(" ");

  if (_WEAK_CIPHER_PATTERNS.some(p => cryptoStr.includes(p))) {
    signals.push("weak_encryption");
  }

  // 7. Mixed content (checked via _MIXED_CONTENT_CACHE, populated separately)
  if (tabId !== undefined && _MIXED_CONTENT_CACHE.has(tabId)) {
    const httpResources = _MIXED_CONTENT_CACHE.get(tabId);
    if (httpResources && httpResources.size > 0) {
      signals.push("mixed_content");
    }
  }

  if (signals.length > 0) {
    console.log("[Sentinel-SSL]", {
      url: url.slice(0, 80),
      signals,
      protocol: secDetails.protocol || "?",
      cipher:   (secDetails.cipher  || "?").slice(0, 40),
    });
  }

  return signals;
}

/**
 * Drains and returns any SSL signals cached for this URL+tab.
 * Consumes the cache entry (deletes it) so signals inject exactly once.
 *
 * @param {string} url   - normalized URL key
 * @param {number} tabId - tab ID for mixed-content lookup
 * @returns {string[]}
 */
function consumeSSLSignals(url, tabId) {
  const cached = _SSL_CACHE.get(url);
  _SSL_CACHE.delete(url);
  const fromCache = cached ? cached.signals : analyzeSSL(url, null, tabId);
  return Array.isArray(fromCache) ? fromCache : [];
}

// webRequest.onHeadersReceived â€” capture securityDetails per main-frame URL
// Fires after the TLS handshake is complete and response headers arrive.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.frameId !== 0) return;
    if (!details.url.startsWith("https://")) return;

    const secDetails  = details.securityDetails || null;
    const sslSignals  = analyzeSSL(details.url, secDetails, details.tabId);

    if (sslSignals.length > 0) {
      _SSL_CACHE.set(details.url, { signals: sslSignals, details: secDetails });
    }

    // Clear mixed-content log for this tab when a new HTTPS main page loads
    _MIXED_CONTENT_CACHE.delete(details.tabId);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

// webRequest.onBeforeRequest â€” detect mixed content (HTTP sub-resources on HTTPS pages)
// Purely observational â€” does NOT use blocking mode.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === "main_frame") return;
    if (!details.url.startsWith("http://")) return;
    const tabId = details.tabId;
    if (tabId < 0) return;

    if (!_MIXED_CONTENT_CACHE.has(tabId)) {
      _MIXED_CONTENT_CACHE.set(tabId, new Set());
    }
    _MIXED_CONTENT_CACHE.get(tabId).add(details.url.slice(0, 120));
  },
  { urls: ["http://*/*"] }
);

// Housekeeping: clear mixed-content cache on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  _MIXED_CONTENT_CACHE.delete(tabId);
});

// SECTION 10 â€” PRIMARY NAVIGATION LISTENER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Main detection handler â€” fires on every navigation start.
 *
 * CRITICAL ORDERING:
 *   Due to MV3 service worker lifecycle constraints, we cannot use a
 *   blocking webRequest listener for heuristic analysis. Instead we use
 *   webNavigation.onBeforeNavigate which fires before DNS resolution,
 *   giving us a window to redirect the tab before the page loads.
 *
 *   Race condition note: chrome.tabs.update is async. On very fast
 *   connections, the original page may resolve before our redirect fires.
 *   The DNR (declarativeNetRequest) rules in rules.json handle known-bad
 *   domains synchronously BEFORE this handler runs, covering the race.
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // â”€â”€ Guard 1: Main frame only â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (details.frameId !== 0) return;

  const rawUrl = details.url;
  const tabId = details.tabId;

  // Reset per-tab behavior risk score on every new top-level navigation
  TAB_BEHAVIOR_RISK.delete(tabId);

  // â”€â”€ Guard 2: Only analyze http/https â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!/^https?:\/\//i.test(rawUrl)) return;

  // â”€â”€ Guard 3: Skip our own warning page navigations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const extensionOrigin = chrome.runtime.getURL("");
  if (rawUrl.startsWith(extensionOrigin)) return;

  // â”€â”€ Step 1: Normalize URL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const normalizedUrl = normalizeCacheKey(rawUrl);

  // â”€â”€ Step 2: Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (isDuplicate(tabId, normalizedUrl)) {
    console.log("[Sentinel] â­ Dedup skip:", normalizedUrl);
    return;
  }

  // VULN-10: Record this navigation as a potential redirect chain origin.
  // If the NEXT navigation on this tab is to a malicious URL within 10s,
  // consumeRedirectOrigin() will identify this URL as the redirect source.
  recordRedirectOrigin(tabId, normalizedUrl);
  const redirectLoop = updateRedirectLoopTelemetry(tabId);
  if (redirectLoop.loopDetected) {
    const prevRisk = TAB_BEHAVIOR_RISK.get(tabId) ?? 0;
    TAB_BEHAVIOR_RISK.set(tabId, Math.min(100, prevRisk + 15));
  }

  console.log("[Sentinel] â–¶ Analyzing:", normalizedUrl);

  // ðŸ§  DEBUG: Log analysis start
  const analysisStartTime = Date.now();

  // â”€â”€ Step 3: Bypass check (FIRST â€” before any blocking logic) â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const bypassed = await isBypassed(normalizedUrl);
  if (bypassed) {
    console.log("[Sentinel] âœ… Bypassed (user-approved):", normalizedUrl);
    return;
  }

  // â”€â”€ Step 4: LRU Cache check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const cached = urlCache.get(normalizedUrl);
  if (cached) {
    console.log("[Sentinel] âš¡ Cache hit:", normalizedUrl, "â†’", cached.status);
    // Still act on cached malicious result â€” user may be revisiting a bad URL
    if (cached.status === "malicious") {
      redirectToWarningPage(tabId, rawUrl, cached);
    }
    return;
  }

  // â”€â”€ Step 5: Detection engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  let result;
  try {
    const engine = globalThis.SentinelDetectionEngine;
    if (!engine || typeof engine.analyzeUrl !== "function") {
      console.error("[Sentinel] Detection engine not loaded!");
      return;
    }
    result = engine.analyzeUrl(normalizedUrl);

    // ðŸ§  AI LAYER
    const aiResult = await callAIAnalysis({
      url: normalizedUrl,
      signals: result.signals || [],
      score: result.score,
      confidence: result.confidence,
      reasons: result.reasons || []
    });

    if (aiResult) {
      result.aiReasoning = aiResult.reasoning;
      result.aiScore = aiResult.riskScore;

      // Optional override logic
      if (aiResult.decision === "malicious") {
        result.status = "malicious";
      } else if (aiResult.decision === "suspicious" && result.status === "safe") {
        result.status = "suspicious";
      }
    }
  } catch (e) {
    console.error("[Sentinel] Detection engine threw:", e);
    return; // Fail-open
  }

  console.log("[Sentinel] ðŸ“Š Base Result:", {
    status: result.status,
    score: result.score,
    confidence: result.confidence,
    attackType: result.attackType,
    appliedRule: result.appliedRule,
  });

  // ðŸ§  DEBUG: Log detailed signals and confidence levels
  if (Array.isArray(result.behaviorSignals) && result.behaviorSignals.length > 0) {
    console.log("[Sentinel-AI] BEHAVIOR SIGNALS:", result.behaviorSignals.map(s => ({
      event: s.event,
      confidence: s.confidence,
      userInitiated: s.userInitiated || false,
      severity: s.severity
    })));
  }

  // â”€â”€ Step 5.5: Inject SSL/TLS signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // consumeSSLSignals() drains the webRequest.onHeadersReceived cache for
  // this URL. For HTTP pages it calls analyzeSSL() directly.
  // Signals are de-duplicated and merged before adaptive scoring so the ML
  // model and threat evaluator both see the full signal set.
  try {
    const sslSignals = consumeSSLSignals(normalizedUrl, tabId);
    if (sslSignals.length > 0) {
      result.signals = [...new Set([...(result.signals || []), ...sslSignals])];

      // Build human-readable reasons for SSL issues (shown in overlay)
      const SSL_REASON_MAP = {
        insecure_http:    "Page loaded over plain HTTP â€” no encryption",
        invalid_ssl:      "SSL certificate could not be validated",
        expired_cert:     "SSL certificate has expired",
        self_signed_cert: "SSL certificate is self-signed (no trusted CA)",
        domain_mismatch:  "SSL certificate domain does not match the site",
        weak_encryption:  "Site uses deprecated/weak encryption (SHA-1/TLS 1.0)",
        mixed_content:    "Page loads insecure HTTP sub-resources (mixed content)",
      };
      const sslReasons = sslSignals
        .map(s => SSL_REASON_MAP[s] || s)
        .filter(Boolean);

      result.reasons = [...new Set([...(result.reasons || []), ...sslReasons])].slice(0, 6);

      // Upgrade status if critical SSL signal present
      const CRITICAL_SSL = ["invalid_ssl", "expired_cert", "domain_mismatch"];
      const hasCriticalSSL = sslSignals.some(s => CRITICAL_SSL.includes(s));
      if (hasCriticalSSL && result.status === "safe") {
        result.status = "suspicious";
        console.log("[Sentinel-SSL] Status upgraded to suspicious due to:", sslSignals);
      }

      console.log("[Sentinel AI] SSL signals merged:", sslSignals);
    }
  } catch (sslErr) {
    // Fail-open: SSL analysis never blocks the detection flow
    console.warn("[Sentinel-SSL] analyzeSSL error:", sslErr?.message);
  }



  // â”€â”€ Step 6: Cache the BASE result (fast path for repeated visits) â”€â”€â”€â”€â”€â”€
  urlCache.set(normalizedUrl, result);

  // â”€â”€ Step 7: Adaptive scoring layer (v3.0) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Reads sentinel_reputation + sentinel_user_profile from storage.
  // Adjusts score via reputation weight + behavior adjustment.
  // Applies dynamic thresholds based on user sensitivity level.
  // Fail-open: if adaptive engine throws, result is used unchanged.
  let hostname = "";
  try { hostname = new URL(normalizedUrl).hostname; } catch {}

  const adaptiveEngine = globalThis.SentinelAdaptiveEngine;
  if (adaptiveEngine && hostname) {
    try {
      result = await adaptiveEngine.applyAdaptiveScoring(result, hostname);
      if (result.wasAdaptivelyChanged) {
        console.log("[Sentinel] ðŸ”„ Adaptive verdict:", result.status,
          "| Rule:", result.adaptiveAppliedRule,
          "| finalScore:", result.finalScore);
      }
    } catch (adaptiveErr) {
      // Fail-open: adaptive layer error â†’ use base result
      console.warn("[Sentinel] Adaptive engine error:", adaptiveErr?.message);
    }
  }

  // Step 7b: unified final risk scoring + XAI + threat intelligence
  result = await applyAdvancedScoring(result, normalizedUrl, tabId);
  if (redirectLoop.loopDetected) {
    result.signals = [...new Set([...(result.signals || []), "redirectLoop"])];
    result.reasons = [...new Set([...(result.reasons || []), `Redirect loop pattern detected (${redirectLoop.count} hops)`])].slice(0, 3);
  }
  
  // â”€â”€ Step 7c: Apply signal decay to reduce noisy signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // This adjusts the risk score downward for signals prone to false positives
  // (e.g., clipboard_hijack on high-trust domains, hidden_iframe in ads)
  if (Array.isArray(result.signals) && result.signals.length > 0) {
    const decayedSignals = applySignalDecay(
      result.signals.map(sig => ({ type: sig }))
    );
    
    // Calculate decay impact: sum of weight differences
    const originalWeight = result.signals.length;
    const decayedWeight = decayedSignals.reduce((sum, s) => sum + s.weight, 0);
    const decayImpact = Math.max(0, (1 - (decayedWeight / originalWeight)) * 100);
    
    // Apply decay to risk score (reduce by impact percentage, but floor at 0)
    if (decayImpact > 0 && result.finalRiskScore > 0) {
      const adjustedScore = result.finalRiskScore * (1 - (decayImpact / 100));
      result.signalDecayApplied = true;
      result.decayImpactPercent = Math.round(decayImpact);
      result.originalRiskScore = result.finalRiskScore;
      result.finalRiskScore = Math.max(0, Math.round(adjustedScore));
      
      console.log("[Sentinel-SignalDecay]", {
        url: normalizedUrl,
        originalScore: result.originalRiskScore,
        adjustedScore: result.finalRiskScore,
        decayImpactPercent: result.decayImpactPercent,
        signals: result.signals.slice(0, 5)
      });
    }
  }
  
  // Refresh cache so downstream overlay path sees enriched context.
  urlCache.set(normalizedUrl, result);

  // â”€â”€ Step 8: Route based on FINAL verdict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (result.status === "malicious") {
    // ðŸŽ¯ MALICIOUS PATH: Even high-confidence verdicts benefit from gating
    // Malicious detections skip some gating (already high confidence) but
    // still check cooldown to prevent spam on the same/similar URLs
    if (!isCooldownActive()) {
      ALERT_COOLDOWN.lastAlertTime = Date.now();
      console.log("[Sentinel] ðŸš« BLOCKING:", normalizedUrl);
      redirectToWarningPage(tabId, rawUrl, result);
      saveThreatHistory(rawUrl, result).catch(e => console.warn("[Sentinel] History save error:", e));

      // Update v3.0 reputation (non-blocking)
      if (adaptiveEngine && hostname) {
        adaptiveEngine.updateDomainReputationV3(hostname, "malicious").catch(() => {});
        adaptiveEngine.updateUserProfile(hostname, "blocked").catch(() => {});
      }
    } else {
      console.log("[Sentinel] â± Malicious alert suppressed: cooldown active");
      saveThreatHistory(rawUrl, result).catch(e => console.warn("[Sentinel] History save error:", e));
    }

  } else if (result.status === "suspicious") {
    // âœ¨ NEW: Apply adaptive alert gating (v3.1)
    // Combines: risk scoring, signal correlation, trust awareness, cooldown
    const adaptiveDecision = shouldShowAlert(result);
    
    if (!adaptiveDecision) {
      console.log("[Sentinel] âœ… ADAPTIVE GATING SUPPRESSED:", normalizedUrl);
      
      // ðŸ§  DEBUG: Log suppression decision with details
      console.log("[Sentinel-AdaptiveGating-Suppressed]", {
        url: normalizedUrl,
        status: result.status,
        riskScore: result.finalRiskScore || result.score,
        signals: Array.isArray(result.signals) ? result.signals.length : 0,
        confidence: result.aiConfidence || result.confidence,
        trustTier: result.trustTier || "unknown",
        timestamp: new Date().toISOString()
      });
      
      // Still log to history but don't show overlay
      const suppressedResult = { ...result, adaptiveGatingApplied: true };
      saveThreatHistory(rawUrl, suppressedResult).catch(e => console.warn("[Sentinel] History save error:", e));
      return;
    }

    console.log("[Sentinel] âš ï¸ Suspicious (Adaptive Alert Approved):", normalizedUrl);
    // NOTE: The overlay is delivered by webNavigation.onCompleted belowâ€”
    // after the page and content script are fully ready at document_idle.
    // Sending here (onBeforeNavigate) arrives before the listener registers
    // and was silently dropped. Dead send removed.
    saveThreatHistory(rawUrl, result).catch(e => console.warn("[Sentinel] History save error:", e));

    // Update v3.0 reputation (non-blocking)
    if (adaptiveEngine && hostname) {
      adaptiveEngine.updateDomainReputationV3(hostname, "suspicious").catch(() => {});
      adaptiveEngine.updateUserProfile(hostname, "warned").catch(() => {});
    }

  } else {
    // Safe â€” skip logging for hard-override trusted domains
    if (result.score !== -5) {
      saveThreatHistory(rawUrl, result).catch(e => console.warn("[Sentinel] History save error:", e));
    }
  }
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 10b â€” LEGACY REPUTATION (DEPRECATED â€” v3.0 uses adaptiveEngine)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// updateDomainReputation() wrote the old v2.1 schema { suspicious, malicious }.
// v3.0 uses updateDomainReputationV3() from adaptiveEngine.js which writes the
// correct { suspiciousHits, maliciousHits, bypassCount } schema with time-decay.
// The old function is intentionally removed to prevent schema conflicts.

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 10c â€” STATUS OVERLAY (webNavigation.onCompleted)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Sends sentinel:show-overlay to content.js with automatic retry.
 *
 * WHY RETRY?
 *   Even at document_idle, on very fast connections Chrome can fire
 *   onCompleted before flushing the content script injection. Two retries
 *   with linear back-off cover this edge case without hammering the tab.
 *
 * WHY NOT IN onBeforeNavigate?
 *   onBeforeNavigate fires BEFORE the page loads. document_idle means the
 *   content script is ready AFTER. The message arrives before the listener
 *   is registered and is silently dropped. onCompleted fires after
 *   document_idle â€” content script is guaranteed to be listening.
 *
 * @param {number} tabId
 * @param {object} payload  â€” full message payload for content.js
 * @param {number} [retries=3]
 */
/**
 * Per-tab accumulated behavior risk score (0â€“100, in-memory only).
 * Populated by BEHAVIOR_ALERT messages from behaviorMonitor.js.
 * Reset on each new navigation so scores never bleed across pages.
 */
const TAB_BEHAVIOR_RISK = new Map();

function sendOverlayWithRetry(tabId, payload, retries = 2) {
  // Idempotent: if the first delivery succeeds (response received),
  // cancel any pending retries so the overlay is shown exactly once.
  let delivered = false;

  function attempt(attemptsLeft) {
    if (delivered) return;
    chrome.tabs.sendMessage(tabId, payload, (response) => {
      if (chrome.runtime.lastError) {
        if (attemptsLeft > 0) {
          // Linear back-off: 400ms, 800ms
          setTimeout(() => attempt(attemptsLeft - 1), 400 * (retries - attemptsLeft + 1));
        }
      } else {
        delivered = true;  // stop any further retries
      }
    });
  }

  attempt(retries);
}

/**
 * Overlay delivery hub â€” fires AFTER the page is fully loaded.
 *
 * Pipeline:
 *   1. Guard: extension pages / non-http(s) / sub-frames   â†’ skip
 *   2. Cache lookup: onBeforeNavigate already ran analyzeUrl()  â†’ O(1) hit
 *   3. Show overlay for analyzed statuses (malicious/suspicious/safe)
 *   4. Suspicious â†’ additionally trigger sentinel:play-alert sound
 *
 * MESSAGE TYPE: "sentinel:show-overlay"
 *   This matches the listener in content.js exactly.
 *   The old "sentinel:suspicious-overlay" type in onBeforeNavigate was the
 *   root cause of the silent failure â€” nobody was listening for that type.
 */
chrome.webNavigation.onCompleted.addListener((details) => {
  // Guard 1: main frame only
  if (details.frameId !== 0) return;

  // Guard 2: extension pages (warning.html, dashboard.html, popup, etc.)
  const extensionOrigin = chrome.runtime.getURL("");
  if (details.url.startsWith(extensionOrigin)) return;

  // Guard 3: http/https only â€” skip chrome://, file://, etc.
  if (!/^https?:\/\//i.test(details.url)) return;

  const tabId = details.tabId;
  const url = details.url;
  const normalizedUrl = normalizeCacheKey(url);
  const result = urlCache.get(url) || urlCache.get(normalizedUrl);
  if (!result) return;

  // Show for all analyzed sites
  const shouldShow =
    result.status === "malicious" ||
    result.status === "suspicious" ||
    result.status === "safe";

  if (!shouldShow) return;

  console.log("[Overlay Trigger]", {
    url,
    status: result.status,
    tabId
  });

  // â”€â”€ NEW: Apply centralized threat evaluator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // This gates alert decisions through structured evaluation:
  // - Weighted signal correlation
  // - Confidence weighting
  // - Trust-aware moderation
  // - Hysteresis (anti-flicker)
  // - Cooldown enforcement
  const evaluator = globalThis.SentinelThreatEvaluator;
  let threatDecision = null;

  if (evaluator && typeof evaluator.evaluateThreat === "function") {
    try {
      threatDecision = evaluator.evaluateThreat(result, {
        url: normalizedUrl,
        trustTier: result.trustTier || "medium",
        userProfile: result.userProfile,
      });

      // Log evaluation in dev_mode
      if (_devModeEnabled && typeof evaluator.logEvaluation === "function") {
        evaluator.logEvaluation(normalizedUrl, threatDecision);
      }

      // If evaluator says "no alert", respect it (cooldown or hysteresis)
      if (!threatDecision.shouldAlert) {
        console.log(
          "[Sentinel] Alert suppressed by threat evaluator:",
          threatDecision.cooldownRequired ? "cooldown" : "hysteresis/gating"
        );
        return;
      }

      // Use evaluator's severity and risk score
      result.status = threatDecision.severity;
      result.finalRiskScore = threatDecision.finalRisk;
      result.evaluatorReasons = threatDecision.reasoning;
    } catch (e) {
      console.warn("[Sentinel] Threat evaluator error:", e);
      // Fail-open: continue with base result if evaluator fails
    }
  }

  // â”€â”€ Step 2: build overlay payload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const isSafe       = result.status === "safe";
  const isSuspicious = result.status === "suspicious";
  const isMalicious  = result.status === "malicious";

  // Compute displayable risk score (prefer finalRiskScore, fall back to score*10)
  const displayRisk = typeof result.finalRiskScore === "number"
    ? result.finalRiskScore
    : (typeof result.score === "number" ? Math.round(result.score * 10) : 0);

  // â”€â”€ [Sentinel AI] Structured overlay decision log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  console.log("[Sentinel AI] Overlay decision", {
    url,
    status:    result.status,
    risk:      displayRisk,
    signals:   Array.isArray(result.signals) ? result.signals : [],
    trustTier: result.trustTier || "medium",
    mlScore:   result.mlRiskScore ?? null,
    decision:  displayRisk >= 40 ? "SHOW" : (isMalicious ? "SHOW (malicious override)" : "SKIP (low risk)"),
    evaluator: threatDecision ? { shouldAlert: threatDecision.shouldAlert, severity: threatDecision.severity } : null,
  });

  // â”€â”€ Risk floor gate: skip overlay for genuinely low-risk pages â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Malicious always shows (redirected to warning.html above, but defence-in-depth).
  // Suspicious/safe need risk >= 40 to justify IPC cost and user disruption.
  if (!isMalicious && displayRisk < 40) {
    console.log("[Sentinel AI] Overlay skipped â€” risk below threshold", displayRisk, "/ 40");
    return;
  }

  const overlayMessage = isSafe
    ? "Site verified â€” no threats detected"
    : `Caution: ${result.attackType
        ? result.attackType.replace(/_/g, " ")
        : "suspicious signals detected"}`;

  // Combine reasoning from detection engine and threat evaluator
  const finalReasons = [
    ...(result.evaluatorReasons || []).slice(0, 2),
    ...(Array.isArray(result.reasons) ? result.reasons.slice(0, 2) : []),
  ].slice(0, 3);

  const payload = {
    type:         "sentinel:show-overlay",   // exact match for content.js listener
    status:       result.status,
    message:      overlayMessage,
    trustScore:   typeof result.trustScore === "number" ? result.trustScore : null,
    score:        typeof result.score === "number" ? result.score : null,
    finalScore:   typeof result.finalRiskScore === "number" ? result.finalRiskScore : null,
    signals:      Array.isArray(result.signals) ? result.signals.slice(0, 12) : [],
    apiCalls:     Array.isArray(result.sources)
      ? result.sources.slice(0, 6).map((s) => `${s?.name || "module"}: ${s?.detail || s?.verdict || ""}`.trim())
      : [],
    riskSteps:    Array.isArray(result.riskSteps) ? result.riskSteps.slice(0, 8) : [],
    explanation:  result.explanation || "",
    aiReasoning:  result.aiReasoning || null,
    breakdown:    result && typeof result.breakdown === "object" ? result.breakdown : null,
    educationTip: isSuspicious
      ? "Do not enter passwords or personal information on this page."
      : "",
    // Use evaluator reasoning if available, fall back to original reasons
    reasons: finalReasons.length > 0 ? finalReasons :
      (isSuspicious && Array.isArray(result.reasons) ? result.reasons.slice(0, 3) : []),
    // Expose final risk score and severity for overlay display
    finalRisk: threatDecision?.finalRisk ?? (result.finalRiskScore || result.score),
    severity: result.status,
  };

  sendOverlayWithRetry(tabId, payload);

  // â”€â”€ Step 3: alert sound for suspicious (nice-to-have, non-fatal) â”€â”€â”€â”€â”€â”€
  if (isSuspicious) {
    chrome.tabs.sendMessage(tabId, {
      type:      "sentinel:play-alert",
      alertType: "suspicious",
    }).catch(() => {});
  }
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 11 â€” MESSAGE HANDLER

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return false;

  switch (message.type) {

    case "sentinel:bypass-url": {
      if (!message.url) { sendResponse({ ok: false, error: "No URL" }); return true; }

      // v3.0: Update user profile + reputation concurrently with bypass registration
      const bypassUrl = message.url;
      let bypassHostname = "";
      try { bypassHostname = new URL(bypassUrl).hostname; } catch {}

      const adaptiveEng = globalThis.SentinelAdaptiveEngine;

      registerBypass(bypassUrl)
        .then(() => {
          // Non-blocking: update user behavior profile and domain reputation
          if (adaptiveEng && bypassHostname) {
            adaptiveEng.updateUserProfile(bypassHostname, "bypass").catch(() => {});
            adaptiveEng.updateDomainReputationV3(bypassHostname, "bypass").catch(() => {});
          }
          sendResponse({ ok: true });
        })
        .catch(e => sendResponse({ ok: false, error: e.message }));
      return true;
    }

    case "sentinel:get-analysis": {
      storageGet([CONFIG.KEYS.LAST_ANALYSIS])
        .then(data => sendResponse({ result: data[CONFIG.KEYS.LAST_ANALYSIS] || null }))
        .catch(e => sendResponse({ result: null, error: e.message }));
      return true;
    }

    case "sentinel:get-history": {
      storageGet([CONFIG.KEYS.HISTORY])
        .then(data => sendResponse({ history: data[CONFIG.KEYS.HISTORY] || [] }))
        .catch(e => sendResponse({ history: [], error: e.message }));
      return true;
    }

    case "sentinel:get-reputation": {
      storageGet([CONFIG.KEYS.REPUTATION])
        .then(data => sendResponse({ reputation: data[CONFIG.KEYS.REPUTATION] || {} }))
        .catch(e => sendResponse({ reputation: {}, error: e.message }));
      return true;
    }

    case "sentinel:get-user-profile": {
      // Returns the full sentinel_user_profile for the dashboard
      storageGet([CONFIG.KEYS.USER_PROFILE])
        .then(data => sendResponse({ profile: data[CONFIG.KEYS.USER_PROFILE] || null }))
        .catch(e => sendResponse({ profile: null, error: e.message }));
      return true;
    }

    case "sentinel:get-adaptive-stats": {
      // Returns combined analytics snapshot (reputation + user profile summary)
      const adaptiveEngStats = globalThis.SentinelAdaptiveEngine;
      if (adaptiveEngStats?.getAdaptiveStats) {
        adaptiveEngStats.getAdaptiveStats()
          .then(stats => sendResponse({ stats }))
          .catch(e => sendResponse({ stats: null, error: e.message }));
      } else {
        sendResponse({ stats: null, error: "Adaptive engine not loaded" });
      }
      return true;
    }

    case "sentinel:revoke-trust": {
      // Revokes user-trusted status for a domain (dashboard action)
      const { hostname: revokeHost } = message;
      if (!revokeHost) { sendResponse({ ok: false, error: "No hostname" }); return true; }

      const adaptiveEngRevoke = globalThis.SentinelAdaptiveEngine;
      if (adaptiveEngRevoke?.revokeTrust) {
        adaptiveEngRevoke.revokeTrust(revokeHost)
          .then(ok => {
            // Evict any cached result for this domain so next visit re-evaluates
            // Note: cache key includes full URL, not just hostname â€” we do a prefix purge
            sendResponse({ ok });
          })
          .catch(e => sendResponse({ ok: false, error: e.message }));
      } else {
        sendResponse({ ok: false, error: "Adaptive engine not loaded" });
      }
      return true;
    }

    case "sentinel:grant-trust": {
      // Manually grants user-trusted status to a domain (dashboard action)
      const { hostname: grantHost } = message;
      if (!grantHost) { sendResponse({ ok: false, error: "No hostname" }); return true; }

      const adaptiveEngGrant = globalThis.SentinelAdaptiveEngine;
      if (adaptiveEngGrant?.grantTrust) {
        adaptiveEngGrant.grantTrust(grantHost)
          .then(ok => sendResponse({ ok }))
          .catch(e => sendResponse({ ok: false, error: e.message }));
      } else {
        sendResponse({ ok: false, error: "Adaptive engine not loaded" });
      }
      return true;
    }

    case "sentinel:clear-history": {
      storageSet({ [CONFIG.KEYS.HISTORY]: [], [CONFIG.KEYS.LAST_ANALYSIS]: null })
        .then(() => sendResponse({ ok: true }))
        .catch(e => sendResponse({ ok: false, error: e.message }));
      return true;
    }

    // â”€â”€ Behavioral Detection Signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Sent by behaviorMonitor.js and content.js when in-page APIs are abused.
    // Risk accumulates per tab; high-risk events immediately trigger overlay.
    case "BEHAVIOR_ALERT": {
      const tabId = sender?.tab?.id;
      if (!tabId) { sendResponse({ ok: false, error: "No tab context" }); return true; }

      const { event = "unknown", severity = "low", url = "", details: alertDetails = {} } = message;
      let alertHost = "";
      try { alertHost = new URL(url || sender?.tab?.url || "").hostname.toLowerCase(); } catch {}
      const trustedEventDomain = isTrustedDomainHost(alertHost);

      // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
      // CLIPBOARD HIJACK SUPPRESSION (v3.0)
      // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
      let suppressionReason = null;
      let processingEvent = event;

      // Determine trust tier for clipboard validation
      let trustTier = "low"; // default: untrusted
      if (trustedEventDomain) {
        trustTier = "high"; // high-trust domains (google.com, .edu, .gov, etc.)
      }

      // Apply strict clipboard validation
      if (event === "clipboard_hijack" || event === "clipboard_write") {
        // For clipboard events, check if they should be suppressed
        // Get current accumulated signals on this tab to check for supporting evidence
        const currentRisk = TAB_BEHAVIOR_RISK.get(tabId) ?? 0;
        
        // If clipboard is the ONLY signal (risk < 20), suppress it for high-trust domains
        if (trustTier === "high" && currentRisk < 20) {
          suppressionReason = "Clipboard access detected but considered benign due to trusted domain";
          console.log(`[Sentinel] ðŸ›‘ Clipboard suppressed: ${suppressionReason}`);
          sendResponse({ ok: true, riskScore: TAB_BEHAVIOR_RISK.get(tabId) ?? 0, suppressed: true, reason: suppressionReason });
          return true;
        }

        // For low-trust domains, require supporting malicious signals
        if (trustTier === "low" && currentRisk < 15) {
          suppressionReason = "Clipboard access detected but no supporting malicious signals on low-trust domain";
          console.log(`[Sentinel] ðŸ›‘ Clipboard suppressed: ${suppressionReason}`);
          sendResponse({ ok: true, riskScore: TAB_BEHAVIOR_RISK.get(tabId) ?? 0, suppressed: true, reason: suppressionReason });
          return true;
        }
      }

      // Accumulate risk with event-aware weighting for realtime protection.
      const BASE_DELTA = { high: 30, medium: 15, low: 5 };
      const EVENT_BONUS = {
        auto_download: 20,
        hidden_download_anchor: 15,
        blob_download: 15,
        hidden_iframe: 12,
        clipboard_hijack: 15,  // Reduced from 18 â€” clipboard alone is not strong signal
        clipboard_write: 10,   // Reduced from 12 â€” requires supporting signals
        redirect_loop: 15,
        phishing_detected: 20,
        sensitive_data_entry: 20,
      };
      const rawDelta = (BASE_DELTA[severity] ?? 5) + (EVENT_BONUS[processingEvent] ?? 0);
      const delta = trustedEventDomain ? Math.max(1, Math.floor(rawDelta * 0.5)) : rawDelta;
      const prevRisk   = TAB_BEHAVIOR_RISK.get(tabId) ?? 0;
      const signalCount = Number((alertDetails && alertDetails.signalCount) || 1);
      const cappedDelta = signalCount <= 1 ? Math.min(30, delta) : delta;
      let newRisk = Math.min(100, prevRisk + cappedDelta);
      
      // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
      // MAXIMUM RISK CAP (v3.0)
      // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
      // Only allow risk > 40 if clipboard_hijack is accompanied by strong signals
      if (processingEvent === "clipboard_hijack" || processingEvent === "clipboard_write") {
        const otherSignals = [
          "phishing_detected",
          "hidden_iframe",
          "redirect_loop",
          "auto_download",
          "sensitive_data_entry"
        ];
        
        // Check if we have other strong signals in the behavioral history
        // (This is a simplified check â€” in production could maintain full signal list)
        const hasStrongSupport = newRisk >= 50; // If already at high risk from other signals
        
        if (!hasStrongSupport && newRisk > 40) {
          newRisk = 40; // Cap clipboard-only risk at 40
          console.log(`[Sentinel] ðŸ“Š Risk capped at 40: clipboard without strong supporting signals`);
        }
      }
      
      if (signalCount <= 1 && newRisk > 60) {
        newRisk = 60;
      }
      TAB_BEHAVIOR_RISK.set(tabId, newRisk);

      console.log(`[Sentinel] ðŸ” Behavior: ${processingEvent} (${severity}) tab=${tabId} risk=${newRisk}`);
      console.log(`[Sentinel AI] Signal: ${processingEvent}`);
      console.log(`[Sentinel AI] Trusted: ${trustedEventDomain}`);

      // Trigger overlay if: severity is high OR accumulated risk â‰¥ 30
      const shouldAlert = severity === "high" || newRisk >= 30;
      console.log(`[Sentinel AI] Action: ${shouldAlert ? "alerted" : "ignored"}`);
      if (shouldAlert) {
        const overlayStatus = newRisk >= 60 ? "suspicious" : "suspicious";

        const BEHAVIOR_MESSAGES = {
          suspicious_redirect:  "Page attempted an unexpected redirect",
          meta_refresh:         "Page used an instant meta-refresh redirect",
          pushstate_abuse:      "Page is rapidly manipulating browser history",
          clipboard_write:      "Page attempted to write to your clipboard",
          programmatic_copy:    "Page performed a silent clipboard copy",
          blob_download:        "Page initiated an automatic file download",
          hidden_download_anchor: "Page contains a hidden auto-download link",
          download_click:       "Page triggered an unsolicited file download",
          hidden_iframe:        "Page contains a suspicious hidden iframe",
          sensitive_data_entry: "Sensitive data entered on a risky domain",
          phishing_detected:    "Login form detected - verifying legitimacy...",
          auto_download:        "Automatic download behavior detected",
          clipboard_hijack:     "Potential clipboard hijack attempt detected",
          redirect_loop:        "Redirect loop behavior detected",
        };

        const overlayMsg = BEHAVIOR_MESSAGES[processingEvent] || `Suspicious behavior: ${processingEvent}`;
        const educationTip = severity === "high"
          ? "This behavior is a common indicator of a malicious page. Consider leaving immediately."
          : suppressionReason ? suppressionReason
          : "Multiple suspicious behaviors detected on this page.";

        const normalizedSignals = Array.from(new Set([
          processingEvent,
          processingEvent === "scam_content_detected" ? "scamContentDetected" : null,
        ].filter(Boolean)));

        const breakdown = {
          domainTrust: "Unverified",
          behavior: suppressionReason || overlayMsg,
          content: processingEvent === "scam_content_detected"
            ? `Scam keywords found: "${String(alertDetails?.keyword || "").slice(0, 80)}"`
            : processingEvent === "phishing_detected"
            ? "Phishing form traits found (password/OTP/CVV/fake login)"
            : "No strong content signals",
          technical: `Behavioral telemetry risk ${newRisk}/100`,
          aiReasoning: suppressionReason || "Behavior-only alert: AI URL model not required for this trigger",
        };
        const highPriority = processingEvent === "sensitive_data_entry" && newRisk >= 50;

        sendOverlayWithRetry(tabId, {
          type:         "sentinel:show-overlay",
          status:       overlayStatus,
          message:      highPriority ? `HIGH PRIORITY: ${overlayMsg}` : overlayMsg,
          trustScore:   null,
          educationTip,
          score:        parseFloat((newRisk / 10).toFixed(1)),
          finalScore:   newRisk,
          explanation:  suppressionReason || `${highPriority ? "High priority" : "Behavior"} alert: ${overlayMsg}`,
          breakdown,
          reasons: [
            `Signal: ${processingEvent}`,
            `Risk score: ${newRisk}/100`,
            severity === "high" ? "Immediate risk - high severity signal" : "Accumulated from multiple signals",
          ],
          riskSteps: [
            `Behavior event: ${processingEvent}`,
            `Severity: ${severity}`,
            `Accumulated tab risk: ${newRisk}/100`,
          ],
        });

        // Log behavioral threat to history
        if (url && url.startsWith("http")) {
          saveThreatHistory(url, {
            status:     overlayStatus,
            attackType: "BEHAVIORAL",
            confidence: newRisk,
            score:      parseFloat((newRisk / 10).toFixed(1)),
            finalRiskScore: newRisk,
            explanation: suppressionReason || `${highPriority ? "High priority" : "Behavior"} alert: ${overlayMsg}`,
            reasons:    [suppressionReason || overlayMsg, `Behavior: ${processingEvent}`],
            topReasons: [suppressionReason || overlayMsg, `Behavior: ${processingEvent}`, `Risk score: ${newRisk}/100`],
            signals:    normalizedSignals,
            sources:    [{ name: "Behavior Monitor", verdict: overlayStatus, triggered: true, detail: processingEvent }],
            breakdown,
            signalFlags: { scamContentDetected: event === "scam_content_detected" },
          }).catch(() => {});
        }
      }

      sendResponse({ ok: true, riskScore: newRisk });
      return true;
    }

    case "sentinel:get-tab-risk": {
      // Returns the current tab's accumulated behavior risk score (0â€“100)
      const riskTabId = sender?.tab?.id ?? message.tabId;
      sendResponse({ riskScore: TAB_BEHAVIOR_RISK.get(riskTabId) ?? 0 });
      return true;
    }


    case "NETWORK_ALERT": {
      const tabId = sender?.tab?.id;
      if (!tabId) { sendResponse({ ok: false, error: "No tab context" }); return true; }
      const reason = String(message.reason || "unknown");
      const mappedEvent = reason === "unknown-domain" ? "clipboard_hijack" : "auto_download";
      const prevRisk = TAB_BEHAVIOR_RISK.get(tabId) ?? 0;
      const newRisk = Math.min(100, prevRisk + (reason === "unknown-domain" ? 18 : 14));
      TAB_BEHAVIOR_RISK.set(tabId, newRisk);
      if (newRisk >= 30) {
        sendOverlayWithRetry(tabId, {
          type: "sentinel:show-overlay",
          status: "suspicious",
          message: mappedEvent === "auto_download"
            ? "Automatic download behavior detected"
            : "Potential clipboard/network hijack behavior detected",
          trustScore: null,
          finalScore: newRisk,
          reasons: [
            `Signal: ${mappedEvent}`,
            `Risk score: ${newRisk}/100`,
            "Realtime protection elevated this event",
          ],
          breakdown: {
            domainTrust: "Unverified",
            behavior: `Network event ${mappedEvent}`,
            content: "No direct page content signal",
            technical: String(message.url || "").slice(0, 140),
            aiReasoning: "Realtime protection event from network monitor",
          },
        });
      }
      sendResponse({ ok: true, riskScore: newRisk, event: mappedEvent });
      return true;
    }

    case "sentinel:mark-safe": {
      const domain = String(message.domain || "").toLowerCase().trim();
      if (!domain) { sendResponse({ ok: false, error: "No domain" }); return true; }
      storageGet([CONFIG.KEYS.SAFE_MARKS]).then((data) => {
        const list = Array.isArray(data[CONFIG.KEYS.SAFE_MARKS]) ? data[CONFIG.KEYS.SAFE_MARKS] : [];
        list.unshift({ domain, timestamp: Date.now(), userAction: "marked_safe" });
        return storageSet({ [CONFIG.KEYS.SAFE_MARKS]: list.slice(0, 500) });
      }).then(() => sendResponse({ ok: true }))
        .catch((e) => sendResponse({ ok: false, error: e.message }));
      return true;
    }
    default:
      return false;
  }
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 11b â€” THREAT INTELLIGENCE LOADER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Fetches threatIntel.json from the extension bundle and injects the data
 * into the detection engine's runtime store via loadThreatIntel().
 *
 * Called at SW initialization, onInstalled, and onStartup so the database
 * is always current even after service worker restarts.
 *
 * Also caches scam keywords to storage (sentinel_threat_intel_keywords)
 * so content.js can read them directly without a background round-trip.
 */
async function loadThreatIntelDB() {
  try {
    const url  = chrome.runtime.getURL("threatIntel.json");
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data   = await resp.json();

    // Inject into the synchronous detection engine
    const engine = globalThis.SentinelDetectionEngine;
    if (engine?.loadThreatIntel) {
      engine.loadThreatIntel(data);
    }
    const threatIntelService = globalThis.SentinelThreatIntelService;
    if (threatIntelService?.hydrate) {
      threatIntelService.hydrate(data);
    }

    // Cache scam keywords in storage for content.js consumption
    await storageSet({
      sentinel_threat_intel_keywords: Array.isArray(data.scamKeywords)
        ? data.scamKeywords : [],
      sentinel_threat_intel_ts: Date.now(),
    });

    console.log("[Sentinel] ðŸ—’ï¸ Threat intel loaded:",
      (data.phishingDomains?.length ?? 0), "domains,",
      (data.scamKeywords?.length    ?? 0), "keywords");
  } catch (e) {
    console.warn("[Sentinel] Threat intel load failed:", e?.message);
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 12 â€” SERVICE WORKER LIFECYCLE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


chrome.runtime.onInstalled.addListener((details) => {
  console.log("[Sentinel] ðŸš€ Extension installed/updated:", details.reason);
  // Load threat intel on install/update so new domains are available immediately
  loadThreatIntelDB();
  if (details.reason === "install") {
    storageSet({
      [CONFIG.KEYS.BYPASSES]:     {},
      [CONFIG.KEYS.HISTORY]:      [],
      [CONFIG.KEYS.LAST_ANALYSIS]: null,
      [CONFIG.KEYS.REPORTS]:      [],
      [CONFIG.KEYS.SAFE_MARKS]:   [],
      [CONFIG.KEYS.REPUTATION]:   {},
      [CONFIG.KEYS.USER_PROFILE]: {
        totalBypasses: 0,
        totalBlocked: 0,
        totalWarned: 0,
        sensitivityLevel: "normal",
        domains: {},
        lastUpdated: Date.now(),
      },
      [CONFIG.KEYS.SETTINGS]: {
        blockMalicious: true,
        warnSuspicious: true,
        version: "3.0.0",
      },
    }).catch(e => console.warn("[Sentinel] Init storage error:", e));
  }
});

chrome.runtime.onStartup.addListener(() => {
  console.log("[Sentinel] â° Service worker restarted â€” LRU cache cleared");
  loadThreatIntelDB(); // Refresh threat intel after SW restart
});

// Clean up in-memory behavior risk scores when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  TAB_BEHAVIOR_RISK.delete(tabId);
  redirectLoopTracker.delete(tabId);
});

// Load threat intel immediately on first SW initialization
loadThreatIntelDB();

console.log("[Sentinel] âœ… Service worker initialized v3.0.0 â€” Adaptive Intelligence Active");

