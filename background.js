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

try {
  importScripts("shared/sentinelResult.js");
} catch (e) {
  console.warn("[Sentinel] Failed to load shared/sentinelResult.js:", e?.message || e);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 1 â€” LOAD DETECTION ENGINE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// importScripts is the only valid way to load external scripts in a
// non-module MV3 service worker.
// CHANGED: Each script in its own try/catch so one failure doesn't block others
try { importScripts("trustedDomains.js"); } catch (e) {
  console.error("[Sentinel] Failed to load trustedDomains.js:", e && e.message ? e.message : e);
}
try { importScripts("maliciousDomains.js"); } catch (e) {
  console.error("[Sentinel] Failed to load maliciousDomains.js:", e && e.message ? e.message : e);
}
try { importScripts("shared/trustedDomains.js"); } catch (e) {
  console.warn("[Sentinel] shared/trustedDomains.js not found (optional)");
}
try { importScripts("shared/signals.js"); } catch (e) {
  console.warn("[Sentinel] shared/signals.js not found (optional)");
}

// CHANGED: Inline critical blocklist — always active regardless of file loading
const CRITICAL_BLOCKLIST = new Set([
  'neverssl.com',
  'expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com',
  'untrusted-root.badssl.com', 'revoked.badssl.com',
  'paypal-secure-login.net', 'amazon-security-alert.com',
  'microsoft-alert-security.com', 'apple-account-locked.net',
  'gooogle.com', 'micosoft.com', 'faceb00k.com', 'paypa1.com',
  'amaz0n.com', 'g00gle.com', 'netfl1x.com',
]);

function isHardBlocked(hostname) {
  if (!hostname) return false;
  const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
  if (CRITICAL_BLOCKLIST.has(h)) return true;
  // Check if maliciousDomains.js loaded its function
  if (typeof globalThis.isMaliciousDomain === 'function') {
    return globalThis.isMaliciousDomain(h);
  }
  return false;
}

try {
  importScripts("detectionEngine.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load detectionEngine.js:", e);
}

// CHANGED: Keepalive alarm to prevent SW sleep during analysis
chrome.alarms.create("sx-keepalive", { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "sx-keepalive") {
    // no-op; wakes the MV3 service worker so tab analysis stays responsive
  }
});

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

// Load SSL/TLS Certificate Analysis Engine
try {
  importScripts("sslDetector.js");
} catch (e) {
  console.error("[Sentinel] CRITICAL: Failed to load sslDetector.js:", e);
}

async function callAIAnalysis(data) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);
  try {
    console.log("[Sentinel AI] Calling AI with:", data);

    const response = await fetch("http://localhost:3000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`AI backend returned ${response.status}`);
    }

    const raw = await response.json();
    const result = {
      decision: typeof raw?.decision === "string" ? raw.decision : "unknown",
      reasoning: typeof raw?.reasoning === "string" ? raw.reasoning : "",
      confidence: typeof raw?.confidence === "number" ? clampScore(raw.confidence) : null,
    };
    console.log("[Sentinel AI] AI response:", result);

    return result;
  } catch (error) {
    console.warn("[Sentinel AI] AI unavailable:", error?.message || error);
    return null;
  } finally {
    clearTimeout(timeoutId);
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

// Singleton cache — persists as long as the service worker is alive
const urlCache = new LRUCache(CONFIG.CACHE_MAX_SIZE, CONFIG.CACHE_TTL_MS);
const tabAnalysisMap = new Map();
/** Tab IDs that requested a force-deep rescan (cleared when canonical is produced). */
const pendingRescanForceDeep = new Map();
// CHANGED: Ensure TAB_BEHAVIOR_RISK exists before any listener uses it
const TAB_BEHAVIOR_RISK = new Map();

// CHANGED: Retry sender for content script delivery (Part 1B)
function notifyContentScript(tabId, result, attempt) {
  attempt = attempt || 1;
  chrome.tabs.sendMessage(tabId, { type: 'ANALYSIS_COMPLETE', result: result }, function(response) {
    if (chrome.runtime.lastError) {
      if (attempt < 4) {
        var delay = [0, 300, 800, 2000][attempt] || 300;
        console.log("[Sentinel] Overlay delivery retry scheduled", { tabId: tabId, attempt: attempt, delayMs: delay }); // CHANGED: observability
        setTimeout(function() {
          notifyContentScript(tabId, result, attempt + 1);
        }, delay);
      } else {
        console.warn("[Sentinel] Fallback activated: executeScript overlay injection", { tabId: tabId }); // CHANGED: observability
        // CHANGED: Final fallback — inject overlay directly via scripting API
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: function(analysisResult) {
            if (window._sentinelShowOverlay) {
              window._sentinelShowOverlay(analysisResult);
            }
          },
          args: [result]
        }, function() {
          if (chrome.runtime.lastError) {
            console.warn('[SentinelX] executeScript fallback failed:', chrome.runtime.lastError.message);
          }
        });
      }
    }
  });
}

function tabAnalysisStorageKey(tabId) {
  return "tab_analysis_" + tabId;
}

function storeTabAnalysis(tabId, result) {
  if (!tabId || !result) return;
  const canonical = globalThis.normalizeSentinelResult
    ? globalThis.normalizeSentinelResult(result)
    : result;
  tabAnalysisMap.set(tabId, canonical);
  const key = "tab_analysis_" + tabId;
  const localKey = "sentinel_tab_" + tabId;
  chrome.storage.session.set({ [key]: canonical }, () => {
    if (chrome.runtime.lastError) {
      console.warn("[SX] session write failed:", chrome.runtime.lastError.message);
    }
  });
  chrome.storage.local.set({ [localKey]: canonical });

  // FIX 5B: Track scan history (last 20 entries)
  const historyEntry = {
    url: canonical.url || "",
    domain: canonical.domain || "",
    status: canonical.status || "suspicious",
    score: canonical.score || 0,
    confidence: canonical.confidence || 0,
    timestamp: Date.now()
  };
  
  chrome.storage.local.get("sentinel_history", (data) => {
    const history = Array.isArray(data.sentinel_history) ? data.sentinel_history : [];
    history.unshift(historyEntry);
    // Cap at 20 entries
    const cappedHistory = history.slice(0, 20);
    chrome.storage.local.set({ sentinel_history: cappedHistory });
  });

  // FIX 6C: Append SUSPICIOUS/MALICIOUS to incident log
  if (canonical.status === "suspicious" || canonical.status === "malicious") {
    const incidentEntry = {
      url: canonical.url || "",
      domain: canonical.domain || "",
      status: canonical.status,
      score: canonical.score || 0,
      signals: canonical.signals || [],
      timestamp: Date.now(),
      userAgent: navigator.userAgent || "unknown"
    };
    
    chrome.storage.local.get("sentinel_incidents", (data) => {
      const incidents = Array.isArray(data.sentinel_incidents) ? data.sentinel_incidents : [];
      incidents.unshift(incidentEntry);
      // Cap at 100 entries
      const cappedIncidents = incidents.slice(0, 100);
      chrome.storage.local.set({ sentinel_incidents: cappedIncidents });
    });
  }
}

function getTabAnalysis(tabId, callback) {
  const fromMap = tabAnalysisMap.get(tabId);
  if (fromMap) {
    callback(fromMap);
    return;
  }
  chrome.storage.session.get(["tab_analysis_" + tabId], (res) => {
    if (chrome.runtime.lastError) {
      callback(null);
      return;
    }
    const stored = res["tab_analysis_" + tabId] || null;
    if (stored) tabAnalysisMap.set(tabId, stored);
    callback(stored);
  });
}

function clearTabAnalysis(tabId) {
  tabAnalysisMap.delete(tabId);
  chrome.storage.session.remove("tab_analysis_" + tabId, () => {
    if (chrome.runtime.lastError) {
      // no-op
    }
  });
  try {
    chrome.storage.local.remove("sentinel_tab_" + tabId, () => void chrome.runtime.lastError);
  } catch (_) {}
}

function isAnalyzableTabUrl(url) {
  return /^https?:\/\//i.test(String(url || ""));
}

try {
  importScripts("report/threatReport.js");
} catch (e) {
  console.error("[Sentinel] Failed to load threat reporting module:", e);
}

function getPopupStatus(score) {
  const s = clampScore(score);
  if (s >= 100) return "blocked";
  if (s >= 60) return "danger";
  if (s >= 30) return "warn";
  return "safe";
}

function signalWeight(type) {
  const key = String(type || "").toLowerCase();
  if (key.includes("known_phishing") || key.includes("malware") || key.includes("credential")) return 40;
  if (key.includes("typosquat") || key.includes("ssl_invalid") || key.includes("clipboard")) return 30;
  if (key.includes("new_domain") || key.includes("bulletproof") || key.includes("redirect")) return 20;
  return 10;
}

function normalizeSignalForPopup(signal) {
  const metaRoot = typeof SIGNAL_META === "object" && SIGNAL_META ? SIGNAL_META : {};
  if (typeof signal === "string") {
    const meta = metaRoot[signal] || {};
    return {
      type: signal,
      name: meta.name || signal.replace(/_/g, " "),
      weight: signalWeight(signal),
      description: meta.description || "",
      category: meta.category || "reputation"
    };
  }
  const type = String(signal?.type || signal?.name || "signal");
  const meta = metaRoot[type] || {};
  return {
    type,
    name: String(signal?.name || meta.name || type).replace(/_/g, " "),
    weight: Number(signal?.weight || signal?.score || signal?.contribution || signalWeight(type)),
    description: String(signal?.description || meta.description || ""),
    category: String(signal?.category || meta.category || "reputation"),
    metadata: signal?.metadata || null,
    brand: signal?.brand || signal?.targetedBrand || null
  };
}

function normalizeSslStatus(rawUrl, result) {
  if (result?.ssl === "valid" || result?.ssl === "invalid") return result.ssl;
  if (result?.tlsInfo?.valid === true || result?.ssl === true) return "valid";
  if (result?.tlsInfo?.valid === false || result?.ssl === false) return "invalid";
  return String(rawUrl || "").startsWith("https:") ? "valid" : "invalid";
}

function generatePreventions(signals) {
  const advice = {
    typosquatting: "Check the real URL - a character may have been swapped",
    credential_form: "Do not enter any passwords or card numbers",
    clipboard_hijack: "Check your clipboard - it may have been tampered with",
    new_domain: "This domain was registered very recently - be extra cautious",
    ssl_invalid: "This site has no valid HTTPS - your data is not encrypted",
    known_phishing: "This URL is in a known phishing database",
    malware_host: "This server is a known malware distribution point",
    bulletproof_hosting: "Hosted on infrastructure used by criminal networks"
  };
  const out = [];
  for (const signal of Array.isArray(signals) ? signals : []) {
    const type = typeof signal === "string" ? signal : (signal?.type || signal?.name || "");
    const key = Object.keys(advice).find(k => String(type).toLowerCase().includes(k));
    if (key && !out.includes(advice[key])) out.push(advice[key]);
  }
  return out;
}

function generateSuggestions(signals) {
  const preventions = generatePreventions(signals);
  return preventions.length ? preventions : [
    "Verify the URL before entering sensitive data",
    "Use the official site from a trusted bookmark",
    "Report suspicious links to your security team"
  ];
}

function autoBlockTab(tabId, domain) {
  chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html?tab=" + tabId) }, () => {
    void chrome.runtime.lastError;
  });
  if (chrome.notifications && chrome.notifications.create) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "assets/icons/icon48.png",
      title: "SentinelX: Threat Blocked",
      message: "A dangerous site was automatically blocked: " + domain
    }, () => {
      void chrome.runtime.lastError;
    });
  }
}

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

function clampScore(s) {
  const n = Number(s);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function isTrustedDomainHost(hostname) {
  if (typeof globalThis.isTrustedDomain === "function") {
    return globalThis.isTrustedDomain(hostname);
  }
  return false;
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

/**
 * True when a behavior payload represents a browser-native permission prompt
 * (notifications, geolocation, etc.) — must not inflate TAB_BEHAVIOR_RISK alone.
 */
function isBrowserNativePermissionPromptSignal(message, event, alertDetails) {
  const details = alertDetails && typeof alertDetails === "object" ? alertDetails : {};
  const sig = message && typeof message.signal === "object" && message.signal !== null
    ? message.signal
    : null;
  if (sig && sig.type === "permission_prompt" && sig.source === "browser_native") {
    return true;
  }
  if (event === "permission_prompt" && (message.source === "browser_native" || details.source === "browser_native")) {
    return true;
  }
  if (details.type === "permission_prompt" && details.source === "browser_native") {
    return true;
  }
  return false;
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
  const list = Array.isArray(signals) ? signals : [];
  if (list.length >= 2) return true;

  const onlySignal = list[0];
  if (!onlySignal) return false;

  if (typeof onlySignal === "string") {
    return /dataset|threat|malware|phishing|credential|password|login|ssl|iframe|insecure/i.test(onlySignal);
  }

  const weight = Number(onlySignal.weight ?? onlySignal.score ?? 0);
  const confidence = Number(onlySignal.confidence ?? 0);
  return weight >= 0.7 || confidence >= 0.8;
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
  if (result.status === "malicious") return true;

  const risk = Number(result.finalRiskScore ?? result.finalRisk ?? result.risk ?? result.score ?? 0);
  const signals = Array.isArray(result.signals) ? result.signals : [];
  const confidence = Number(result.confidence ?? result.scoreConfidence ?? 1);

  if (risk >= 50) return true;
  if (risk >= 25 && signals.length > 0 && confidence >= 0.5) return true;
  return false;
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
  // CHANGED: Only suppress if EXPLICITLY in trusted domain list
  // Do NOT suppress based on trustScore alone — that kills legit overlays
  if (!result || result.status === "malicious") return false;
  const risk = Number(result.finalRiskScore ?? result.finalRisk ?? result.risk ?? result.score ?? 0);
  // Only suppress if hard-override trusted domain AND risk is near zero
  const isHardTrusted = result.appliedRule === "HARD_OVERRIDE_TRUSTED_DOMAIN" ||
    result.appliedRule === "WHITELIST_TRUSTED_DOMAIN" ||
    result.appliedRule === "HARD_OVERRIDE_SEARCH";
  return isHardTrusted && risk < 15;
}

/**
 * Cooldown system state: { lastAlertTime: number }
 * Prevents alert spam within 5-second windows.
 * 
 * @type {object}
 */
// CHANGED: Per-tab cooldown (same-alert burst suppression only)
// Suppresses repeated alerts for the *same key* within COOLDOWN_MS.
const TAB_COOLDOWN = new Map(); // tabId → { time: number, key: string }
const COOLDOWN_MS = 5000;

/**
 * Checks if alert cooldown is active.
 * Returns true if an alert was triggered within the last 5 seconds.
 * 
 * @returns {boolean}
 */
function isCooldownActive(tabId, key) {
  const entry = TAB_COOLDOWN.get(tabId) || { time: 0, key: "" };
  if (!key || entry.key !== key) return false;
  return Date.now() - entry.time < COOLDOWN_MS;
}

function setCooldown(tabId, key) {
  TAB_COOLDOWN.set(tabId, { time: Date.now(), key: String(key || "") });
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
function shouldShowAlert(result, tabId) {
  if (!result) return false;
  
  // Rule 1: Cooldown check
  // CHANGED: cooldown is keyed per-tab + per-alert-type, not global
  const riskNow = Number(result.finalRiskScore ?? result.finalRisk ?? result.risk ?? result.score ?? 0);
  const hostNow = String(result.domain || "").toLowerCase();
  const rootNow = hostNow ? getRootDomain(hostNow) : "";
  const cooldownKey = `suspicious:${rootNow}:${Math.floor(riskNow / 10)}`;
  if (isCooldownActive(tabId, cooldownKey)) {
    console.log("[Sentinel-AdaptiveGating] Cooldown active - alert suppressed");
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
    console.log("[Sentinel-AdaptiveGating] High-trust suppression applied");
    return false;
  }

  // Rule 4: Correlation requirement
  if (!hasCorrelation(result.signals)) {
    console.log("[Sentinel-AdaptiveGating] Low-correlation suppression applied");
    return false;
  }

  // Rule 5: All checks passed
  // CHANGED: tabId not available in shouldShowAlert — cooldown is set by caller
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

  // Check if root domain is trusted
  const rootDomain = getRootDomain(hostname);
  const isTrusted = typeof globalThis.isTrustedDomain === "function"
    ? globalThis.isTrustedDomain(rootDomain)
    : false;

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
  const baseRaw     = typeof result?.score === "number" ? clampScore(result.score) : 0;
  const aiRaw       = result?.aiDecision !== "safe" && typeof result?.aiScore === "number"
    ? clampScore(result.aiScore)
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

  const finalRiskScore = clampScore(weighted);
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

/** Low-confidence soft status: align with shared resolveStatus(score, signals, confidence). */
function softenSuspiciousWithResolveStatus(result) {
  if (!result || result.status !== "suspicious" || typeof globalThis.resolveStatus !== "function") return;
  const score = Math.round(Math.min(100, Math.max(0, Number(result.score) || 0)));
  let c = typeof result.confidence === "number"
    ? result.confidence
    : (typeof result.aiConfidence === "number" ? result.aiConfidence : 100);
  if (c > 0 && c <= 1) c = Math.round(c * 100);
  c = Math.min(100, Math.max(0, Math.round(c)));
  const rawSignals = Array.isArray(result.signals) ? result.signals : [];
  const reasonSignals = Array.isArray(result.reasons) ? result.reasons : [];
  const normalized = [...rawSignals, ...reasonSignals].map((s) =>
    typeof s === "string" ? { type: "signal", label: s } : s
  );
  if (globalThis.resolveStatus(score, normalized, c) === "uncertain") result.status = "uncertain";
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

  softenSuspiciousWithResolveStatus(out);

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
      score: clampScore(result.score || 0),
      finalRiskScore: clampScore(result.finalRiskScore || result.score || 0),
      trustScore: Number(result.trustScore || 100),
      confidence: Number(result.confidence || 0),
      aiReasoning: result.aiReasoning || null,
      aiScore: typeof result.aiScore === "number" ? clampScore(result.aiScore) : null,
      aiDecision: result.aiDecision || "unknown",
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
  (async () => {
    const redirectUrl = buildWarningURL(result, blockedUrl);
    const warningUrlObj = new URL(redirectUrl);
    const warningParams = warningUrlObj.searchParams;
    let domain = "";
    try { domain = new URL(blockedUrl).hostname; } catch {}

    // At the top of the block/redirect handler:
    const soundKey = `sx_sound_played_${domain}`;
    const alreadyPlayed = await chrome.storage.session.get(soundKey);

    if (!alreadyPlayed[soundKey]) {
      // Mark as played for this session
      await chrome.storage.session.set({ [soundKey]: true });
      // Pass sound=1 in the warning URL so warning.js knows to play
      warningParams.set('sound', '1');
    } else {
      // Already played for this domain this session — suppress
      warningParams.set('sound', '0');
    }

    chrome.tabs.update(tabId, { url: warningUrlObj.toString() }, () => {
      if (chrome.runtime.lastError) {
        console.error("[Sentinel] Tab update failed:", chrome.runtime.lastError.message);
      } else {
        console.log("[Sentinel] â›” Warning page shown for:", blockedUrl);
      }
    });
  })().catch((e) => {
    console.warn("[Sentinel] warning redirect sound throttle failed:", e?.message);
    const redirectUrl = buildWarningURL(result, blockedUrl);
    chrome.tabs.update(tabId, { url: redirectUrl }, () => void chrome.runtime.lastError);
  });
}

function buildWarningURL(result, originalURL) {
  const base = chrome.runtime.getURL("warning.html");
  let domain = "";
  try { domain = new URL(originalURL).hostname; } catch {}

  const signalStrings = (result?.signals || [])
    .filter((s) => {
      if (s && typeof s === "object") return s.type !== "trust" && (s.value || s.reason);
      return true;
    })
    .map((s) => String((s && typeof s === "object") ? (s.value || s.reason || s.type || "") : s))
    .filter(Boolean)
    .slice(0, 5);

  const params = new URLSearchParams({
    url: originalURL,
    score: String(result?.score ?? 0),
    status: result?.status ?? "malicious",
    confidence: String(result?.confidence ?? 0),
    domain,
    signals: signalStrings.join("|"),
    categories: (result?.signals || [])
      .filter((s) => s && typeof s === "object" && s.type === "category")
      .map((s) => s.value)
      .slice(0, 4)
      .join("|"),
    reasoning: (result?.reasons || []).slice(0, 2).join(" "),
  });
  return `${base}?${params.toString()}`;
}

function redirectToBlock(tabId, url, result) {
  if (!tabId) return;
  const warningUrl = buildWarningURL(result, url);
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) {
      console.error("[SX] redirect failed:", chrome.runtime.lastError?.message || "tab missing");
      return;
    }
    chrome.tabs.update(tabId, { url: warningUrl }, () => {
      if (chrome.runtime.lastError) {
        console.error("[SX] redirect failed:", chrome.runtime.lastError.message);
      }
    });
  });
}

function computeTrustLevel(result) {
  const score = result.score || 0;
  if (score >= 60) return "LOW";
  if (score >= 30) return "MEDIUM";
  return "HIGH";
}

function sendOverlayToTab(tabId, result, attempt = 0) {
  chrome.tabs.sendMessage(tabId, { type: "SENTINEL_SHOW_OVERLAY", data: result }, (resp) => {
    if (!chrome.runtime.lastError && resp && resp.ok) return;
    if (attempt < 4) {
      const delay = [500, 1000, 2000, 3000][attempt];
      setTimeout(() => sendOverlayToTab(tabId, result, attempt + 1), delay);
    }
  });
}

function finalizeAndRoute(tabId, rawUrl, result, startTime) {
  result.scanMs = Date.now() - startTime;
  result.url = rawUrl;
  result.domain = result.domain || (() => {
    try { return new URL(rawUrl).hostname; } catch { return ""; }
  })();
  result.score = Math.max(0, Math.min(100, Math.round(result.score || 0)));
  result.trustLevel = computeTrustLevel(result);

  // Ensure async enrichment is applied in-order before routing.
  applySensitivityAdjustments(result, () => {
    applyFalsePositiveAdjustment(result, () => {
      applyManagedPolicies(result, tabId, rawUrl);
    });
  });
}

// FIX 6D: Adjust detection thresholds based on sensitivity setting
function applySensitivityAdjustments(result, done) {
  chrome.storage.local.get("sentinel_sensitivity", (data) => {
    const sensitivity = data.sentinel_sensitivity || "medium"; // default: medium
    try {
      const engine = globalThis.SentinelDetectionEngine;
      if (engine && typeof engine.setSensitivityMode === "function") {
        engine.setSensitivityMode(sensitivity);
      }
    } catch {}
    
    // Adjust suspicious/malicious thresholds based on sensitivity
    if (sensitivity === "high") {
      // High sensitivity: lower thresholds, more alerts
      // score >= 15 → suspicious, score >= 80 → malicious (unchanged)
      if (result.score >= 15 && result.score < 30) {
        result.status = "suspicious";
      }
      result.confidenceThreshold = 0.80;
    } else if (sensitivity === "low") {
      // Low sensitivity: higher thresholds, fewer alerts
      // score >= 50 → suspicious, score >= 80 → malicious
      if (result.score >= 50 && result.score < 80) {
        result.status = "suspicious";
      } else if (result.score < 50) {
        result.status = "safe";
      }
      result.confidenceThreshold = 0.50;
    } else {
      // Medium sensitivity (default): current thresholds
      // score >= 30 → suspicious, score >= 80 → malicious
      result.confidenceThreshold = 0.65;
    }
    
    result.sensitivityMode = sensitivity;
    if (typeof done === "function") done();
  });
}

function applyFalsePositiveAdjustment(result, done) {
  const domain = String(result.domain || "").toLowerCase();
  if (!domain) {
    if (typeof done === "function") done();
    return;
  }
  const key = "fp_reports_" + domain;
  chrome.storage.local.get(key, (data) => {
    const count = Number(data[key] || 0);
    if (count >= 3) {
      result.score = Math.max(0, Number(result.score || 0) - 20);
      if (result.status === "malicious" && result.score < 80) {
        result.status = "suspicious";
      } else if (result.status === "suspicious" && result.score < 30) {
        result.status = "safe";
      }
      result.falsePositiveAdjustment = true;
      result.reason = [result.reason, "Score reduced by trusted-user false-positive feedback"]
        .filter(Boolean)
        .join("; ");
    }
    if (typeof done === "function") done();
  });
}

// FIX 6A: Check and apply managed storage policies for allowlist/blocklist
function applyManagedPolicies(result, tabId, rawUrl) {
  const domain = result.domain || "";
  if (!domain) {
    finalizeAndRouteAfterPolicies(tabId, rawUrl, result);
    return;
  }
  
  chrome.storage.managed.get(["sentinel_allowlist", "sentinel_blocklist"], (policies) => {
    const allowlist = Array.isArray(policies?.sentinel_allowlist) ? policies.sentinel_allowlist : [];
    const blocklist = Array.isArray(policies?.sentinel_blocklist) ? policies.sentinel_blocklist : [];
    
    const matchesPolicy = (entry) => domain === entry || domain.endsWith("." + entry);

    if (blocklist.some(matchesPolicy)) {
      result.status = "malicious";
      result.score = 100;
      result.reason = "Blocked by IT policy";
      result.appliedRule = "MANAGED_BLOCKLIST";
      result.managedByOrganization = true;
    } else if (allowlist.some(matchesPolicy)) {
      result.status = "safe";
      result.score = 0;
      result.reason = "Allowed by IT policy";
      result.appliedRule = "MANAGED_ALLOWLIST";
      result.managedByOrganization = true;
    }
    
    if (policies?.sentinel_allowlist || policies?.sentinel_blocklist) {
      result.policyBadge = "Managed by your organisation";
    }
    
    finalizeAndRouteAfterPolicies(tabId, rawUrl, result);
  });
}

// Continue with routing after policies are applied
function finalizeAndRouteAfterPolicies(tabId, rawUrl, result) {
  const wasForceDeepRescan = pendingRescanForceDeep.get(tabId) === true;
  if (wasForceDeepRescan) pendingRescanForceDeep.delete(tabId);

  softenSuspiciousWithResolveStatus(result);
  let canonical = globalThis.normalizeSentinelResult({
    ...result,
    url: rawUrl,
    timestamp: Date.now()
  });
  if (wasForceDeepRescan && canonical.confidence < 25) {
    canonical = { ...canonical, sxExtendedRescanLowConfidence: true };
  }

  storeTabAnalysis(tabId, canonical);
  chrome.storage.local.set({ "sentinel_last_report": canonical });

  if (canonical.status === "malicious") {
    sendOverlayToTab(tabId, canonical);
    setTimeout(() => {
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) return;
        const warnUrl = buildWarningURL(canonical, rawUrl);
        chrome.tabs.update(tabId, { url: warnUrl });
      });
    }, 3000);
    return;
  }

  sendOverlayToTab(tabId, canonical);
}

function runFullAnalysis(tabId, rawUrl, hostname, options = {}) {
  const domain = String(hostname || (() => {
    try { return new URL(rawUrl).hostname; } catch { return ""; }
  })()).toLowerCase();
  const now = Date.now();

  chrome.storage.local.get(["sentinel_bypasses", "sentinel_user_trust"], (res) => {
    const bypasses = res?.sentinel_bypasses || {};
    const userTrust = res?.sentinel_user_trust || {};
    const bypass = domain ? bypasses[domain] : null;
    const isBypassed = Boolean(bypass && bypass.expiresAt > now);
    const isUserTrusted = Boolean(domain && userTrust[domain]);

    if ((isBypassed || isUserTrusted) && !options.forceDeep) {
      pendingRescanForceDeep.delete(tabId);
      const safeResult = globalThis.normalizeSentinelResult({
        status: "safe",
        score: 0,
        confidence: 80,
        reasons: [
          isUserTrusted
            ? "You have marked this domain as safe."
            : "You chose to proceed past the security warning (bypass active for 30 minutes)."
        ],
        signals: ["user_override"],
        url: rawUrl,
        domain,
        timestamp: now
      });
      storeTabAnalysis(tabId, safeResult);
      chrome.storage.local.set({ "sentinel_last_report": safeResult });
      sendOverlayToTab(tabId, safeResult);
      return;
    }

    runFullAnalysisCore(tabId, rawUrl, hostname, options);
  });
}

/**
 * Re-run analysis for a tab (used by SENTINEL_RESCAN). Clears URL/tab caches
 * and optional legacy storage keys. When forceDeep is true, skips user
 * bypass / trust short-circuits so the engine runs a full scan.
 */
async function analyzeTab(tabId, url, options = {}) {
  if (!tabId || !url) return;
  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    throw new Error("invalid url");
  }
  const normUrl = normalizeCacheKey(url);
  if (!options.forceDeep) {
    try {
      const cachedData = await storageGet([`sentinel_result_${url}`, `sentinel_result_${normUrl}`]);
      const cached = cachedData[`sentinel_result_${url}`] || cachedData[`sentinel_result_${normUrl}`];
      if (cached && cached.cachedAt) {
        const age = Date.now() - cached.cachedAt;
        const ttl = cached.ttl || (5 * 60 * 1000); // default 5 min
        if (age < ttl) {
          const canonicalCached = globalThis.normalizeSentinelResult
            ? globalThis.normalizeSentinelResult({ ...cached, url, timestamp: Date.now() })
            : cached;
          storeTabAnalysis(tabId, canonicalCached);
          sendOverlayToTab(tabId, canonicalCached);
          return canonicalCached;
        }
      }
    } catch (_) {}
  }
  try {
    await chrome.storage.local.remove([
      `sentinel_result_${url}`,
      `sentinel_cache_${url}`,
      `sentinel_result_${normUrl}`,
      `sentinel_cache_${normUrl}`,
      `sx_result_${tabId}`,
    ]);
  } catch (_) {}
  try {
    urlCache.delete(normUrl);
  } catch (_) {}
  clearTabAnalysis(tabId);
  if (options.forceDeep) pendingRescanForceDeep.set(tabId, true);
  runFullAnalysis(tabId, url, hostname, options);
}

function runFullAnalysisCore(tabId, rawUrl, hostname, options = {}) {
  const startTime = Date.now();
  let result = null;

  try {
    const engine = globalThis.SentinelDetectionEngine;
    if (!engine || typeof engine.analyzeUrl !== "function") {
      console.error("[SX] DetectionEngine not available");
      pendingRescanForceDeep.delete(tabId);
      return;
    }
    result = engine.analyzeUrl(rawUrl, { forceDeep: Boolean(options && options.forceDeep) });
    // Cache high-reputation safe results for longer (24h) to avoid
    // unnecessary rescans that can surface transient uncertain states.
    if (
      typeof globalThis.isHighReputationDomain === "function" &&
      globalThis.isHighReputationDomain(rawUrl) &&
      result &&
      result.status === "safe"
    ) {
      const cacheKey = `sentinel_result_${rawUrl}`;
      storageSet({
        [cacheKey]: {
          ...result,
          cachedAt: Date.now(),
          ttl: 24 * 60 * 60 * 1000 // 24 hours
        }
      }).catch(() => {});
    }
  } catch (err) {
    console.error("[SX] analyzeUrl threw:", err);
    pendingRescanForceDeep.delete(tabId);
    return;
  }

  if (!result) {
    pendingRescanForceDeep.delete(tabId);
    return;
  }

  const continueWithResult = (finalResult) => {
    if (globalThis.SentinelAdaptiveEngine &&
        typeof globalThis.SentinelAdaptiveEngine.applyAdaptiveScoring === "function") {
      try {
        globalThis.SentinelAdaptiveEngine.applyAdaptiveScoring(finalResult, hostname)
          .then((adaptedResult) => {
            if (adaptedResult) finalResult = adaptedResult;
            finalizeAndRoute(tabId, rawUrl, finalResult, startTime);
          })
          .catch(() => { finalizeAndRoute(tabId, rawUrl, finalResult, startTime); });
      } catch {
        finalizeAndRoute(tabId, rawUrl, finalResult, startTime);
      }
    } else {
      finalizeAndRoute(tabId, rawUrl, finalResult, startTime);
    }
  };

  enrichScanWithPageContext(tabId, rawUrl, result)
    .then((enriched) => continueWithResult(enriched || result))
    .catch(() => continueWithResult(result));
}

async function enrichScanWithPageContext(tabId, url, existingResult) {
  try {
    const pageData = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({
        title: document.title,
        hasSSL: location.protocol === "https:",
        hasCanonical: !!document.querySelector('link[rel="canonical"]'),
        hasStructuredData: !!document.querySelector('script[type="application/ld+json"]'),
        metaDescription: document.querySelector('meta[name="description"]')?.content || "",
        hasContactPage: !!document.querySelector('a[href*="contact"]'),
        hasPolicyPage: !!document.querySelector('a[href*="privacy"], a[href*="terms"]'),
        knownPaymentRefs: ["razorpay", "payu", "ccavenue", "stripe", "paypal"]
          .filter(p => document.body.innerHTML.toLowerCase().includes(p)),
        hasProductSchema: document.body.innerHTML.includes('"Product"') ||
                          document.body.innerHTML.includes('"ItemList"'),
        hasReviewSchema: document.body.innerHTML.includes('"Review"') ||
                         document.body.innerHTML.includes('"AggregateRating"'),
      })
    });

    const ctx = pageData?.[0]?.result;
    if (!ctx) return existingResult;

    let confidenceBoost = 0;
    let scoreReduction = 0;
    if (ctx.hasSSL) confidenceBoost += 10;
    if (ctx.hasCanonical) confidenceBoost += 5;
    if (ctx.hasStructuredData) confidenceBoost += 8;
    if (ctx.hasPolicyPage) { confidenceBoost += 7; scoreReduction += 5; }
    if (ctx.hasContactPage) { confidenceBoost += 5; scoreReduction += 3; }
    if (ctx.knownPaymentRefs.length > 0) { confidenceBoost += 10; scoreReduction += 8; }
    if (ctx.hasProductSchema) { confidenceBoost += 8; scoreReduction += 5; }
    if (ctx.hasReviewSchema) { confidenceBoost += 5; scoreReduction += 3; }

    existingResult.confidence = Math.min(99, Number(existingResult.confidence || 0) + confidenceBoost);
    existingResult.score = Math.max(0, Number(existingResult.score || 0) - scoreReduction);
    existingResult._enrichedWithPageContext = true;
    existingResult._pageSignals = ctx;
    return existingResult;
  } catch (_) {
    return existingResult; // Fail gracefully
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


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
  // Legacy pipeline disabled in favor of canonical runFullAnalysis flow.
  return;
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

  console.log("[Sentinel] Analysis triggered:", { tabId, url: normalizedUrl }); // CHANGED: observability

  // ðŸ§  DEBUG: Log analysis start
  const analysisStartTime = Date.now();

  // â”€â”€ Step 3: Bypass check (FIRST â€” before any blocking logic) â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const bypassed = await isBypassed(normalizedUrl);
  if (bypassed) {
    console.log("[Sentinel] âœ… Bypassed (user-approved):", normalizedUrl);
    return;
  }

  // CHANGED: Hard block check (inline + maliciousDomains.js)
  let hardHost = '';
  try { hardHost = new URL(normalizedUrl).hostname.toLowerCase(); } catch {}
  if (isHardBlocked(hardHost)) {
    console.log('[Sentinel] 🚫 HARD BLOCKED:', hardHost); // CHANGED: observability
    const blockedResult = {
      score: 100,
      status: 'malicious',
      verdict: 'CRITICAL',
      domain: hardHost,
      url: normalizedUrl,
      signals: [{ label: 'Known malicious domain', weight: 100 }],
      reasons: ['Domain is in known malicious blocklist'],
      trustLevel: 'MALICIOUS',
      confidence: 99,
      source: 'blocklist'
    };
    const canonical = globalThis.normalizeSentinelResult({ ...blockedResult, url: rawUrl, timestamp: Date.now() });
    storeTabAnalysis(tabId, canonical);
    chrome.storage.local.set({ "sentinel_last_report": canonical });
    notifyContentScript(tabId, canonical, 1);
    redirectToWarningPage(tabId, rawUrl, blockedResult);
    saveThreatHistory(rawUrl, blockedResult).catch(() => {});
    return;
  }

  // â”€â”€ Step 4: LRU Cache check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const cached = urlCache.get(normalizedUrl);
  if (cached) {
    const canonical = globalThis.normalizeSentinelResult({ ...cached, url: rawUrl, timestamp: Date.now() });
    storeTabAnalysis(tabId, canonical);
    chrome.storage.local.set({ "sentinel_last_report": canonical });
    // CHANGED: Notify content script (retry) so overlay can appear without clicks
    notifyContentScript(tabId, canonical, 1);
    if (canonical.score >= 100) {
      autoBlockTab(tabId, canonical.domain);
      return;
    }
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
    result.aiScore = null;
    result.aiDecision = "unknown";
    result.aiReasoning = "";

    // AI layer: fail-open. If unavailable, keep aiScore null and do not change verdict.
    const aiResult = await callAIAnalysis({
      url: normalizedUrl,
      signals: result.signals || [],
      score: result.score,
      confidence: result.confidence,
      reasons: result.reasons || []
    });

    if (aiResult && typeof aiResult.confidence === "number") {
      result.aiScore = clampScore(aiResult.confidence);
      result.aiConfidence = result.aiScore;
      result.aiDecision = aiResult.decision ?? "unknown";
      result.aiReasoning = aiResult.reasoning ?? "";

      // Optional override logic
      if (result.aiDecision === "malicious") {
        result.status = "malicious";
      } else if (result.aiDecision === "suspicious" && result.status === "safe") {
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
  softenSuspiciousWithResolveStatus(result);
  const canonical = globalThis.normalizeSentinelResult({ ...result, url: rawUrl, timestamp: Date.now() });
  storeTabAnalysis(tabId, canonical);
  chrome.storage.local.set({ "sentinel_last_report": canonical });
  
  // CHANGED: Notify content.js with retry logic after storing analysis
  notifyContentScript(tabId, canonical, 1);

  if (canonical.score >= 100) {
    autoBlockTab(tabId, canonical.domain);
  }

  // â”€â”€ Step 8: Route based on FINAL verdict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (result.status === "malicious") {
    // CHANGED: MALICIOUS must never be suppressed by cooldown
    console.log("[Sentinel] ðŸš« BLOCKING:", normalizedUrl);
    redirectToWarningPage(tabId, rawUrl, result);
    saveThreatHistory(rawUrl, result).catch(e => console.warn("[Sentinel] History save error:", e));

    // Update v3.0 reputation (non-blocking)
    if (adaptiveEngine && hostname) {
      adaptiveEngine.updateDomainReputationV3(hostname, "malicious").catch(() => {});
      adaptiveEngine.updateUserProfile(hostname, "blocked").catch(() => {});
    }

  } else if (result.status === "suspicious") {
    // âœ¨ NEW: Apply adaptive alert gating (v3.1)
    // Combines: risk scoring, signal correlation, trust awareness, cooldown
    const adaptiveDecision = shouldShowAlert(result, tabId);
    
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

    // CHANGED: per-tab cooldown keyed to this alert type + band
    const cdHost = String(result.domain || hostname || "").toLowerCase();
    const cdRoot = cdHost ? getRootDomain(cdHost) : "";
    const cdRisk = Number(result.finalRiskScore ?? result.score ?? 0);
    setCooldown(tabId, `suspicious:${cdRoot}:${Math.floor(cdRisk / 10)}`);
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

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  const rawUrl = details.url;
  if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) return;

  let hostname = "";
  try { hostname = new URL(rawUrl).hostname.toLowerCase(); } catch { return; }

  // Hard blocklist — instant block, no analysis needed
  if (typeof isHardBlocked === "function" && isHardBlocked(hostname)) {
    const result = {
      score: 100, status: "malicious", domain: hostname, url: rawUrl,
      reasons: ["Domain is on the SentinelX hard blocklist"],
      signals: [{ name: "hard_blocklist", weight: 100,
        description: "Exact match in known-malicious domain database" }],
      trustLevel: "LOW", aiConfidence: 99
    };
    storeTabAnalysis(tabId, result);
    redirectToBlock(tabId, rawUrl, result);
    return;
  }

  // Trusted domain — skip full analysis, mark safe
  if (typeof globalThis.isTrustedDomain === "function" && globalThis.isTrustedDomain(hostname)) {
    const result = {
      score: 5, status: "safe", domain: hostname, url: rawUrl,
      reasons: ["Domain is on SentinelX trusted whitelist"],
      signals: [], trustLevel: "HIGH", aiConfidence: 98, scanMs: 0
    };
    storeTabAnalysis(tabId, result);
    return;
  }

  // Bypass check
  if (typeof isBypassed === "function") {
    isBypassed(rawUrl).then((bypassed) => {
      if (bypassed) return;
      runFullAnalysis(tabId, rawUrl, hostname);
    }).catch(() => {
      runFullAnalysis(tabId, rawUrl, hostname);
    });
  } else {
    runFullAnalysis(tabId, rawUrl, hostname);
  }
});

// CHANGED: SPA navigation support (React/Vue/Angular) — re-analyze on history updates
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  try {
    if (!details || details.frameId !== 0) return;
    if (!details.tabId || !details.url) return;
    if (!/^https?:\/\//i.test(details.url)) return;
    const extensionOrigin = chrome.runtime.getURL("");
    if (details.url.startsWith(extensionOrigin)) return;
    // CHANGED: Fire a non-blocking re-analysis; rely on internal dedupe
    runFullAnalysis(
      details.tabId,
      details.url,
      (() => { try { return new URL(details.url).hostname; } catch { return ""; } })()
    );
  } catch (e) {
    // fail-open
  }
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 10b â€” LEGACY REPUTATION (DEPRECATED â€” v3.0 uses adaptiveEngine)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function analyzeTabUrl(tabId, url, options = {}) {
  runFullAnalysis(
    tabId,
    url,
    (() => { try { return new URL(url).hostname; } catch { return ""; } })()
  );
  return null;

  if (!Number.isInteger(tabId) || !isAnalyzableTabUrl(url)) return null;

  const rawUrl = url;
  const normalizedUrl = normalizeCacheKey(rawUrl);
  const startTime = Date.now();

  if (!options.force && isDuplicate(tabId, normalizedUrl)) {
    return tabAnalysisMap.get(tabId) || null;
  }

  try {
    const bypassed = await isBypassed(normalizedUrl);
    if (bypassed) return null;

    let result = urlCache.get(normalizedUrl);
    if (!result) {
      const engine = globalThis.SentinelDetectionEngine;
      if (!engine || typeof engine.analyzeUrl !== "function") {
        console.error("[SentinelX] Detection engine unavailable");
        return null;
      }

      result = engine.analyzeUrl(normalizedUrl);
      result.aiScore = null;
      result.aiDecision = "unknown";
      result.aiReasoning = "";

      const aiResult = await callAIAnalysis({
        url: normalizedUrl,
        signals: result.signals || [],
        score: result.score,
        confidence: result.confidence,
        reasons: result.reasons || []
      });

      if (aiResult && typeof aiResult.confidence === "number") {
        result.aiScore = clampScore(aiResult.confidence);
        result.aiConfidence = result.aiScore;
        result.aiDecision = aiResult.decision ?? "unknown";
        result.aiReasoning = aiResult.reasoning ?? "";
        if (result.aiDecision === "malicious") {
          result.status = "malicious";
        } else if (result.aiDecision === "suspicious" && result.status === "safe") {
          result.status = "suspicious";
        }
      }

      try {
        const sslSignals = consumeSSLSignals(normalizedUrl, tabId);
        if (sslSignals.length > 0) {
          result.signals = [...new Set([...(result.signals || []), ...sslSignals])];
          const criticalSSL = ["invalid_ssl", "expired_cert", "domain_mismatch"];
          if (sslSignals.some(s => criticalSSL.includes(s)) && result.status === "safe") {
            result.status = "suspicious";
          }
        }
      } catch (sslErr) {
        console.warn("[SentinelX] SSL analysis failed:", sslErr?.message);
      }

      let hostname = "";
      try { hostname = new URL(normalizedUrl).hostname; } catch {}
      const adaptiveEngine = globalThis.SentinelAdaptiveEngine;
      if (adaptiveEngine && hostname) {
        try {
          result = await adaptiveEngine.applyAdaptiveScoring(result, hostname);
        } catch (adaptiveErr) {
          console.warn("[SentinelX] Adaptive scoring failed:", adaptiveErr?.message);
        }
      }

      result = await applyAdvancedScoring(result, normalizedUrl, tabId);
      urlCache.set(normalizedUrl, result);
    }

    const canonical = globalThis.normalizeSentinelResult({ ...result, url: rawUrl, timestamp: Date.now() });
    if (options.onDemand) canonical.onDemand = true;
    storeTabAnalysis(tabId, canonical);
    chrome.storage.local.set({ "sentinel_last_report": canonical });
    // CHANGED: Notify content script (retry) so overlay can appear without clicks
    notifyContentScript(tabId, canonical, 1);

    if (canonical.score >= 100) {
      chrome.tabs.update(tabId, {
        url: buildWarningURL(canonical, rawUrl)
      }, () => {
        if (chrome.runtime.lastError) {
          console.warn("[SentinelX] warning redirect failed:", chrome.runtime.lastError.message);
        }
      });
      return canonical;
    }
    return canonical;
  } catch (err) {
    console.error("[SentinelX] analyzeTabUrl failed for", rawUrl, err);
    return null;
  }
}

// updateDomainReputation() wrote the old v2.1 schema { suspicious, malicious }.
// v3.0 uses updateDomainReputationV3() from adaptiveEngine.js which writes the
// correct { suspiciousHits, maliciousHits, bypassCount } schema with time-decay.
// The old function is intentionally removed to prevent schema conflicts.

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CHANGED: Legacy onCompleted overlay delivery removed.
// Overlay delivery on navigation is now via notifyContentScript() (ANALYSIS_COMPLETE)
// and content.js self-fetch fallback.

// CHANGED: Keep a minimal retry helper for legacy overlay senders (behavior alerts, etc.)
function sendOverlayWithRetry(tabId, payload, attempt) {
  attempt = attempt || 1;
  chrome.tabs.sendMessage(tabId, payload, function() {
    if (chrome.runtime.lastError) {
      if (attempt < 4) {
        var delay = attempt === 1 ? 300 : attempt === 2 ? 800 : 2000;
        setTimeout(function() {
          sendOverlayWithRetry(tabId, payload, attempt + 1);
        }, delay);
      }
    }
  });
}
// SECTION 11 â€” MESSAGE HANDLER

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (!message || typeof message !== "object") return false;

    if (typeof message.action === "string") {
      switch (message.action) {
        case "SENTINEL_RESCAN": {
          const tabId = sender?.tab?.id ?? message.tabId;
          const url = sender?.tab?.url ?? message.url;
          if (!tabId || !url || !/^https?:\/\//i.test(String(url))) {
            sendResponse({ ok: false, error: "missing tab or url" });
            return true;
          }
          (async () => {
            try {
              await chrome.tabs
                .sendMessage(tabId, {
                  action: "SENTINEL_SCANNING",
                  text: message.text || "Rescanning page…",
                })
                .catch(() => {});
              await analyzeTab(tabId, url, { forceDeep: Boolean(message.forceDeep) });
              sendResponse({ ok: true });
            } catch (e) {
              sendResponse({
                ok: false,
                error: e && e.message ? e.message : String(e),
              });
            }
          })();
          return true;
        }
        default:
          break;
      }
    }

    if (typeof message.type !== "string") return false;

    switch (message.type) {

      case "GET_CURRENT_TAB_ID": {
        sendResponse({ tabId: sender?.tab?.id ?? null });
        return true;
      }

      case "GET_TAB_ANALYSIS": {
        getTabAnalysis(message.tabId, (result) => {
          if (!result) {
            sendResponse(null);
            return;
          }
          const canonical = globalThis.normalizeSentinelResult
            ? globalThis.normalizeSentinelResult(result)
            : result;
          sendResponse(canonical);
        });
        return true;
      }

      case "TRIGGER_ANALYSIS": {
        if (!message.tabId || !message.url) {
          sendResponse({ error: "missing params" });
          return true;
        }
        runFullAnalysis(message.tabId, message.url,
          (() => { try { return new URL(message.url).hostname; } catch { return ""; } })()
        );
        setTimeout(() => {
          getTabAnalysis(message.tabId, (r) => {
            if (!r) { sendResponse(null); return; }
            const canonical = globalThis.normalizeSentinelResult
              ? globalThis.normalizeSentinelResult(r)
              : r;
            sendResponse(canonical);
          });
        }, 1200);
        return true;
      }

      case "FORCE_BLOCK": {
        const forcedResult = {
          status: "malicious",
          score: 100,
          confidence: 95,
          reasons: ["Manual force block requested"],
          signals: [{ type: "category", value: "manual_block" }],
        };
        chrome.tabs.update(message.tabId, { url: buildWarningURL(forcedResult, message.url || "") }, () => {
          void chrome.runtime.lastError;
          sendResponse({ ok: true });
        });
        return true;
      }

      case "GENERATE_THREAT_REPORT": {
        if (typeof generateThreatReport !== "function") {
          sendResponse({ ok: false, error: "Threat reporting unavailable" });
          return true;
        }
        (async () => {
          try {
            const report = await generateThreatReport(message.tabId, Boolean(message.exportHtml));
            sendResponse({ ok: true, reportId: report.reportId, report });
          } catch (e) {
            sendResponse({ ok: false, error: e?.message || "Report generation failed" });
          }
        })();
        return true;
      }

      case "sentinel:open-dashboard": {
        chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") }, () => {
          void chrome.runtime.lastError;
          sendResponse({ ok: true });
        });
        return true;
      }

      case "sentinel:bypass-url": {
        if (!message.url) { sendResponse({ ok: false, error: "No URL" }); return true; }

        try {
          // v3.0: Update user profile + reputation concurrently with bypass registration
          const bypassUrl = message.url;
          let bypassHostname = "";
          try { bypassHostname = new URL(bypassUrl).hostname; } catch {}

          const adaptiveEng = globalThis && globalThis.SentinelAdaptiveEngine;

          registerBypass(bypassUrl)
            .then(() => {
              try {
                // Non-blocking: update user behavior profile and domain reputation
                if (adaptiveEng && bypassHostname && typeof adaptiveEng.updateUserProfile === "function") {
                  adaptiveEng.updateUserProfile(bypassHostname, "bypass").catch(() => {});
                }
                if (adaptiveEng && bypassHostname && typeof adaptiveEng.updateDomainReputationV3 === "function") {
                  adaptiveEng.updateDomainReputationV3(bypassHostname, "bypass").catch(() => {});
                }
              } catch (e) {
                console.warn("[Sentinel] Adaptive update failed:", e);
              }
              sendResponse({ ok: true });
            })
            .catch(e => {
              console.error("[Sentinel] Bypass registration failed:", e);
              sendResponse({ ok: false, error: e?.message || "Bypass failed" });
            });
        } catch (e) {
          console.error("[Sentinel] Bypass handler error:", e);
          sendResponse({ ok: false, error: e?.message || "Unknown error" });
        }
        return true;
      }

      case "sentinel:get-analysis": {
        try {
          const senderTabId = sender?.tab?.id;
          const tabResult = Number.isInteger(senderTabId) ? tabAnalysisMap.get(senderTabId) : null;
          sendResponse({ result: tabResult || null });
        } catch (e) {
          console.error("[Sentinel] get-analysis handler error:", e);
          sendResponse({ result: null, error: e?.message || "Unknown error" });
        }
        return true;
      }

      case "sentinel:get-history": {
        try {
          storageGet([CONFIG.KEYS.HISTORY])
            .then(data => {
              try {
                sendResponse({ history: (data && data[CONFIG.KEYS.HISTORY]) || [] });
              } catch (e) {
                console.error("[Sentinel] Error in get-history response:", e);
                sendResponse({ history: [], error: "Response failed" });
              }
            })
            .catch(e => {
              console.error("[Sentinel] get-history failed:", e);
              sendResponse({ history: [], error: e?.message || "Storage read failed" });
            });
        } catch (e) {
          console.error("[Sentinel] get-history handler error:", e);
          sendResponse({ history: [], error: e?.message || "Unknown error" });
        }
        return true;
      }

      case "sentinel:get-reputation": {
        try {
          storageGet([CONFIG.KEYS.REPUTATION])
            .then(data => {
              try {
                sendResponse({ reputation: (data && data[CONFIG.KEYS.REPUTATION]) || {} });
              } catch (e) {
                console.error("[Sentinel] Error in get-reputation response:", e);
                sendResponse({ reputation: {}, error: "Response failed" });
              }
            })
            .catch(e => {
              console.error("[Sentinel] get-reputation failed:", e);
              sendResponse({ reputation: {}, error: e?.message || "Storage read failed" });
            });
        } catch (e) {
          console.error("[Sentinel] get-reputation handler error:", e);
          sendResponse({ reputation: {}, error: e?.message || "Unknown error" });
        }
        return true;
      }

      case "sentinel:get-user-profile": {
        try {
          // Returns the full sentinel_user_profile for the dashboard
          storageGet([CONFIG.KEYS.USER_PROFILE])
            .then(data => {
              try {
                sendResponse({ profile: (data && data[CONFIG.KEYS.USER_PROFILE]) || null });
              } catch (e) {
                console.error("[Sentinel] Error in get-user-profile response:", e);
                sendResponse({ profile: null, error: "Response failed" });
              }
            })
            .catch(e => {
              console.error("[Sentinel] get-user-profile failed:", e);
              sendResponse({ profile: null, error: e?.message || "Storage read failed" });
            });
        } catch (e) {
          console.error("[Sentinel] get-user-profile handler error:", e);
          sendResponse({ profile: null, error: e?.message || "Unknown error" });
        }
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

      // Native browser prompts are not inherently malicious
      if (isBrowserNativePermissionPromptSignal(message, event, alertDetails)) {
        console.log("[Sentinel] Skipping threat score for browser-native permission prompt");
        sendResponse({
          ok: true,
          riskScore: TAB_BEHAVIOR_RISK.get(tabId) ?? 0,
          suppressed: true,
          reason: "Native browser permission prompts are not scored as threats",
        });
        return true;
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

    case "SENTINEL_LEAVE_SITE": {
      chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" });
      return true;
    }

    case "SENTINEL_OPEN_REPORT": {
      const tabId = sender?.tab?.id;
      const query = Number.isFinite(tabId) ? `?tabId=${tabId}` : "";
      chrome.tabs.create({
        url: chrome.runtime.getURL(`report/report.html${query}`)
      });
      return true;
    }

    case "SENTINEL_BYPASS": {
      (async () => {
        try {
          const { url, bypassType } = message || {};
          if (!url) {
            sendResponse({ ok: false, error: "Missing url" });
            return;
          }

          // Log the bypass with type for audit history
          const history = await chrome.storage.local.get("sx_bypass_history");
          const log = history.sx_bypass_history || [];
          log.unshift({
            url,
            bypassType,     // 'warned' or 'direct'
            timestamp: Date.now(),
            score: message.score || 0
          });
          // Keep last 100 bypass events
          await chrome.storage.local.set({
            sx_bypass_history: log.slice(0, 100)
          });

          // Add to session whitelist so the page loads on redirect
          const session = await chrome.storage.session.get("sx_session_bypass");
          const bypassed = session.sx_session_bypass || [];
          bypassed.push(url);
          await chrome.storage.session.set({ sx_session_bypass: bypassed });

          // Keep per-domain bypass count for warning page history badge
          let bypassDomain = "";
          try { bypassDomain = new URL(url).hostname; } catch {}
          if (bypassDomain) {
            const countData = await chrome.storage.local.get("sx_bypass_counts");
            const counts = countData.sx_bypass_counts || {};
            counts[bypassDomain] = Number(counts[bypassDomain] || 0) + 1;
            await chrome.storage.local.set({ sx_bypass_counts: counts });
          }

          sendResponse({ ok: true });
        } catch (e) {
          sendResponse({ ok: false, error: e?.message || "Bypass failed" });
        }
      })();
      return true;
    }

    case "SENTINEL_MARK_SAFE": {
      const { domain: safeDomain, timestamp: safeTs } = message;
      if (!safeDomain) {
        sendResponse({ ok: false, error: "Missing domain" });
        return true;
      }
      chrome.storage.local.get(["sentinel_user_trust"], (res) => {
        const trust = res.sentinel_user_trust || {};
        trust[safeDomain] = { markedAt: safeTs, source: "user" };
        chrome.storage.local.set({ sentinel_user_trust: trust });
      });
      chrome.storage.local.get(["sentinel_fp_log"], (res) => {
        const log = res.sentinel_fp_log || [];
        log.push({ domain: safeDomain, url: message.url, timestamp: safeTs });
        chrome.storage.local.set({ sentinel_fp_log: log.slice(-50) }, () => {
          sendResponse({ ok: true });
        });
      });
      return true;
    }

    case "SENTINEL_REPORT_SITE": {
      const { domain: rDomain, url: rUrl, score: rScore, timestamp: rTs } = message;
      chrome.storage.local.get(["sentinel_reports"], (res) => {
        const reports = res.sentinel_reports || [];
        reports.push({ domain: rDomain, url: rUrl, score: rScore, timestamp: rTs });
        chrome.storage.local.set({ sentinel_reports: reports.slice(-100) }, () => {
          sendResponse({ ok: true });
        });
      });
      return true;
    }

    case "GET_BYPASS_COUNT": {
      const domain = String(message.domain || "").toLowerCase();
      if (!domain) {
        sendResponse({ count: 0 });
        return true;
      }
      chrome.storage.local.get("sx_bypass_counts", (res) => {
        const counts = res.sx_bypass_counts || {};
        sendResponse({ count: Number(counts[domain] || 0) });
      });
      return true;
    }

    case "SENTINEL_REPORT_FALSE_POSITIVE": {
      // FIX 5A: Increment false positive count for domain
      const domain = String(message.domain || "").toLowerCase().trim();
      if (domain) {
        const fpKey = "fp_reports_" + domain;
        chrome.storage.local.get(fpKey, (data) => {
          const nextCount = Number(data[fpKey] || 0) + 1;
          chrome.storage.local.set({ [fpKey]: nextCount });

          // If count >= 3, lower domain score next analysis
          if (nextCount >= 3) {
            console.log(`[Sentinel] Domain ${domain} marked as safe (3+ reports)`);
          }
        });
      }
      return true;
    }

    case "sentinel:get-scan-history": {
      // FIX 5B: Return last 20 scans for popup history view
      chrome.storage.local.get("sentinel_history", (data) => {
        sendResponse({ history: data.sentinel_history || [] });
      });
      return true;
    }

    case "sentinel:get-incidents": {
      // FIX 6C: Return incident log (last 10 SUSPICIOUS/MALICIOUS hits)
      chrome.storage.local.get("sentinel_incidents", (data) => {
        const incidents = data.sentinel_incidents || [];
        sendResponse({ incidents: incidents.slice(0, 10) });
      });
      return true;
    }

    case "sentinel:set-sensitivity": {
      // FIX 6D: Save sensitivity mode (low / medium / high)
      const mode = message.mode || "medium";
      chrome.storage.local.set({ sentinel_sensitivity: mode });
      sendResponse({ ok: true });
      return true;
    }

    case "sentinel:get-admin-stats": {
      // FIX 6E: Return admin stats for popup badge (today's counts)
      const today = new Date().toDateString();
      chrome.storage.local.get(["sentinel_history", "sentinel_incidents"], (data) => {
        const history = data.sentinel_history || [];
        const incidents = data.sentinel_incidents || [];
        
        const todayScans = history.filter(h => new Date(h.timestamp).toDateString() === today);
        const todayThreats = incidents.filter(i => new Date(i.timestamp).toDateString() === today);
        
        sendResponse({
          scans: todayScans.length,
          threats: todayThreats.length,
          incidents: incidents.length
        });
      });
      return true;
    }

    default:
      return false;
  }
} catch (e) {
  console.error("[Sentinel] Message handler error:", e);
  try {
    sendResponse({ ok: false, error: e?.message || "Handler error" });
  } catch {}
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
  // CHANGED: Keepalive alarm so SW does not sleep mid-analysis (Part 1D)
  chrome.alarms.create("sx-keepalive", { periodInMinutes: 0.4 });
  // Load threat intel on install/update so new domains are available immediately
  loadThreatIntelDB();
  chrome.tabs.query({}, (tabs) => {
    if (chrome.runtime.lastError) return;
    tabs.forEach(tab => {
      if (!tab || !isAnalyzableTabUrl(tab.url)) return;
      setTimeout(() => {
        runFullAnalysis(
          tab.id,
          tab.url,
          (() => { try { return new URL(tab.url).hostname; } catch { return ""; } })()
        );
      }, 500);
    });
  });
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
  // CHANGED: Keepalive alarm so SW does not sleep mid-analysis (Part 1D)
  chrome.alarms.create("sx-keepalive", { periodInMinutes: 0.4 });
  loadThreatIntelDB(); // Refresh threat intel after SW restart
  // CHANGED: Reload recovery — analyze existing tabs after SW restart
  chrome.tabs.query({}, (tabs) => {
    if (chrome.runtime.lastError) return;
    (tabs || []).forEach((tab) => {
      if (!tab || !isAnalyzableTabUrl(tab.url)) return;
      setTimeout(() => {
        runFullAnalysis(
          tab.id,
          tab.url,
          (() => { try { return new URL(tab.url).hostname; } catch { return ""; } })()
        );
      }, 500);
    });
  });
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab || !tab.url) return;
    if (!/^https?:\/\//i.test(tab.url)) return;
    getTabAnalysis(tabId, (existing) => {
      if (existing) return;
      runFullAnalysis(tabId, tab.url,
        (() => { try { return new URL(tab.url).hostname; } catch { return ""; } })()
      );
    });
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !/^https?:\/\//i.test(tab.url)) return;

  getTabAnalysis(tabId, (existing) => {
    if (existing && existing.url === tab.url) return;
    runFullAnalysis(tabId, tab.url,
      (() => { try { return new URL(tab.url).hostname; } catch { return ""; } })()
    );
  });
});

// Clean up in-memory behavior risk scores when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  TAB_BEHAVIOR_RISK.delete(tabId);
  redirectLoopTracker.delete(tabId);
  clearTabAnalysis(tabId);
  TAB_COOLDOWN.delete(tabId); // CHANGED: cleanup per-tab cooldown
});
// Load threat intel immediately on first SW initialization
function initSentinel() {
  console.log("[Sentinel] Detection started");
  loadThreatIntelDB();
  console.log("[Sentinel] Service worker initialized");
}

try {
  initSentinel();
} catch (err) {
  console.error("[Sentinel Fatal Error]", err);
}

