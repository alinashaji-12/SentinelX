/**
 * warning.js â€” Sentinel Browse Extension v2.0
 *
 * WARNING PAGE CONTROLLER
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 *
 * DATA LOADING STRATEGY (three-tier, most â†’ least reliable):
 *
 *   Tier 1: URL query parameters (primary)
 *     â€” Set by background.js redirect (service-worker triggered blocks)
 *     â€” Available immediately, no async required
 *     â€” May be truncated at ~2KB; we trim values accordingly
 *
 *   Tier 2: chrome.storage.local[sentinel_last_analysis] (fallback)
 *     â€” Used when URL params are absent or incomplete
 *     â€” Covers: SW-triggered blocks where params somehow failed
 *
 *   Tier 3: DNR mode (source=dnr query param)
 *     â€” declarativeNetRequest redirects only pass ?source=dnr&domain=<domain>
 *     â€” No detection result is available (DNR blocks happen before JS)
 *     â€” We show a domain-level warning with a generic message
 *
 * BYPASS FLOW:
 *   1. User clicks "Proceed Anyway"
 *   2. First click: show confirmation state (change button text)
 *   3. Second click: write bypass to chrome.storage.local via message to SW
 *   4. Navigate to original URL
 *
 *   The bypass is stored in chrome.storage.local (not in-memory)
 *   so it survives service worker restarts.
 *
 * STORAGE KEYS:
 *   sentinel_last_analysis  â€” last detection result object
 *   sentinel_bypasses       â€” map of { url_key: { expiresAt } }
 *   sentinel_bypass_log     â€” audit log of bypass events
 */

"use strict";





// Fallback for chrome API
if (!window.chrome) window.chrome = {};
if (!window.chrome.storage) window.chrome.storage = {
  local: { get: (keys, cb) => cb({}), set: (data, cb) => cb() }
};
if (!window.chrome.runtime) window.chrome.runtime = {
  sendMessage: async (msg) => ({})
};

// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════

// Handle uncaught errors
window.addEventListener('error', (event) => {
  console.error('[Sentinel] Uncaught error in warning page:', event.error);
  event.preventDefault();
}, true);

// Handle promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('[Sentinel] Unhandled promise rejection in warning page:', event.reason);
  event.preventDefault();
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 1 â€” STORAGE HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const STORAGE_KEYS = {
  LAST_ANALYSIS: "sentinel_last_analysis",
  BYPASSES: "sentinel_bypasses",
  BYPASS_LOG: "sentinel_bypass_log",
  REPORTS: "sentinel_reports",
  SAFE_MARKS: "sentinel_safe_marks",
};

const MAX_BYPASS_LOG = 200;

/**
 * Promisified chrome.storage.local.get
 * IMPORTANT: keys MUST be an array â€” not a string.
 * Passing a string is documented but has inconsistent behavior.
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 2 â€” URL PARAMETER PARSING
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Safely decodes a query parameter value.
 * Handles: percent-encoding, null values, JSON parse errors.
 *
 * @param {URLSearchParams} params
 * @param {string} name
 * @param {*} defaultValue
 * @param {boolean} isJson â€” if true, attempt JSON.parse
 * @returns {*}
 */
function getParam(params, name, defaultValue = null, isJson = false) {
  const raw = params.get(name);
  if (raw === null || raw === undefined || raw === "") return defaultValue;

  try {
    const decoded = decodeURIComponent(raw);
    if (isJson) {
      return JSON.parse(decoded);
    }
    return decoded;
  } catch {
    // Malformed encoding or JSON â€” return raw or default
    try { return isJson ? defaultValue : raw; } catch { return defaultValue; }
  }
}

/**
 * Determines the detection data source from URL parameters.
 *
 * @param {URLSearchParams} params
 * @returns {"sw" | "dnr" | "unknown"}
 */
function detectSource(params) {
  const source = params.get("source");
  if (source === "dnr") return "dnr";
  if (source === "sw") return "sw";
  // Fallback: if we have a 'url' param with detection data, it's SW
  if (params.get("url") && params.get("attackType")) return "sw";
  return "unknown";
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 3 â€” DATA LOADING
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Loads detection data from all available sources.
 * Returns a normalized data object regardless of source.
 *
 * @returns {Promise<{
 *   blockedUrl: string,
 *   attackType: string,
 *   confidence: number,
 *   score: number,
 *   reasons: string[],
 *   signals: string[],
 *   sources: object[],
 *   isDNR: boolean,
 *   dnrDomain: string
 * }>}
 */
async function loadDetectionData() {
  const params = new URLSearchParams(window.location.search);
  const source = detectSource(params);

  // â”€â”€ DNR mode: minimal data available â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (source === "dnr") {
    const domain = getParam(params, "domain") || "unknown domain";
    return {
      blockedUrl: `https://${domain}/`,
      attackType: "MALWARE",
      confidence: 99,
      score: 10,
      reasons: [
        `Domain "${domain}" is in Sentinel's local phishing/malware database`,
        "This domain has been confirmed as a known threat",
        "Access was blocked at the network layer before any content loaded",
      ],
      signals: ["Phishing/Malware dataset match", "DNS-level block"],
      sources: [
        {
          name: "Phishing Database (DNR)",
          verdict: "malicious",
          triggered: true,
          detail: `Domain "${domain}" matched static blocklist`,
        },
      ],
      isDNR: true,
      dnrDomain: domain,
    };
  }

  // â”€â”€ SW mode: read URL params â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const urlParam      = getParam(params, "url");
  const attackType    = getParam(params, "attackType", "PHISHING");
  const confidence    = Number(getParam(params, "confidence", 0));
  const score         = Number(getParam(params, "score", 0));
  const trustScore    = Number(getParam(params, "trustScore", NaN));
  const finalRiskScore = Number(getParam(params, "finalRiskScore", 0));
  const explanation   = getParam(params, "explanation", "");
  const aiReasoning   = getParam(params, "aiReasoning", "");
  const domainAgeDays = Number(getParam(params, "domainAgeDays", NaN));
  const serverLocation = getParam(params, "serverLocation", "");
  const reasonStr     = getParam(params, "reason", "");
  const signalsJson   = getParam(params, "signals", [], true);
  const sourcesJson   = getParam(params, "sources", [], true);
  const breakdownJson = getParam(params, "breakdown", null, true);

  // â”€â”€ Adaptive params (present only when adaptive engine ran) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // background.js encodes these when result.finalScore is set.
  // If the param is absent (e.g. engine wasn't loaded), value is undefined
  // so renderAdaptiveContext() will correctly skip the panel.
  const finalScore = params.get("finalScore") !== null
    ? Number(getParam(params, "finalScore"))
    : undefined;
  const reputationWeight = params.get("repWeight") !== null
    ? Number(getParam(params, "repWeight"))
    : undefined;
  const userTrusted       = params.get("userTrusted")   === "1";
  const autoEscalated     = params.get("autoEscalated") === "1";
  const reputationSnapshot = getParam(params, "repSnap",      null, true);
  const sensitivityLevel   = getParam(params, "sensitivity",  null);
  const adaptiveAppliedRule = getParam(params, "adaptiveRule", null);

  const hasParamData = Boolean(urlParam && attackType);

  // If we have param data, use it
  if (hasParamData) {
    const reasons = reasonStr
      ? reasonStr.split(";").map(r => r.trim()).filter(Boolean)
      : ["Multiple threat signals detected"];

    return {
      blockedUrl: urlParam || "Unknown",
      attackType: attackType || "PHISHING",
      confidence: isNaN(confidence) ? 0 : confidence,
      score: isNaN(score) ? 0 : score,
      trustScore: isNaN(trustScore) ? null : trustScore,
      finalRiskScore: isNaN(finalRiskScore) ? null : finalRiskScore,
      explanation: String(explanation || ""),
      aiReasoning: String(aiReasoning || ""),
      domainAgeDays: isNaN(domainAgeDays) ? null : domainAgeDays,
      serverLocation: String(serverLocation || ""),
      reasons,
      topReasons: reasons.slice(0, 3),
      signals: Array.isArray(signalsJson) ? signalsJson : [],
      sources: Array.isArray(sourcesJson) ? sourcesJson : [],
      breakdown: breakdownJson && typeof breakdownJson === "object" ? breakdownJson : null,
      isDNR: false,
      dnrDomain: "",
      // â”€â”€ Adaptive fields â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      finalScore,
      reputationWeight,
      userTrusted,
      autoEscalated,
      reputationSnapshot,
      sensitivityLevel,
      adaptiveAppliedRule,
    };
  }

  // â”€â”€ Tier 2 fallback: chrome.storage.local â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // NOTE: Keys must be an array â€” NOT a string â€” for consistent behavior
  try {
    if (!STORAGE_KEYS || !STORAGE_KEYS.LAST_ANALYSIS) { console.error("[Sentinel] Storage keys not configured"); return null; }
    const stored = await storageGet([STORAGE_KEYS.LAST_ANALYSIS]);
    const r = stored[STORAGE_KEYS.LAST_ANALYSIS];

    if (r && r.url) {
      const reasons = Array.isArray(r.reasons) && r.reasons.length > 0
        ? r.reasons
        : r.reason
          ? r.reason.split(";").map(x => x.trim()).filter(Boolean)
          : ["Threat detected"];

      return {
        blockedUrl: r.url || "Unknown",
        attackType: r.attackType || "PHISHING",
        confidence: Number(r.confidence || 0),
        score: Number(r.score || 0),
        trustScore: Number(r.trustScore || 0),
        finalRiskScore: Number(r.finalRiskScore || 0),
        explanation: String(r.explanation || ""),
        aiReasoning: String(r.aiReasoning || ""),
        domainAgeDays: r.domainAgeDays ?? null,
        serverLocation: String(r.serverLocation || ""),
        reasons,
        topReasons: Array.isArray(r.topReasons) ? r.topReasons.slice(0, 3) : reasons.slice(0, 3),
        signals: Array.isArray(r.signals) ? r.signals : [],
        sources: Array.isArray(r.sources) ? r.sources : [],
        breakdown: r.breakdown && typeof r.breakdown === "object" ? r.breakdown : null,
        isDNR: false,
        dnrDomain: "",
        // â”€â”€ Adaptive fields passthrough from stored result â”€â”€â”€â”€â”€â”€â”€â”€
        finalScore:          r.finalScore,
        reputationWeight:    r.reputationWeight,
        userTrusted:         r.userTrusted         || false,
        autoEscalated:       r.autoEscalated       || false,
        reputationSnapshot:  r.reputationSnapshot  || null,
        sensitivityLevel:    r.sensitivityLevel     || null,
        adaptiveAppliedRule: r.adaptiveAppliedRule  || null,
      };
    }
  } catch (e) {
    console.warn("[Sentinel Warning] Storage fallback failed:", e);
  }

  // â”€â”€ Ultimate fallback: no data available â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  return {
    blockedUrl: urlParam || "Unknown",
    attackType: "PHISHING",
    confidence: 0,
    score: 0,
    trustScore: null,
    finalRiskScore: null,
    explanation: "",
    aiReasoning: "",
    domainAgeDays: null,
    serverLocation: "",
    reasons: ["This site was flagged as potentially dangerous"],
    topReasons: ["This site was flagged as potentially dangerous"],
    signals: [],
    sources: [],
    breakdown: null,
    isDNR: false,
    dnrDomain: "",
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 4 â€” UI RENDERING
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Maps attack type to a human-readable display string.
 * @param {string} type
 * @returns {string}
 */
function formatAttackType(type) {
  const map = {
    PHISHING:          "Phishing Attack",
    MALWARE:           "Malware / Known Threat",
    OBFUSCATED_URL:    "Obfuscated URL",
    BRAND_IMPERSONATION: "Brand Impersonation",
    SAFE:              "Safe",
  };
  return map[type] || type || "Threat Detected";
}

/**
 * Renders all UI elements with detection data.
 * @param {object} data
 */
function renderUI(data) {
  const $ = id => { const el = document.getElementById(id); if (!el) console.warn(`[Sentinel] DOM element #${id} not found`); return el; };

  // â”€â”€ Attack badge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const badgeEl = $("attackBadge");
  const badgeText = $("attackTypeText");
  if (badgeText) badgeText.textContent = formatAttackType(data.attackType);
  const subtitle = $("subtitleText");
  if (subtitle && (data.domainAgeDays || data.serverLocation)) {
    const bits = [];
    if (data.domainAgeDays) bits.push(`Domain age: ${data.domainAgeDays} days`);
    if (data.serverLocation) bits.push(`Server: ${data.serverLocation}`);
    subtitle.textContent = `Sentinel blocked this page. ${bits.join(" Â· ")}`;
  }

  // â”€â”€ DNR notice â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (data.isDNR) {
    const dnrNotice = $("dnrNotice");
    const dnrDomain = $("dnrDomain");
    if (dnrNotice) dnrNotice.classList.add("visible");
    if (dnrDomain) dnrDomain.textContent = data.dnrDomain;
    const dnrSubtitle = $("subtitleText");
    if (dnrSubtitle) dnrSubtitle.textContent =
      "This domain is in Sentinel's threat database and was blocked at the network level.";
  }

  // â”€â”€ Blocked URL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const urlEl = $("blockedUrl");
  if (urlEl) {
    try {
      urlEl.textContent = decodeURIComponent(data.blockedUrl);
    } catch {
      urlEl.textContent = data.blockedUrl;
    }
  }

  // â”€â”€ Reasons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const reasonsBox = $("reasonsBox");
  if (reasonsBox) {
    reasonsBox.innerHTML = "";
    const topReasons = Array.isArray(data.topReasons) && data.topReasons.length
      ? data.topReasons.slice(0, 3)
      : data.reasons.slice(0, 3);
    if (topReasons.length === 0) {
      reasonsBox.textContent = "No detailed reasons available.";
    } else {
      topReasons.forEach((reason, i) => {
        const item = document.createElement("div");
        item.className = "reason-item";
        item.style.animationDelay = `${i * 60}ms`;
        item.innerHTML = `<div class="reason-dot" aria-hidden="true"></div><span>${escapeHtml(reason)}</span>`;
        reasonsBox.appendChild(item);
      });
      if (data.aiReasoning) {
        const ai = document.createElement("div");
        ai.className = "reason-item";
        ai.style.marginTop = "12px";
        ai.innerHTML = `<div class="reason-dot" aria-hidden="true"></div><span><strong>AI:</strong> ${escapeHtml(data.aiReasoning)}</span>`;
        reasonsBox.appendChild(ai);
      }
    }
  }

  // â”€â”€ XAI breakdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  renderBreakdownContext(data?.breakdown);

  // â”€â”€ Stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const confEl = $("confidenceValue");
  if (confEl) confEl.textContent = `${data.confidence}%`;

  const scoreEl = $("scoreValue");
  if (scoreEl) {
    if (typeof data.finalRiskScore === "number" && !isNaN(data.finalRiskScore)) {
      scoreEl.textContent = `${Math.max(0, Math.min(100, Math.round(data.finalRiskScore)))}`;
    } else {
      scoreEl.textContent = data.score > 0 ? `${data.score.toFixed(1)}` : "â€”";
    }
  }

  const sigCountEl = $("signalCountValue");
  if (sigCountEl) sigCountEl.textContent = data.signals.length || "â€”";

  // Trust score: inverse of confidence for malicious
  const trustScoreEl = $("trustScoreValue");
  if (trustScoreEl) {
    const trust = typeof data.trustScore === "number"
      ? Math.max(0, Math.min(100, data.trustScore))
      : data.isDNR ? 0 : Math.max(0, 100 - data.confidence);
    trustScoreEl.textContent = `${trust}%`;
  }

  // â”€â”€ Risk meter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const meterFill = $("riskMeterFill");
  if (meterFill) {
    const riskPct = typeof data.finalRiskScore === "number"
      ? Math.min(100, Math.max(0, data.finalRiskScore))
      : data.isDNR ? 100 : Math.min(100, data.confidence);
    // Delay to allow CSS transition to animate visibly
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        meterFill.style.width = `${riskPct}%`;
      });
    });
  }

  // â”€â”€ Signal chips â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const signalsRow = $("signalsRow");
  if (signalsRow) {
    signalsRow.innerHTML = "";
    const signals = data.isDNR
      ? ["Phishing/Malware database", "DNS-level block"]
      : data.signals;

    if (signals.length === 0) {
      signalsRow.innerHTML = `<span class="loading" style="margin:0">No individual signals</span>`;
    } else {
      signals.slice(0, 12).forEach(signal => {
        const chip = document.createElement("span");
        chip.className = "signal-chip";
        chip.textContent = escapeHtml(String(signal));
        chip.setAttribute("role", "listitem");
        signalsRow.appendChild(chip);
      });
    }
  }

  // â”€â”€ Sources panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const sourcesPanel = $("sourcesPanel");
  if (sourcesPanel) {
    sourcesPanel.innerHTML = "";
    if (data.sources.length === 0) {
      sourcesPanel.innerHTML = `<span class="loading" style="margin:0">No module breakdown available</span>`;
    } else {
      data.sources.forEach(src => {
        const triggered = Boolean(src.triggered);
        const row = document.createElement("div");
        row.className = "source-row";
        row.setAttribute("role", "listitem");
        row.innerHTML = `
          <div class="source-dot ${triggered ? "triggered" : "safe"}" aria-hidden="true"></div>
          <span class="source-name">${escapeHtml(String(src.name || "Unknown"))}</span>
          <span class="source-verdict ${triggered ? "triggered" : "safe"}"
                aria-label="Verdict: ${triggered ? src.verdict || "triggered" : "safe"}">
            ${triggered ? (src.verdict || "triggered").toUpperCase() : "SAFE"}
          </span>
        `;
        if (src.detail) {
          const detail = document.createElement("span");
          detail.className = "source-detail";
          detail.textContent = escapeHtml(String(src.detail));
          row.appendChild(detail);
        }
        sourcesPanel.appendChild(row);
      });
    }
  }

  // â”€â”€ Adaptive context panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  renderAdaptiveContext(data);
}

/**
 * Renders the structured explanation breakdown (XAI++) as a compact panel.
 * Injected dynamically below the reasons section to avoid warning.html edits.
 *
 * @param {object|null} breakdown
 */
function renderBreakdownContext(breakdown) {
  if (!breakdown || typeof breakdown !== "object") return;
  if (document.getElementById("sentinelBreakdownCtx")) return;

  const reasonsBox = document.getElementById("reasonsBox");
  if (!reasonsBox) return;

  const rows = Object.entries(breakdown)
    .filter(([k, v]) => k && v)
    .slice(0, 6)
    .map(([k, v]) => `
      <div class="xai-row">
        <span class="xai-k">${escapeHtml(k)}</span>
        <span class="xai-v">${escapeHtml(String(v))}</span>
      </div>
    `).join("");

  if (!rows) return;

  const panel = document.createElement("div");
  panel.id = "sentinelBreakdownCtx";
  panel.setAttribute("role", "region");
  panel.setAttribute("aria-label", "Structured explanation");
  panel.innerHTML = `
    <style>
      #sentinelBreakdownCtx {
        margin-top: 14px;
        padding: 14px 16px;
        border-radius: 8px;
        background: rgba(56, 189, 248, 0.06);
        border: 1px solid rgba(56, 189, 248, 0.18);
      }
      #sentinelBreakdownCtx .xai-header {
        font-size: 10px;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        margin-bottom: 10px;
      }
      #sentinelBreakdownCtx .xai-row {
        display: grid;
        grid-template-columns: 120px 1fr;
        gap: 10px;
        padding: 6px 0;
        border-top: 1px solid rgba(56, 189, 248, 0.10);
      }
      #sentinelBreakdownCtx .xai-row:first-of-type { border-top: none; padding-top: 0; }
      #sentinelBreakdownCtx .xai-k {
        font-size: 10px;
        font-weight: 700;
        color: rgba(56, 189, 248, 0.9);
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }
      #sentinelBreakdownCtx .xai-v { color: #94a3b8; font-size: 12px; line-height: 1.4; }
    </style>
    <div class="xai-header">Explainability (XAI++)</div>
    ${rows}
  `;

  // Insert right after the reasons box
  reasonsBox.insertAdjacentElement("afterend", panel);
}

/**
 * Escapes HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Saves a community report locally (chrome.storage.local.sentinel_reports).
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
async function saveCommunityReport(domain) {
  const host = String(domain || "").trim().toLowerCase();
  if (!host) return false;

  const stored = await storageGet([STORAGE_KEYS.REPORTS]);
  const reports = Array.isArray(stored[STORAGE_KEYS.REPORTS]) ? stored[STORAGE_KEYS.REPORTS] : [];
  reports.unshift({
    domain: host,
    timestamp: Date.now(),
    userAction: "reported_malicious",
  });

  await storageSet({ [STORAGE_KEYS.REPORTS]: reports.slice(0, 500) });

  // Inform background to refresh its in-memory report counts (best-effort).
  try { await chrome.runtime.sendMessage({ type: "sentinel:reports-updated" }).catch(e => console.error("[Sentinel] sendMessage error:", e)); } catch {}
  return true;
}

/**
 * Saves a community safe mark locally and notifies background.
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
async function saveCommunitySafeMark(domain) {
  const host = String(domain || "").trim().toLowerCase();
  if (!host) return false;

  const stored = await storageGet([STORAGE_KEYS.SAFE_MARKS]);
  const marks = Array.isArray(stored[STORAGE_KEYS.SAFE_MARKS]) ? stored[STORAGE_KEYS.SAFE_MARKS] : [];
  marks.unshift({
    domain: host,
    timestamp: Date.now(),
    userAction: "marked_safe",
  });

  await storageSet({ [STORAGE_KEYS.SAFE_MARKS]: marks.slice(0, 500) });
  try { await chrome.runtime.sendMessage({ type: "sentinel:mark-safe", domain: host }).catch(e => console.error("[Sentinel] sendMessage error:", e)); } catch {}
  return true;
}

/**
 * Renders a non-intrusive adaptive intelligence context panel.
 *
 * Injected dynamically into the DOM below the signals row â€” no warning.html
 * changes required. Panel is only inserted when there is meaningful adaptive
 * data to display (reputation history, trust status, escalation, or a
 * non-default sensitivity level).
 *
 * Shows:
 *   â€¢ User-trusted badge â€” if domain was bypassed â‰¥ TRUST_BYPASS_THRESHOLD times
 *   â€¢ Auto-escalated badge â€” if reputation promoted suspicious â†’ malicious
 *   â€¢ Domain history counts â€” malicious / suspicious hits + prior bypasses
 *   â€¢ Adaptive final score â€” base + reputation + behavior components
 *   â€¢ Sensitivity level â€” if high or low (not shown for normal / default)
 *
 * @param {object} data â€” The detection data object returned by loadDetectionData
 */
function renderAdaptiveContext(data) {
  // Determine whether there is anything adaptive to show
  const hasRepHistory = data.reputationSnapshot &&
    (data.reputationSnapshot.maliciousHits > 0 || data.reputationSnapshot.suspiciousHits > 0);
  const hasRepWeight   = typeof data.reputationWeight === "number" && data.reputationWeight > 0;
  const hasBehavior    = data.userTrusted || data.autoEscalated;
  const hasSensitivity = data.sensitivityLevel && data.sensitivityLevel !== "normal";
  const hasFinalScore  = data.finalScore !== null && data.finalScore !== undefined;

  if (!hasRepHistory && !hasRepWeight && !hasBehavior && !hasSensitivity && !hasFinalScore) return;

  // Find an insertion anchor (after signalsRow, before sourcesPanel)
  const signalsRow = document.getElementById("signalsRow");
  if (!signalsRow || document.getElementById("sentinelAdaptiveCtx")) return; // already injected

  /* â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ BUILD BADGES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  let rows = "";

  if (data.userTrusted) {
    rows += `
      <div class="adaptive-row">
        <span class="adaptive-badge trusted">USER-TRUSTED</span>
        <span class="adaptive-text">You previously marked this domain as safe.
          The system softened its verdict but still flagged new signals.</span>
      </div>`;
  }

  if (data.autoEscalated) {
    rows += `
      <div class="adaptive-row">
        <span class="adaptive-badge escalated">AUTO-ESCALATED</span>
        <span class="adaptive-text">Repeated malicious reputation caused the threat
          level to be promoted from suspicious to malicious.</span>
      </div>`;
  }

  if (hasRepHistory) {
    const snap = data.reputationSnapshot;
    const lastSeenStr = snap.lastSeen
      ? new Date(snap.lastSeen).toLocaleDateString(undefined, { month: "short", day: "numeric" })
      : null;
    rows += `
      <div class="adaptive-row">
        <span class="adaptive-badge history">DOMAIN HISTORY</span>
        <span class="adaptive-text">
          ${snap.maliciousHits} malicious Â· ${snap.suspiciousHits} suspicious Â·
          ${snap.bypassCount} bypass${snap.bypassCount !== 1 ? "es" : ""}
          ${lastSeenStr ? `Â· last seen ${lastSeenStr}` : ""}
        </span>
      </div>`;
  }

  if (hasFinalScore) {
    const scoreLabel = data.reputationWeight > 0
      ? `${data.finalScore} (base + ${data.reputationWeight} reputation)`
      : String(data.finalScore);
    rows += `
      <div class="adaptive-row">
        <span class="adaptive-badge score">ADAPTIVE SCORE</span>
        <span class="adaptive-text">${escapeHtml(scoreLabel)}</span>
      </div>`;
  }

  if (hasSensitivity) {
    const sensLabel = data.sensitivityLevel === "high"
      ? "High â€” alerts triggered at lower risk thresholds"
      : "Reduced â€” thresholds raised based on your bypass history";
    rows += `
      <div class="adaptive-row">
        <span class="adaptive-badge sensitivity">SENSITIVITY</span>
        <span class="adaptive-text">${escapeHtml(sensLabel)}</span>
      </div>`;
  }

  /* â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ INJECT PANEL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const panel = document.createElement("div");
  panel.id = "sentinelAdaptiveCtx";
  panel.setAttribute("role", "region");
  panel.setAttribute("aria-label", "Adaptive Intelligence Context");
  panel.innerHTML = `
    <style>
      #sentinelAdaptiveCtx {
        margin-top: 16px;
        padding: 12px 16px;
        border-radius: 8px;
        background: rgba(245, 158, 11, 0.06);
        border: 1px solid rgba(245, 158, 11, 0.22);
      }
      #sentinelAdaptiveCtx .adaptive-header {
        font-size: 10px;
        font-weight: 700;
        color: #f59e0b;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        margin-bottom: 10px;
      }
      #sentinelAdaptiveCtx .adaptive-row {
        display: flex;
        align-items: baseline;
        gap: 10px;
        margin-bottom: 6px;
        font-size: 12px;
        line-height: 1.4;
      }
      #sentinelAdaptiveCtx .adaptive-row:last-child { margin-bottom: 0; }
      #sentinelAdaptiveCtx .adaptive-badge {
        flex-shrink: 0;
        font-size: 9px;
        font-weight: 700;
        letter-spacing: 0.07em;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
      }
      #sentinelAdaptiveCtx .adaptive-badge.trusted    { background: rgba(52,211,153,0.18); color: #34d399; }
      #sentinelAdaptiveCtx .adaptive-badge.escalated  { background: rgba(249,115,22,0.18); color: #f97316; }
      #sentinelAdaptiveCtx .adaptive-badge.history    { background: rgba(148,163,184,0.18); color: #94a3b8; }
      #sentinelAdaptiveCtx .adaptive-badge.score      { background: rgba(139,92,246,0.18); color: #a78bfa; }
      #sentinelAdaptiveCtx .adaptive-badge.sensitivity{ background: rgba(56,189,248,0.18); color: #38bdf8; }
      #sentinelAdaptiveCtx .adaptive-text { color: #94a3b8; }
    </style>
    <div class="adaptive-header">âš¡ Adaptive Intelligence</div>
    ${rows}
  `;

  signalsRow.insertAdjacentElement("afterend", panel);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 5 â€” BYPASS HANDLER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * Logs a bypass event to chrome.storage.local for dashboard auditing.
 * @param {string} url
 * @param {string} attackType
 */
async function logBypass(url, attackType) {
  try {
    const stored = await storageGet([STORAGE_KEYS.BYPASS_LOG]);
    const log = Array.isArray(stored[STORAGE_KEYS.BYPASS_LOG])
      ? stored[STORAGE_KEYS.BYPASS_LOG]
      : [];

    log.unshift({
      url: String(url || ""),
      attackType: String(attackType || ""),
      timestamp: new Date().toISOString(),
      action: "user_bypassed",
    });

    await storageSet({
      [STORAGE_KEYS.BYPASS_LOG]: log.slice(0, MAX_BYPASS_LOG),
    });
  } catch (e) {
    console.warn("[Sentinel Warning] Bypass log error:", e);
  }
}

/**
 * Registers the bypass with the service worker and navigates to the URL.
 *
 * VULN-07 FIX: When the SW is dead (restarted between warning page load and
 * user clicking "Proceed"), chrome.runtime.sendMessage() throws an error.
 * The previous code only caught this silently and proceeded without registering
 * the bypass â€” so the user would be re-blocked on the very next visit.
 *
 * Fix: On SW message failure, write the bypass DIRECTLY to chrome.storage.local
 * from the warning page. chrome.storage.local is accessible from any extension
 * context (content scripts, pages, background) â€” no SW required.
 *
 * @param {string} targetUrl
 * @param {string} attackType
 * @returns {Promise<void>}
 */
async function executeProceed(targetUrl, attackType) {
  await logBypass(targetUrl, attackType);

  let bypassRegistered = false;

  // Attempt 1: Send message to SW (preferred â€” SW does atomic read-modify-write)
  try {
    const response = await chrome.runtime.sendMessage({
      type: "sentinel:bypass-url",
      url: targetUrl,
    }).catch(e => console.error("[Sentinel] sendMessage error:", e));
    if (response && response.ok) {
      bypassRegistered = true;
      console.log("[Sentinel Warning] Bypass registered via SW.");
    }
  } catch (e) {
    console.warn("[Sentinel Warning] SW message failed (SW may be dead):", e.message);
  }

  // Attempt 2: VULN-07 FIX â€” Direct storage write if SW message failed.
  // This is safe from the warning page because it has the 'storage' permission.
  if (!bypassRegistered) {
    try {
      const BYPASS_TTL_MS = 5 * 60 * 1000; // Must match background.js CONFIG
      const STORAGE_KEY = "sentinel_bypasses";

      // Normalize the bypass key the same way background.js does
      let normalizedUrl = targetUrl;
      try {
        for (let i = 0; i < 4; i++) {
          const d = decodeURIComponent(normalizedUrl);
          if (d === normalizedUrl) break;
          normalizedUrl = d;
        }
        normalizedUrl = normalizedUrl.replace(/\x00/g, "");
        const p = new URL(normalizedUrl);
        p.hash = "";
        normalizedUrl = p.protocol.toLowerCase() + "//" + p.host.toLowerCase() + p.pathname + p.search;
      } catch { normalizedUrl = targetUrl; }

      // Read-modify-write directly
      await new Promise((resolve, reject) => {
        chrome.storage.local.get([STORAGE_KEY], (data) => { try {
          const bypasses = (data && data[STORAGE_KEY]) || {};
          bypasses[normalizedUrl] = {
            url: targetUrl,
            registeredAt: Date.now(),
            expiresAt: Date.now() + BYPASS_TTL_MS,
            registeredBy: "warning-page-fallback",
          };
          chrome.storage.local.set({ [STORAGE_KEY]: bypasses }, () => {
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else resolve();
          });
        });
      });

      bypassRegistered = true;
      console.log("[Sentinel Warning] Bypass registered via direct storage (SW fallback).");
    } catch (storageError) {
      // Both methods failed â€” proceed anyway (user's explicit choice)
      console.error("[Sentinel Warning] Both bypass methods failed:", storageError);
    }
  }

  // Navigate to original URL regardless of bypass registration success
  window.location.href = targetUrl;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECTION 6 â€” INITIALIZATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

document.addEventListener("DOMContentLoaded", async () => {
  // Load detection data from all available sources
  let data;
  try {
    data = await loadDetectionData();
  } catch (e) {
    console.error("[Sentinel Warning] Critical: loadDetectionData failed:", e);
    data = {
      blockedUrl: "Unknown",
      attackType: "PHISHING",
      confidence: 0,
      score: 0,
      reasons: ["An error occurred while loading threat details"],
      signals: [],
      sources: [],
      isDNR: false,
      dnrDomain: "",
    };
  }

  // Render UI with loaded data
  renderUI(data);

  const targetUrl = data.blockedUrl;
  let targetHost = "";
  try { targetHost = new URL(targetUrl).hostname.toLowerCase(); } catch { targetHost = ""; }

  // â”€â”€ Go Back button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const goBackBtn = document.getElementById("goBackBtn");
  if (goBackBtn) {
    goBackBtn.addEventListener("click", () => {
      // Try chrome.tabs.goBack first (MV3 preferred), fall back to history.back()
      try {
        chrome.tabs.goBack(undefined, () => {
          if (chrome.runtime.lastError) {
            // goBack failed (no history), go to new tab
            window.history.back();
          }
        });
      } catch {
        window.history.back();
      }
    });
  }

  // â”€â”€ Proceed Anyway button (two-click confirm) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const proceedBtn = document.getElementById("proceedBtn");
  if (proceedBtn) {
    let confirmStep = false;

    proceedBtn.addEventListener("click", async () => {
      if (!targetUrl || targetUrl === "Unknown") {
        // No URL to navigate to â€” disable button
        proceedBtn.textContent = "No URL available";
        proceedBtn.disabled = true;
        return;
      }

      if (!confirmStep) {
        // First click: show confirmation
        confirmStep = true;
        proceedBtn.textContent = "âš  Click again to confirm";
        proceedBtn.classList.add("confirming");

        // Auto-reset after 4 seconds if user doesn't confirm
        setTimeout(() => {
          if (confirmStep && !proceedBtn.disabled) {
            confirmStep = false;
            proceedBtn.textContent = "Proceed Anyway";
            proceedBtn.classList.remove("confirming");
          }
        }, 4000);

      } else {
        // Second click: execute bypass and navigate
        proceedBtn.disabled = true;
        proceedBtn.textContent = "Navigatingâ€¦";

        try {
          await executeProceed(targetUrl, data.attackType);
        } catch (e) {
          console.error("[Sentinel Warning] Proceed failed:", e);
          proceedBtn.textContent = "Failed â€” try again";
          proceedBtn.disabled = false;
          confirmStep = false;
        }
      }
    });
  }

  // â”€â”€ Report this site button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const reportBtn = document.getElementById("reportBtn");
  if (reportBtn) {
    reportBtn.addEventListener("click", async () => {
      if (!targetHost) {
        reportBtn.textContent = "No domain";
        reportBtn.disabled = true;
        return;
      }
      reportBtn.disabled = true;
      reportBtn.textContent = "Reportingâ€¦";
      try {
        const ok = await saveCommunityReport(targetHost);
        reportBtn.textContent = ok ? "Reported" : "Report failed";
      } catch {
        reportBtn.textContent = "Report failed";
      }
    });
  }

  const markSafeBtn = document.getElementById("markSafeBtn");
  if (markSafeBtn) {
    markSafeBtn.addEventListener("click", async () => {
      if (!targetHost) {
        markSafeBtn.textContent = "No domain";
        markSafeBtn.disabled = true;
        return;
      }
      markSafeBtn.disabled = true;
      markSafeBtn.textContent = "Saving...";
      try {
        const ok = await saveCommunitySafeMark(targetHost);
        markSafeBtn.textContent = ok ? "Marked safe" : "Failed";
      } catch {
        markSafeBtn.textContent = "Failed";
      }
    });
  }
});

