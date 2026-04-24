/* global chrome */

"use strict";

const STORAGE_KEYS = {
  LAST_ANALYSIS: "sentinel_last_analysis",
  REPUTATION: "sentinel_reputation",
  REPORTS: "sentinel_reports",
  SAFE_MARKS: "sentinel_safe_marks",
  DEV_MODE: "dev_mode",
};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// âš¡ THREAT ANALYSIS DASHBOARD â€” State
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Persists across Refresh clicks within the same popup session.
const eventLog = [];

function $(id) {
  return document.getElementById(id);
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function statusIcon(status) {
  if (status === "safe") return "âœ…";
  if (status === "suspicious") return "âš ï¸";
  if (status === "malicious") return "ðŸš«";
  return "ðŸ›¡ï¸";
}

function formatAttackType(type) {
  const map = {
    PHISHING: "Phishing",
    MALWARE: "Malware / Known Threat",
    OBFUSCATED_URL: "Obfuscated URL",
    BRAND_IMPERSONATION: "Brand Impersonation",
    BEHAVIORAL: "Behavioral",
    SAFE: "Safe",
  };
  return map[type] || type || "â€”";
}

function storageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (data) => resolve(data || {}));
  });
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs.length ? tabs[0] : null;
}

function getHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function getRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  const DOUBLE_TLDS = new Set([
    "co.uk", "co.in", "co.nz", "co.jp", "co.za",
    "com.au", "com.br", "com.sg", "com.my", "com.hk",
    "gov.uk", "gov.in", "gov.au", "gov.sg",
    "org.uk", "net.uk", "ac.uk", "edu.au",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  if (DOUBLE_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

async function saveUserReport(domain) {
  const host = String(domain || "").trim().toLowerCase();
  if (!host) return false;

  const entry = {
    domain: host,
    timestamp: Date.now(),
    userAction: "reported_malicious",
  };

  const stored = await storageGet([STORAGE_KEYS.REPORTS]);
  const reports = Array.isArray(stored[STORAGE_KEYS.REPORTS]) ? stored[STORAGE_KEYS.REPORTS] : [];
  reports.unshift(entry);

  await new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.REPORTS]: reports.slice(0, 500) }, resolve);
  });

  return true;
}

async function saveSafeMark(domain) {
  const host = String(domain || "").trim().toLowerCase();
  if (!host) return false;

  const entry = {
    domain: host,
    timestamp: Date.now(),
    userAction: "marked_safe",
  };

  const stored = await storageGet([STORAGE_KEYS.SAFE_MARKS]);
  const marks = Array.isArray(stored[STORAGE_KEYS.SAFE_MARKS]) ? stored[STORAGE_KEYS.SAFE_MARKS] : [];
  marks.unshift(entry);

  await new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.SAFE_MARKS]: marks.slice(0, 500) }, resolve);
  });

  return true;
}

function computeRiskScore(analysis) {
  if (typeof analysis?.finalRiskScore === "number") {
    return clamp(Math.round(analysis.finalRiskScore), 0, 100);
  }
  const trust = typeof analysis?.trustScore === "number" ? analysis.trustScore : null;
  if (trust !== null) return clamp(Math.round(100 - trust), 0, 100);

  const raw = typeof analysis?.score === "number" ? analysis.score : 0;
  return clamp(Math.round(raw * 10), 0, 100);
}

function setTrustMeter(trustScore) {
  const trust = typeof trustScore === "number" ? clamp(Math.round(trustScore), 0, 100) : null;
  const fill = $("trustFill");
  const label = $("trustScore");
  if (!fill || !label) return;

  if (trust === null) {
    fill.style.width = "0%";
    fill.style.background = "#9ca3af";
    label.textContent = "â€”";
    return;
  }

  fill.style.width = `${trust}%`;
  fill.style.background = trust >= 75 ? "#169c54" : trust >= 45 ? "#d69e2e" : "#dc2626";
  label.textContent = `${trust}/100`;
}

function renderSignals(listEl, signals) {
  if (!listEl) return;
  listEl.innerHTML = "";
  const safe = Array.isArray(signals) ? signals.filter(Boolean).slice(0, 12) : [];
  if (!safe.length) {
    const li = document.createElement("li");
    li.className = "signal-item";
    li.textContent = "No signals recorded";
    listEl.appendChild(li);
    return;
  }
  for (const s of safe) {
    const li = document.createElement("li");
    li.className = "signal-item";
    li.textContent = String(s);
    listEl.appendChild(li);
  }
}

function renderXai(xaiEl, breakdown, fallbackReasons, data = null) {
  if (!xaiEl) return;
  const aiReasoning = (data && typeof data.aiReasoning === "string" && data.aiReasoning.trim())
    ? data.aiReasoning.trim()
    : "No AI reasoning available";
  const aiConfidence = (data && typeof data.aiConfidence === "number")
    ? data.aiConfidence
    : "N/A";
  const aiPrefix = `AI: ${aiReasoning} (confidence: ${aiConfidence})`;
  if (breakdown && typeof breakdown === "object") {
    const lines = Object.entries(breakdown)
      .filter(([k, v]) => k && v)
      .slice(0, 6)
      .map(([k, v]) => `${k}: ${v}`);
    if (lines.length) {
      xaiEl.textContent = `${aiPrefix} â€¢ ${lines.join(" â€¢ ")}`;
      return;
    }
  }
  const reasons = Array.isArray(fallbackReasons) ? fallbackReasons.filter(Boolean).slice(0, 3) : [];
  xaiEl.textContent = reasons.length
    ? `${aiPrefix} â€¢ ${reasons.join(" â€¢ ")}`
    : aiPrefix;
}

function formatReputation(rep) {
  if (!rep || typeof rep !== "object") return "â€”";
  const suspiciousHits = Number(rep.suspiciousHits || 0);
  const maliciousHits = Number(rep.maliciousHits || 0);
  const bypassCount = Number(rep.bypassCount || 0);
  return `${maliciousHits} malicious Â· ${suspiciousHits} suspicious Â· ${bypassCount} bypass`;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// âš¡ THREAT ANALYSIS DASHBOARD â€” Rendering
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Renders the animated risk bar inside #attack-dashboard.
 * Drives width, gradient colour, and label from a 0â€“100 score.
 * @param {number} score - 0..100
 * @param {string} status - "safe" | "suspicious" | "malicious"
 */
function renderRisk(score, status) {
  const fill  = $("risk-bar");
  const label = $("riskBarLabel");
  const liveDot = $("dashLiveDot");
  if (!fill) return;

  const s = clamp(Math.round(score ?? 0), 0, 100);
  const level = status === "malicious" ? "malicious"
              : status === "suspicious" || s > 40 ? "suspicious"
              : "safe";

  // Let the browser paint at 0 first so the transition always animates
  requestAnimationFrame(() => {
    fill.style.width   = s + "%";
    fill.dataset.level = level;
    if (label) label.textContent = `${s}/100`;
  });

  // Mark live dot stale if no real analysis is available
  if (liveDot) {
    if (score == null || score === 0) {
      liveDot.classList.add("stale");
    } else {
      liveDot.classList.remove("stale");
    }
  }
}

/**
 * Infers a severity class for a signal string.
 * Used to colour-code chips in the Active Signals panel.
 * @param {string} signal
 * @returns {"malicious"|"suspicious"|"safe"}
 */
function inferSignalSeverity(signal) {
  const s = String(signal || "").toLowerCase();
  if (
    s.includes("phishing") || s.includes("malware") ||
    s.includes("hijack") || s.includes("keylogger") ||
    s.includes("ransomware") || s.includes("obfuscated")
  ) return "malicious";
  if (
    s.includes("redirect") || s.includes("iframe") ||
    s.includes("injection") || s.includes("suspicious") ||
    s.includes("scam") || s.includes("brand") ||
    s.includes("tld") || s.includes("domain")
  ) return "suspicious";
  return "safe";
}

/**
 * Renders colour-coded signal chips in #signals-list (inside #attack-dashboard).
 * @param {string[]} signals
 */
function renderDashboardSignals(signals) {
  const container = $("signals-list");
  if (!container) return;
  container.innerHTML = "";

  const safe = Array.isArray(signals) ? signals.filter(Boolean).slice(0, 16) : [];

  if (!safe.length) {
    const chip = document.createElement("span");
    chip.className = "dash-signal-chip chip-none";
    chip.textContent = "No signals detected";
    container.appendChild(chip);
    return;
  }

  // Severity icons for quick visual scanning
  const ICONS = { malicious: "ðŸ›‘", suspicious: "âš ï¸", safe: "â„¹ï¸" };

  for (const signal of safe) {
    const severity = inferSignalSeverity(signal);
    const chip = document.createElement("span");
    chip.className = `dash-signal-chip chip-${severity}`;
    chip.title     = signal;
    chip.textContent = `${ICONS[severity]} ${String(signal).replace(/_/g, " ")}`;
    container.appendChild(chip);
  }
}

/**
 * Adds a new event to the detection timeline and re-renders.
 * Called once per renderDashboard() with the current analysis verdict.
 * @param {string} signal  - readable description
 * @param {string} status  - "safe" | "suspicious" | "malicious" | "info"
 */
function logEvent(signal, status = "info") {
  eventLog.unshift({          // newest first
    signal: String(signal || ""),
    status: ["safe", "suspicious", "malicious", "info"].includes(status) ? status : "info",
    time:   new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  });
  if (eventLog.length > 20) eventLog.length = 20;   // cap at 20 entries
  renderTimeline();
}

/**
 * Renders the timeline list from the in-memory eventLog array.
 */
function renderTimeline() {
  const tl = $("timeline");
  if (!tl) return;
  tl.innerHTML = "";

  if (!eventLog.length) {
    const empty = document.createElement("div");
    empty.className = "timeline-empty";
    empty.textContent = "No events recorded yet.";
    tl.appendChild(empty);
    return;
  }

  for (const entry of eventLog) {
    const row = document.createElement("div");
    row.className = "timeline-entry";

    const dot = document.createElement("span");
    dot.className = `tl-dot tl-dot-${entry.status}`;

    const time = document.createElement("span");
    time.className = "tl-time";
    time.textContent = entry.time;

    const sig = document.createElement("span");
    sig.className = "tl-signal";
    sig.textContent = entry.signal;
    sig.title       = entry.signal;

    row.appendChild(dot);
    row.appendChild(time);
    row.appendChild(sig);
    tl.appendChild(row);
  }
}

async function renderDashboard() {
  const [tab, stored] = await Promise.all([
    getActiveTab(),
    storageGet([STORAGE_KEYS.LAST_ANALYSIS, STORAGE_KEYS.REPUTATION]),
  ]);

  const analysis = stored[STORAGE_KEYS.LAST_ANALYSIS] || null;

  const siteUrl = analysis?.url || tab?.url || "â€”";
  $("siteUrl").textContent = siteUrl;

  const status = analysis?.status || "â€”";
  const statusEl = $("status");
  statusEl.textContent = status;
  statusEl.classList.remove("safe", "suspicious", "malicious");
  if (status === "safe" || status === "suspicious" || status === "malicious") {
    statusEl.classList.add(status);
  }

  const risk = computeRiskScore(analysis);
  $("riskScore").textContent = `${risk}/100`;

  $("verdictIcon").textContent = statusIcon(status);
  $("attackType").textContent = formatAttackType(analysis?.attackType);

  setTrustMeter(analysis?.trustScore);

  const hostname = getHostname(siteUrl);
  const reputationDb = stored[STORAGE_KEYS.REPUTATION] || {};
  const rep = hostname ? reputationDb[hostname] : null;
  $("domainReputation").textContent = `Domain reputation: ${formatReputation(rep)}`;
  const metaBits = [];
  if (typeof analysis?.domainAgeDays === "number" && analysis.domainAgeDays > 0) {
    metaBits.push(`age ${analysis.domainAgeDays} days`);
  }
  if (analysis?.serverLocation) {
    metaBits.push(`server ${analysis.serverLocation}`);
  }
  $("domainMeta").textContent = `Domain intel: ${metaBits.length ? metaBits.join(" Â· ") : "not available"}`;

  // Current-tab behavior risk (0â€“100) from background in-memory map
  let behaviorRisk = null;
  try {
    const tabId = tab?.id;
    if (tabId !== undefined && tabId !== null) {
      const resp = await chrome.runtime.sendMessage({ type: "sentinel:get-tab-risk", tabId });
      behaviorRisk = typeof resp?.riskScore === "number" ? resp.riskScore : null;
    }
  } catch {
    behaviorRisk = null;
  }

  const behaviorSignals = Array.isArray(analysis?.signals)
    ? analysis.signals.filter(s =>
        typeof s === "string" &&
        (s.includes("clipboard") || s.includes("download") || s.includes("redirect") || s.includes("iframe") || s === "scamContentDetected"))
    : [];

  const behaviorParts = [];
  if (typeof behaviorRisk === "number") behaviorParts.push(`tab risk ${behaviorRisk}/100`);
  if (behaviorSignals.length) behaviorParts.push(behaviorSignals.slice(0, 3).join(", "));
  $("behaviorRisk").textContent = `Behavior alerts: ${behaviorParts.length ? behaviorParts.join(" Â· ") : "none"}`;

  const tldHigh = Array.isArray(analysis?.signals) && (
    analysis.signals.includes("tldRiskHigh") ||
    analysis.signals.some(s => typeof s === "string" && s.startsWith("High-risk TLD"))
  );
  $("tldRisk").textContent = `TLD risk: ${tldHigh ? "HIGH" : "normal"}`;

  renderXai($("xai"), analysis?.breakdown, analysis?.reasons || [], analysis);
  renderSignals($("signalsList"), analysis?.signals || []);

  // â”€â”€ THREAT ANALYSIS DASHBOARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Populate the three dashboard widgets from data already fetched above.
  renderRisk(risk, analysis?.status || "safe");
  renderDashboardSignals(analysis?.signals || []);

  const _tlStatus = (analysis?.status || "info").toUpperCase();
  const _tlType   = analysis?.attackType || "scan complete";
  const _tlLabel  = analysis?.status
    ? (_tlStatus + " \u2014 " + _tlType + " (risk " + risk + "/100)")
    : "No analysis data yet";
  logEvent(_tlLabel, analysis?.status || "info");

  if (Array.isArray(analysis?.signals)) {
    const _HIGH_SIGS = [
      "phishing_form", "clipboard_hijack", "malware_signature",
      "keylogger_detected", "hidden_iframe", "obfuscated_script",
      "external_script_injection",
    ];
    for (const _sig of analysis.signals) {
      if (_HIGH_SIGS.includes(_sig)) {
        logEvent("Signal: " + _sig.replace(/_/g, " "), inferSignalSeverity(_sig));
      }
    }
  }

  // If the latest analyzed site isn't the active tab, make that visible.
  if (tab?.url && analysis?.url && tab.url !== analysis.url) {
    $("siteUrl").textContent = `${analysis.url} (active tab: ${tab.url})`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("refreshBtn")?.addEventListener("click", () => renderDashboard().catch(() => {}));
  $("reportBtn")?.addEventListener("click", async () => {
    const btn = $("reportBtn");
    try {
      const tab = await getActiveTab();
      const url = tab?.url || "";
      const host = getHostname(url);
      const root = getRootDomain(host);
      const ok = await saveUserReport(root || host);
      if (btn) {
        btn.textContent = ok ? "Reported" : "Report failed";
        btn.disabled = ok;
      }
      // Ping background so it can refresh report counts immediately.
      try { await chrome.runtime.sendMessage({ type: "sentinel:reports-updated" }); } catch {}
    } catch {
      if (btn) btn.textContent = "Report failed";
    }
  });
  $("markSafeBtn")?.addEventListener("click", async () => {
    const btn = $("markSafeBtn");
    try {
      const tab = await getActiveTab();
      const url = tab?.url || "";
      const host = getHostname(url);
      const root = getRootDomain(host);
      const ok = await saveSafeMark(root || host);
      try { await chrome.runtime.sendMessage({ type: "sentinel:mark-safe", domain: root || host }); } catch {}
      if (btn) {
        btn.textContent = ok ? "Marked safe" : "Failed";
        btn.disabled = ok;
      }
    } catch {
      if (btn) btn.textContent = "Failed";
    }
  });
  $("closeBtn")?.addEventListener("click", () => window.close());

  // Developer mode toggle (chrome.storage.local.dev_mode)
  const toggle = $("devModeToggle");
  if (toggle) {
    chrome.storage.local.get([STORAGE_KEYS.DEV_MODE], (data) => {
      toggle.checked = Boolean(data && data[STORAGE_KEYS.DEV_MODE]);
    });
    toggle.addEventListener("change", () => {
      chrome.storage.local.set({ [STORAGE_KEYS.DEV_MODE]: Boolean(toggle.checked) });
    });
  }

  renderDashboard().catch(() => {});
});
