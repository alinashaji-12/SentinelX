/* global chrome */

"use strict";

const STORAGE_KEYS = {
  LAST_ANALYSIS: "sentinel_last_analysis",
  REPUTATION: "sentinel_reputation",
  REPORTS: "sentinel_reports",
  SAFE_MARKS: "sentinel_safe_marks",
  DEV_MODE: "dev_mode",
};

function $(id) {
  return document.getElementById(id);
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function statusIcon(status) {
  if (status === "safe") return "✅";
  if (status === "suspicious") return "⚠️";
  if (status === "malicious") return "🚫";
  return "🛡️";
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
  return map[type] || type || "—";
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
    label.textContent = "—";
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
      xaiEl.textContent = `${aiPrefix} • ${lines.join(" • ")}`;
      return;
    }
  }
  const reasons = Array.isArray(fallbackReasons) ? fallbackReasons.filter(Boolean).slice(0, 3) : [];
  xaiEl.textContent = reasons.length
    ? `${aiPrefix} • ${reasons.join(" • ")}`
    : aiPrefix;
}

function formatReputation(rep) {
  if (!rep || typeof rep !== "object") return "—";
  const suspiciousHits = Number(rep.suspiciousHits || 0);
  const maliciousHits = Number(rep.maliciousHits || 0);
  const bypassCount = Number(rep.bypassCount || 0);
  return `${maliciousHits} malicious · ${suspiciousHits} suspicious · ${bypassCount} bypass`;
}

async function renderDashboard() {
  const [tab, stored] = await Promise.all([
    getActiveTab(),
    storageGet([STORAGE_KEYS.LAST_ANALYSIS, STORAGE_KEYS.REPUTATION]),
  ]);

  const analysis = stored[STORAGE_KEYS.LAST_ANALYSIS] || null;

  const siteUrl = analysis?.url || tab?.url || "—";
  $("siteUrl").textContent = siteUrl;

  const status = analysis?.status || "—";
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
  $("domainMeta").textContent = `Domain intel: ${metaBits.length ? metaBits.join(" · ") : "not available"}`;

  // Current-tab behavior risk (0–100) from background in-memory map
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
  $("behaviorRisk").textContent = `Behavior alerts: ${behaviorParts.length ? behaviorParts.join(" · ") : "none"}`;

  const tldHigh = Array.isArray(analysis?.signals) && (
    analysis.signals.includes("tldRiskHigh") ||
    analysis.signals.some(s => typeof s === "string" && s.startsWith("High-risk TLD"))
  );
  $("tldRisk").textContent = `TLD risk: ${tldHigh ? "HIGH" : "normal"}`;

  renderXai($("xai"), analysis?.breakdown, analysis?.reasons || [], analysis);
  renderSignals($("signalsList"), analysis?.signals || []);

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
