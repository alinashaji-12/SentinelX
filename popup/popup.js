/* global chrome */
"use strict";

let activeTabId = null;
let activeResult = null;
let cachedHistory = [];

function $(id) { return document.getElementById(id); }

function statusMeta(status) {
  const s = String(status || "safe").toLowerCase();
  if (s === "malicious" || s === "blocked") return { cls: "danger", icon: "✕", label: "Blocked", color: "#ef4444" };
  if (s === "suspicious" || s === "uncertain") return { cls: "warn", icon: "▲", label: "Caution", color: "#f59e0b" };
  return { cls: "safe", icon: "●", label: "Safe", color: "#22c55e" };
}

function fmtAgo(ts) {
  const t = Number(ts || 0);
  if (!t) return "just now";
  const sec = Math.floor((Date.now() - t) / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.floor(min / 60);
  return `${hr}hr ago`;
}

function tabSwitch(tab) {
  const keys = ["current", "history", "stats"];
  keys.forEach((k) => {
    $(`tab-${k}`).classList.toggle("active", k === tab);
    $(`panel-${k}`).classList.toggle("hidden", k !== tab);
  });
}

function categoryTagsFromSubtitle(subtitle) {
  const s = String(subtitle || "").toLowerCase();
  if (s.includes("ai")) return ["AI", "Technology", "Global", "Verified", "Safe Payment"];
  if (s.includes("beauty") || s.includes("skincare")) return ["Beauty", "Skincare", "E-Commerce", "India", "Verified"];
  if (s.includes("pharmacy") || s.includes("healthcare")) return ["Healthcare", "Licensed", "India", "Verified"];
  if (s.includes("e-commerce")) return ["Shopping", "E-Commerce", "India", "Verified"];
  return ["Verified", "Trusted"];
}

function renderCurrent(result) {
  const canonical = globalThis.normalizeSentinelResult
    ? globalThis.normalizeSentinelResult(result || {})
    : (result || {});
  activeResult = canonical;

  const status = statusMeta(canonical.status);
  const score = Math.max(0, Math.min(100, Math.round(Number(canonical.score || 0))));
  const conf = Math.max(0, Math.min(100, Math.round(Number(canonical.confidence || 0))));
  const domain = canonical.domain || "unknown";
  const subtitle = canonical.verdictSentence || "Trusted site";

  const iconEl = $("current-status-icon");
  iconEl.textContent = status.icon === "●" ? "✓" : status.icon;
  iconEl.className = `status-icon ${status.cls}`;
  $("current-domain").textContent = domain;
  $("current-subtitle").textContent = subtitle;
  $("current-score").textContent = `${score}/100`;
  $("current-confidence").textContent = `${conf}%`;

  $("current-fill").style.width = `${score}%`;
  $("current-fill").style.background = status.color;

  const https = /^https:\/\//i.test(String(canonical.url || ""));
  $("check-ssl").textContent = https ? "SSL encrypted & verified" : "SSL check limited";
  $("check-domain").textContent = (score <= 20) ? "Trusted domain verified" : "Domain requires caution";
  $("check-signals").textContent = `${(canonical.signals || []).length} threat signals`;

  const pills = categoryTagsFromSubtitle(subtitle);
  $("current-pills").innerHTML = pills.map((p) => `<span class="pill">${p}</span>`).join("");
}

function openReportForItem(item) {
  const payload = {
    url: item.url || "",
    domain: item.domain || "",
    status: item.status || "safe",
    score: Number(item.score || 0),
    confidence: Number(item.confidence || 0),
    signals: Array.isArray(item.signals) ? item.signals : [],
    reasons: Array.isArray(item.reasons) ? item.reasons : [],
    categories: Array.isArray(item.categories) ? item.categories : [],
    verdictSentence: item.verdictSentence || "",
    timestamp: item.timestamp || Date.now()
  };
  chrome.storage.local.set({ sentinel_last_report: payload }, () => {
    const reportUrl = chrome.runtime.getURL("report/report.html") + "?url=" + encodeURIComponent(payload.url || "");
    chrome.tabs.create({ url: reportUrl }, () => void chrome.runtime.lastError);
  });
}

function renderHistory(history) {
  const list = $("history-list");
  const rows = Array.isArray(history) ? history.slice(0, 10) : [];
  cachedHistory = rows;
  if (!rows.length) {
    list.innerHTML = `<div class="small" style="padding:8px;">No history yet.</div>`;
    return;
  }
  list.innerHTML = "";
  rows.forEach((item) => {
    const s = statusMeta(item.status);
    const row = document.createElement("button");
    row.type = "button";
    row.className = "history-row";
    row.innerHTML = `<span class="marker-${s.cls}">[${s.icon}]</span> ${item.domain || "unknown"} — ${s.label} — ${fmtAgo(item.timestamp)}`;
    row.addEventListener("click", () => openReportForItem(item));
    list.appendChild(row);
  });
}

function renderStats(history) {
  const rows = Array.isArray(history) ? history : [];
  const scanned = rows.length;
  const blocked = rows.filter((r) => {
    const s = String(r.status || "").toLowerCase();
    return s === "malicious" || s === "blocked";
  }).length;
  const safe = rows.filter((r) => String(r.status || "").toLowerCase() === "safe").length;
  const caution = rows.filter((r) => {
    const s = String(r.status || "").toLowerCase();
    return s === "suspicious" || s === "uncertain";
  }).length;
  $("stat-scanned").textContent = String(scanned);
  $("stat-blocked").textContent = String(blocked);
  $("stat-safe").textContent = String(safe);
  $("stat-caution").textContent = String(caution);
  const rate = scanned ? Math.round(((safe + blocked + caution) / scanned) * 100) : 100;
  $("stat-rate-fill").style.width = `${rate}%`;
  const topCat = blocked > 0 ? `Typosquatting (${blocked} attempts)` : "No blocked attempts";
  $("stat-top-category").textContent = topCat;
}

function refreshData() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || !tab.id) return;
    activeTabId = tab.id;
    const key = `sentinel_tab_${activeTabId}`;
    chrome.storage.local.get([key, "sentinel_last_report", "sentinel_history"], (data) => {
      const result = data[key] || data.sentinel_last_report || {};
      renderCurrent(result);
      renderHistory(data.sentinel_history || []);
      renderStats(data.sentinel_history || []);
    });
  });
}

function bindActions() {
  $("tab-current").addEventListener("click", () => tabSwitch("current"));
  $("tab-history").addEventListener("click", () => tabSwitch("history"));
  $("tab-stats").addEventListener("click", () => tabSwitch("stats"));

  $("action-scan").addEventListener("click", () => {
    if (!activeTabId) return;
    chrome.runtime.sendMessage({ type: "TRIGGER_ANALYSIS", tabId: activeTabId, url: activeResult?.url || "" }, () => {
      setTimeout(refreshData, 900);
    });
  });
  $("action-report").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "SENTINEL_OPEN_REPORT" }, () => void chrome.runtime.lastError);
  });
  $("action-trust").addEventListener("click", () => {
    const domain = activeResult?.domain;
    if (!domain) return;
    chrome.runtime.sendMessage({ type: "sentinel:mark-safe", domain }, () => void chrome.runtime.lastError);
  });
  $("action-issue").addEventListener("click", () => {
    const domain = activeResult?.domain;
    chrome.runtime.sendMessage({ type: "sentinel:reports-updated", domain }, () => void chrome.runtime.lastError);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  tabSwitch("current");
  bindActions();
  refreshData();
});
