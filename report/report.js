"use strict";

function el(id) { return document.getElementById(id); }
function esc(v) { return String(v ?? "").replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[m])); }
function parseUrl(url) { try { return new URL(url); } catch { return null; } }

function getTabIdFromQuery() {
  try {
    const sp = new URLSearchParams(window.location.search || "");
    const id = Number(sp.get("tabId"));
    return Number.isFinite(id) && id > 0 ? id : null;
  } catch {
    return null;
  }
}

function statusMeta(status) {
  const s = String(status || "safe").toLowerCase();
  if (s === "malicious" || s === "blocked") return { cls: "danger", icon: "✗", line: "This site is blocked", color: "#ff5f6f" };
  if (s === "suspicious" || s === "uncertain") return { cls: "warn", icon: "⚠", line: "Proceed with care", color: "#ffb548" };
  return { cls: "safe", icon: "✓", line: "This site is safe", color: "#25d27f" };
}

function formatTime(ts) {
  const d = new Date(ts || Date.now());
  return `Analysed at ${d.toLocaleTimeString("en-GB")} on ${d.toLocaleDateString("en-GB")}`;
}

function isHighRep(hostOrUrl) {
  return typeof globalThis.isHighReputationDomain === "function"
    ? globalThis.isHighReputationDomain(hostOrUrl || "")
    : false;
}

function animateScoreBar(score, color) {
  const bar = el("scoreBar");
  if (!bar) return;
  bar.style.background = color;
  bar.style.width = "0%";
  requestAnimationFrame(() => {
    bar.style.width = `${Math.max(0, Math.min(100, Number(score || 0)))}%`;
  });
}

function renderFacts(result) {
  const parsed = parseUrl(result.url || "");
  const domain = result.domain || parsed?.hostname || "unknown";
  const parts = domain.split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "unknown";
  const subdomain = parts.length > 2 ? parts.slice(0, -2).join(".") : "none";
  const protocol = parsed ? parsed.protocol.replace(":", "").toUpperCase() : "Unknown";
  const sslValid = ((parsed && parsed.protocol === "https:") || /^https:\/\//i.test(String(result.url || "")))
    ? "Encrypted ✓"
    : (result.sslValid === false ? "No" : "Unknown");

  const left = [
    ["Full URL", result.url || "unknown"],
    ["Domain", domain],
    ["Subdomain", subdomain],
    ["TLD", tld]
  ];
  const right = [
    ["SSL", sslValid],
    ["Domain Age", result.domainAge || result.whoisAge || "Unknown"],
    ["Category", (Array.isArray(result.categories) && result.categories[0]) || "Unknown"],
    ["Payment gateways", result.paymentGateways || "Not detected"]
  ];

  el("leftFacts").innerHTML = left.map(([k, v]) => `<div class="fact"><div>${esc(k)}</div><strong>${esc(v)}</strong></div>`).join("");
  el("rightFacts").innerHTML = right.map(([k, v]) => `<div class="fact"><div>${esc(k)}</div><strong>${esc(v)}</strong></div>`).join("");
}

function normalizeSignals(result) {
  const raw = Array.isArray(result.signals) ? result.signals : [];
  return raw.map((s) => {
    if (typeof s === "string") {
      return { name: s.replace(/_/g, " "), detail: "Pattern observed during scan", score: 0 };
    }
    return {
      name: String(s.label || s.name || s.type || "Signal"),
      detail: String(s.description || s.reason || "Pattern observed during scan"),
      score: Number(s.weight || s.score || s.contribution || 0)
    };
  });
}

function renderSignals(result) {
  const tbody = el("riskRows");
  const status = String(result.status || "safe").toLowerCase();
  const domain = result.domain || "this domain";
  const highRep = isHighRep(domain) || isHighRep(result.url || "");
  const signals = normalizeSignals(result);

  if (status === "safe") {
    tbody.innerHTML = `<tr><td colspan="3" class="muted">No threat signals detected.</td></tr>`;
    return;
  }
  if (highRep) {
    tbody.innerHTML = `<tr><td colspan="3" class="muted">${esc(domain)} is a verified trusted domain. No threat analysis required.</td></tr>`;
    return;
  }
  if (!signals.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="muted">Signals unavailable for this scan.</td></tr>`;
    return;
  }
  const total = Math.max(1, Math.round(Number(result.score || 0)));
  tbody.innerHTML = signals.slice(0, 8).map((s) => {
    const part = Math.max(1, Math.round(s.score || (total / Math.max(signals.length, 1))));
    return `<tr><td>${esc(s.name)}</td><td>${esc(s.detail)}</td><td>+${part}</td></tr>`;
  }).join("");
}

function renderAnalysis(result) {
  el("reasoning").textContent = result.verdictSentence || "Scan complete.";
  const categories = Array.isArray(result.categories) ? result.categories : [];
  el("categories").innerHTML = categories.length
    ? categories.map((c) => `<span style="display:inline-block;margin-right:6px;padding:4px 10px;border-radius:999px;background:rgba(124,216,255,.15);border:1px solid rgba(124,216,255,.35);">${esc(c)}</span>`).join("")
    : `<span class="muted">No category tags.</span>`;
  const behavior = Array.isArray(result.behaviorEvents) ? result.behaviorEvents : [];
  el("behavior").innerHTML = behavior.length
    ? behavior.map((b) => `<li>${esc(b)}</li>`).join("")
    : `<li class="muted">No suspicious runtime behaviour detected.</li>`;

  const status = String(result.status || "safe").toLowerCase();
  const actions = status === "safe"
    ? ["No action needed. Continue browsing normally."]
    : status === "suspicious" || status === "uncertain"
      ? ["Proceed only if you trust this site.", "Avoid entering passwords or payment details."]
      : ["Go back to safety immediately.", "Do not enter credentials or download files."];
  el("actions").innerHTML = actions.map((a) => `<li>${esc(a)}</li>`).join("");
}

function renderHeader(result) {
  const status = String(result.status || "safe").toLowerCase();
  const meta = statusMeta(status);
  const score = Math.max(0, Math.min(100, Math.round(Number(result.score || 0))));
  const confidence = Math.max(0, Math.min(100, Math.round(Number(result.confidence || 0))));
  const domain = result.domain || parseUrl(result.url || "")?.hostname || "this site";
  const highRep = isHighRep(domain) || isHighRep(result.url || "");
  const conf = highRep && status === "safe" ? Math.max(confidence, 92) : confidence;

  const verdictCard = el("verdictCard");
  verdictCard.classList.remove("warn", "danger");
  if (meta.cls === "warn") verdictCard.classList.add("warn");
  if (meta.cls === "danger") verdictCard.classList.add("danger");

  el("badge").textContent = `${meta.icon} ${meta.line}`;
  el("summary").textContent = result.verdictSentence || `${domain} has been scanned by SentinelX.`;
  el("score").textContent = `${score} / 100`;
  el("confidence").textContent = `${conf}% confidence`;
  animateScoreBar(score, meta.color);
}

function renderReport(result) {
  renderHeader(result);
  renderFacts(result);
  renderSignals(result);
  renderAnalysis(result);

  el("analysedUrl").textContent = result.url || "";
  el("analysedAt").textContent = formatTime(result.timestamp);
  el("version").textContent = result.version || "2.0.0";
}

function wireButtons(result) {
  el("printBtn")?.addEventListener("click", () => window.print());
  el("falsePositiveBtn")?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "sentinel:reports-updated", domain: result.domain || "" }, () => void chrome.runtime.lastError);
  });
  el("exportJsonBtn")?.addEventListener("click", () => {
    const data = JSON.stringify(result, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sentinelx-report-${(result.domain || "site").replace(/[^\w.-]/g, "_")}-${result.timestamp || Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

function resolveReportSource(tabScoped, fallback) {
  const src = tabScoped || fallback;
  if (!src) return null;
  const canonical = src; // display exactly cached canonical result
  canonical.version = (chrome.runtime.getManifest && chrome.runtime.getManifest().version) || "2.0.0";
  return canonical;
}

function boot() {
  const tabId = getTabIdFromQuery();
  if (tabId) {
    const key = `sentinel_tab_${tabId}`;
    chrome.storage.local.get([key, "sentinel_last_report"], (data) => {
      const report = resolveReportSource(data && data[key], data && data.sentinel_last_report);
      if (!report) {
        el("root").innerHTML = `<div class="muted">No analysis data found. Visit a page first.</div>`;
        return;
      }
      renderReport(report);
      wireButtons(report);
    });
    return;
  }

  chrome.storage.local.get("sentinel_last_report", ({ sentinel_last_report }) => {
    const report = resolveReportSource(null, sentinel_last_report);
    if (!report) {
      el("root").innerHTML = `<div class="muted">No analysis data found. Visit a page first.</div>`;
      return;
    }
    renderReport(report);
    wireButtons(report);
  });
}

document.addEventListener("DOMContentLoaded", boot);
