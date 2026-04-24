/**
 * dashboard.js — Sentinel Browse Extension v3.0
 *
 * PRODUCTION DASHBOARD CONTROLLER
 * ═══════════════════════════════════════════════════════════════════════
 *
 * IMPORTANT: This is a PLAIN SCRIPT (no ES imports).
 * dashboard.html loads detectionEngine.js before this file so that
 * SentinelDetectionEngine is available for the simulation panel.
 *
 * DATA SOURCES:
 *   sentinel:get-history       → threat history table
 *   sentinel:get-adaptive-stats → reputation + user profile panel
 *   sentinel:revoke-trust       → trust management action
 *   SentinelDetectionEngine     → simulation (loaded in page)
 */

"use strict";

// ══════════════════════════════════════════════════════════════════════
// SECTION 1 — MESSAGE & UTILITY HELPERS
// ══════════════════════════════════════════════════════════════════════

/**
 * Sends a message to the background service worker and returns a Promise.
 * @param {object} message
 * @returns {Promise<object>}
 */
function sendMsg(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response || {});
        }
      });
    } catch (e) {
      reject(e);
    }
  });
}

/** Escapes HTML special chars to prevent XSS in dynamic content. */
function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/** Formats an ISO timestamp for display. */
function toDisplayTime(isoTime) {
  if (!isoTime) return "—";
  const date = new Date(isoTime);
  if (isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

/** Converts snake_case/UPPER_CASE to Title Case for display. */
function toDisplayLabel(value) {
  const input = String(value || "").trim();
  if (!input || input === "none") return "None";
  return input.replace(/[-_]+/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 2 — HISTORY TABLE
// ══════════════════════════════════════════════════════════════════════

let selectedFilter = "all";
let historyItems   = [];
let latestReport   = null;

function applyFilter(items, filter) {
  if (filter === "malicious")  return items.filter(i => i.status === "malicious");
  if (filter === "suspicious") return items.filter(i => i.status === "suspicious");
  if (filter === "bypassed")   return items.filter(i => i.action === "bypassed");
  return items;
}

function getTrustScoreTone(ts) {
  if (ts >= 80) return "high";
  if (ts >= 50) return "medium";
  return "low";
}

function renderTable() {
  const bodyEl    = document.getElementById("historyBody");
  const emptyEl   = document.getElementById("emptyState");
  if (!bodyEl) return;

  const filtered = applyFilter(historyItems, selectedFilter);
  bodyEl.innerHTML = "";

  if (filtered.length === 0) {
    if (emptyEl) emptyEl.hidden = false;
    return;
  }

  if (emptyEl) emptyEl.hidden = true;

  for (const item of filtered) {
    // Normalize action field
    const action = item.action === "bypassed" ? "bypassed"
                 : item.action === "allowed"   ? "allowed"
                 : "blocked";

    const row = document.createElement("tr");
    if (action === "bypassed") row.classList.add("row-bypassed");

    // URL cell
    const urlCell = document.createElement("td");
    urlCell.className = "url-cell";
    urlCell.textContent = item.url || "—";

    // Status pill
    const statusCell = document.createElement("td");
    const statusPill = document.createElement("span");
    statusPill.className = `status-pill ${item.status || "safe"}`;
    statusPill.textContent = String(item.status || "safe").toUpperCase();
    statusCell.appendChild(statusPill);

    // Trust score pill
    const trustCell = document.createElement("td");
    const trustPill = document.createElement("span");
    trustPill.className = `trust-pill ${getTrustScoreTone(Number(item.trustScore || 0))}`;
    trustPill.textContent = `${Number(item.trustScore || 0)}/100`;
    trustCell.appendChild(trustPill);

    // Confidence pill
    const confCell = document.createElement("td");
    const confPill = document.createElement("span");
    confPill.className = "confidence-pill";
    confPill.textContent = `${Number(item.confidence || 0)}%`;
    confCell.appendChild(confPill);

    // Action pill
    const actionCell = document.createElement("td");
    const actionPill = document.createElement("span");
    actionPill.className = `action-pill ${action}`;
    actionPill.textContent = action === "bypassed" ? "Bypassed"
                           : action === "allowed"   ? "Allowed"
                           : "Blocked";
    actionCell.appendChild(actionPill);

    // Reasons cell
    const reasonCell = document.createElement("td");
    reasonCell.className = "reason-cell";
    const reasons = Array.isArray(item.reasons) && item.reasons.length > 0
      ? item.reasons
      : (item.reason ? [item.reason] : ["—"]);
    const ul = document.createElement("ul");
    ul.className = "reason-list";
    reasons.slice(0, 3).forEach(r => {
      const li = document.createElement("li");
      li.textContent = String(r).trim();
      ul.appendChild(li);
    });
    reasonCell.appendChild(ul);

    // Time cell
    const timeCell = document.createElement("td");
    timeCell.textContent = toDisplayTime(item.timestamp);

    row.append(urlCell, statusCell, trustCell, confCell, actionCell, reasonCell, timeCell);
    bodyEl.appendChild(row);
  }
}

function setupFilters() {
  const buttons = Array.from(document.querySelectorAll(".filter-btn[data-filter]"));
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      selectedFilter = btn.dataset.filter || "all";
      buttons.forEach(b => b.classList.toggle("active", b === btn));
      renderTable();
    });
  });
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 3 — HISTORY LOADING
// ══════════════════════════════════════════════════════════════════════

async function loadHistory() {
  try {
    const response = await sendMsg({ type: "sentinel:get-history" });
    const history  = Array.isArray(response.history) ? response.history : [];
    historyItems   = history;
    latestReport   = generateReport(history); // Pre-compute for "Generate Report" button
    renderTable();
  } catch (e) {
    console.warn("[Dashboard] History load failed:", e);
    const bodyEl = document.getElementById("historyBody");
    if (bodyEl) {
      bodyEl.innerHTML = `<tr><td colspan="7" class="empty-state">Failed to load history. Is the extension active?</td></tr>`;
    }
  }
}

/**
 * Renders latest intelligence snapshot (final risk + AI + domain metadata).
 */
async function loadLatestIntel() {
  const panel = document.getElementById("latestIntelPanel");
  if (!panel) return;

  panel.innerHTML = `<p class="empty-state" style="margin:0">Loading latest analysis…</p>`;
  try {
    const analysisResp = await sendMsg({ type: "sentinel:get-analysis" });
    const a = analysisResp?.result || null;
    if (!a) {
      panel.innerHTML = `<p class="empty-state" style="margin:0">No analysis captured yet.</p>`;
      return;
    }

    const finalRisk = typeof a.finalRiskScore === "number"
      ? Math.max(0, Math.min(100, Math.round(a.finalRiskScore)))
      : Math.max(0, Math.min(100, Math.round((Number(a.score || 0)) * 10)));
    const behaviorSignals = Array.isArray(a.signals)
      ? a.signals.filter(s => typeof s === "string" && /(clipboard|download|redirect|iframe|phishing|scam|behavior)/i.test(s))
      : [];

    panel.innerHTML = `
      <div class="adaptive-summary">
        <div class="adaptive-stat-card">
          <span class="adaptive-stat-label">Final Risk Score</span>
          <strong class="adaptive-stat-value" style="color:${finalRisk >= 75 ? "#b91c1c" : finalRisk >= 45 ? "#d97706" : "#15803d"}">${finalRisk}/100</strong>
        </div>
        <div class="adaptive-stat-card">
          <span class="adaptive-stat-label">Domain Age</span>
          <strong class="adaptive-stat-value">${a.domainAgeDays ? `${a.domainAgeDays} days` : "Unknown"}</strong>
        </div>
        <div class="adaptive-stat-card">
          <span class="adaptive-stat-label">Server Location</span>
          <strong class="adaptive-stat-value">${escapeHtml(a.serverLocation || "Unknown")}</strong>
        </div>
        <div class="adaptive-stat-card">
          <span class="adaptive-stat-label">Behavior Logs</span>
          <strong class="adaptive-stat-value">${behaviorSignals.length}</strong>
        </div>
      </div>
      <div class="adaptive-section">
        <div class="adaptive-section-label">AI Reasoning</div>
        <p style="margin:8px 0 0;color:#334155;">${escapeHtml(a.aiReasoning || a.explanation || "No AI reasoning available.")}</p>
      </div>
    `;
  } catch (e) {
    console.warn("[Dashboard] Latest intelligence load failed:", e);
    panel.innerHTML = `<p class="empty-state" style="margin:0">Failed to load latest intelligence.</p>`;
  }
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 4 — ADAPTIVE INTELLIGENCE PANEL
// ══════════════════════════════════════════════════════════════════════

/**
 * Loads and renders the adaptive intelligence stats panel.
 * Connects to sentinel:get-adaptive-stats message handler in background.js.
 */
async function loadAdaptiveStats() {
  const panel = document.getElementById("adaptiveStatsPanel");
  if (!panel) return;

  panel.innerHTML = `<p class="empty-state" style="margin:0">Loading adaptive data…</p>`;

  try {
    const response = await sendMsg({ type: "sentinel:get-adaptive-stats" });
    const stats = response.stats;

    if (!stats) {
      panel.innerHTML = `<p class="empty-state" style="margin:0">No adaptive data yet. Start browsing to build your threat profile.</p>`;
      return;
    }

    panel.innerHTML = ""; // Clear loading state

    const rep  = stats.reputation  || {};
    const prof = stats.userProfile || {};

    // ── Sensitivity level color coding ──────────────────────────────
    const sensColor = prof.sensitivityLevel === "high" ? "#15803d"
                    : prof.sensitivityLevel === "low"  ? "#b45309"
                    : "#374151";
    const sensNote  = prof.sensitivityLevel === "high"
      ? "Tighter — alerts fire at lower risk scores"
      : prof.sensitivityLevel === "low"
      ? "Relaxed — adapted to your high bypass rate"
      : "Standard thresholds active";

    const bypassRate = typeof prof.bypassRate === "number"
      ? (prof.bypassRate * 100).toFixed(1)
      : "0.0";

    // ── Summary stats grid ─────────────────────────────────────────
    const summaryEl = document.createElement("div");
    summaryEl.className = "adaptive-summary";
    summaryEl.innerHTML = `
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Sensitivity Mode</span>
        <strong class="adaptive-stat-value" style="color:${sensColor}; font-size:18px">
          ${escapeHtml(String(prof.sensitivityLevel || "normal").toUpperCase())}
        </strong>
        <span class="adaptive-stat-note">${escapeHtml(sensNote)}</span>
      </div>
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Total Blocked</span>
        <strong class="adaptive-stat-value">${prof.totalBlocked || 0}</strong>
      </div>
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Total Warned</span>
        <strong class="adaptive-stat-value">${prof.totalWarned || 0}</strong>
      </div>
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Bypasses</span>
        <strong class="adaptive-stat-value">${prof.totalBypasses || 0}</strong>
        <span class="adaptive-stat-note">Bypass rate: ${bypassRate}%</span>
      </div>
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Tracked Domains</span>
        <strong class="adaptive-stat-value">${rep.totalTrackedDomains || 0}</strong>
      </div>
      <div class="adaptive-stat-card">
        <span class="adaptive-stat-label">Auto-Escalated</span>
        <strong class="adaptive-stat-value" style="color:${(rep.autoEscalatedDomains || 0) > 0 ? "#b91c1c" : "inherit"}">
          ${rep.autoEscalatedDomains || 0}
        </strong>
        <span class="adaptive-stat-note">Suspicious → Malicious</span>
      </div>
    `;
    panel.appendChild(summaryEl);

    // ── Top threat domains ─────────────────────────────────────────
    const topThreats = (rep.topThreats || []).slice(0, 8);
    if (topThreats.length > 0) {
      const section = document.createElement("div");
      section.className = "adaptive-section";
      section.innerHTML = `<div class="adaptive-section-label">🔴 Top Threat Domains (by reputation weight)</div>`;

      topThreats.forEach(t => {
        const lastSeen = t.lastSeen
          ? new Date(t.lastSeen).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })
          : "—";
        const row = document.createElement("div");
        row.className = "adaptive-threat-row";
        row.innerHTML = `
          <code class="adaptive-threat-host">${escapeHtml(t.host)}</code>
          <div class="adaptive-threat-badges">
            ${t.maliciousHits > 0
              ? `<span class="adaptive-badge-pill malicious">${t.maliciousHits} malicious</span>`
              : ""}
            ${t.suspiciousHits > 0
              ? `<span class="adaptive-badge-pill suspicious">${t.suspiciousHits} suspicious</span>`
              : ""}
            ${t.bypassCount > 0
              ? `<span class="adaptive-badge-pill bypass">${t.bypassCount} bypass${t.bypassCount !== 1 ? "es" : ""}</span>`
              : ""}
            ${t.autoEscalated
              ? `<span class="adaptive-badge-pill escalated">AUTO-ESC</span>`
              : ""}
          </div>
          <span class="adaptive-threat-meta">Last seen: ${escapeHtml(lastSeen)}</span>
        `;
        section.appendChild(row);
      });

      panel.appendChild(section);
    }

    // ── User-trusted domains with revoke controls ──────────────────
    const trusted = (prof.userTrustedDomains || []).slice(0, 15);
    const trustSection = document.createElement("div");
    trustSection.className = "adaptive-section";

    if (trusted.length > 0) {
      trustSection.innerHTML = `<div class="adaptive-section-label">✅ User-Trusted Domains (${trusted.length}) — <span style="font-weight:400;color:#6b7280">bypassed ${5}+ times</span></div>`;

      trusted.forEach(d => {
        const grantedDate = d.trustGrantedAt
          ? new Date(d.trustGrantedAt).toLocaleDateString(undefined, { month: "short", day: "numeric" })
          : "—";

        const row = document.createElement("div");
        row.className = "adaptive-trust-row";

        const revokeBtn = document.createElement("button");
        revokeBtn.className = "revoke-btn";
        revokeBtn.type = "button";
        revokeBtn.textContent = "Revoke Trust";

        revokeBtn.addEventListener("click", async () => {
          revokeBtn.disabled = true;
          revokeBtn.textContent = "Revoking…";
          try {
            const res = await sendMsg({ type: "sentinel:revoke-trust", hostname: d.host });
            if (res.ok) {
              row.style.opacity = "0.4";
              setTimeout(() => row.remove(), 400);
            } else {
              revokeBtn.disabled = false;
              revokeBtn.textContent = "Failed — retry";
            }
          } catch {
            revokeBtn.disabled = false;
            revokeBtn.textContent = "Error";
          }
        });

        row.innerHTML = `
          <code class="adaptive-trust-host">${escapeHtml(d.host)}</code>
          <div class="adaptive-trust-meta">
            <span>${d.bypassCount || 0} bypass${(d.bypassCount || 0) !== 1 ? "es" : ""}</span>
            <span>trusted since ${escapeHtml(grantedDate)}</span>
          </div>
        `;
        row.appendChild(revokeBtn);
        trustSection.appendChild(row);
      });

    } else {
      trustSection.innerHTML = `
        <div class="adaptive-section-label">✅ User-Trusted Domains</div>
        <p class="empty-state" style="margin:0; padding:10px 0">
          No domains auto-trusted yet. After bypassing the same domain 5+ times, it becomes user-trusted and the system softens warnings for it.
        </p>
      `;
    }

    panel.appendChild(trustSection);

  } catch (e) {
    console.warn("[Dashboard] Adaptive stats load failed:", e);
    if (panel) {
      panel.innerHTML = `<p class="empty-state" style="margin:0">Adaptive engine unavailable. Ensure the extension is active and reload.</p>`;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 5 — SIMULATION (uses SentinelDetectionEngine loaded in page)
// ══════════════════════════════════════════════════════════════════════

/**
 * Runs a detection simulation on a user-supplied URL.
 * Uses SentinelDetectionEngine.analyzeUrl() loaded via <script> in dashboard.html.
 * Shows the base detection result (without adaptive adjustment since that
 * requires querying live storage — use the extension on a real site for that).
 */
async function runSimulation() {
  const inputEl   = document.getElementById("simulationUrl");
  const resultEl  = document.getElementById("simulationResult");
  const statusEl  = document.getElementById("simulationStatus");
  const confEl    = document.getElementById("simulationConfidence");
  const trustEl   = document.getElementById("simulationTrustScore");
  const reasonsEl = document.getElementById("simulationReasons");
  const sourcesEl = document.getElementById("simulationSources");

  const inputUrl = String(inputEl?.value || "").trim();
  if (!inputUrl || !resultEl) return;

  const engine = globalThis.SentinelDetectionEngine;
  if (!engine || typeof engine.analyzeUrl !== "function") {
    if (statusEl) {
      statusEl.textContent = "ENGINE UNAVAILABLE";
      statusEl.className = "metric-value malicious";
    }
    return;
  }

  const normalizedUrl = /^https?:\/\//i.test(inputUrl) ? inputUrl : `https://${inputUrl}`;

  let result;
  try {
    result = engine.analyzeUrl(normalizedUrl);
  } catch (e) {
    console.warn("[Dashboard] Simulation engine error:", e);
    if (statusEl) {
      statusEl.textContent = "ERROR";
      statusEl.className = "metric-value malicious";
    }
    return;
  }

  // Render verdict
  if (statusEl) {
    statusEl.textContent = String(result.status || "safe").toUpperCase();
    statusEl.className   = `metric-value ${String(result.status || "safe").toLowerCase()}`;
  }

  if (confEl)  confEl.textContent  = `${Number(result.confidence || 0)}%`;
  if (trustEl) trustEl.textContent = `${Number(result.trustScore || 0)}/100`;

  // Render reasons
  if (reasonsEl) {
    reasonsEl.innerHTML = "";
    const ul = document.createElement("ul");
    ul.className = "reason-list";
    const reasons = result.reasons && result.reasons.length > 0
      ? result.reasons
      : ["No threats detected — URL appears safe"];
    reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = String(r).trim();
      ul.appendChild(li);
    });
    reasonsEl.appendChild(ul);
  }

  // Render detection module breakdown
  if (sourcesEl) {
    sourcesEl.innerHTML = "";
    const sources = Array.isArray(result.sources) ? result.sources : [];
    if (sources.length === 0) {
      sourcesEl.textContent = "No module breakdown available.";
    } else {
      const ul = document.createElement("ul");
      ul.className = "reason-list";
      sources.forEach(src => {
        const li = document.createElement("li");
        li.textContent = `${src.triggered ? "⚠ TRIGGERED" : "✓ Clear"}: ${src.name}${src.detail ? ` — ${src.detail}` : ""}`;
        ul.appendChild(li);
      });
      sourcesEl.appendChild(ul);
    }
  }

  resultEl.hidden = false;
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 6 — REPORT GENERATION
// ══════════════════════════════════════════════════════════════════════

/**
 * Generates a summary report object from the threat history array.
 * @param {object[]} history — Items from sentinel_history
 * @returns {object}
 */
function generateReport(history) {
  const malicious  = history.filter(h => h.status === "malicious");
  const suspicious = history.filter(h => h.status === "suspicious");
  const safe       = history.filter(h => h.status === "safe");

  // Count attack types across malicious+suspicious
  const typeCounts = {};
  malicious.concat(suspicious).forEach(h => {
    const t = h.attackType || "UNKNOWN";
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });
  const topType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0] || ["None", 0];

  // Count domains across malicious
  const domainCounts = {};
  malicious.forEach(h => {
    const d = h.domain || (() => {
      try { return new URL(h.url).hostname; } catch { return h.url || "unknown"; }
    })();
    domainCounts[d] = (domainCounts[d] || 0) + 1;
  });
  const topDomain = Object.entries(domainCounts).sort((a, b) => b[1] - a[1])[0] || ["None", 0];

  return {
    generatedAt: new Date().toISOString(),
    totalUrlsScanned:              history.length,
    maliciousCount:                malicious.length,
    suspiciousCount:               suspicious.length,
    safeCount:                     safe.length,
    mostCommonThreatType:          topType[0],
    mostCommonThreatTypeCount:     topType[1],
    mostFrequentMaliciousDomain:   topDomain[0],
    mostFrequentMaliciousDomainCount: topDomain[1],
  };
}

/**
 * Renders the generated report into the report card section.
 * @param {object} report
 */
function renderReportCard(report) {
  const cardEl    = document.getElementById("reportCard");
  const gridEl    = document.getElementById("reportGrid");
  const tsEl      = document.getElementById("reportTimestamp");
  const typeEl    = document.getElementById("reportThreatType");
  const domainEl  = document.getElementById("reportMaliciousDomain");
  const jsonEl    = document.getElementById("reportJsonOutput");
  const exportBtn = document.getElementById("exportReportBtn");

  if (!cardEl || !gridEl) return;

  const metrics = [
    { label: "Total Scanned",  value: report.totalUrlsScanned },
    { label: "Malicious",      value: report.maliciousCount },
    { label: "Suspicious",     value: report.suspiciousCount },
    { label: "Safe / Clean",   value: report.safeCount },
  ];

  gridEl.innerHTML = "";
  metrics.forEach(m => {
    const card = document.createElement("article");
    card.className = "report-metric";
    const lbl = document.createElement("span");
    lbl.className = "metric-label";
    lbl.textContent = m.label;
    const val = document.createElement("strong");
    val.className = "metric-value";
    val.textContent = String(m.value);
    card.append(lbl, val);
    gridEl.appendChild(card);
  });

  if (tsEl)     tsEl.textContent    = `Generated ${toDisplayTime(report.generatedAt)}`;
  if (typeEl)   typeEl.textContent  = `${toDisplayLabel(report.mostCommonThreatType)} (${report.mostCommonThreatTypeCount})`;
  if (domainEl) domainEl.textContent = `${toDisplayLabel(report.mostFrequentMaliciousDomain)} (${report.mostFrequentMaliciousDomainCount})`;
  if (jsonEl)   jsonEl.textContent  = JSON.stringify(report, null, 2);

  cardEl.hidden = false;
  if (exportBtn) exportBtn.hidden = false;
}

function downloadJsonReport(report) {
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href     = url;
  link.download = `sentinel-report-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 7 — INITIALIZATION
// ══════════════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {

  // ── Filter buttons ──────────────────────────────────────────────────
  setupFilters();

  // ── Generate Report button ──────────────────────────────────────────
  const generateBtn = document.getElementById("generateReportBtn");
  if (generateBtn) {
    generateBtn.addEventListener("click", () => {
      if (latestReport) renderReportCard(latestReport);
    });
  }

  // ── Export JSON button ──────────────────────────────────────────────
  const exportBtn = document.getElementById("exportReportBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (latestReport) downloadJsonReport(latestReport);
    });
  }

  // ── Simulation controls ─────────────────────────────────────────────
  const simBtn   = document.getElementById("runSimulationBtn");
  const simInput = document.getElementById("simulationUrl");
  if (simBtn)   simBtn.addEventListener("click", () => void runSimulation());
  if (simInput) {
    simInput.addEventListener("keydown", e => {
      if (e.key === "Enter") { e.preventDefault(); void runSimulation(); }
    });
  }

  // ── Clear history button ────────────────────────────────────────────
  const clearBtn = document.getElementById("clearHistoryBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Clear all threat history? This cannot be undone.")) return;
      clearBtn.disabled = true;
      clearBtn.textContent = "Clearing…";
      try {
        await sendMsg({ type: "sentinel:clear-history" });
        historyItems = [];
        latestReport = generateReport([]);
        renderTable();
        clearBtn.textContent = "Cleared ✓";
        setTimeout(() => {
          clearBtn.disabled = false;
          clearBtn.textContent = "Clear History";
        }, 2000);
      } catch (e) {
        console.warn("[Dashboard] Clear failed:", e);
        clearBtn.disabled  = false;
        clearBtn.textContent = "Clear History";
      }
    });
  }

  // ── Load all data ───────────────────────────────────────────────────
  loadHistory();
  loadAdaptiveStats();
  loadLatestIntel();

});
