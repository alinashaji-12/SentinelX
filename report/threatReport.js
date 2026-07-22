/* global chrome, tabAnalysisMap, SIGNAL_META */

"use strict";

function scoreToVerdict(n) {
  const score = Math.max(0, Math.min(100, Math.round(Number(n) || 0)));
  if (score < 30) return "safe";
  if (score < 60) return "suspicious";
  if (score < 100) return "danger";
  return "blocked";
}

function signalKey(signal) {
  return String(signal?.type || signal?.key || signal?.name || signal || "")
    .toLowerCase()
    .replace(/\s+/g, "_");
}

function signalMatches(signal, name) {
  const key = signalKey(signal);
  return key === name || key.includes(name);
}

function getSignalMeta(signal) {
  const key = signalKey(signal);
  const meta = (typeof SIGNAL_META === "object" && SIGNAL_META && SIGNAL_META[key]) || null;
  return {
    name: String(signal?.name || meta?.name || key || "signal").replace(/_/g, " "),
    weight: Math.max(0, Math.round(Number(signal?.weight || signal?.score || signal?.contribution || 0))),
    description: String(signal?.description || meta?.description || ""),
    category: String(signal?.category || meta?.category || "reputation"),
    metadata: signal?.metadata || null,
    brand: signal?.brand || signal?.targetedBrand || null
  };
}

function hasSignal(signals, name) {
  return signals.some(signal => signalMatches(signal, name));
}

function computeTrustLevel(data) {
  let score = 0;
  const ageDays = Number(data.whoisAgeDays || 0);
  const reputation = Number(data.reputation || 0);
  const ipOrigin = String(data.ipOrigin || "");
  const signals = Array.isArray(data.signals) ? data.signals : [];

  if (ageDays > 365 * 2) score += 30;
  else if (ageDays > 30) score += 15;
  if (reputation >= 80) score += 30;
  else if (reputation >= 50) score += 15;
  if (data.ssl === "valid") score += 20;
  if (!hasSignal(signals, "typosquatting")) score += 10;
  if (ipOrigin.includes("CDN") || ipOrigin.includes("US")) score += 10;
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

function buildTrustFactors(data) {
  const signals = Array.isArray(data.signals) ? data.signals : [];
  return {
    domainAge: data.whoisAge || "unknown",
    reputation: Number(data.reputation || 0),
    tlsStatus: data.ssl || "unknown",
    certIssuer: data.certIssuer || "unknown",
    ipHostType: data.ipOrigin || "unknown",
    lookalike: hasSignal(signals, "typosquatting"),
    whoisPrivacy: data.whoisPrivacy || "unknown"
  };
}

function generateRecommendations(signals, score) {
  const map = {
    typosquatting: "Navigate to the real site by typing the URL directly — do not follow links",
    credential_form: "Do not enter passwords, card numbers, or personal data on this page",
    new_domain: "This domain is newly registered — a common phishing tactic",
    ssl_invalid: "Connection is not securely verified — data can be intercepted",
    clipboard_hijack: "Check your clipboard — it may have been tampered with by this page",
    known_phishing: "This URL appears in known phishing databases — treat as hostile",
    malware_host: "This server distributes malware — do not download anything",
    bulletproof_hosting: "Hosted on infrastructure used by criminal networks"
  };
  const out = [];
  Object.keys(map).forEach(name => {
    if (hasSignal(signals, name)) out.push(map[name]);
  });
  out.push("If you interacted with this page, run a full malware scan");
  if (Number(score) >= 60) out.push("Report this URL to your national cybercrime authority");
  return [...new Set(out)];
}

function extractTargetedBrand(signals) {
  const typo = signals.find(signal => signalMatches(signal, "typosquatting"));
  return typo?.metadata?.brand || typo?.brand || typo?.targetedBrand || null;
}

function buildPredictionFlags(data) {
  const signals = Array.isArray(data.signals) ? data.signals : [];
  const domain = String(data.domain || "").toLowerCase();
  const ipOrigin = String(data.ipOrigin || "").toLowerCase();
  const likelyPhishingCampaign = hasSignal(signals, "typosquatting") &&
    hasSignal(signals, "new_domain") &&
    hasSignal(signals, "credential_form");

  return {
    likelyPhishingCampaign,
    targetedBrand: likelyPhishingCampaign ? extractTargetedBrand(signals) : null,
    attackVector: likelyPhishingCampaign ? (data.attackVector || "email") : "unknown",
    campaignPattern: /\.(tk|ml|cf|ga|gq)$/i.test(domain)
      ? "Free-TLD phishing campaign — low-cost, high-volume attack pattern"
      : null,
    futureRisk: ipOrigin.includes("ru") || ipOrigin.includes("bulletproof")
      ? "High — campaign likely ongoing, infrastructure designed to resist takedown"
      : null,
    submittedToFeed: true
  };
}

function storageGetLocal(keys) {
  return new Promise(resolve => {
    chrome.storage.local.get(keys, data => {
      if (chrome.runtime.lastError) {
        resolve({});
        return;
      }
      resolve(data || {});
    });
  });
}

function storageSetLocal(data) {
  return new Promise(resolve => {
    chrome.storage.local.set(data, () => {
      resolve(!chrome.runtime.lastError);
    });
  });
}

async function generateThreatReport(tabId, shouldExportHtml) {
  const data = tabAnalysisMap.get(tabId);
  if (!data) throw new Error("No analysis found for tab");

  const riskScore = Math.max(0, Math.min(100, Math.round(Number(data.score) || 0)));
  const signals = (Array.isArray(data.signals) ? data.signals : []).map(getSignalMeta);
  const report = {
    reportId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    url: data.url || "",
    domain: data.domain || "",
    ipAddress: data.ipAddress || "unknown",
    riskScore,
    verdict: scoreToVerdict(riskScore),
    confidence: Math.max(0, Math.min(100, Math.round(Number(data.aiConfidence) || 0))),
    trustLevel: computeTrustLevel(data),
    trustFactors: buildTrustFactors(data),
    signals,
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    recommendations: generateRecommendations(signals, riskScore),
    predictionFlags: buildPredictionFlags({ ...data, signals })
  };

  const stored = await storageGetLocal(["report_index"]);
  const reportIndex = Array.isArray(stored.report_index) ? stored.report_index : [];
  reportIndex.unshift(report.reportId);
  await storageSetLocal({
    ["report:" + report.reportId]: JSON.stringify(report),
    report_index: reportIndex.slice(0, 500)
  });

  if (shouldExportHtml) exportReportAsHTML(report);
  return report;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[ch]));
}

function verdictColor(verdict) {
  if (verdict === "safe") return "#00c896";
  if (verdict === "suspicious") return "#ffb830";
  return "#ff3d57";
}

function trustColor(level) {
  if (level === "HIGH") return "#00c896";
  if (level === "MEDIUM") return "#ffb830";
  return "#ff3d57";
}

function factorRows(factors) {
  return Object.keys(factors).map(key => (
    `<tr><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08);color:rgba(255,255,255,0.55)">${escapeHtml(key)}</td><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08)">${escapeHtml(factors[key])}</td></tr>`
  )).join("");
}

function signalRows(signals) {
  return signals.map(signal => (
    `<tr><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08)">${escapeHtml(signal.name)}</td><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08);font-family:monospace">${escapeHtml(signal.weight)}</td><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08)">${escapeHtml(signal.category)}</td><td style="padding:9px;border-bottom:1px solid rgba(255,255,255,0.08)">${escapeHtml(signal.description)}</td></tr>`
  )).join("");
}

function recommendationList(items) {
  return items.map((item, index) => `<li style="margin:8px 0"><span style="color:#00e5ff;font-family:monospace">${index + 1}.</span> ${escapeHtml(item)}</li>`).join("");
}

function predictionRows(flags) {
  return Object.keys(flags).map(key => (
    `<div style="display:grid;grid-template-columns:210px 1fr;gap:12px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.08)"><span style="color:rgba(255,255,255,0.55)">${escapeHtml(key)}</span><strong>${escapeHtml(flags[key] === null ? "null" : flags[key])}</strong></div>`
  )).join("");
}

function exportReportAsHTML(report) {
  const domain = String(report.domain || "unknown").replace(/[^a-z0-9.-]/gi, "_");
  const color = verdictColor(report.verdict);
  const confidenceWidth = Math.max(0, Math.min(100, Number(report.confidence) || 0));
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelX Report — ${escapeHtml(report.domain)}</title>
</head>
<body style="margin:0;background:#0d1117;color:#fff;font:14px system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<main style="max-width:1040px;margin:0 auto;padding:32px">
<header style="display:flex;justify-content:space-between;gap:18px;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:18px">
  <div><h1 style="margin:0;color:#00e5ff;letter-spacing:0">SentinelX</h1><p style="margin:6px 0 0;color:rgba(255,255,255,0.55)">Browser Security Threat Report</p></div>
  <div style="text-align:right;font-family:monospace;color:rgba(255,255,255,0.75)"><div>${escapeHtml(report.reportId)}</div><div>${escapeHtml(report.timestamp)}</div></div>
</header>
<section style="margin:18px 0;padding:20px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22">
  <div style="font:900 54px monospace;color:${color}">${escapeHtml(report.riskScore)}/100</div>
  <div style="font-weight:900;color:${color};text-transform:uppercase">${escapeHtml(report.verdict)}</div>
  <div style="margin-top:14px;color:rgba(255,255,255,0.55)">Confidence ${escapeHtml(report.confidence)}%</div>
  <div style="height:8px;background:rgba(255,255,255,0.08);border-radius:999px;overflow:hidden;margin-top:7px"><div style="width:${confidenceWidth}%;height:100%;background:${color}"></div></div>
</section>
<section style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin:18px 0">
  <div style="padding:14px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22"><span style="display:block;color:rgba(255,255,255,0.55)">URL</span><code style="color:#00e5ff;font-family:monospace;word-break:break-all">${escapeHtml(report.url)}</code></div>
  <div style="padding:14px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22"><span style="display:block;color:rgba(255,255,255,0.55)">IP</span><code style="font-family:monospace">${escapeHtml(report.ipAddress)}</code></div>
  <div style="padding:14px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22"><span style="display:block;color:rgba(255,255,255,0.55)">Domain Age</span><strong>${escapeHtml(report.trustFactors.domainAge)}</strong></div>
</section>
<section style="margin:18px 0;padding:18px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22">
  <h2 style="margin:0 0 12px">Trust Level <span style="color:${trustColor(report.trustLevel)};border:1px solid ${trustColor(report.trustLevel)};border-radius:999px;padding:3px 8px;font-size:12px">${escapeHtml(report.trustLevel)}</span></h2>
  <table style="width:100%;border-collapse:collapse">${factorRows(report.trustFactors)}</table>
</section>
<section style="margin:18px 0;padding:18px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22">
  <h2 style="margin:0 0 12px">Signals</h2>
  <table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;color:rgba(255,255,255,0.55);padding:9px">Signal name</th><th style="text-align:left;color:rgba(255,255,255,0.55);padding:9px">Weight</th><th style="text-align:left;color:rgba(255,255,255,0.55);padding:9px">Category</th><th style="text-align:left;color:rgba(255,255,255,0.55);padding:9px">Detail</th></tr></thead><tbody>${signalRows(report.signals)}</tbody></table>
</section>
<section style="margin:18px 0;padding:18px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22"><h2 style="margin:0 0 12px">Recommendations</h2><ol style="margin:0;padding-left:20px">${recommendationList(report.recommendations)}</ol></section>
<section style="margin:18px 0;padding:18px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;background:#161b22"><h2 style="margin:0 0 12px">Attack Prediction</h2>${predictionRows(report.predictionFlags)}</section>
<footer style="margin-top:24px;color:rgba(255,255,255,0.55)">Generated by SentinelX Browser Security · ${escapeHtml(report.timestamp)}</footer>
</main>
</body>
</html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({
    url,
    filename: "sentinelx-" + domain + "-" + report.reportId.slice(0, 8) + ".html",
    saveAs: false
  }, () => {
    if (chrome.runtime.lastError) console.warn("Download failed", chrome.runtime.lastError);
    URL.revokeObjectURL(url);
  });
  return html;
}

function showToast(message) {
  console.log("[SentinelX]", message);
}

function copyReportAsJSON(report) {
  navigator.clipboard.writeText(JSON.stringify(report, null, 2)).then(() => {
    showToast("Report JSON copied to clipboard");
  }, () => {
    showToast("Copy failed - try Export HTML instead");
  });
}
