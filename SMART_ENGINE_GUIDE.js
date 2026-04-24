/**
 * SMART ENGINE IMPLEMENTATION GUIDE
 *
 * Strategy: Let requests through, analyze dynamically, redirect if malicious
 *
 * 1. declarativeNetRequest rules = fallback/quick blocks
 * 2. chrome.tabs.onUpdated = intelligent analysis trigger
 * 3. Risk scoring engine = dynamic verdict
 * 4. chrome.tabs.update() = manual redirect if needed
 */

import { analyzeRisk, mapVerdictToStatus } from "./detection/riskScoring.js";

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1: Listen for Tab Updates
// ─────────────────────────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only analyze when page is loading
  if (changeInfo.status !== "loading") return;

  const url = tab.url || changeInfo.url;
  if (!url) return;

  // Analyze URL with smart engine
  analyzeAndRespond(tabId, url);
});

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2: Analyze URL with Smart Risk Scoring
// ─────────────────────────────────────────────────────────────────────────────

async function analyzeAndRespond(tabId, url) {
  try {
    // Extract signals from detection modules
    const signals = await extractSignals(url);

    // Get pro-level risk analysis
    const analysis = analyzeRisk(signals, signals.keywordMatches || []);
    const verdict = mapVerdictToStatus(analysis.verdict);

    // Store result for popup display
    await chrome.storage.local.set({
      [`analysis_${tabId}`]: {
        url,
        verdict: analysis.verdict,
        confidence: analysis.confidence,
        attackType: analysis.attackType,
        explanation: analysis.explanation,
        reasons: analysis.reasons,
        status: verdict.status,
        trustScore: verdict.trustScore,
      }
    });

    // STEP 3: Respond to malicious URLs
    if (verdict.status === "malicious") {
      redirectToWarning(tabId, url, analysis);
    } else if (verdict.status === "suspicious") {
      showWarning(tabId, url, analysis);
    }

  } catch (error) {
    console.error("[Sentinel] Analysis error:", error);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3a: Redirect Malicious URLs
// ─────────────────────────────────────────────────────────────────────────────

function redirectToWarning(tabId, url, analysis) {
  // Create warning page with threat info
  const warningUrl = chrome.runtime.getURL("warning.html") +
    "?url=" + encodeURIComponent(url) +
    "&type=" + encodeURIComponent(analysis.attackType) +
    "&confidence=" + analysis.confidence;

  // Redirect tab to warning page
  chrome.tabs.update(tabId, { url: warningUrl });

  // Log incident
  logThreat(url, analysis);
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3b: Show Warning for Suspicious URLs
// ─────────────────────────────────────────────────────────────────────────────

function showWarning(tabId, url, analysis) {
  // Inject content script to show warning banner
  chrome.tabs.sendMessage(tabId, {
    action: "showWarning",
    url,
    analysis: {
      attackType: analysis.attackType,
      confidence: analysis.confidence,
      explanation: analysis.explanation,
      reasons: analysis.reasons,
    }
  }).catch(() => {
    // Content script not loaded yet, that's ok
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 4: Extract Signals from URL
// ─────────────────────────────────────────────────────────────────────────────

async function extractSignals(url) {
  const lowerUrl = url.toLowerCase();
  const hostname = new URL(url).hostname;

  // Run all detection modules in parallel
  const [
    intentResult,
    domainResult,
    obfuscResult,
    safeBrowsingResult,
    datasetResult,
  ] = await Promise.allSettled([
    detectPhishingIntent(url),
    detectDomainAnomaly(hostname),
    detectObfuscation(url),
    checkSafeBrowsing(url),
    checkDataset(hostname),
  ]).then(results =>
    results.map(r => r.status === "fulfilled" ? r.value : {})
  );

  // Convert module results to signal format
  return {
    hasPhishingKeywords: intentResult.hasIntent || false,
    hasSuspiciousTLD: domainResult.hasSuspiciousTLD || false,
    hasObfuscation: obfuscResult.isObfuscated || false,
    hasIP: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname),
    hasLongURL: url.length > 200,
    hasRedirectParam: url.includes("url=") || url.includes("redirect="),
    hasSafeBrowsing: safeBrowsingResult.isMalicious || false,
    hasDataset: datasetResult.flag || false,
    hasDomainAnomaly: domainResult.flag || false,

    // Include details for explanation
    keywordMatches: intentResult.phishingKeywords || [],
    attackType: intentResult.attackType,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection Module Stubs (replace with actual implementations)
// ─────────────────────────────────────────────────────────────────────────────

async function detectPhishingIntent(url) {
  // TODO: Integrate with your ML model or keyword detection
  return {
    hasIntent: false,
    phishingKeywords: [],
    attackType: "SAFE",
  };
}

async function detectDomainAnomaly(hostname) {
  // TODO: Integrate with your domain behavior analysis
  return {
    flag: false,
    hasSuspiciousTLD: false,
    reason: "No anomalies detected",
  };
}

async function detectObfuscation(url) {
  // TODO: Integrate with your obfuscation detection
  return {
    isObfuscated: false,
    reason: "No obfuscation detected",
  };
}

async function checkSafeBrowsing(url) {
  // TODO: Call Google Safe Browsing API or local database
  return {
    isMalicious: false,
  };
}

async function checkDataset(hostname) {
  // TODO: Check against phishing/malware datasets
  return {
    flag: false,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging & Metrics
// ─────────────────────────────────────────────────────────────────────────────

async function logThreat(url, analysis) {
  const now = new Date().toISOString();

  const threat = {
    timestamp: now,
    url,
    attackType: analysis.attackType,
    confidence: analysis.confidence,
    verdict: analysis.verdict,
  };

  // Store in local storage for dashboard/reports
  const { threats = [] } = await chrome.storage.local.get("threats");
  threats.push(threat);

  // Keep only last 1000 threats
  if (threats.length > 1000) {
    threats.shift();
  }

  await chrome.storage.local.set({ threats });

  console.log(`[Sentinel] Threat logged: ${analysis.verdict} - ${url}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean up old analysis data
// ─────────────────────────────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`analysis_${tabId}`);
});

console.log("[Sentinel] Smart engine initialized");
