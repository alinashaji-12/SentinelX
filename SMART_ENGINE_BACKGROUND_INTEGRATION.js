/**
 * INTEGRATION: Add This to background.js
 *
 * This shows how to integrate the smart engine with your existing background.js
 */

// ─────────────────────────────────────────────────────────────────────────────
// ADD TO YOUR IMPORTS (at top of background.js)
// ─────────────────────────────────────────────────────────────────────────────

/*
// Remove "type":"module" from manifest.json to use classic scripts
// Instead, import functions inline via dynamic import or service worker event

import { analyzeRisk, mapVerdictToStatus } from "./detection/riskScoring.js";
*/

// ─────────────────────────────────────────────────────────────────────────────
// ADD THIS SECTION to background.js (after your existing listeners)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Smart Engine: Monitor tab updates and analyze URLs dynamically
 *
 * This listener:
 * 1. Triggers when a tab starts loading
 * 2. Analyzes the URL with your risk-scoring engine
 * 3. Redirects to warning page if malicious
 * 4. Shows banner if suspicious
 */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only analyze when page is loading
  if (changeInfo.status !== "loading") return;

  const url = tab.url || changeInfo.url;
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) return;

  // Analyze URL with smart detection
  analyzeUrlAndRespond(tabId, url);
});

// ─────────────────────────────────────────────────────────────────────────────
// Main Analysis Function
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyzes URL and responds appropriately:
 * - MALICIOUS: Redirect to warning page
 * - SUSPICIOUS: Show warning banner
 * - SAFE: Allow navigation
 */
async function analyzeUrlAndRespond(tabId, url) {
  try {
    // Step 1: Extract signals from URL using your existing detection modules
    const signals = extractSignalsFromUrl(url);

    // Step 2: Get pro-level risk analysis
    // NOTE: This requires importing riskScoring.js
    // For now, use your existing advancedEngine.js logic
    const analysis = analyzeUrlWithRiskScoring(signals);

    // Step 3: Store result for popup/dashboard
    await chrome.storage.local.set({
      [`result_${tabId}`]: {
        url,
        analysis,
        timestamp: new Date().toISOString(),
      }
    });

    // Step 4: Take action based on verdict
    if (analysis.status === "malicious") {
      redirectToWarning(tabId, url, analysis);
    } else if (analysis.status === "suspicious") {
      showWarningBanner(tabId, url, analysis);
    }

  } catch (error) {
    console.error("[Sentinel] Error analyzing URL:", error);
    // Fail open: allow navigation on error
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal Extraction (use your existing detection modules)
// ─────────────────────────────────────────────────────────────────────────────

function extractSignalsFromUrl(url) {
  return {
    // From your ML model
    hasPhishingKeywords: detectKeywords(url),

    // From your domain analysis
    hasSuspiciousTLD: detectSuspiciousTLD(url),
    hasDomainAnomaly: false, // Set by your behavior.js

    // From obfuscation detection
    hasObfuscation: detectObfuscation(url),

    // Simple checks
    hasIP: /^(\d{1,3}\.){3}\d{1,3}$/.test(new URL(url).hostname),
    hasLongURL: url.length > 200,
    hasRedirectParam: url.includes("url=") || url.includes("redirect="),

    // External checks (would be async in production)
    hasSafeBrowsing: false, // Set by your safebrowsing.js
    hasDataset: false,      // Set by your dataset.js
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Redirect to Warning Page (MALICIOUS)
// ─────────────────────────────────────────────────────────────────────────────

function redirectToWarning(tabId, url, analysis) {
  // Build warning page URL with threat info
  const warningUrl = chrome.runtime.getURL("warning.html") +
    "?url=" + encodeURIComponent(url) +
    "&type=" + encodeURIComponent(analysis.attackType) +
    "&confidence=" + analysis.confidence +
    "&reason=" + encodeURIComponent(analysis.reason);

  // Redirect the tab
  chrome.tabs.update(tabId, { url: warningUrl });

  // Log the threat
  logThreatDetection({
    url,
    type: analysis.attackType,
    confidence: analysis.confidence,
    status: "blocked",
  });

  console.log(`[Sentinel] BLOCKED: ${analysis.attackType} - ${url}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Show Warning Banner (SUSPICIOUS)
// ─────────────────────────────────────────────────────────────────────────────

function showWarningBanner(tabId, url, analysis) {
  // Send message to content script to show warning
  chrome.tabs.sendMessage(tabId, {
    action: "showWarning",
    data: {
      url,
      attackType: analysis.attackType,
      confidence: analysis.confidence,
      explanation: analysis.explanation,
      reasons: analysis.reasons,
    }
  }).catch(() => {
    // Content script not ready yet, that's fine
  });

  console.log(`[Sentinel] WARNED: ${analysis.attackType} - ${url}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk Scoring (integrate with your riskScoring.js)
// ─────────────────────────────────────────────────────────────────────────────

function analyzeUrlWithRiskScoring(signals) {
  // TODO: Import and call analyzeRisk from riskScoring.js
  // For now, use your existing advancedEngine.js logic

  // Calculate score based on signals
  let score = 0;
  if (signals.hasSafeBrowsing) score += 6;
  if (signals.hasDataset) score += 5;
  if (signals.hasPhishingKeywords) score += 3;
  if (signals.hasDomainAnomaly) score += 2;
  if (signals.hasObfuscation) score += 2;
  if (signals.hasIP) score += 3;
  if (signals.hasRedirectParam) score += 2;

  // Determine status
  let status = "safe";
  if (score >= 6) status = "malicious";
  else if (score >= 3) status = "suspicious";

  return {
    status,
    score,
    confidence: score >= 6 ? 85 : score >= 3 ? 60 : 25,
    attackType: determineAttackType(signals),
    explanation: buildExplanation(signals),
    reasons: buildReasons(signals),
    reason: "See reasons array",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions (use your existing keyword/TLD detection)
// ─────────────────────────────────────────────────────────────────────────────

function detectKeywords(url) {
  // Use your existing PHISHING_KEYWORDS set
  const keywords = ["login", "verify", "account", "secure", "password"];
  return keywords.some(kw => url.toLowerCase().includes(kw));
}

function detectSuspiciousTLD(url) {
  // Use your existing HIGH_RISK_TLDS set
  const riskTLDs = ["xyz", "tk", "ml", "ga"];
  const hostname = new URL(url).hostname;
  return riskTLDs.some(tld => hostname.endsWith("." + tld));
}

function detectObfuscation(url) {
  // Use your existing obfuscation detection module
  return url.includes("%") || url.includes("punycode");
}

function determineAttackType(signals) {
  if (signals.hasPhishingKeywords && signals.hasDomainAnomaly) return "PHISHING";
  if (signals.hasSafeBrowsing || signals.hasDataset) return "MALWARE";
  if (signals.hasObfuscation) return "OBFUSCATED_URL";
  return "SAFE";
}

function buildExplanation(signals) {
  if (signals.hasSafeBrowsing) return "Google Safe Browsing flagged this site";
  if (signals.hasPhishingKeywords && signals.hasDomainAnomaly) {
    return "This URL exhibits phishing attack characteristics";
  }
  return "This URL has suspicious characteristics";
}

function buildReasons(signals) {
  const reasons = [];
  if (signals.hasSafeBrowsing) reasons.push("Known malicious site (Safe Browsing)");
  if (signals.hasPhishingKeywords) reasons.push("Contains phishing keywords");
  if (signals.hasDomainAnomaly) reasons.push("Suspicious domain structure");
  if (signals.hasObfuscation) reasons.push("Uses URL obfuscation");
  if (signals.hasIP) reasons.push("Uses raw IP address");
  return reasons;
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat Logging (for dashboard/reporting)
// ─────────────────────────────────────────────────────────────────────────────

async function logThreatDetection(threat) {
  const { threats = [] } = await chrome.storage.local.get("threats");

  threats.push({
    ...threat,
    timestamp: new Date().toISOString(),
  });

  // Keep only last 500 threats
  if (threats.length > 500) {
    threats.shift();
  }

  await chrome.storage.local.set({ threats });
}

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup (remove old analysis data when tab closes)
// ─────────────────────────────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`result_${tabId}`);
});

console.log("[Sentinel] Smart detection engine initialized");
