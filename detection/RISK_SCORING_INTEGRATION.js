/**
 * INTEGRATION GUIDE: Pro-Level Risk Scoring
 *
 * This example shows how to use the new riskScoring.js module
 * alongside your existing detection engine.
 */

import { analyzeRisk, mapVerdictToStatus } from "./detection/riskScoring.js";

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 1: Simple URL Analysis
// ─────────────────────────────────────────────────────────────────────────────

function analyzeURLSimple(url, detectionResults) {
  // Extract signals from your existing detection modules
  const signals = {
    hasPhishingKeywords: detectionResults.mlResult?.hasIntent || false,
    hasSuspiciousTLD: detectionResults.domainResult?.hasSuspiciousTLD || false,
    hasObfuscation: detectionResults.obfuscationResult?.isObfuscated || false,
    hasIP: detectionResults.usesIPAddress || false,
    hasLongURL: url.length > 200,
    hasRedirectParam: url.includes("redirect=") || url.includes("url="),
    hasSafeBrowsing: detectionResults.safeBrowsingResult?.isMalicious || false,
    hasDataset: detectionResults.datasetResult?.flag || false,
    hasDomainAnomaly: detectionResults.behaviorResult?.flag || false,
  };

  // Analyze risk
  const analysis = analyzeRisk(signals, detectionResults.mlResult?.phishingKeywords || []);

  // Convert to standard output format
  const status = mapVerdictToStatus(analysis.verdict);

  return {
    status: status.status,              // "safe" | "suspicious" | "malicious"
    trustScore: status.trustScore,      // 10-95
    confidence: analysis.confidence,    // 0-100
    attackType: analysis.attackType,    // MALWARE | PHISHING | etc.
    explanation: analysis.explanation,  // Human-readable
    reasons: analysis.reasons,          // Array of specific reasons
    score: analysis.score,              // Raw 0-10 score
    verdict: analysis.verdict,          // SAFE | CAUTION | SUSPICIOUS | MALICIOUS
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 2: Batch Analysis (for reports/dashboards)
// ─────────────────────────────────────────────────────────────────────────────

function analyzeBatch(urls) {
  return urls.map(url => {
    const analysis = analyzeRisk(extractSignals(url), []);
    return {
      url,
      verdict: analysis.verdict,
      confidence: analysis.confidence,
      attackType: analysis.attackType,
      needsReview: analysis.needsReview,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 3: Real-time Content Script Integration
// ─────────────────────────────────────────────────────────────────────────────

// In your content.js or popup:
function updateUIWithRiskAnalysis(verdict, analysis) {
  const ui = {
    icon: getIcon(analysis.verdict),
    color: getColor(analysis.verdict),
    message: analysis.explanation,
    confidence: `${analysis.confidence}% confident`,
    details: analysis.reasons.map(r => `• ${r}`).join("\n"),
  };

  // Render UI based on verdict
  if (analysis.verdict === "MALICIOUS") {
    showBlockingWarning(ui);
  } else if (analysis.verdict === "SUSPICIOUS") {
    showCautionWarning(ui);
  } else if (analysis.verdict === "CAUTION") {
    showMinorWarning(ui);
  }
}

function getIcon(verdict) {
  const icons = {
    SAFE: "✓",
    CAUTION: "ℹ️",
    SUSPICIOUS: "⚠️",
    MALICIOUS: "🚨",
  };
  return icons[verdict] || "?";
}

function getColor(verdict) {
  const colors = {
    SAFE: "#388e3c",      // Green
    CAUTION: "#1976d2",   // Blue
    SUSPICIOUS: "#f57c00", // Orange
    MALICIOUS: "#d32f2f", // Red
  };
  return colors[verdict] || "#808080";
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 4: Comparative Analysis (current vs. new scoring)
// ─────────────────────────────────────────────────────────────────────────────

function compareScoring(url, modernResult, legacyResult) {
  console.log("Modern Risk Scoring:");
  console.log(`  Verdict: ${modernResult.verdict}`);
  console.log(`  Confidence: ${modernResult.confidence}%`);
  console.log(`  Score: ${modernResult.score}/10`);

  console.log("\nLegacy Scoring:");
  console.log(`  Status: ${legacyResult.status}`);
  console.log(`  Trust: ${legacyResult.trustScore}`);
  console.log(`  Confidence: ${legacyResult.confidence}%`);

  // Check for divergence
  if (modernResult.verdict !== legacyResult.status) {
    console.warn("⚠️ DIVERGENCE DETECTED: Modern and legacy scoring disagree!");
    console.log(`  Modern says: ${modernResult.verdict}`);
    console.log(`  Legacy says: ${legacyResult.status}`);
    console.log(`  Reason: Check signal extraction or weighting`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// QUICK START: Copy this into your detection code
// ─────────────────────────────────────────────────────────────────────────────

/*

// In your background.js or main detector:

import { analyzeRisk, mapVerdictToStatus } from "./detection/riskScoring.js";

function detectUrl(url, moduleResults) {
  // Your existing signal extraction
  const signals = {
    hasPhishingKeywords: moduleResults.intent?.hasKeywords || false,
    hasSuspiciousTLD: /* your TLD check */ false,
    hasObfuscation: moduleResults.obfuscation?.isObfuscated || false,
    hasIP: /* your IP check */ false,
    hasLongURL: url.length > 200,
    hasRedirectParam: url.includes("url=") || url.includes("redirect="),
    hasSafeBrowsing: moduleResults.sb?.isMalicious || false,
    hasDataset: moduleResults.dataset?.flag || false,
    hasDomainAnomaly: moduleResults.domain?.flag || false,
  };

  // Get pro-level analysis
  const analysis = analyzeRisk(signals, moduleResults.intent?.keywords || []);

  // Convert to your output format
  const verdict = mapVerdictToStatus(analysis.verdict);

  return {
    status: verdict.status,
    trustScore: verdict.trustScore,
    confidence: analysis.confidence,
    attackType: analysis.attackType,
    explanation: analysis.explanation,
    reasons: analysis.reasons,
    score: analysis.score,
  };
}

*/
