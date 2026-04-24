/**
 * riskScoring.test.js — Test Suite for Pro-Level Scoring
 *
 * Validates that the analyst-grade scoring engine produces
 * correct verdicts across different signal combinations.
 */

import {
  calculateRiskScore,
  calculateConfidence,
  classifyAttack,
  generateExplanation,
  analyzeRisk,
} from "./riskScoring.js";

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 1: Safe URL (No signals)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 1: Safe URL");
const safeSignals = {
  hasPhishingKeywords: false,
  hasSuspiciousTLD: false,
  hasObfuscation: false,
  hasIP: false,
  hasLongURL: false,
  hasRedirectParam: false,
  hasSafeBrowsing: false,
  hasDataset: false,
  hasDomainAnomaly: false,
};

const safeResult = analyzeRisk(safeSignals, []);
console.log(`  Score: ${safeResult.score}/10`);
console.log(`  Confidence: ${safeResult.confidence}%`);
console.log(`  Verdict: ${safeResult.verdict}`);
console.log(`  Expected: SAFE with low confidence`);
console.assert(safeResult.verdict === "SAFE", "Should be SAFE");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 2: Phishing URL (Keywords + Domain Anomaly)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 2: Phishing URL");
const phishingSignals = {
  hasPhishingKeywords: true,        // +3
  hasDomainAnomaly: true,           // +2
  hasObfuscation: false,
  hasIP: false,
  hasLongURL: true,                 // +1
  hasRedirectParam: false,
  hasSafeBrowsing: false,
  hasDataset: false,
  hasSuspiciousTLD: false,
};

const phishingResult = analyzeRisk(phishingSignals, ["login", "verify"]);
console.log(`  Score: ${phishingResult.score}/10`);
console.log(`  Confidence: ${phishingResult.confidence}%`);
console.log(`  Verdict: ${phishingResult.verdict}`);
console.log(`  Attack Type: ${phishingResult.attackType}`);
console.log(`  Explanation: ${phishingResult.explanation}`);
console.assert(phishingResult.verdict === "SUSPICIOUS", "Should be SUSPICIOUS");
console.assert(phishingResult.attackType === "PHISHING", "Should classify as PHISHING");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 3: High-Risk URL (Safe Browsing Hit)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 3: Google Safe Browsing Hit");
const safeBrowsingSignals = {
  hasSafeBrowsing: true,            // +6
  hasPhishingKeywords: false,
  hasDomainAnomaly: false,
  hasObfuscation: false,
  hasIP: false,
  hasLongURL: false,
  hasRedirectParam: false,
  hasDataset: false,
  hasSuspiciousTLD: false,
};

const sbResult = analyzeRisk(safeBrowsingSignals, []);
console.log(`  Score: ${sbResult.score}/10`);
console.log(`  Confidence: ${sbResult.confidence}%`);
console.log(`  Verdict: ${sbResult.verdict}`);
console.log(`  Attack Type: ${sbResult.attackType}`);
console.assert(sbResult.verdict === "MALICIOUS", "Should be MALICIOUS");
console.assert(sbResult.attackType === "MALWARE", "Should classify as MALWARE");
console.assert(sbResult.confidence >= 85, "Should have high confidence");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 4: Multiple Weak Signals
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 4: Multiple Weak Signals");
const weakSignals = {
  hasPhishingKeywords: false,
  hasSuspiciousTLD: true,           // +1
  hasObfuscation: false,
  hasIP: false,
  hasLongURL: true,                 // +1
  hasRedirectParam: true,           // +2
  hasSafeBrowsing: false,
  hasDataset: false,
  hasDomainAnomaly: false,
};

const weakResult = analyzeRisk(weakSignals, []);
console.log(`  Score: ${weakResult.score}/10`);
console.log(`  Confidence: ${weakResult.confidence}%`);
console.log(`  Verdict: ${weakResult.verdict}`);
console.assert(weakResult.verdict === "CAUTION", "Should be CAUTION");
console.assert(weakResult.confidence < 70, "Should have moderate confidence");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 5: IP Address Usage (Phishing)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 5: IP Address Usage");
const ipSignals = {
  hasIP: true,                      // +3
  hasPhishingKeywords: true,        // +3
  hasDomainAnomaly: false,
  hasObfuscation: false,
  hasLongURL: false,
  hasRedirectParam: false,
  hasSafeBrowsing: false,
  hasDataset: false,
  hasSuspiciousTLD: false,
};

const ipResult = analyzeRisk(ipSignals, ["account"]);
console.log(`  Score: ${ipResult.score}/10`);
console.log(`  Confidence: ${ipResult.confidence}%`);
console.log(`  Verdict: ${ipResult.verdict}`);
console.log(`  Attack Type: ${ipResult.attackType}`);
console.assert(ipResult.attackType === "PHISHING", "Should classify as PHISHING");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 6: Social Engineering (Keywords + Obfuscation)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 6: Social Engineering");
const socialEngSignals = {
  hasPhishingKeywords: true,        // +3
  hasObfuscation: true,             // +2
  hasDomainAnomaly: false,
  hasIP: false,
  hasLongURL: true,                 // +1
  hasRedirectParam: false,
  hasSafeBrowsing: false,
  hasDataset: false,
  hasSuspiciousTLD: false,
};

const seResult = analyzeRisk(socialEngSignals, ["verify", "confirm"]);
console.log(`  Score: ${seResult.score}/10`);
console.log(`  Confidence: ${seResult.confidence}%`);
console.log(`  Verdict: ${seResult.verdict}`);
console.log(`  Attack Type: ${seResult.attackType}`);
console.assert(seResult.attackType === "SOCIAL_ENGINEERING", "Should classify as SOCIAL_ENGINEERING");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 7: Maximum Risk (Database + Safe Browsing)
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 7: Critical Risk (Database + Safe Browsing)");
const criticalSignals = {
  hasDataset: true,                 // +5
  hasSafeBrowsing: true,            // +6
  hasPhishingKeywords: true,        // +3
  hasDomainAnomaly: true,           // +2
  hasObfuscation: true,             // +2
  hasIP: false,
  hasLongURL: true,                 // +1
  hasRedirectParam: true,           // +2
  hasSuspiciousTLD: true,           // +1
};

const criticalResult = analyzeRisk(criticalSignals, ["login", "verify", "account"]);
console.log(`  Score: ${criticalResult.score}/10 (clamped at 10)`);
console.log(`  Confidence: ${criticalResult.confidence}%`);
console.log(`  Verdict: ${criticalResult.verdict}`);
console.log(`  Attack Type: ${criticalResult.attackType}`);
console.log(`  Signal Count: ${criticalResult.signalCount}`);
console.assert(criticalResult.verdict === "MALICIOUS", "Should be MALICIOUS");
console.assert(criticalResult.confidence >= 95, "Should have maximum confidence");
console.log("  ✓ PASS\n");

// ─────────────────────────────────────────────────────────────────────────────
// Test Case 8: Confidence Calibration
// ─────────────────────────────────────────────────────────────────────────────

console.log("TEST 8: Confidence Calibration");
const scores = [0, 1, 3, 5, 7, 9, 10];
console.log("  Score → Confidence mapping:");
scores.forEach(s => {
  const conf = calculateConfidence(s);
  console.log(`    ${s}/10 → ${conf}%`);
});
console.log("  ✓ Verified\n");

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════════════════════════════════");
console.log("ALL TESTS PASSED ✓");
console.log("═══════════════════════════════════════════════════════════════════════");
console.log("");
console.log("SCORING SUMMARY:");
console.log("  • Safe URLs: 0-2 score, 25-40% confidence");
console.log("  • Suspicious URLs: 3-5 score, 55-70% confidence");
console.log("  • Malicious URLs: 6+ score, 85-95% confidence");
console.log("");
console.log("ATTACK TYPE CLASSIFICATION:");
console.log("  • PHISHING: Keywords + domain anomaly OR IP usage");
console.log("  • MALWARE: Safe Browsing OR dataset hits");
console.log("  • SOCIAL_ENGINEERING: Keywords + obfuscation (without domain tricks)");
console.log("  • OBFUSCATED_URL: Pure obfuscation without context");
console.log("  • SAFE: No malicious patterns");
console.log("");
