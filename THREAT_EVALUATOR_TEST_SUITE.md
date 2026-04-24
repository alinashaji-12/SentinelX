# Threat Evaluator Test Suite

## Test Categories

### Category 1: Core Decision Logic

#### Test 1.1: Hard Safety Override (Phishing Form)
```javascript
const result = {
  status: "suspicious",
  score: 30,
  confidence: 85,  // High confidence
  signals: ["phishing_form"],
  reasons: ["Login form detected"]
};

const decision = evaluateThreat(result, { url: "test.xyz", trustTier: "low" });

// EXPECTED:
// ✓ decision.severity === "malicious"
// ✓ decision.shouldAlert === true
// ✓ decision.finalRisk === 100
// ✓ decision.reasoning includes "Critical signals"
```

#### Test 1.2: Hard Safety Override - Clipboard Hijack
```javascript
const result = {
  status: "suspicious",
  score: 25,
  confidence: 75,
  signals: ["clipboard_hijack"],
  reasons: ["Clipboard access detected"]
};

const decision = evaluateThreat(result, { url: "test.xyz", trustTier: "medium" });

// EXPECTED:
// ✓ decision.severity === "malicious"
// ✓ decision.finalRisk === 100
```

#### Test 1.3: Hard Safety Override Blocked by Low Confidence
```javascript
const result = {
  status: "suspicious",
  score: 30,
  confidence: 45,  // Low confidence
  signals: ["phishing_form"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz", trustTier: "medium" });

// EXPECTED:
// ✓ decision.severity === "suspicious" (NOT malicious)
// ✓ decision.shouldAlert === true
// ✓ decision.finalRisk < 80
```

### Category 2: Signal Correlation

#### Test 2.1: Single Weak Signal (Below Threshold)
```javascript
const result = {
  status: "safe",
  score: 5,
  confidence: 60,
  signals: ["url_shortener"],  // Weight: 1.0
  reasons: ["URL shortener"]
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "safe"
// ✓ decision.shouldAlert === false
```

#### Test 2.2: Multiple Medium Signals (Correlation)
```javascript
const result = {
  status: "suspicious",
  score: 45,
  confidence: 70,
  signals: [
    "typosquatting",          // 2.5
    "hidden_iframe",          // 1.5
    "high_risk_tld"           // 1.5
  ],  // Total: 5.5
  reasons: ["Multiple signals"]
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "suspicious" OR "malicious"
// ✓ decision.shouldAlert === true
// ✓ decision.reasoning includes "Multiple threat signals correlated"
// ✓ decision.finalRisk >= 40
```

#### Test 2.3: Signal Strength Just Below Suspicious Threshold
```javascript
const result = {
  status: "safe",
  score: 20,
  confidence: 50,
  signals: [
    "url_shortener",          // 1.0
    "URL_encoding"            // 0.5
  ],  // Total: 1.5
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "safe"
// ✓ decision.shouldAlert === false
```

### Category 3: Confidence Weighting

#### Test 3.1: High Confidence, High Risk
```javascript
const result = {
  status: "suspicious",
  score: 60,
  confidence: 95,  // Very high
  signals: ["phishing_keyword", "login_form_on_suspicious"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "suspicious"
// ✓ decision.finalRisk >= 55  (60 * 0.95)
```

#### Test 3.2: Low Confidence Reduces Risk
```javascript
const result = {
  status: "suspicious",
  score: 60,
  confidence: 30,  // Very low
  signals: ["entropy_anomaly"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.finalRisk < 20  (60 * 0.3 * 0.7)
// ✓ decision.reasoning includes "Low confidence"
// ✓ decision.severity === "safe"
```

#### Test 3.3: Medium Confidence, Borderline Risk
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 50,
  signals: ["hidden_iframe"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.finalRisk approx 17.5  (50 * 0.5 * 0.7)
```

### Category 4: Trust-Aware Risk Moderation

#### Test 4.1: High-Trust Domain Reduces Risk
```javascript
const result = {
  status: "suspicious",
  score: 70,  // Would normally trigger malicious
  confidence: 80,
  signals: ["hidden_iframe"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "google.com/test", trustTier: "high" });

// EXPECTED:
// ✓ decision.finalRisk approx 33.6  (70 * 0.8 * 0.6)
// ✓ decision.severity === "suspicious" (NOT malicious)
```

#### Test 4.2: Low-Trust Domain Increases Risk
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 80,
  signals: ["entropy_anomaly"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "suspicious.xyz", trustTier: "low" });

// EXPECTED:
// ✓ decision.finalRisk approx 48  (50 * 0.8 * 1.2)
// ✓ decision.severity === "suspicious"
```

#### Test 4.3: Medium-Trust Domain (No Modifier)
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 80,
  signals: ["hidden_iframe"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "unknown.com", trustTier: "medium" });

// EXPECTED:
// ✓ decision.finalRisk approx 40  (50 * 0.8 * 1.0)
```

### Category 5: Alert Hysteresis (Anti-Flicker)

#### Test 5.1: Malicious Stays Malicious
```javascript
// First evaluation on URL
let decision1 = evaluateThreat({
  status: "malicious",
  score: 90,
  confidence: 90,
  signals: ["phishing_form"],
  reasons: []
}, { url: "evil.com" });

// Immediate re-evaluation with lower risk
let decision2 = evaluateThreat({
  status: "suspicious",  // Changed to suspicious
  score: 35,
  confidence: 50,
  signals: ["hidden_iframe"],
  reasons: []
}, { url: "evil.com" });

// EXPECTED:
// ✓ decision1.severity === "malicious"
// ✓ decision2.severity === "malicious"  (KEPT malicious, didn't downgrade)
// ✓ decision2.debugInfo.afterHysteresis === "malicious"
```

#### Test 5.2: Suspicious Can Downgrade to Safe
```javascript
let decision1 = evaluateThreat({
  status: "suspicious",
  score: 45,
  confidence: 70,
  signals: ["hidden_iframe"],
  reasons: []
}, { url: "maybesafe.com" });

let decision2 = evaluateThreat({
  status: "safe",
  score: 5,
  confidence: 90,
  signals: [],
  reasons: []
}, { url: "maybesafe.com" });

// EXPECTED:
// ✓ decision1.severity === "suspicious"
// ✓ decision2.severity === "safe"  (allowed to downgrade)
```

#### Test 5.3: Safe Can Upgrade to Suspicious
```javascript
let decision1 = evaluateThreat({
  status: "safe",
  score: 10,
  confidence: 80,
  signals: [],
  reasons: []
}, { url: "changing.com" });

let decision2 = evaluateThreat({
  status: "suspicious",
  score: 50,
  confidence: 90,
  signals: ["typosquatting"],
  reasons: []
}, { url: "changing.com" });

// EXPECTED:
// ✓ decision1.severity === "safe"
// ✓ decision2.severity === "suspicious"  (allowed to upgrade)
```

### Category 6: Cooldown System (Anti-Spam)

#### Test 6.1: First Suspicious Alert Shown
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 80,
  signals: ["hidden_iframe"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "repeat.com" });

// EXPECTED:
// ✓ decision.shouldAlert === true
// ✓ decision.cooldownRequired === false
```

#### Test 6.2: Immediate Repeat Suppressed by Cooldown
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 80,
  signals: ["hidden_iframe"],
  reasons: []
};

let decision1 = evaluateThreat(result, { url: "repeat.com" });
let decision2 = evaluateThreat(result, { url: "repeat.com" });  // Called immediately

// EXPECTED:
// ✓ decision1.shouldAlert === true
// ✓ decision2.shouldAlert === false
// ✓ decision2.cooldownRequired === true
// ✓ decision2.cooldownDuration === 5000  (5 seconds)
```

#### Test 6.3: Malicious Never Cools Down
```javascript
const result = {
  status: "malicious",
  score: 95,
  confidence: 90,
  signals: ["phishing_form"],
  reasons: []
};

let decision1 = evaluateThreat(result, { url: "malware.com" });
let decision2 = evaluateThreat(result, { url: "malware.com" });

// EXPECTED:
// ✓ decision1.shouldAlert === true
// ✓ decision2.shouldAlert === true  (malicious alerts always shown)
// ✓ decision2.cooldownRequired === false
```

### Category 7: Reasoning Generation

#### Test 7.1: Comprehensive Reasoning
```javascript
const result = {
  status: "suspicious",
  score: 55,
  confidence: 75,
  signals: ["phishing_keyword", "hidden_iframe", "high_risk_tld"],
  reasons: ["Login form detected", "Unusual domain structure"]
};

const decision = evaluateThreat(result, { url: "test.xyz", trustTier: "low" });

// EXPECTED:
// ✓ Array.isArray(decision.reasoning)
// ✓ decision.reasoning.length >= 2
// ✓ decision.reasoning includes text mentioning signals OR detection engine reasons
```

#### Test 7.2: Hard Override Reasoning
```javascript
const result = {
  status: "safe",
  score: 10,
  confidence: 80,
  signals: ["clipboard_hijack"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.reasoning.some(r => r.includes("CRITICAL") || r.includes("override"))
// ✓ decision.reasoning.some(r => r.includes("clipboard"))
```

#### Test 7.3: Low Confidence Warning
```javascript
const result = {
  status: "suspicious",
  score: 45,
  confidence: 25,
  signals: ["entropy_anomaly"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.reasoning.some(r => r.toLowerCase().includes("low confidence"))
// ✓ decision.reasoning.some(r => r.toLowerCase().includes("false positive"))
```

### Category 8: Edge Cases & Error Handling

#### Test 8.1: Null Result
```javascript
const decision = evaluateThreat(null, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "safe"
// ✓ decision.shouldAlert === false
// ✓ decision.finalRisk === 0
```

#### Test 8.2: Missing Signals
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 80
  // signals field missing
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ No exception thrown
// ✓ decision is valid object
// ✓ decision.finalRisk > 0 (uses base score)
```

#### Test 8.3: Invalid Confidence (> 100)
```javascript
const result = {
  status: "suspicious",
  score: 50,
  confidence: 150,  // Out of range
  signals: ["hidden_iframe"],
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ No exception thrown
// ✓ decision.finalRisk correctly clamped (confidence treated as 100)
```

#### Test 8.4: Empty Signals Array
```javascript
const result = {
  status: "safe",
  score: 5,
  confidence: 80,
  signals: [],  // Empty
  reasons: []
};

const decision = evaluateThreat(result, { url: "test.xyz" });

// EXPECTED:
// ✓ decision.severity === "safe"
// ✓ decision.shouldAlert === false
```

## Integration Tests

### Integration Test A: Real Detection Engine Output

```javascript
// Run analyzeUrl from detectionEngine
const detectionResult = globalThis.SentinelDetectionEngine.analyzeUrl(
  "https://paypal-update-account.xyz"
);

// Pass through evaluator
const decision = globalThis.SentinelThreatEvaluator.evaluateThreat(detectionResult, {
  url: detectionResult.normalized || "https://paypal-update-account.xyz",
  trustTier: "low",
  userProfile: { sensitivityLevel: "high" }
});

// EXPECTED:
// ✓ decision.severity in ["safe", "suspicious", "malicious"]
// ✓ decision.finalRisk is number between 0-100
// ✓ Array.isArray(decision.reasoning)
// ✓ typeof decision.shouldAlert === "boolean"
```

### Integration Test B: Overlay Message Delivery

```javascript
// Simulate background.js flow
const url = "https://suspicious-site.xyz";
const result = analyzeUrl(url);  // From detection engine

// Apply evaluator
const evaluator = globalThis.SentinelThreatEvaluator;
const threatDecision = evaluator.evaluateThreat(result, {
  url: url,
  trustTier: "medium"
});

// Build payload like background.js does
const payload = {
  type: "sentinel:show-overlay",
  status: threatDecision.severity,
  reasons: threatDecision.reasoning.slice(0, 3),
  finalRisk: threatDecision.finalRisk,
  shouldAlert: threatDecision.shouldAlert
};

// EXPECTED (for malicious):
// ✓ payload.type === "sentinel:show-overlay"
// ✓ payload.status === "malicious" OR "suspicious"
// ✓ Array.isArray(payload.reasons)
// ✓ payload.finalRisk >= 40 (for suspicious) or >= 80 (for malicious)
```

### Integration Test C: Dev Mode Logging

```javascript
// Enable dev mode
chrome.storage.local.set({ dev_mode: true });

const result = analyzeUrl("https://test-phishing.com");
const decision = globalThis.SentinelThreatEvaluator.evaluateThreat(result, {
  url: "https://test-phishing.com"
});

// Log should be printed
globalThis.SentinelThreatEvaluator.logEvaluation(
  "https://test-phishing.com",
  decision
);

// EXPECTED (in console):
// [Sentinel Threat Evaluation]
// URL: https://test-phishing.com
// Signals: [...]
// Signal Strength: X
// ... (complete analysis)
```

## Test Execution Guide

### Manual Testing

1. **Setup:**
   ```javascript
   // In background.js dev console
   const evaluator = globalThis.SentinelThreatEvaluator;
   console.assert(evaluator, "Threat evaluator not loaded");
   ```

2. **Run Individual Test:**
   ```javascript
   // Test 1.1: Hard Safety Override
   const result = {
     status: "suspicious",
     score: 30,
     confidence: 85,
     signals: ["phishing_form"],
     reasons: ["Login form detected"]
   };

   const decision = evaluator.evaluateThreat(result, {
     url: "test.xyz",
     trustTier: "low"
   });

   console.assert(decision.severity === "malicious", "Should be malicious");
   console.assert(decision.finalRisk === 100, "Risk should be 100");
   ```

3. **Check Console Output:**
   - Look for assertion errors
   - Verify no uncaught exceptions
   - Check dev_mode logs for details

### Automated Testing (Jest/Mocha)

```javascript
// test/threatEvaluator.test.js
describe("ThreatEvaluator", () => {
  let evaluator;

  beforeEach(() => {
    // Import threatEvaluator.js
    evaluator = globalThis.SentinelThreatEvaluator;
  });

  describe("Hard Safety Override", () => {
    it("should force malicious on phishing_form with high confidence", () => {
      const result = {
        status: "safe",
        score: 10,
        confidence: 80,
        signals: ["phishing_form"],
        reasons: []
      };

      const decision = evaluator.evaluateThreat(result, { url: "test" });

      expect(decision.severity).toBe("malicious");
      expect(decision.shouldAlert).toBe(true);
      expect(decision.finalRisk).toBe(100);
    });

    it("should NOT override when confidence < 70%", () => {
      const result = {
        status: "safe",
        score: 10,
        confidence: 50,
        signals: ["phishing_form"],
        reasons: []
      };

      const decision = evaluator.evaluateThreat(result, { url: "test" });

      expect(decision.severity).not.toBe("malicious");
    });
  });

  // ... more test suites
});
```

## Regression Testing Checklist

After making changes to threatEvaluator.js:

- [ ] All 8 test categories pass
- [ ] Backward compatibility maintained (old payload formats work)
- [ ] No new console warnings/errors
- [ ] Hysteresis state properly isolated per URL
- [ ] Cooldown state properly cleared after expiration
- [ ] High-trust domains reduce false positives
- [ ] Hard safety overrides work reliably
- [ ] Dev mode logging is informative and correct
- [ ] Performance < 5ms per call
- [ ] Memory usage stable over 100+ URLs

---

**Test Suite Version:** 1.0  
**Last Updated:** 2026-04-23
