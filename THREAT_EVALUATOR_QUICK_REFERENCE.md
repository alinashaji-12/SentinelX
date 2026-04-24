# Threat Evaluator - Quick Reference

## TL;DR

**What:** Centralized threat alert decision engine  
**Where:** `threatEvaluator.js` (600 lines)  
**How:** One function: `evaluateThreat(result, context)`  
**Status:** ✅ Production-ready  

## The One Function You Need

```javascript
const evaluator = globalThis.SentinelThreatEvaluator;
const decision = evaluator.evaluateThreat(result, {
  url: "https://...",
  trustTier: "low"  // or "high", "medium"
});

// Returns:
// {
//   shouldAlert: true,
//   severity: "malicious",      // or "suspicious", "safe"
//   finalRisk: 75,              // 0-100
//   reasoning: ["reason 1", "reason 2", ...],
//   cooldownRequired: false,
//   cooldownDuration: 0
// }
```

## Core Features (In Priority Order)

| Feature | What It Does | When It Activates |
|---------|--------------|-------------------|
| **Hard Override** | Force malicious | If signal is `phishing_form` + confidence > 70% |
| **Signal Correlation** | Multiple weak signals = strong threat | 3+ signals weighted > 4 total |
| **Confidence Weighting** | Reduce risk if uncertain | Multiply risk × (confidence/100) |
| **Trust Moderation** | Reduce false positives on trusted domains | High-trust domains: 40% risk reduction |
| **Hysteresis** | Prevent alert flicker | Malicious won't downgrade until reload |
| **Cooldown** | Prevent alert spam | Suppress suspicious alerts for 5 seconds |

## Configuration

### Signal Weights
```javascript
// In threatEvaluator.js
SIGNAL_WEIGHTS = {
  "phishing_form": 3.5,        // Critical
  "hidden_iframe": 1.5,        // Low
  // ... 20+ types
}

// Weights sum to determine threat level:
// < 2:   ignore
// 2–4:   suspicious
// > 4:   malicious
```

### Risk Thresholds
```javascript
RISK_THRESHOLDS = {
  malicious: 80,      // >= 80 → "malicious"
  suspicious: 40,     // >= 40 → "suspicious"
  safe: 0             // < 40  → "safe"
}
```

### Trust Modifiers
```javascript
TRUST_MODIFIERS = {
  "high": 0.6,       // google.com, microsoft.com, etc.
  "medium": 1.0,     // unknown domains
  "low": 1.2         // suspicious-looking domains
}
```

### Cooldown Durations
```javascript
COOLDOWN_CONFIG = {
  "malicious": { enabled: false, duration: 0 },       // Always show
  "suspicious": { enabled: true, duration: 5000 },    // 5-second silence
  "safe": { enabled: false, duration: 0 }             // Don't alert
}
```

## Common Use Cases

### 1. Basic Alert Decision
```javascript
const result = detectionEngine.analyzeUrl("https://site.xyz");
const decision = evaluator.evaluateThreat(result);

if (decision.shouldAlert) {
  showOverlay(decision.severity, decision.reasoning);
}
```

### 2. With Trust Awareness
```javascript
const decision = evaluator.evaluateThreat(result, {
  url: "https://paypal.com",
  trustTier: "high"  // Reduces false positives
});
```

### 3. Debug/Troubleshoot
```javascript
evaluator.logEvaluation(url, decision);
// Prints detailed evaluation to console

// Check what suppressed the alert
if (!decision.shouldAlert) {
  console.log(
    decision.cooldownRequired ? "Cooldown suppressed" : "Hysteresis suppressed"
  );
}
```

### 4. Custom Threshold
```javascript
// Don't change the evaluator code — instead, adjust inputs:

// To be stricter on low-trust sites:
const decision = evaluator.evaluateThreat(result, {
  url: "...",
  trustTier: "low"  // Increases risk by 20%
});

// Or adjust detection engine confidence
result.confidence = 90;  // Make detection more confident
```

## Decision Flow (Simplified)

```
1. Check for hard override signals (phishing_form, etc.)
   ├─ If yes AND confidence > 70% → MALICIOUS ✓
   └─ If no → continue

2. Calculate signal correlation strength
   ├─ Sum weights of all signals
   └─ Classify: ignore / suspicious / malicious

3. Apply confidence weighting
   ├─ finalRisk = baseRisk × (confidence / 100)
   ├─ If confidence < 50% → further reduce by 30%
   └─ Result: adjusted risk score

4. Apply trust moderation
   ├─ High-trust domains: reduce risk by 40%
   ├─ Low-trust domains: increase risk by 20%
   └─ Result: final risk score

5. Classify severity by risk
   ├─ >= 80 → "malicious"
   ├─ >= 40 → "suspicious"
   └─ < 40  → "safe"

6. Apply hysteresis (anti-flicker)
   ├─ If last severity was "malicious" → keep "malicious"
   ├─ If last was "suspicious" → allow any
   └─ If last was "safe" → allow any

7. Check cooldown (anti-spam)
   ├─ If malicious → always alert
   ├─ If suspicious within 5s → suppress
   └─ If safe → never alert

8. Generate reasoning & return decision
```

## Red Flags (What to Check)

### "Why are safe sites being flagged as suspicious?"
1. Check `trustTier` — is it set to "high" for trusted domains?
2. Check confidence — is detection engine overly confident?
3. Check signals — are there legitimate signals being misclassified?
4. Solution: Adjust `TRUST_MODIFIERS` or detection engine thresholds

### "Why aren't malicious sites being blocked?"
1. Check signal weights — are critical signals weighted high enough?
2. Check confidence — is it above 70% for hard override?
3. Check trust moderation — is high-trust modifier too aggressive?
4. Solution: Check `HARD_SAFETY_OVERRIDES` is in signals

### "Why are alerts suppressed?"
1. Check cooldown: `decision.cooldownRequired`
2. Check hysteresis: `decision.debugInfo.afterHysteresis`
3. Check trust moderation reduced risk below threshold
4. Solution: Check dev_mode logs or adjust thresholds

## Dev Mode

**Enable:**
```javascript
chrome.storage.local.set({ dev_mode: true });
```

**Output:**
```
[Sentinel Threat Evaluation]
URL: https://...
Signals: [phishing_form, hidden_iframe]
Signal Strength: 5.0
Base Risk Score: 50
Confidence: 85
Trust Tier: low
After Confidence Weighting: 42.5
After Trust Moderation: 51.0
Final Risk: 51.0
Severity: suspicious
Should Alert: true
Reasoning:
- Multiple threat signals correlated
- Domain has low reputation
```

**Disable:**
```javascript
chrome.storage.local.set({ dev_mode: false });
```

## State Cleanup

### Clear Hysteresis (Force Fresh Decision)
```javascript
globalThis.SentinelThreatEvaluator.clearHysteresisState();
```

### Clear Cooldown (Allow Repeated Alerts)
```javascript
globalThis.SentinelThreatEvaluator.clearCooldownState();
```

## Files to Know

| File | Purpose |
|------|---------|
| `threatEvaluator.js` | Core module (modify constants here) |
| `background.js` | Integration point (search "evaluateThreat") |
| `THREAT_EVALUATOR_GUIDE.md` | Full documentation |
| `THREAT_EVALUATOR_TEST_SUITE.md` | Test cases & examples |
| `THREAT_EVALUATOR_IMPLEMENTATION.md` | Architecture & metrics |

## Quick Test

```javascript
// Copy-paste into background.js console

const evaluator = globalThis.SentinelThreatEvaluator;
console.assert(evaluator, "Not loaded");

// Test 1: Hard override
const test1 = evaluator.evaluateThreat(
  { status: "safe", score: 10, confidence: 80, signals: ["phishing_form"], reasons: [] },
  { url: "test" }
);
console.assert(test1.severity === "malicious", "Hard override failed");
console.log("✓ Test 1 passed");

// Test 2: Cooldown
const test2a = evaluator.evaluateThreat(
  { status: "suspicious", score: 50, confidence: 80, signals: ["hidden_iframe"], reasons: [] },
  { url: "same" }
);
const test2b = evaluator.evaluateThreat(
  { status: "suspicious", score: 50, confidence: 80, signals: ["hidden_iframe"], reasons: [] },
  { url: "same" }
);
console.assert(test2a.shouldAlert === true && test2b.shouldAlert === false, "Cooldown failed");
console.log("✓ Test 2 passed");

// Test 3: Trust moderation
const test3 = evaluator.evaluateThreat(
  { status: "suspicious", score: 70, confidence: 80, signals: [], reasons: [] },
  { url: "test", trustTier: "high" }
);
console.assert(test3.finalRisk < 42, "Trust moderation failed");
console.log("✓ Test 3 passed");

console.log("✅ All quick tests passed!");
```

## Support

Need help?
1. Check `THREAT_EVALUATOR_GUIDE.md` for detailed docs
2. Check `THREAT_EVALUATOR_TEST_SUITE.md` for examples
3. Enable dev_mode for detailed logs
4. Look at `threatEvaluator.js` comments

---

**Last Updated:** 2026-04-23  
**Version:** 1.0
