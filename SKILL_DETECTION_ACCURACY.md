# SKILL: Detection Accuracy Improvement & False Positive Elimination

**Expert Level:** Senior Cybersecurity Engineer  
**Domain:** Browser-based phishing & malware detection  
**Objective:** Eliminate false positives while maintaining threat detection integrity  

---

## PROBLEM STATEMENT

### Current Issues
1. **False Positives on Legitimate Sites**
   - Clipboard events on Google Docs, GitHub, Notion flagged as hijacking
   - Single weak signal (e.g., long URL) triggers HIGH-risk overlay
   - Trusted domain + low-confidence behavior = inappropriate alert

2. **Inconsistent Risk Scoring**
   - UI messages contradict trust scores ("low trust" but 100/100 score)
   - Single behavioral event can push score > 60 despite low confidence
   - No weighting based on signal reliability

3. **Lack of Context Awareness**
   - User-initiated clipboard writes treated same as automated writes
   - Legitimate redirects (e.g., OAuth flows) flagged identically to malicious chains
   - No confidence levels on individual signals

---

## SOLUTION ARCHITECTURE

### Phase 1: Behavioral Signal Confidence System

**Every behavior detection must include:**
```javascript
{
  type: "clipboard_hijack" | "redirect_chain" | "auto_download" | etc,
  confidence: "LOW" | "MEDIUM" | "HIGH",
  severity: "LOW" | "MEDIUM" | "HIGH",
  userInitiated: boolean,
  context: { /* signal-specific metadata */ }
}
```

**Confidence Rules by Signal Type:**

#### Clipboard Events
- **HIGH confidence** → Clipboard modified WITHOUT any user interaction AND unknown context
- **MEDIUM confidence** → Modified with timing ambiguity (within 500ms of user action)
- **LOW confidence** → Triggered by explicit user event (copy/paste click) OR trusted domain

#### Redirect Chains
- **HIGH confidence** → 3+ rapid redirects (< 2s intervals) to different domains
- **MEDIUM confidence** → 2 redirects with suspicious destination patterns
- **LOW confidence** → 1 redirect OR known OAuth/login flow OR trusted domain chain

#### Auto Downloads
- **HIGH confidence** → File download WITHOUT user interaction
- **MEDIUM confidence** → Download initiated by script after user click
- **LOW confidence** → User-initiated download click

#### Domain Structure
- **HIGH confidence** → Multiple overlapping anomalies (homograph + high-risk TLD + excessive hyphens)
- **MEDIUM confidence** → Single strong indicator (homograph match OR SafeBrowsing flag)
- **LOW confidence** → Isolated weak signal (unusual TLD alone)

---

### Phase 2: Weighted Risk Scoring Formula

**Replace additive scoring with weighted composite:**

```
finalRiskScore = (domainScore × 0.3) + 
                 (behaviorScore × 0.3) + 
                 (contentScore × 0.2) + 
                 (aiScore × 0.2)

Where each component score is:
  = Σ(signal_weight × signal_confidence) / max_possible_weight
```

**Signal Weighting Rules:**
- **HIGH confidence signals** → Full weight (1.0x)
- **MEDIUM confidence signals** → 0.6x weight
- **LOW confidence signals** → 0.2x weight
- Single signal MUST NOT exceed 60-point contribution (cap behavioral impact)

**Clipping:** 
- `finalRiskScore ≤ 30` = SAFE (no alert)
- `30 < finalRiskScore ≤ 60` = SUSPICIOUS (overlay only)
- `finalRiskScore > 60` = MALICIOUS (full warning + sound)

---

### Phase 3: False Positive Filter Layer

**Before triggering overlay, validate against whitelist:**

```javascript
if (finalRiskScore ≤ 60) {
  // SUSPICIOUS threshold
  const hasTrustedDomain = isTrustedDomain(url);
  const hasHighConfidenceSignal = signals.some(s => s.confidence === "HIGH");
  
  if (hasTrustedDomain && !hasHighConfidenceSignal) {
    // Trusted domain + only low/medium signals = IGNORE or DOWNGRADE
    return { alert: "suppress", reason: "trusted_domain_low_confidence" };
  }
}
```

**Trusted domains:** Google, Microsoft, Apple, GitHub, educational institutions (.edu), banks with verified certificates, company intranets

---

### Phase 4: Context-Aware Messaging

**Map trust score to human-readable explanations:**

| Trust Score | Current (BAD) | Improved (GOOD) |
|-------------|---------------|-----------------|
| ≥ 90 | "Suspicious site" | "No security concerns detected" |
| 70-89 | "Low trust domain" | "Sensitive fields detected. Verify site authenticity." |
| 50-69 | "Moderate risk detected" | "Some unusual activity (likely legitimate)" |
| < 50 | "Critical threat" | "High-risk activity detected (automated/unauthorized)" |

**Message Format:**
```
[Risk Score: 45/100]
[Confidence: MEDIUM]
Reason: Clipboard activity detected (likely user-triggered)
Action: Monitor for additional signals | Proceed cautiously
```

---

### Phase 5: Signal Aggregation Rules

**Prevent alerts on isolated weak signals:**

**Suppress alert if:**
- Single signal AND confidence = LOW
- Single signal AND confidence = MEDIUM AND domain is trusted
- All signals are below MEDIUM severity

**Trigger alert only if:**
- 2+ independent signals with ≥ MEDIUM confidence, OR
- 1 signal with HIGH confidence

**Example Scenarios:**
- ✗ Google Docs + clipboard write (low confidence) → NO alert
- ✓ Unknown domain + clipboard write + redirect + auto-download (3 high-confidence) → ALERT
- ✓ SafeBrowsing flag alone (1 HIGH-confidence signal) → ALERT

---

### Phase 6: Debug Logging

**Add structured logging to trace detection decisions:**

```javascript
console.log(`[Sentinel-AI]
  URL: ${url}
  Signal: clipboard_write
  Confidence: LOW
  UserInitiated: true
  Domain: trusted (google.com)
  Decision: IGNORED (trusted domain + low confidence)
  FinalScore: 15/100
  Timestamp: ${new Date().toISOString()}
`);
```

**Log on every:**
- Signal detection
- Confidence assignment
- Score calculation
- Alert suppress/trigger decision

---

### Phase 7: UI Improvements

**Update overlay to show decision transparency:**

```
┌─────────────────────────────────────────┐
│  SENTINEL BROWSE SECURITY ANALYSIS      │
├─────────────────────────────────────────┤
│ OVERALL RISK SCORE: 35/100              │
│ Confidence Level: MEDIUM                │
│ Status: ⚠️  MONITOR (proceed cautiously) │
├─────────────────────────────────────────┤
│ DETECTED SIGNALS:                       │
│ • Clipboard write (LOW confidence)      │
│ • Minor URL anomaly (LOW confidence)    │
├─────────────────────────────────────────┤
│ REASON:                                 │
│ Low-confidence clipboard activity       │
│ detected (likely user-triggered).       │
│ Typical on legitimate sites.            │
│                                         │
│ Verify the site is authentic by:        │
│ • Checking browser address bar          │
│ • Looking for https:// lock icon        │
│ • Confirming with official channels     │
├─────────────────────────────────────────┤
│ [Continue] [Report Concern] [Details]   │
└─────────────────────────────────────────┘
```

---

## IMPLEMENTATION CHECKLIST

### Code Changes Required
- [ ] 1. Update `behaviorMonitor.js` to add confidence/context tracking
- [ ] 2. Refactor `riskScoring.js` with weighted formula
- [ ] 3. Add false positive filter in `background.js` decision logic
- [ ] 4. Update overlay messaging in `warning.html` & `content.js`
- [ ] 5. Implement signal aggregation rules in detection engine
- [ ] 6. Add debug logging to all signal handlers
- [ ] 7. Update UI components to show scores + confidence

### Testing Protocol
1. **Regression Testing:** Verify malicious URLs still blocked
2. **False Positive Testing:** Test on legitimate sites (Google, GitHub, Microsoft)
3. **Edge Cases:** 
   - Trusted domains with suspicious behavior
   - Multiple weak signals vs single strong signal
   - Confidence level boundary conditions
4. **Logging Verification:** Ensure all decisions are logged with reasoning

### Deployment
- [ ] Merge to staging branch
- [ ] Run full test suite
- [ ] Deploy to beta testers (small user group)
- [ ] Monitor false positive rate (target: < 1% on trusted sites)
- [ ] Merge to production when metrics validated

---

## SUCCESS CRITERIA

**False Positive Rate:** < 1% on top 100 legitimate domains  
**Malicious Detection:** Maintain ≥ 95% detection of known malicious URLs  
**UI Clarity:** Users understand why alert was triggered (measured by support tickets)  
**Performance:** Detection adds < 5ms latency per page load  

---

## RELATED SKILLS

- **Signal Weighting & Confidence Scoring** — Deep dive into Bayesian weighting
- **Whitelist Maintenance** — Keeping trusted domain list current
- **A/B Testing Detection Changes** — Measuring false positive reduction
- **Threat Intelligence Integration** — Enriching signals with external data

---

## COMMON PITFALLS

❌ **Don't:** Weight behavioral signals equally with domain signals  
✅ **Do:** Use 0.3 weight for behavior ONLY when high-confidence + multiple signals  

❌ **Don't:** Show alerts on trusted domains automatically  
✅ **Do:** Suppress or downgrade alerts on trusted domains without HIGH-confidence signals  

❌ **Don't:** Log only when alerts trigger  
✅ **Do:** Log every signal detection + confidence assignment for audit trail  

❌ **Don't:** Assume clipboard.write is always malicious  
✅ **Do:** Check user interaction timestamps and domain context first  

---

## QUICK REFERENCE

**7-Step Implementation Order:**
1. Add confidence system to behavior detectors
2. Update risk scoring with weighted formula  
3. Implement false positive filter
4. Update messaging logic
5. Add signal aggregation rules
6. Enable debug logging
7. Refresh UI components

**Revert Decision:** If false positive rate > 5%, revert to previous weighted scoring but keep confidence system

