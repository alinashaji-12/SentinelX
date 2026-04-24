# QUICK REFERENCE — THREE NEW MODULES

## 📦 Module 1: Explanation Engine
**File:** `detection/advancedEngine.js`  
**Function:** `generateExplanation(result)`  
**Input:** Detection result object  
**Output:** `{ explanation, signals, confidence }`

```javascript
// Called from analyzeUrlAdvanced()
const explanationData = generateExplanation(result);
result.explanation = explanationData.explanation;
result.signalSummary = explanationData.signals;
result.narrativeConfidence = explanationData.confidence;
```

**Example Output:**
```
explanation: "⚠️ MALICIOUS: This URL exhibits multiple strong indicators..."
signals: ["Phishing intent detected", "Suspicious domain structure", ...]
confidence: 87
```

---

## 🎯 Module 2: Attack Pattern Classifier  
**File:** `detection/patterns.js` (NEW)  
**Function:** `classifyAttackPattern(url, signals, keywordMatches)`  
**Input:** URL + signal groups + detected keywords  
**Output:** `{ type, severity, description, reasoning }`

```javascript
// Called from popup.js
const pattern = classifyAttackPattern(url, signalGroups, keywordMatches);
// pattern.type: "PHISHING" | "MALWARE" | "SOCIAL_ENGINEERING" | "OBFUSCATED_URL" | "SAFE"
// pattern.severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
```

**Decision Logic:**
- `PHISHING` — hasIntent + hasDomainAnomaly
- `MALWARE` — (hasObfuscation OR hasSignature) + (hasDataset OR hasSafeBrowsing)
- `SOCIAL_ENGINEERING` — hasIntent + hasObfuscation (but not domain anomaly)
- `OBFUSCATED_URL` — hasObfuscation alone (no intent, no dataset)
- `SAFE` — No signals present

---

## 🖥️ Module 3: Analyst Dashboard UI
**Files:** `popup/popup.html` + `popup/popup.js` + `popup/popup.css`

### HTML Structure:
```html
<main class="popup">
  <div class="header">              <!-- Logo + subtitle -->
  <div class="url-section">         <!-- URL being analyzed -->
  <div class="status-section">      <!-- Risk level + confidence -->
  <div class="attack-type-section"> <!-- Attack type badge (conditional) -->
  <div class="explanation-section"> <!-- Detailed explanation -->
  <div class="signals-section">     <!-- List of triggered signals -->
  <div class="trust-score-section"> <!-- Visual 0-100 bar -->
  <div class="action-buttons">      <!-- View Report / Close -->
</main>
```

### JavaScript Flow:
```javascript
// 1. Load detection result from history
await loadCurrentTabStatus();

// 2. Render analysis
displayAnalysisResult(url, result);
  ├─ Set status + confidence
  ├─ Show explanation text
  ├─ Classify attack pattern
  ├─ Display attack type + severity
  ├─ Enumerate signals
  └─ Color trust score bar

// 3. Handle user actions
viewDashboardBtn.click → open dashboard
closeBtn.click → close popup
```

### CSS Grid Layout:
```css
.popup {
  max-width: 380px;
  display: flex;
  flex-direction: column;
  gap: 14px;  /* Space between sections */
}
```

Colors:
- Green: Safe (#4caf50)
- Orange: Suspicious (#ff9800)
- Red: Malicious (#f44336)
- Blue background: Explanations
- Purple background: Signals
- Gray background: Inputs/neutral

---

## 🔄 Integration Points

### 1. Detection → Storage
**File:** `background.js`, function `saveThreatHistory()`

```javascript
// BEFORE: Stored basic fields
// AFTER: Stores enhanced fields
history.unshift({
  // ... existing fields ...
  explanation: result.explanation || "",           // NEW
  signalSummary: result.signalSummary || [],      // NEW
  narrativeConfidence: result.narrativeConfidence || 0,  // NEW
  signalGroups: result.signalGroups || {},        // NEW
  keywordMatches: result.keywordMatches || []     // NEW
});
```

### 2. Storage → Display
**File:** `popup/popup.js`, function `displayAnalysisResult()`

```javascript
// Retrieves all fields from history entry
const {
  status, trustScore, explanation,      // NEW
  signalSummary, narrativeConfidence,  // NEW
  signalGroups, keywordMatches,        // NEW
} = result;

// Renders using all three modules
displayAnalysisResult(url, result);
```

---

## 🧪 Quick Test Cases

### Test 1: Phishing URL
```
Input: "paypal-verify-urgent.xyz"
Expected signalGroups: { hasIntent: true, hasDomainAnomaly: true, ... }
Expected pattern.type: "PHISHING"
Expected explanation: Contains "phishing keywords" + "suspicious domain"
```

### Test 2: Safe URL
```
Input: "google.com"
Expected signalGroups: { all false }
Expected pattern.type: "SAFE"
Expected explanation: "✓ SAFE: No significant malicious indicators..."
```

### Test 3: Obfuscated URL
```
Input: "bit.ly/3mP9xLq"
Expected signalGroups: { hasObfuscation: true, others false }
Expected pattern.type: "OBFUSCATED_URL"
Expected explanation: Contains "URL shortener" + "hide true destination"
```

---

## 🛠️ Custom Workflow

### To customize explanation narratives:
1. Open `detection/advancedEngine.js`
2. Find `generateExplanation()` function
3. Modify the `explanation` string construction
4. Examples: Change "⚠️ MALICIOUS" to "🚨 CRITICAL", etc.

### To add new attack patterns:
1. Open `detection/patterns.js`
2. Find `classifyAttackPattern()` function
3. Add new `if (...)` block with pattern logic
4. Return new `{ type, severity, description, reasoning }`

### To change UI styling:
1. Open `popup/popup.css`
2. Modify color variables (--safe, --suspicious, --malicious)
3. Adjust section backgrounds (.attack-type-section, etc.)
4. Change width, padding, fonts as needed

### To extend popup display:
1. Add new `<div class="section">` in `popup.html`
2. Add DOM reference in `popup.js`
3. Add data assignment in `displayAnalysisResult()`
4. Style in `popup.css`

---

## 📊 Data Flow Diagram

```
URL arrives
    ↓
analyzeUrlAdvanced() [advancedEngine.js]
    ├─ generateExplanation()     ← MODULE 1
    └─ returns: status, trustScore, explanation, signalSummary, ...
    ↓
saveThreatHistory() [background.js] ← UPDATED
    └─ stores: explanation, signalSummary, narrativeConfidence, signalGroups, keywordMatches
    ↓
popup.js loads history
    ├─ displayAnalysisResult()
    ├─ classifyAttackPattern()    ← MODULE 2
    └─ renders UI                 ← MODULE 3
    ↓
User sees analyst-grade dashboard ✓
```

---

## ⚙️ Key Variables

| Variable | Type | Where Set | Where Used |
|----------|------|-----------|-----------|
| `explanation` | string | advancedEngine.js | popup display |
| `signalSummary` | string[] | advancedEngine.js | signals list |
| `narrativeConfidence` | number (0-100) | advancedEngine.js | confidence % |
| `pattern.type` | enum | patterns.js | attack badge |
| `pattern.severity` | enum | patterns.js | icon + color |
| `trustScore` | number (0-100) | advancedEngine.js | bar width |
| `signalGroups` | object | advancedEngine.js | pattern classification |

---

## 🚀 Single-Command Verification

```bash
# Verify all files exist:
ls -l detection/patterns.js popup/popup.* detection/advancedEngine.js background.js

# In Chrome DevTools (Service Worker console):
# 1. Navigate to suspicious URL
# 2. Check storage: chrome.storage.local.get(['threatHistory'], d => console.log(d.threatHistory[0]))
# 3. Verify: explanation, signalSummary, narrativeConfidence fields present
# 4. Click popup, verify UI renders without errors
```

---

## 📚 Related Documentation

- **`ANALYST_UPGRADE.md`** — Full architecture + examples
- **`INTEGRATION_TEST_GUIDE.md`** — Unit tests + manual tests + debugging
- **`IMPLEMENTATION_SUMMARY.md`** — Complete change log + data flow

---

**That's it! Three modules, three files touched, zero breaking changes, 100% better analysis.** 🎯
