/**
 * SMART ENGINE ARCHITECTURE
 *
 * How the two-layer detection system works:
 */

/*
═══════════════════════════════════════════════════════════════════════════════
LAYER 1: DECLARATIVE RULES (Fast Path)
═══════════════════════════════════════════════════════════════════════════════

Browser → declarativeNetRequest rules (rules.json)
                ↓
  ┌─────────────────────────────────────────┐
  │ Rule 1-24: Specific known phishing      │  (Priority 2)
  │ - paypal-login-secure.com               │
  │ - facebook-verification.net             │
  │ - etc.                                  │
  └─────────────────────────────────────────┘
                ↓
  ┌─────────────────────────────────────────┐
  │ Rule 25: Generic "login" catch          │  (Priority 1)
  │ - Any URL containing "login"            │
  └─────────────────────────────────────────┘
                ↓
         Match? → Redirect to /warning.html
         No match? → Continue to Layer 2


═══════════════════════════════════════════════════════════════════════════════
LAYER 2: SMART ENGINE (Dynamic Analysis)
═══════════════════════════════════════════════════════════════════════════════

Browser Request
     ↓
[chrome.tabs.onUpdated listener]
     ↓
Allow request through (no blocking)
     ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                    SIGNAL EXTRACTION                                    │
│                                                                         │
│  Input: URL                                                            │
│  ├─ Keyword Detection (ML Model)                                      │
│  │  └─ hasPhishingKeywords?                                           │
│  ├─ Domain Analysis (Behavior Engine)                                 │
│  │  ├─ hasDomainAnomaly?                                             │
│  │  └─ hasSuspiciousTLD?                                             │
│  ├─ Obfuscation Detection                                            │
│  │  └─ hasObfuscation?                                               │
│  ├─ External Checks                                                   │
│  │  ├─ Google Safe Browsing API                                      │
│  │  └─ Phishing/Malware Dataset                                      │
│  └─ URL Patterns                                                       │
│     ├─ hasIP? (raw IP vs domain)                                    │
│     ├─ hasLongURL? (> 200 chars)                                    │
│     └─ hasRedirectParam? (url= / redirect=)                         │
└─────────────────────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────────────────────┐
│              RISK SCORING (riskScoring.js)                             │
│                                                                         │
│  calculateRiskScore(signals) → 0-10 scale                             │
│  │                                                                      │
│  ├─ Safe Browsing hit?        → +6                                   │
│  ├─ Dataset match?            → +5                                   │
│  ├─ Phishing keywords?        → +3                                   │
│  ├─ Domain anomaly?           → +2                                   │
│  ├─ Obfuscation?              → +2                                   │
│  ├─ IP address?               → +3                                   │
│  ├─ Redirect param?           → +2                                   │
│  ├─ Suspicious TLD?           → +1                                   │
│  └─ Long URL?                 → +1                                   │
│                                                                         │
│  Score: 0-2    → 25-40% confidence → SAFE                           │
│  Score: 3-5    → 55-70% confidence → CAUTION/SUSPICIOUS             │
│  Score: 6-8    → 75-85% confidence → SUSPICIOUS/MALICIOUS           │
│  Score: 9-10   → 95%+ confidence  → MALICIOUS                       │
└─────────────────────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────────────────────┐
│            ATTACK CLASSIFICATION (riskScoring.js)                       │
│                                                                         │
│  ├─ MALWARE         (Safe Browsing OR Dataset)                        │
│  ├─ PHISHING        (Keywords + Domain anomaly OR IP usage)           │
│  ├─ SOCIAL_ENGINEERING (Keywords + Obfuscation, no domain tricks)   │
│  ├─ OBFUSCATED_URL  (Pure obfuscation)                               │
│  └─ SAFE            (No signals)                                     │
└─────────────────────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────────────────────┐
│           EXPLANATION GENERATION (riskScoring.js)                      │
│                                                                         │
│  Convert technical signals to human-readable reasons                  │
│  ├─ "Contains phishing keywords like login, verify"                 │
│  ├─ "Domain structure mimics legitimate sites"                      │
│  ├─ "Uses URL encoding to hide true destination"                    │
│  └─ "Google Safe Browsing identified this as malicious"             │
└─────────────────────────────────────────────────────────────────────────┘
     ↓
     VERDICT DECISION
     ↓
  ┌─ MALICIOUS (confidence ≥ 85%)
  │  └─ chrome.tabs.update(tabId, { url: "/warning.html?..." })
  │     └─ Redirect tab to warning page
  │
  ├─ SUSPICIOUS (confidence 55-70%)
  │  └─ chrome.tabs.sendMessage(tabId, { action: "showWarning" })
  │     └─ Inject warning banner into page
  │
  └─ SAFE (confidence < 55%)
     └─ Allow navigation normally


═══════════════════════════════════════════════════════════════════════════════
COMBINED FLOW (Both Layers)
═══════════════════════════════════════════════════════════════════════════════

User clicks link
     ↓
Browser initiates request
     ↓
  ┌──────────────────────────────────────────┐
  │ DeclarativeNetRequest Rules Check        │  (< 10ms)
  │ (Instant, before page loads)             │
  │                                          │
  │ Known phishing domain? → BLOCK           │
  │ Contains "login"? → BLOCK                │
  │ Otherwise... → Pass through              │
  └──────────────────────────────────────────┘
     ↓
  Page starts loading...
     ↓
  ┌──────────────────────────────────────────┐
  │ Smart Engine Analysis (Async)            │  (< 500ms)
  │ (While page loads in background)         │
  │                                          │
  │ Run all detection modules                │
  │ + Risk scoring                           │
  │ + Attack classification                  │
  │ = Verdict                                │
  │                                          │
  │ If MALICIOUS:                            │
  │   Redirect to warning before visible     │
  │                                          │
  │ If SUSPICIOUS:                           │
  │   Show warning banner on page            │
  │                                          │
  │ If SAFE:                                 │
  │   Allow normal navigation                │
  └──────────────────────────────────────────┘
     ↓
User sees result


═══════════════════════════════════════════════════════════════════════════════
ADVANTAGES OF THIS ARCHITECTURE
═══════════════════════════════════════════════════════════════════════════════

✓ FAST BLOCKING
  - declarativeNetRequest provides instant protection against known threats
  - No processing delay for dangerous sites

✓ SMART ANALYSIS
  - Risk scoring gives you transparency into detection logic
  - Can explain why something is flagged (confidence level + reasons)

✓ FALLBACK PROTECTION
  - If declarativeNetRequest rules fail, smart engine catches it
  - If smart engine is slow, rules still block known threats

✓ FLEXIBILITY
  - Rules = quick patterns (domains, keywords)
  - Smart engine = context-aware (combinations, ML, external APIs)

✓ LOW FALSE POSITIVES
  - Confidence scoring prevents blocking safe sites
  - Only malicious (85%+) sites are auto-blocked
  - Suspicious (55-70%) get warning banner

✓ USER CONTROL
  - Warning page lets users proceed if they want
  - Confidence score shows why decision was made
  - Reasons explain each detected signal


═══════════════════════════════════════════════════════════════════════════════
IMPLEMENTATION CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

✅ manifest.json
   ✓ Updated permissions to declarativeNetRequest
   ✓ Added host_permissions: ["<all_urls>"]
   ✓ Configured declarative_net_request ruleset

✅ rules.json
   ✓ Contains 25 blocking rules
   ✓ Ready for browser enforcement

✅ riskScoring.js (NEW)
   ✓ calculateRiskScore() - weighted scoring
   ✓ calculateConfidence() - confidence mapping
   ✓ classifyAttack() - attack type detection
   ✓ generateExplanation() - human explanations
   ✓ analyzeRisk() - orchestration function

⚠️ background.js (TODO)
   ✓ Add chrome.tabs.onUpdated listener
   ✓ Integrate signal extraction
   ✓ Call analyzeRisk() from riskScoring.js
   ✓ Implement redirectToWarning() for malicious URLs
   ✓ Implement showWarningBanner() for suspicious URLs
   ✓ Add threat logging for dashboards

⚠️ warning.html (TODO)
   ✓ Design warning page UI
   ✓ Show attack type + confidence
   ✓ List reasons the URL was blocked
   ✓ Allow user to proceed if confident
   ✓ Log user decisions

⚠️ content.js (TODO)
   ✓ Handle chrome.tabs.onMessage for warning banners
   ✓ Render warning banner on suspicious pages
   ✓ Allow dom-level user override

⚠️ Detection modules integration (TODO)
   ✓ connectriskScoring.js to existing detection modules
   ✓ Ensure signal extraction works with your ML model
   ✓ Ensure Safe Browsing + Dataset checks work
   ✓ Ensure domain behavior analysis integrates

═══════════════════════════════════════════════════════════════════════════════
*/

console.log("Smart Engine Architecture Loaded");
