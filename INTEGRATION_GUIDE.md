/**
 * ═══════════════════════════════════════════════════════════════════════════
 * SENTINEL BROWSE EXTENSION — COMPLETE SYSTEM INTEGRATION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * ARCHITECTURE & DATA FLOW
 * ═════════════════════════════════════════════════════════════════════════
 *
 *  USER VISITS URL
 *        ↓
 *  background.js:webRequest.onBeforeRequest (PASS 1 — Synchronous)
 *        ↓
 *  analyzeUrlAdvancedSync() — PRE-DNS Check
 *  • Checks: phishing keywords, domain structure, IP address
 *  • NO network calls (FAST: <5ms)
 *  • Returns: {status: "malicious"|"suspicious"|"safe", ...}
 *        ↓
 *  IF MALICIOUS: redirect to warning.html
 *  IF SUSPICIOUS: allow but show overlay
 *  IF SAFE: allow navigation
 *        ↓
 *  background.js:webNavigation.onCompleted (PASS 2 — Async)
 *        ↓
 *  Full analysis (optional Safe Browsing check)
 *        ↓
 *  saveThreatHistory(url, result)  ← STORES in chrome.storage.local
 *  • Saves: threatHistory (history array)
 *  • CRITICAL: Saves lastAnalysis (latest result — used by popup/warning)
 *        ↓
 *  User opens popup.js
 *        ↓
 *  popup.js:loadCurrentTabStatus()
 *  • Reads: lastAnalysis + history from chrome.storage.local
 *  • Displays: status, trustScore, attackType, explanation, signals, confidence
 *        ↓
 *  User sees beautified threat analysis in popup
 *
 * ═════════════════════════════════════════════════════════════════════════
 * UNIFIED OUTPUT FORMAT (SINGLE SOURCE OF TRUTH)
 * ═════════════════════════════════════════════════════════════════════════
 *
 * ALL detection results use this exact structure:
 *
 * {
 *   // Status/Verdict
 *   status: "safe" | "suspicious" | "malicious",
 *   trustScore: number (0-100),
 *   attackType: "PHISHING" | "MALWARE" | "SOCIAL_ENGINEERING" | "OBFUSCATED_URL" | "SAFE",
 *   
 *   // User-Facing Explanation
 *   explanation: string,           // Human-readable threat analysis
 *   signals: string[],             // List of detected signals
 *   confidence: number (0-100),    // Confidence percentage
 *   
 *   // Technical Details
 *   reason: string,                // Concatenated reasons
 *   reasons: string[],             // Array of reasons
 *   score: number,                 // Internal score
 *   
 *   // Detailed Breakdown
 *   sources: object[],             // Each detection module's result
 *   signalGroups: object,          // Signal presence (hasIntent, hasDomain, etc.)
 *   keywordMatches: string[],      // Detected phishing keywords
 *   
 *   // Metadata
 *   domainProfile: object,
 *   flag: boolean,                 // status !== "safe"
 *   fastPath: boolean              // Whether from fast synchronous check
 * }
 *
 * ═════════════════════════════════════════════════════════════════════════
 * EXAMPLE OUTPUTS
 * ═════════════════════════════════════════════════════════════════════════
 *
 * SCENARIO 1: MALICIOUS (Phishing attempt)
 * ──────────────────────────────────────────
 *
 * URL: https://login-secure-account-verify.xyz/update
 *
 * {
 *   status: "malicious",
 *   trustScore: 10,
 *   attackType: "PHISHING",
 *   explanation: "⚠️ MALICIOUS: This URL exhibits multiple strong indicators of malicious intent. Phishing keywords (login, secure, account) combined with suspicious domain structure. URL uses obfuscation techniques common in attack delivery. Uses raw IP address instead of domain name.",
 *   signals: [
 *     "Phishing intent detected",
 *     "Suspicious domain structure",
 *     "URL obfuscation detected",
 *     "High-risk TLD (.xyz)"
 *   ],
 *   confidence: 92,
 *   reason: "Phishing intent: keywords [login, secure, account] + domain anomaly; High-risk TLD (.xyz); Punycode domain",
 *   reasons: [
 *     "Phishing intent: keywords [login, secure, account] + domain anomaly",
 *     "High-risk TLD (.xyz)",
 *     "Punycode domain (possible homoglyph attack)"
 *   ],
 *   score: 9.2,
 *   sources: [
 *     {
 *       name: "Signature Analysis",
 *       verdict: "safe",
 *       triggered: false,
 *       detail: "No notable signal."
 *     },
 *     {
 *       name: "Domain Intelligence",
 *       verdict: "suspicious",
 *       triggered: true,
 *       detail: "Domain has unusual structural patterns indicating phishing"
 *     },
 *     {
 *       name: "Obfuscation Analysis",
 *       verdict: "suspicious",
 *       triggered: true,
 *       detail: "Punycode detected"
 *     },
 *     {
 *       name: "Google Safe Browsing",
 *       verdict: "safe",
 *       triggered: false,
 *       detail: "Not in Safe Browsing database"
 *     },
 *     {
 *       name: "Phishing Dataset",
 *       verdict: "safe",
 *       triggered: false,
 *       detail: "Not in known phishing dataset"
 *     },
 *     {
 *       name: "Intent Detection",
 *       verdict: "malicious",
 *       triggered: true,
 *       detail: "Phishing keywords detected"
 *     }
 *   ],
 *   signalGroups: {
 *     hasIntent: true,
 *     hasDomainAnomaly: true,
 *     hasObfuscation: true,
 *     hasSignature: false,
 *     hasDataset: false,
 *     hasSafeBrowsing: false,
 *     hasIpAddress: false
 *   },
 *   keywordMatches: ["login", "secure", "account"],
 *   domainProfile: {
 *     hostname: "login-secure-account-verify.xyz",
 *     rootDomain: "account-verify.xyz",
 *     isTrusted: false,
 *     isSearchQuery: false,
 *     protected: false
 *   },
 *   flag: true,
 *   fastPath: true
 * }
 *
 * ──────────────────────────────────────────
 * SCENARIO 2: SUSPICIOUS (Unusual patterns)
 * ──────────────────────────────────────────
 *
 * URL: https://strange-bank-secure.online/
 *
 * {
 *   status: "suspicious",
 *   trustScore: 45,
 *   attackType: "PHISHING",
 *   explanation: "⚠️ SUSPICIOUS: This URL has some characteristics that warrant caution. Domain has unusual structural patterns typical of phishing sites. May be early-stage phishing domain or brand impersonation attempt. Proceed with caution.",
 *   signals: [
 *     "Domain anomalies",
 *     "High-risk TLD (.online)"
 *   ],
 *   confidence: 62,
 *   reason: "Domain anomaly: Multiple hyphens (hyphen-heavy domain); High-risk TLD (.online)",
 *   reasons: [
 *     "Domain anomaly: Multiple hyphens (hyphen-heavy domain matching phishing patterns)",
 *     "High-risk TLD (.online)"
 *   ],
 *   score: 5.5,
 *   sources: [
 *     {...},
 *     {
 *       name: "Domain Intelligence",
 *       verdict: "suspicious",
 *       triggered: true,
 *       detail: "Multiple hyphens in domain"
 *     },
 *     {...}
 *   ],
 *   signalGroups: {
 *     hasIntent: false,
 *     hasDomainAnomaly: true,
 *     hasObfuscation: false,
 *     hasSignature: false,
 *     hasDataset: false,
 *     hasSafeBrowsing: false,
 *     hasIpAddress: false
 *   },
 *   keywordMatches: [],
 *   flag: true,
 *   fastPath: true
 * }
 *
 * ──────────────────────────────────────────
 * SCENARIO 3: SAFE (No threats)
 * ──────────────────────────────────────────
 *
 * URL: https://github.com/anthropics/claude
 *
 * {
 *   status: "safe",
 *   trustScore: 95,
 *   attackType: "SAFE",
 *   explanation: "✓ SAFE: No significant malicious indicators detected.",
 *   signals: ["No threats identified"],
 *   confidence: 0,
 *   reason: "Trusted domain (github.com) — all scoring bypassed",
 *   reasons: ["Trusted domain (github.com) — all scoring bypassed"],
 *   score: -5,
 *   sources: [
 *     {
 *       name: "Signature Analysis",
 *       verdict: "safe",
 *       triggered: false,
 *       detail: "No notable signal."
 *     },
 *     // ... all safe
 *   ],
 *   signalGroups: {
 *     hasIntent: false,
 *     hasDomainAnomaly: false,
 *     hasObfuscation: false,
 *     hasSignature: false,
 *     hasDataset: false,
 *     hasSafeBrowsing: false,
 *     hasIpAddress: false
 *   },
 *   keywordMatches: [],
 *   domainProfile: {
 *     hostname: "github.com",
 *     rootDomain: "github.com",
 *     isTrusted: true,
 *     isSearchQuery: false,
 *     protected: true
 *   },
 *   flag: false,
 *   fastPath: false
 * }
 *
 * ═════════════════════════════════════════════════════════════════════════
 * CHROME STORAGE SCHEMA
 * ═════════════════════════════════════════════════════════════════════════
 *
 * chrome.storage.local keys:
 *
 *   "threatHistory": [
 *     {unified result object + timestamp},
 *     {unified result object + timestamp},
 *     ...
 *   ]
 *   (oldest entries culled at 500 items)
 *
 *   "lastAnalysis": {
 *     unified result object + timestamp
 *   }
 *   (CRITICAL: Latest analysis — used by popup & warning page)
 *
 *   "bypassHistory": [
 *     {url, timestamp, reasons, trustScore, action: "bypassed"},
 *     ...
 *   ]
 *   (User bypass log — max 250 items)
 *
 * ═════════════════════════════════════════════════════════════════════════
 * INTEGRATION POINTS
 * ═════════════════════════════════════════════════════════════════════════
 *
 * 1. BACKGROUND → POPUP
 *    ├─ background.js saves result to chrome.storage.local.lastAnalysis
 *    └─ popup.js reads chrome.storage.local.lastAnalysis and displays
 *
 * 2. BACKGROUND → WARNING PAGE
 *    ├─ background.js passes data via URL parameters
 *    ├─ background.js also saves to lastAnalysis
 *    └─ warning.js loads from lastAnalysis to enrich incomplete params
 *
 * 3. POPUP ↔ PATTERNS CLASSIFIER
 *    ├─ popup.js calls classifyAttackPattern(url, signalGroups, keywordMatches)
 *    └─ patterns.js returns {type, severity, description, reasoning}
 *
 * 4. ALL MODULES → UNIFIED FORMAT
 *    ├─ advancedEngine.js.analyzeUrlAdvanced() returns unified format
 *    ├─ advancedEngine.js.fastAnalyzeUrl() returns unified format
 *    └─ All downstream consumers (popup, warning, dashboard) expect unified format
 *
 * ═════════════════════════════════════════════════════════════════════════
 * ATTACK PATTERN PRIORITY (Classification Rules)
 * ═════════════════════════════════════════════════════════════════════════
 *
 * IF hasSafeBrowsing OR hasDataset
 *   → type = "MALWARE", severity = "CRITICAL"
 *
 * ELSE IF hasIntent + hasDomainAnomaly
 *   → type = "PHISHING", severity = "CRITICAL"
 *   → escalate if also hasObfuscation
 *
 * ELSE IF hasIntent + hasObfuscation (but NOT domain anomaly)
 *   → type = "SOCIAL_ENGINEERING", severity = "HIGH"
 *   → indicates urgency/scarcity tactic hidden in URL
 *
 * ELSE IF hasObfuscation (alone, no intent, no dataset)
 *   → type = "OBFUSCATED_URL", severity = "MEDIUM"
 *   → hiding destination is inherently suspicious
 *
 * ELSE IF hasDomainAnomaly (alone, no intent)
 *   → type = "PHISHING", severity = "MEDIUM"
 *   → structure matches phishing templates but no explicit intent signals
 *
 * ELSE IF hasIpAddress
 *   → type = "PHISHING", severity = "MEDIUM"
 *   → raw IPs are phishing-common
 *
 * ELSE
 *   → type = "SAFE", severity = "INFO"
 *
 * ═════════════════════════════════════════════════════════════════════════
 * UI DISPLAY (Popup & Warning Page)
 * ═════════════════════════════════════════════════════════════════════════
 *
 * POPUP.html displays:
 *   ├─ URL (truncated if >60 chars)
 *   ├─ Risk badge: "Safe" (green), "Suspicious" (orange), "Malicious" (red)
 *   ├─ Confidence: "{confidence}%"
 *   ├─ Attack Type (if not SAFE): "{PHISHING|MALWARE|...} (CRITICAL|HIGH|...)"
 *   ├─ Explanation: User-friendly threat narrative
 *   ├─ Signals Detected: List of technical signals (safe only shows empty)
 *   ├─ Trust Score: Visual bar from 0-100 (green/orange/red)
 *   └─ Buttons: View Report, Close
 *
 * WARNING.html displays:
 *   ├─ URL
 *   ├─ Reasons (bulleted list)
 *   ├─ Risk Level badge
 *   ├─ Confidence % + Signal Count
 *   ├─ Source Breakdown (each detection module)
 *   ├─ Safety Tip
 *   └─ Buttons: Go Back, Proceed Anyway
 *
 * ═════════════════════════════════════════════════════════════════════════
 * PERFORMANCE TARGETS
 * ═════════════════════════════════════════════════════════════════════════
 *
 * ✓ Pre-DNS detection (background.js PASS 1):  <5ms   (all local)
 * ✓ Popup UI load & display:                   <100ms (read storage + render)
 * ✓ Warning page load & display:               <200ms (read storage + enrichment)
 * ✓ Full PASS 2 analysis:                      <500ms (includes optional Safe Browsing)
 * ✓ Extension startup:                         instant (service worker always ready)
 *
 * ═════════════════════════════════════════════════════════════════════════
 * ERROR HANDLING
 * ═════════════════════════════════════════════════════════════════════════
 *
 * Background.js errors → FAIL-OPEN (allow navigation)
 * Popup.js errors → Display "Unable to read current tab" + SAFE
 * Warning.js errors → Load from params + storage fallback
 * Storage errors → Graceful handling, log warnings
 * No data → Show "No analysis yet" or default SAFE
 *
 * ═════════════════════════════════════════════════════════════════════════
 * QUICK INTEGRATION CHECKLIST
 * ═════════════════════════════════════════════════════════════════════════
 *
 * ✓ advancedEngine.js → returns unified format
 * ✓ patterns.js → classifies attack types correctly
 * ✓ background.js → stores lastAnalysis in chrome.storage.local
 * ✓ popup.js → reads lastAnalysis + displays correctly
 * ✓ warning.js → reads from storage + enriches params
 * ✓ No duplicate logic across modules
 * ✓ Attack type priority respected
 * ✓ All modules use consistent signal names
 * ✓ Error handling prevents crashes
 * ✓ Performance targets met
 *
 */
