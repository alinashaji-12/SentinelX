/**
 * ═══════════════════════════════════════════════════════════════════════════
 * SENTINEL BROWSE EXTENSION — COMPLETE WORKING EXAMPLE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This document traces a complete analysis cycle from URL to user-visible result.
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * EXAMPLE 1: User visits malicious phishing site
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * [STEP 1] User types URL in browser:
 * ─────────────────────────────────
 * https://login-verify-account-secure.xyz/apple-id
 *
 *
 * [STEP 2] Chrome intercepts with webRequest.onBeforeRequest
 * ──────────────────────────────────────────────────────────
 * background.js line 385-439:
 *
 *   chrome.webRequest.onBeforeRequest.addListener(
 *     function (details) {
 *       if (details.type !== "main_frame") return {};
 *       var url = details.url; // "https://login-verify-account-secure.xyz/apple-id"
 *       var result = analyzeUrlAdvancedSync(url);  // SYNCHRONOUS ANALYSIS
 *       if (result.status === "malicious") {
 *         // REDIRECT TO WARNING PAGE
 *         return {
 *           redirectUrl: chrome.runtime.getURL("warning.html") +
 *             "?url=" + encodeURIComponent(url) +
 *             "&reason=" + encodeURIComponent(result.reasons.join("; ")) +
 *             "&trustScore=" + result.trustScore
 *         };
 *       }
 *       return {};
 *     }
 *   );
 *
 *
 * [STEP 3] Synchronous analysis in background.js (analyzeUrlAdvancedSync)
 * ────────────────────────────────────────────────────────────────────────
 * Runs in ~2ms (all local, no network):
 *
 *   // Parse URL
 *   hostname = "login-verify-account-secure.xyz"
 *   pathname = "/apple-id"
 *   root = "secure.xyz"
 *
 *   // Check if trusted (NO)
 *   if (isTrusted(hostname)) return safe();  // NO, not trusted
 *
 *   // Check dataset (NO)
 *   if (PHISHING_DATASET.has(root)) return malicious(...);  // NO
 *
 *   // Check TLD (YES)
 *   tld = "xyz"
 *   if (HIGH_RISK_TLDS.has(tld)) {  // YES, "xyz" is high-risk
 *     score += 2;
 *     hasDomainRisk = true;
 *   }
 *
 *   // Check hyphens (YES)
 *   hyphens = 3  // "login-verify-account-secure"
 *   if (hyphens >= 3) {  // YES
 *     score += 2;  // score = 4
 *     hasDomainRisk = true;
 *   }
 *
 *   // Check keywords + urgency (YES)
 *   hostnameTokens = ["login", "verify", "account", "secure"]
 *   keywords = ["login", "account"] (2 found)
 *   if (keywords.length >= 2) {  // YES, multiple keywords
 *     score += 3;  // score = 7
 *     hasIntent = true;
 *   }
 *
 *   // Decision logic (background.js line 304-350)
 *   if (keywords.length >= 2 && HIGH_RISK_TLDS.has(tld)) {  // YES
 *     return malicious(reasons, score);  // DECISION: MALICIOUS
 *   }
 *
 *   // Synchronous result:
 *   return {
 *     status: "malicious",
 *     score: 7,
 *     trustScore: 30,
 *     reasons: [
 *       "Multi-keyword phishing hostname: [login, account] — 2 sensitive words...",
 *       "High-risk TLD (.xyz)",
 *       "Heavy hyphen use (3 hyphens — brand impersonation pattern)"
 *     ]
 *   };
 *
 *
 * [STEP 4] Redirect to warning page
 * ─────────────────────────────────
 * Browser redirects to:
 * chrome-extension://abc123/warning.html?url=https%3A%2F%2Flogin-verify-account-secure.xyz%2Fapple-id&reason=Multi-keyword...&trustScore=30
 *
 * Warning page loads (warning.js executed)
 *
 *
 * [STEP 5] Asynchronous PASS 2 (background.js line 446-511)
 * ─────────────────────────────────────────────────────────
 * After page loads, async flow runs:
 *
 *   chrome.webNavigation.onCompleted.addListener(function(details) {
 *     if (details.frameId !== 0) return;
 *     processLoadedUrl(details.tabId, details.url);
 *   });
 *
 *   async function processLoadedUrl(tabId, url) {
 *     var result = analyzeUrlAdvancedSync(url);  // Same as PASS 1
 *     await saveThreatHistory(url, result);
 *       // CRITICAL: Stores to chrome.storage.local
 *       // Sets: "threatHistory" array + "lastAnalysis" object
 *   }
 *
 *   // saveThreatHistory (background.js line 552-580)
 *   async function saveThreatHistory(url, result) {
 *     await setStorage({
 *       "threatHistory": [...history, entry],
 *       "lastAnalysis": {  // ← CRITICAL
 *         url: "https://login-verify-account-secure.xyz/apple-id",
 *         status: "malicious",
 *         trustScore: 30,
 *         reason: "...",
 *         reasons: [...],
 *         timestamp: "2026-04-15T10:30:00.000Z"
 *       }
 *     });
 *   }
 *
 *
 * [STEP 6] Warning page displays (warning.js)
 * ──────────────────────────────────────────
 * warning.js line 165-169:
 *
 *   loadAnalysisFromStorage().then(() => {
 *     updateWarningPageUI();
 *   });
 *
 * Browser renders:
 * ┌─────────────────────────────────────────────────┐
 * │ ⚠️ Deceptive Site Ahead                         │
 * │                                                 │
 * │ Sentinel blocked this page to protect your      │
 * │ data and account security.                      │
 * │                                                 │
 * │ Blocked URL:                                    │
 * │ login-verify-account-secure.xyz/apple-id       │
 * │                                                 │
 * │ Reasons:                                        │
 * │ • Multi-keyword phishing hostname: [login,      │
 * │   account] — 2 sensitive words...               │
 * │ • High-risk TLD (.xyz)                          │
 * │ • Heavy hyphen use (3 hyphens —...              │
 * │                                                 │
 * │ Confidence: 92%                                 │
 * │ Signals Triggered: 3                            │
 * │                                                 │
 * │ [Go Back] [Proceed Anyway]                      │
 * └─────────────────────────────────────────────────┘
 *
 *
 * [STEP 7] User clicks popup icon
 * ───────────────────────────────
 * popup.js line 124-154:
 *
 *   async function loadCurrentTabStatus() {
 *     const [tab] = await chrome.tabs.query({active, currentWindow});
 *     const currentUrl = tab.url;
 *
 *     const data = await getStorageLocal(["lastAnalysis", "threatHistory"]);
 *     const lastAnalysis = data.lastAnalysis;
 *
 *     if (lastAnalysis && getHostname(lastAnalysis.url) === getHostname(currentUrl)) {
 *       displayAnalysisResult(currentUrl, lastAnalysis);
 *     }
 *   }
 *
 * Popup displays:
 * ┌──────────────────────────────┐
 * │ Sentinel Browse              │
 * │ Threat Analysis Engine       │
 * │                              │
 * │ Current URL                  │
 * │ login-verify-account-...     │
 * │                              │
 * │ Risk Level: Malicious        │
 * │ Confidence: 92%              │
 * │                              │
 * │ Attack Type: PHISHING        │
 * │ (CRITICAL)                   │
 * │ Phishing attempts to steal   │
 * │ credentials...               │
 * │                              │
 * │ Analysis:                    │
 * │ ⚠️ MALICIOUS: Multi-keyword   │
 * │ phishing hostname detected...│
 * │                              │
 * │ Signals Detected:            │
 * │ • Domain anomalies           │
 * │ • High-risk TLD (.xyz)       │
 * │ • Phishing keywords present  │
 * │                              │
 * │ Trust Score: 30/100 [===]    │
 * │                              │
 * │ [View Report] [✕]            │
 * └──────────────────────────────┘
 *
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * EXAMPLE 2: User visits Google (SAFE)
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * [STEP 1] User visits
 * URL: https://www.google.com/search?q=hello+world
 *
 *
 * [STEP 2] background.js webRequest.onBeforeRequest
 * ───────────────────────────────────────────────────
 * analyzeUrlAdvancedSync() returns:
 *
 *   hostname = "www.google.com"
 *   if (isTrusted(hostname)) {
 *     return {
 *       status: "safe",
 *       trustScore: 100,
 *       reasons: ["Trusted domain (google.com) — all scoring bypassed"]
 *     };
 *   }
 *
 * Chrome allows navigation (status === "safe")
 *
 *
 * [STEP 3] PASS 2 async saveThreatHistory
 * ────────────────────────────────────────
 * Stores to chrome.storage.local:
 *
 *   {
 *     "lastAnalysis": {
 *       url: "https://www.google.com/search...",
 *       status: "safe",
 *       trustScore: 100,
 *       reason: "Trusted domain (google.com)...",
 *       timestamp: "2026-04-15T10:35:00.000Z"
 *     }
 *   }
 *
 *
 * [STEP 4] User clicks popup
 * ───────────────────────────
 * popup.js loads lastAnalysis → displays:
 *
 * ┌──────────────────────────────┐
 * │ Sentinel Browse              │
 * │                              │
 * │ Current URL                  │
 * │ www.google.com/search?...    │
 * │                              │
 * │ Risk Level: Safe             │
 * │ Confidence: 0%               │
 * │                              │
 * │ Analysis:                    │
 * │ ✓ SAFE: No significant...    │
 * │                              │
 * │ Trust Score: 100/100 [====]  │
 * │                              │
 * │ [View Report] [✕]            │
 * └──────────────────────────────┘
 *
 * (No "Attack Type" section shown for SAFE status)
 *
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * COMPLETE DATA STRUCTURE FLOW
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * [1] background.js analyzeUrlAdvancedSync(url)
 *     ↓
 *     Returns: {status, score, trustScore, reasons, signals}
 *
 * [2] background.js saveThreatHistory(url, result)
 *     ↓
 *     Takes result from [1]
 *     ↓
 *     Transforms to full unified format with timestamp
 *     ↓
 *     Stores:
 *       • chrome.storage.local.threatHistory (array)
 *       • chrome.storage.local.lastAnalysis (single object) ← CRITICAL
 *
 * [3a] warning.html loads
 *      ↓
 *      warning.js reads from URL params
 *      ↓
 *      warning.js loadAnalysisFromStorage()
 *        → Reads lastAnalysis from chrome.storage.local
 *        → Backfills missing params
 *      ↓
 *      warning.js updateWarningPageUI()
 *        → Renders HTML with complete data
 *
 * [3b] popup.html opens
 *      ↓
 *      popup.js loadCurrentTabStatus()
 *      ↓
 *      chrome.storage.local.get(["lastAnalysis", "threatHistory"])
 *      ↓
 *      popup.js displayAnalysisResult(url, lastAnalysis)
 *      ↓
 *      popup.js calls:
 *        • classifyAttackPattern(url, signalGroups, keywordMatches)
 *        • getSeverityMeta(pattern.severity)
 *        • getAttackTypeDescription(pattern.type)
 *      ↓
 *      Renders unified UI with all details
 *
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * MODULE RESPONSIBILITIES
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * advancedEngine.js
 *   ✓ analyzeUrlAdvanced(url, results, context)
 *     → Returns unified format object
 *     → Called by FUTURE full analysis (currently in background.js inline)
 *   ✓ fastAnalyzeUrl(url, context)
 *     → Returns unified format object
 *     → Fallback for pre-navigation check
 *   ✓ classifyAttackType(signals)
 *     → Returns attack type string
 *     → Internal to unified format generation
 *   ✓ generateExplanation(result)
 *     → Returns {explanation, signals}
 *     → Used to humanize technical results
 *
 * patterns.js
 *   ✓ classifyAttackPattern(url, signals, keywordMatches)
 *     → Returns {type, severity, description, reasoning}
 *     → Called by popup.js to display attack type
 *   ✓ getSeverityMeta(severity)
 *     → Returns {color, icon, label}
 *     → UI styling metadata
 *   ✓ getAttackTypeDescription(attackType)
 *     → Returns user-friendly description
 *
 * background.js
 *   ✓ analyzeUrlAdvancedSync(url)
 *     → Synchronous pre-DNS check
 *     → Returns {status, score, trustScore, reasons}
 *   ✓ saveThreatHistory(url, result)
 *     → Transforms result → unified format
 *     → Stores to chrome.storage.local
 *
 * popup.js
 *   ✓ loadCurrentTabStatus()
 *     → Reads chrome.storage.local.lastAnalysis
 *     → Calls displayAnalysisResult()
 *   ✓ displayAnalysisResult(url, result)
 *     → Renders popup UI
 *     → Calls patterns.js classifiers
 *
 * warning.js
 *   ✓ loadAnalysisFromStorage()
 *     → Reads chrome.storage.local.lastAnalysis
 *     → Backfills URL params
 *   ✓ updateWarningPageUI()
 *     → Renders warning page
 *
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * VALIDATION CHECKLIST
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * ✓ All modules use unified format
 * ✓ background.js saves lastAnalysis on every PASS 2
 * ✓ popup.js reads from lastAnalysis (PRIMARY) or history (FALLBACK)
 * ✓ warning.js loads from lastAnalysis to enrich params
 * ✓ patterns.js called correctly from popup.js
 * ✓ Attack type priority respected
 * ✓ No duplicate signal generation
 * ✓ No circular dependencies
 * ✓ Error handling prevents crashes
 * ✓ Performance targets met (<50ms detection)
 * ✓ All error paths fail-safe (default to SAFE)
 *
 */
