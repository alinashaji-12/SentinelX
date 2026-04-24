/**
 * PHISHING BYPASS TEST SUITE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests 7 real-world phishing attack patterns against Sentinel's detection engine.
 * Verifies that analyzeUrlAdvancedSync() correctly identifies each as malicious/suspicious.
 *
 * HOW TO RUN:
 *   1. Open Chrome DevTools in any privileged extension context
 *   2. Copy the detection logic from background.js (analyzeUrlAdvancedSync function)
 *   3. Run this script with complete test URLs
 *
 * WHAT IT CHECKS:
 *   ✓ Does analyzeUrlAdvancedSync trigger?
 *   ✓ Is result = malicious/suspicious?
 *   ✓ Does it build correct redirect URL?
 *   ✓ Does warning page receive FULL data (url, reason, signals, sources, confidence)?
 */

// ═══════════════════════════════════════════════════════════════════════════
// TEST DATA — Real-World Phishing Patterns
// ═══════════════════════════════════════════════════════════════════════════

const TEST_URLS = [
  {
    url: "http://secure-login-account-update.xyz",
    name: "🧪 Test 1: Keyword + Suspicious TLD",
    expectedStatus: "malicious",
    expectedAttackType: "PHISHING",
    expectedReasons: ["Multi-keyword phishing hostname", "High-risk TLD"],
    description: "Classic phishing: 4 keywords (secure, login, account, update) on .xyz TLD",
    signals: ["Phishing intent", "High-risk TLD", "Multiple hyphens"]
  },
  {
    url: "http://google.com.secure-login.xyz",
    name: "🧪 Test 2: Subdomain Spoofing",
    expectedStatus: "malicious",
    expectedAttackType: "PHISHING",
    expectedReasons: ["Multi-keyword phishing hostname", "High-risk TLD"],
    description: "Homograph attack: real domain (google.com) embedded inside fake domain",
    signals: ["Domain spoofing", "Phishing keywords", "High-risk TLD"]
  },
  {
    url: "http://example.com/login%2Fsecure%2Fupdate",
    name: "🧪 Test 3: URL Obfuscation (% encoding)",
    expectedStatus: "suspicious",
    expectedAttackType: "OBFUSCATED_URL",
    expectedReasons: ["Percent-encoding in hostname or path"],
    description: "URL path obfuscation using percent-encoding to hide sensitive segments",
    signals: ["URL obfuscation", "Encoded path"]
  },
  {
    url: "http://192.168.0.1/login",
    name: "🧪 Test 4: IP-based Phishing",
    expectedStatus: "malicious",
    expectedAttackType: "MALWARE",
    expectedReasons: ["Raw IP address used"],
    description: "Direct IP address instead of domain name (instant red flag)",
    signals: ["IP address usage", "No legitimate site uses bare IP"]
  },
  {
    url: "http://secure-login-account.com/session=asdkj1231231asd123asd",
    name: "🧪 Test 5: Long Random Token Attack",
    expectedStatus: "suspicious",
    expectedAttackType: "PHISHING",
    expectedReasons: ["Multi-keyword phishing hostname"],
    description: "Tracking and obfuscation: 3 keywords on legitimate TLD with long token",
    signals: ["Phishing keywords", "Session token pattern"]
  },
  {
    url: "http://example.com/login?redirect=secure-update-account.xyz",
    name: "🧪 Test 6: Redirect Trap",
    expectedStatus: "safe",  // example.com is trusted
    expectedAttackType: "SAFE",
    expectedReasons: ["Trusted domain"],
    description: "Legitimate domain with hidden redirect to phishing site (Pass 1 sees trusted domain, Pass 2 can catch redirect)",
    signals: ["Trusted domain override"]
  },
  {
    url: "http://paypaI.com.login-secure.xyz",
    name: "🧪 Test 7: Homograph-style Trick (Visual Spoof)",
    expectedStatus: "malicious",
    expectedAttackType: "PHISHING",
    expectedReasons: ["Multi-keyword phishing hostname", "High-risk TLD"],
    description: "Brand spoofing: capital 'I' (looks like lowercase 'l'), domains combo-spoofing PayPal",
    signals: ["Visual homograph", "Brand spoofing", "Phishing keywords on high-risk TLD"]
  }
];

// ═══════════════════════════════════════════════════════════════════════════
// EMBEDDED DETECTION LOGIC (from background.js)
// ═══════════════════════════════════════════════════════════════════════════

const HIGH_RISK_TLDS = new Set([
  "xyz", "tk", "ml", "ga", "cf", "gq",
  "top", "club", "online", "site", "web",
  "ru", "cn", "pw", "cc", "ws",
  "info", "biz", "click", "link", "live", "stream", "zip", "mov"
]);

const PHISHING_KEYWORDS = new Set([
  "login", "signin", "logon", "verify", "verification", "validate",
  "account", "accounts", "secure", "security", "password", "passwd",
  "credential", "wallet", "banking", "confirm", "confirmation",
  "update", "upgrade", "recover", "recovery", "suspend", "suspended",
  "appleid"
]);

const URGENCY_WORDS = new Set([
  "urgent", "urgently", "immediately", "immediate", "now", "asap",
  "alert", "warning", "critical", "expire", "expires", "expiring",
  "limited", "action", "locked", "lock", "blocked", "unusual", "activity", "deadline"
]);

const TRUSTED_DOMAINS = new Set([
  "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
  "github.com", "githubusercontent.com", "microsoft.com", "office.com",
  "microsoftonline.com", "sharepoint.com", "azure.com",
  "apple.com", "icloud.com", "amazon.com", "aws.amazon.com",
  "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
  "linkedin.com", "reddit.com", "stackoverflow.com",
  "cloudflare.com", "npmjs.com", "pypi.org", "wikipedia.org",
  "mozilla.org", "firefox.com", "opera.com", "chrome.google.com",
  "openai.com", "chatgpt.com", "bing.com", "yahoo.com", "duckduckgo.com",
  "example.com"  // NOTE: example.com IS trusted (RFC reserved)
]);

const SEARCH_ENGINE_HOSTS = new Set([
  "google.com", "www.google.com", "search.yahoo.com", "www.bing.com",
  "duckduckgo.com", "www.duckduckgo.com", "search.brave.com", "ecosia.org"
]);

const PHISHING_DATASET = new Set([
  "paypal-login-secure.com", "paypa1-account.com", "paypal-update-required.net",
  "amazon-update-account.xyz", "amazon-account-alert.net", "banking-verify-now.com",
  "secure-bankofamerica.com", "chase-security-alert.com",
  "facebook-verification.net", "facebook-login-secure.com",
  "apple-id-verify.com", "apple-account-locked.net",
  "microsoft-support-alert.com", "google-account-recovery.xyz",
  "crypto-wallet-recover.xyz", "phishing-site.net",
  "secure-verify-login.com", "account-suspended-alert.com",
  "login-secure-update.com", "verify-account-now.xyz",
  "metamask-security.net", "coinbase-verify.net", "malicious.com"
]);

// ─── Helper functions ───────────────────────────────────────────────────────

function safeParseUrl(url) {
  try { return new URL(String(url || "")); } catch { return null; }
}

function getRootDomain(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

function getTLD(hostname) {
  const parts = hostname.split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : "";
}

function isSupportedUrl(url) {
  return /^https?:\/\//i.test(url);
}

function isTrusted(hostname) {
  const root = getRootDomain(hostname);
  if (TRUSTED_DOMAINS.has(root) || TRUSTED_DOMAINS.has(hostname)) return true;
  for (const d of TRUSTED_DOMAINS) {
    if (hostname.endsWith("." + d)) return true;
  }
  return false;
}

function isSearchEngineQuery(hostname, pathname) {
  if (!SEARCH_ENGINE_HOSTS.has(hostname)) return false;
  if (!pathname) return true;
  return pathname === "/" || pathname.startsWith("/search") || pathname.startsWith("/webhp");
}

function tokenize(text) {
  return (text || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function countHyphens(hostname) {
  return (hostname.match(/-/g) || []).length;
}

function usesIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function hasPunycode(hostname) {
  return hostname.split(".").some((l) => l.startsWith("xn--"));
}

function classifyAttackType(reasons) {
  const reasonStr = (reasons || []).join(" ").toLowerCase();
  if (reasonStr.includes("dataset") || reasonStr.includes("ip address")) {
    return "MALWARE";
  }
  if (reasonStr.includes("phishing") || (reasonStr.includes("keyword") && reasonStr.includes("domain"))) {
    return "PHISHING";
  }
  if (reasonStr.includes("punycode") || reasonStr.includes("obfuscation") || reasonStr.includes("encoding")) {
    return "OBFUSCATED_URL";
  }
  return "SUSPICIOUS";
}

function buildSourcesArray(reasons) {
  const sources = [];
  if (reasons && reasons.length > 0) {
    reasons.forEach((reason) => {
      sources.push({
        name: extractSourceName(reason),
        verdict: "malicious",
        triggered: true,
        detail: reason
      });
    });
  }
  return sources;
}

function extractSourceName(reason) {
  const reasonStr = String(reason || "");
  if (reasonStr.includes("dataset")) return "Domain Dataset";
  if (reasonStr.includes("IP")) return "IP Address Detection";
  if (reasonStr.includes("phishing")) return "Phishing Intent Detection";
  if (reasonStr.includes("punycode")) return "Obfuscation Detection";
  if (reasonStr.includes("TLD")) return "High-Risk TLD Detection";
  if (reasonStr.includes("keyword")) return "Keyword Analysis";
  if (reasonStr.includes("hyphen")) return "Domain Structure Analysis";
  return "Multi-Signal Analysis";
}

function safe(reasons) {
  const explanation = "No malicious signals detected.";
  return {
    status: "safe",
    score: 0,
    trustScore: 100,
    reason: explanation,
    reasons: reasons || [],
    signals: [],
    attackType: "SAFE",
    confidence: 0,
    explanation: explanation,
    sources: []
  };
}

function suspicious(reasons, score) {
  const s = score || 0;
  const signals = (reasons || []).map((r) => {
    return String(r || "").split(":")[0].trim();
  }).filter(Boolean);
  const explanation = "Several risk signals detected: " + (reasons || []).join("; ");

  return {
    status: "suspicious",
    score: s,
    trustScore: Math.max(0, 100 - s * 10),
    reason: explanation,
    reasons: reasons || [],
    signals: signals,
    attackType: "SUSPICIOUS",
    confidence: Math.min(100, s * 15),
    explanation: explanation,
    sources: buildSourcesArray(reasons || [])
  };
}

function malicious(reasons, score) {
  const s = score || 0;
  const signals = (reasons || []).map((r) => {
    return String(r || "").split(":")[0].trim();
  }).filter(Boolean);
  const explanation = "Malicious site detected: " + (reasons || []).join("; ");

  return {
    status: "malicious",
    score: s,
    trustScore: Math.max(0, 100 - s * 10),
    reason: explanation,
    reasons: reasons || [],
    signals: signals,
    attackType: classifyAttackType(reasons || []),
    confidence: Math.min(100, s * 15),
    explanation: explanation,
    sources: buildSourcesArray(reasons || [])
  };
}

// ─── Main detection function ───────────────────────────────────────────────

function analyzeUrlAdvancedSync(url) {
  try {
    const input = String(url || "");
    if (!isSupportedUrl(input)) return safe();

    const parsed = safeParseUrl(input);
    if (!parsed) return safe();

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const root = getRootDomain(hostname);

    // ── Trusted / search: always SAFE ─────────────────────────────────
    if (isTrusted(hostname)) return safe(["Trusted domain"]);
    if (isSearchEngineQuery(hostname, pathname)) return safe(["Search engine query"]);

    let reasons = [];
    let score = 0;
    let hasIntent = false;
    let hasDomainRisk = false;
    let hasObfusc = false;

    // ── Dataset match (hard malicious) ──────────────────────────────
    if (PHISHING_DATASET.has(root) || PHISHING_DATASET.has(hostname)) {
      return malicious(["Domain matched phishing dataset: " + root], 10);
    }

    // ── IP address ───────────────────────────────────────────────────
    if (usesIpAddress(hostname)) {
      score += 2;
      reasons.push("Raw IP address used as host");
    }

    // ── TLD risk ─────────────────────────────────────────────────────
    const tld = getTLD(hostname);
    if (tld && HIGH_RISK_TLDS.has(tld)) {
      score += 2; hasDomainRisk = true;
      reasons.push("High-risk TLD (." + tld + ")");
    }

    // ── Hyphens ──────────────────────────────────────────────────────
    const hyphens = countHyphens(hostname);
    if (hyphens >= 3) {
      score += 2; hasDomainRisk = true;
      reasons.push("Heavy hyphen use (" + hyphens + " hyphens — brand impersonation pattern)");
    } else if (hyphens >= 2) {
      score += 1; hasDomainRisk = true;
      reasons.push("Multiple hyphens in domain (" + hyphens + ")");
    }

    // ── Deep subdomain ───────────────────────────────────────────────
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length >= 5) {
      score += 2; hasDomainRisk = true;
      reasons.push("Deep subdomain nesting (" + parts.length + " labels)");
    } else if (parts.length === 4) {
      score += 1; hasDomainRisk = true;
      reasons.push("Elevated subdomain depth");
    }

    // ── Long hostname ────────────────────────────────────────────────
    if (hostname.length > 45) {
      score += 1; hasDomainRisk = true;
      reasons.push("Unusually long hostname (" + hostname.length + " chars)");
    }

    // ── Punycode ─────────────────────────────────────────────────────
    if (hasPunycode(hostname)) {
      score += 3; hasObfusc = true;
      reasons.push("Punycode domain (" + hostname + ") — possible homoglyph attack");
    }

    // ── Percent-encoding in hostname/path ────────────────────────────
    if (/%[0-9a-f]{2}/i.test(hostname + pathname)) {
      score += 2; hasObfusc = true;
      reasons.push("Percent-encoding in hostname or path");
    }

    // ── IP address direct block ──────────────────────────────────────
    if (usesIpAddress(hostname)) {
      score += 3;
      reasons.push("Raw IP address — no legitimate site uses bare IP for main domain");
      return malicious(reasons, score);
    }

    // ── Intent detection ──────────────────────────────────────────────
    const hostnameTokens = tokenize(hostname);
    const allTokens = tokenize(hostname + " " + pathname);
    const keywords = hostnameTokens.filter((t) => PHISHING_KEYWORDS.has(t));
    const urgency = allTokens.filter((t) => URGENCY_WORDS.has(t));

    if (keywords.length > 0 && urgency.length > 0) {
      score += 3; hasIntent = true;
      reasons.push(
        "Phishing intent: keywords [" + keywords.join(",") + "]" +
        " + urgency [" + urgency.join(",") + "]"
      );
    } else if (keywords.length >= 2) {
      score += 3; hasIntent = true;
      reasons.push(
        "Multi-keyword phishing hostname: [" + keywords.join(", ") + "] — " +
        keywords.length + " sensitive words combined in one domain"
      );
    } else if (keywords.length === 1) {
      score += 1;
      reasons.push("Phishing keyword in hostname (weak — single signal): " + keywords[0]);
    }

    // ── Decision ladder ───────────────────────────────────────────────
    console.log("[Sentinel] Pre-DNS Detection:", {
      url: hostname,
      keywords: keywords,
      urgency: urgency,
      tld: tld,
      score: score,
      hasIntent: hasIntent,
      hasDomainRisk: hasDomainRisk,
      hasObfusc: hasObfusc
    });

    if (hasIntent && hasDomainRisk && hasObfusc) {
      return malicious(reasons, score);
    }
    if (hasIntent && hasDomainRisk && score >= 5) {
      return malicious(reasons, score);
    }
    if (keywords.length >= 2 && tld && HIGH_RISK_TLDS.has(tld)) {
      reasons.push("Confirmed phishing pattern: " + keywords.length +
        " sensitive keywords on high-risk TLD (." + tld + ")");
      return malicious(reasons, score);
    }
    if (hasPunycode(hostname) && hasIntent) {
      return malicious(reasons, score);
    }
    if (hasPunycode(hostname)) {
      return suspicious(reasons, score);
    }
    if (score >= 2) {
      return suspicious(reasons, score);
    }

    return safe();

  } catch (err) {
    console.error("[Sentinel][Sync] analyzeUrlAdvancedSync error:", err);
    return safe();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST RUNNER
// ═══════════════════════════════════════════════════════════════════════════

function runTests() {
  console.log("\n" + "═".repeat(80));
  console.log("  SENTINEL PHISHING BYPASS TEST SUITE");
  console.log("═".repeat(80) + "\n");

  let passed = 0;
  let failed = 0;
  const results = [];

  TEST_URLS.forEach((test, index) => {
    console.log(`\n${test.name}`);
    console.log(`URL: ${test.url}`);
    console.log(`Description: ${test.description}`);
    console.log("-".repeat(80));

    try {
      const result = analyzeUrlAdvancedSync(test.url);

      // ── Verify detection triggered ────────────────────────────────────
      const detectionTriggered = result.status !== "safe";
      console.log(`✓ Detection triggered: ${detectionTriggered ? "YES" : "NO"}`);

      // ── Verify verdict matches expected ───────────────────────────────
      const verdictMatch = result.status === test.expectedStatus;
      console.log(`✓ Status matches (expected: ${test.expectedStatus}, got: ${result.status}): ${verdictMatch ? "PASS" : "FAIL"}`);

      // ── Verify attack type ───────────────────────────────────────────
      const typeMatch = result.attackType === test.expectedAttackType;
      console.log(`✓ Attack type matches (expected: ${test.expectedAttackType}, got: ${result.attackType}): ${typeMatch ? "PASS" : "FAIL"}`);

      // ── Verify signals detected ──────────────────────────────────────
      console.log(`✓ Signals detected: ${result.signals.length} (${result.signals.join(", ")})`);

      // ── Verify warning page data would be passed ──────────────────────
      const warningUrl = `warning.html?url=${encodeURIComponent(test.url)}&attackType=${encodeURIComponent(result.attackType || "UNKNOWN")}&confidence=${encodeURIComponent(result.confidence || 0)}&reason=${encodeURIComponent(result.reason || "Threat detected")}&signals=${encodeURIComponent(JSON.stringify(result.signals || []))}&sources=${encodeURIComponent(JSON.stringify(result.sources || []))}`;

      console.log(`✓ Warning URL would include:`);
      console.log(`  - URL: ${test.url}`);
      console.log(`  - Attack Type: ${result.attackType}`);
      console.log(`  - Confidence: ${result.confidence}%`);
      console.log(`  - Signals: [${result.signals.join(", ")}]`);
      console.log(`  - Sources: ${result.sources.map(s => s.name).join(", ")}`);

      // ── Final verdict ────────────────────────────────────────────────
      const allPass = verdictMatch && typeMatch && detectionTriggered;
      if (allPass) {
        console.log(`\n✅ TEST PASSED`);
        passed++;
      } else {
        console.log(`\n❌ TEST FAILED`);
        failed++;
      }

      results.push({
        test: test.name,
        url: test.url,
        passed: allPass,
        result: result
      });

    } catch (err) {
      console.error(`❌ ERROR: ${err.message}`);
      failed++;
      results.push({
        test: test.name,
        url: test.url,
        passed: false,
        error: err.message
      });
    }
  });

  // ── Summary ────────────────────────────────────────────────────────────
  console.log("\n" + "═".repeat(80));
  console.log(`  TEST SUMMARY: ${passed} PASSED, ${failed} FAILED (${passed + failed} TOTAL)`);
  console.log("═".repeat(80) + "\n");

  return {
    passed,
    failed,
    total: passed + failed,
    results
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT & RUN
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== "undefined" && module.exports) {
  module.exports = { runTests, analyzeUrlAdvancedSync, TEST_URLS };
}

// Auto-run if not in module context
if (typeof window !== "undefined") {
  window.runPhishingTests = runTests;
  console.log("✅ Run tests with: runPhishingTests()");
}
