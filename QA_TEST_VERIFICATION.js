/**
 * QA VERIFICATION TEST SUITE
 * Senior Cybersecurity QA Engineer
 *
 * Tests the 5 critical validation checks for Sentinel Browse Extension
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════
// EXTRACT analyzeUrlAdvancedSync FROM background.js (for testing)
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

const TRUSTED_DOMAINS = new Set([
  "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
  "github.com", "githubusercontent.com", "microsoft.com", "office.com",
  "microsoftonline.com", "sharepoint.com", "azure.com",
  "apple.com", "icloud.com", "amazon.com", "aws.amazon.com",
  "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
  "linkedin.com", "reddit.com", "stackoverflow.com",
  "cloudflare.com", "npmjs.com", "pypi.org", "wikipedia.org",
  "mozilla.org", "firefox.com", "opera.com", "chrome.google.com",
  "openai.com", "chatgpt.com", "bing.com", "yahoo.com", "duckduckgo.com"
]);

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
  return hostname.split(".").some(function (l) { return l.startsWith("xn--"); });
}

function buildSourcesArray(reasons) {
  var sources = [];
  if (reasons && reasons.length > 0) {
    reasons.forEach(function(reason) {
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
  var reasonStr = String(reason || "");
  if (reasonStr.includes("dataset")) return "Domain Dataset";
  if (reasonStr.includes("IP")) return "IP Address Detection";
  if (reasonStr.includes("phishing")) return "Phishing Intent Detection";
  if (reasonStr.includes("punycode")) return "Obfuscation Detection";
  if (reasonStr.includes("TLD")) return "High-Risk TLD Detection";
  if (reasonStr.includes("keyword")) return "Keyword Analysis";
  if (reasonStr.includes("hyphen")) return "Domain Structure Analysis";
  return "Multi-Signal Analysis";
}

function classifyAttackType(reasons) {
  var reasonStr = (reasons || []).join(" ").toLowerCase();
  if (reasonStr.includes("dataset") || reasonStr.includes("ip address")) {
    return "MALWARE";
  }
  if (reasonStr.includes("phishing") || (reasonStr.includes("keyword") && reasonStr.includes("domain"))) {
    return "PHISHING";
  }
  if (reasonStr.includes("punycode") || reasonStr.includes("obfuscation") || reasonStr.includes("encoding")) {
    return "OBFUSCATED_URL";
  }
  return "SAFE";
}

function safe(reasons) {
  return {
    status: "safe",
    score: 0,
    trustScore: 100,
    reasons: reasons || [],
    signals: [],
    attackType: "SAFE",
    confidence: 0,
    explanation: "No malicious signals detected.",
    sources: []
  };
}

function suspicious(reasons, score) {
  var s = score || 0;
  var signals = (reasons || []).map(function(r) {
    return String(r || "").split(":")[0].trim();
  }).filter(Boolean);

  return {
    status: "suspicious",
    score: s,
    trustScore: Math.max(0, 100 - s * 10),
    reasons: reasons || [],
    signals: signals,
    attackType: "SUSPICIOUS",
    confidence: Math.min(100, s * 15),
    explanation: "Several risk signals detected: " + (reasons || []).join("; "),
    sources: buildSourcesArray(reasons || [])
  };
}

function malicious(reasons, score) {
  var s = score || 0;
  var signals = (reasons || []).map(function(r) {
    return String(r || "").split(":")[0].trim();
  }).filter(Boolean);

  return {
    status: "malicious",
    score: s,
    trustScore: Math.max(0, 100 - s * 10),
    reasons: reasons || [],
    signals: signals,
    attackType: classifyAttackType(reasons || []),
    confidence: Math.min(100, s * 15),
    explanation: "Malicious site detected: " + (reasons || []).join("; "),
    sources: buildSourcesArray(reasons || [])
  };
}

function analyzeUrlAdvancedSync(url) {
  try {
    var input = String(url || "");
    if (!isSupportedUrl(input)) return safe();

    var parsed = safeParseUrl(input);
    if (!parsed) return safe();

    var hostname = parsed.hostname.toLowerCase();
    var pathname = parsed.pathname.toLowerCase();
    var root = getRootDomain(hostname);

    if (isTrusted(hostname)) return safe(["Trusted domain"]);

    var reasons = [];
    var score = 0;
    var hasIntent = false;
    var hasDomainRisk = false;
    var hasObfusc = false;

    if (PHISHING_DATASET.has(root) || PHISHING_DATASET.has(hostname)) {
      return malicious(["Domain matched phishing dataset: " + root], 10);
    }

    if (usesIpAddress(hostname)) {
      score += 2;
      reasons.push("Raw IP address used as host");
    }

    var tld = getTLD(hostname);
    if (tld && HIGH_RISK_TLDS.has(tld)) {
      score += 2; hasDomainRisk = true;
      reasons.push("High-risk TLD (." + tld + ")");
    }

    var hyphens = countHyphens(hostname);
    if (hyphens >= 3) {
      score += 2; hasDomainRisk = true;
      reasons.push("Heavy hyphen use (" + hyphens + " hyphens — brand impersonation pattern)");
    } else if (hyphens >= 2) {
      score += 1; hasDomainRisk = true;
      reasons.push("Multiple hyphens in domain (" + hyphens + ")");
    }

    var parts = hostname.split(".").filter(Boolean);
    if (parts.length >= 5) {
      score += 2; hasDomainRisk = true;
      reasons.push("Deep subdomain nesting (" + parts.length + " labels)");
    } else if (parts.length === 4) {
      score += 1; hasDomainRisk = true;
      reasons.push("Elevated subdomain depth");
    }

    if (hostname.length > 45) {
      score += 1; hasDomainRisk = true;
      reasons.push("Unusually long hostname (" + hostname.length + " chars)");
    }

    if (hasPunycode(hostname)) {
      score += 3; hasObfusc = true;
      reasons.push("Punycode domain (" + hostname + ") — possible homoglyph attack");
    }

    if (/%[0-9a-f]{2}/i.test(hostname + pathname)) {
      score += 2; hasObfusc = true;
      reasons.push("Percent-encoding in hostname or path");
    }

    if (usesIpAddress(hostname)) {
      score += 3;
      reasons.push("Raw IP address — no legitimate site uses bare IP for main domain");
      return malicious(reasons, score);
    }

    var hostnameTokens = tokenize(hostname);
    var allTokens = tokenize(hostname + " " + pathname);
    var keywords = hostnameTokens.filter(function (t) { return PHISHING_KEYWORDS.has(t); });
    var urgency = allTokens.filter(function (t) { return URGENCY_WORDS.has(t); });

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
// TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════

const tests = [
  {
    name: "Dataset match - malicious.com",
    url: "http://malicious.com/page",
    expectedStatus: "malicious"
  },
  {
    name: "Multi-keyword phishing on high-risk TLD",
    url: "https://login-secure-account.xyz/verify",
    expectedStatus: "malicious"
  },
  {
    name: "Phishing keywords + urgency intent",
    url: "https://apple-verify-urgent.com/confirm",
    expectedStatus: "malicious"
  },
  {
    name: "IP address hosting",
    url: "http://192.168.1.1/page",
    expectedStatus: "malicious"
  },
  {
    name: "Punycode + phishing intent",
    url: "https://xn--e1afmkfd.xn--p1ai/login",
    expectedStatus: "malicious"
  },
  {
    name: "Safe domain - google.com",
    url: "https://www.google.com/search",
    expectedStatus: "safe"
  },
  {
    name: "Non-existent TLD (.xyz without phishing pattern)",
    url: "https://legit-startup.xyz",
    expectedStatus: "safe"
  }
];

console.log("\n" + "═".repeat(80));
console.log("CRITICAL VALIDATION TEST SUITE");
console.log("═".repeat(80) + "\n");

let passCount = 0;
let failCount = 0;

tests.forEach((test, index) => {
  const result = analyzeUrlAdvancedSync(test.url);
  const passed = result.status === test.expectedStatus;

  console.log(`\n[TEST ${index + 1}] ${test.name}`);
  console.log(`URL: ${test.url}`);
  console.log(`Expected: ${test.expectedStatus} | Got: ${result.status}`);
  console.log(`Status: ${passed ? "✅ PASS" : "❌ FAIL"}`);

  if (!passed) {
    failCount++;
  } else {
    passCount++;
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// CRITICAL BUG VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n\n" + "═".repeat(80));
console.log("CRITICAL BUG VALIDATION - DATA PIPELINE");
console.log("═".repeat(80) + "\n");

const testUrl = "http://malicious.com/page";
const result = analyzeUrlAdvancedSync(testUrl);

console.log("[RESULT OBJECT ANALYSIS]");
console.log(JSON.stringify(result, null, 2));

console.log("\n[FIELD COMPLETENESS CHECK]");
console.log(`✓ status: ${result.status}`);
console.log(`✓ trustScore: ${result.trustScore}`);
console.log(`✓ attackType: ${result.attackType}`);
console.log(`✓ confidence: ${result.confidence}`);
console.log(`✓ explanation: ${result.explanation}`);
console.log(`✓ signals: ${JSON.stringify(result.signals)}`);
console.log(`✓ sources: ${JSON.stringify(result.sources)}`);

console.log("\n[URL REDIRECT PARAMETER GENERATION]");
const redirectUrl = "chrome://warning.html" +
  "?url=" + encodeURIComponent(testUrl) +
  "&attackType=" + encodeURIComponent(result.attackType || "UNKNOWN") +
  "&confidence=" + encodeURIComponent(result.confidence || 0) +
  "&reason=" + encodeURIComponent(result.reason || "Threat detected") +
  "&signals=" + encodeURIComponent(JSON.stringify(result.signals || [])) +
  "&sources=" + encodeURIComponent(JSON.stringify(result.sources || []));

console.log(`\nGenerated Redirect URL:`);
console.log(redirectUrl);

console.log("\n[BUG DETECTION]");
if (!result.reason && result.status === "malicious") {
  console.log("❌ BUG: result.reason is UNDEFINED for malicious URL");
  console.log("   This will cause warning page to show 'Threat detected' instead of actual reason");
  console.log(`   Solution: Use result.explanation or build from reasons array`);
  console.log(`   Value: ${result.explanation}`);
} else if (result.reason) {
  console.log(`✓ result.reason exists: ${result.reason}`);
} else {
  console.log(`⚠️  result.reason missing (field doesn't exist)`);
}

if (result.signals.length === 0 && result.status === "malicious") {
  console.log("❌ BUG: signals array is EMPTY for malicious URL");
} else if (result.signals.length > 0) {
  console.log(`✓ signals array: ${result.signals.length} items`);
} else {
  console.log(`⚠️  signals has ${result.signals.length} items`);
}

if (result.sources.length === 0 && result.status === "malicious") {
  console.log("❌ BUG: sources array is EMPTY for malicious URL");
} else if (result.sources.length > 0) {
  console.log(`✓ sources array: ${result.sources.length} items`);
}

console.log("\n" + "═".repeat(80));
console.log(`TEST SUMMARY: ${passCount} passed, ${failCount} failed`);
console.log("═".repeat(80) + "\n");
