/**
 * patterns.js — Sentinel Browse Extension
 *
 * Attack Pattern Classifier
 * Identifies the type and severity of detected threats.
 *
 * Classification:
 *   PHISHING         — Credential theft focused
 *   MALWARE          — Code execution, exploit delivery
 *   SOCIAL_ENGINEERING — Urgency/scarcity tricks
 *   OBFUSCATED_URL   — Hiding malicious intent
 *   SAFE             — No threat indicators
 */

/**
 * Classifies the type of attack being attempted.
 *
 * @param {string} url
 * @param {object} signals — signal groups from detection
 * @param {string[]} keywordMatches — detected phishing keywords
 * @returns {{
 *   type: 'PHISHING' | 'MALWARE' | 'SOCIAL_ENGINEERING' | 'OBFUSCATED_URL' | 'SAFE',
 *   severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
 *   description: string,
 *   reasoning: string[]
 * }}
 */
export function classifyAttackPattern(url = "", signals = {}, keywordMatches = []) {
  const reasoning = [];
  let type = "SAFE";
  let severity = "INFO";
  let description = "No threats detected";

  const {
    hasIntent = false,
    hasDomainAnomaly = false,
    hasObfuscation = false,
    hasSignature = false,
    hasDataset = false,
    hasSafeBrowsing = false,
    hasIpAddress = false,
  } = signals;

  // ── Pattern 1: Direct credential phishing ────────────────────────────────
  if (hasIntent && hasDomainAnomaly) {
    type = "PHISHING";
    severity = "CRITICAL";
    description = "Credential Phishing Attack";
    reasoning.push(
      "URL contains phishing keywords (login, verify, account, etc.)",
      "Domain structure mimics legitimate sites to deceive users",
      "Designed to harvest login credentials or personal data"
    );

    // Escalate to CRITICAL if also obfuscated
    if (hasObfuscation) {
      reasoning.push("Additional obfuscation suggests sophisticated phishing kit");
    }

    return { type, severity, description, reasoning };
  }

  // ── Pattern 2: Malware delivery & exploitation ───────────────────────────
  if ((hasObfuscation || hasSignature) && (hasDataset || hasSafeBrowsing)) {
    type = "MALWARE";
    severity = "CRITICAL";
    description = "Malware Distribution Site";
    reasoning.push(
      "Known malicious destination flagged by security researchers",
      hasObfuscation ? "URL uses obfuscation to hide delivery mechanism" : "",
      hasSignature ? "Matches known malware signature patterns" : ""
    ).filter(Boolean);
    return { type, severity, description, reasoning };
  }

  // ── Pattern 3: Social engineering (urgency, scarcity, fear) ──────────────
  if (hasIntent && !hasDomainAnomaly && hasObfuscation) {
    // Intent without domain risk but with obfuscation = hiding a social eng tactic
    type = "SOCIAL_ENGINEERING";
    severity = "HIGH";
    description = "Social Engineering Attack";
    reasoning.push(
      "Uses phishing keywords combined with URL obfuscation",
      "Likely employing urgency/scarcity tactics to bypass critical thinking",
      "URL hidden intransparency suggests deceptive intent"
    );
    return { type, severity, description, reasoning };
  }

  // ── Pattern 4: Pure obfuscation attempts ─────────────────────────────────
  if (hasObfuscation && !hasIntent && !hasDataset) {
    type = "OBFUSCATED_URL";
    severity = "MEDIUM";
    description = "Suspicious URL Obfuscation";
    reasoning.push(
      "URL uses encoding, punycode, or shorteners to hide true destination",
      "Unclear destination may indicate malicious redirect",
      "Legitimate sites rarely need this level of obfuscation"
    );
    return { type, severity, description, reasoning };
  }

  // ── Pattern 5: Domain-only anomalies ─────────────────────────────────────
  if (hasDomainAnomaly && !hasIntent) {
    type = "PHISHING";
    severity = "MEDIUM";
    description = "Suspicious Domain Structure";
    reasoning.push(
      "Domain uses common phishing patterns (hyphens, risky TLDs, deep nesting)",
      "No explicit phishing keywords, but structure matches known attack templates",
      "May be early-stage phishing domain or brand impersonation attempt"
    );
    return { type, severity, description, reasoning };
  }

  // ── Pattern 6: Known dangerous site ──────────────────────────────────────
  if (hasSafeBrowsing || hasDataset) {
    type = "MALWARE";
    severity = "CRITICAL";
    description = "Known Malicious Site";
    reasoning.push(
      "Domain flagged by Google Safe Browsing or phishing/malware database",
      "Reported by security researchers as actively exploiting users",
      "Browser block recommended"
    );
    return { type, severity, description, reasoning };
  }

  // ── Pattern 7: IP address usage ──────────────────────────────────────────
  if (hasIpAddress) {
    type = "PHISHING";
    severity = "MEDIUM";
    description = "IP Address Usage";
    reasoning.push(
      "Site uses raw IP address instead of legitimate domain name",
      "Common in quick-turnaround phishing and exploit delivery",
      "Harder to trace and block compared to domain-based attacks"
    );
    return { type, severity, description, reasoning };
  }

  // ── Default: No significant patterns detected ────────────────────────────
  return {
    type: "SAFE",
    severity: "INFO",
    description: "No Threat Detected",
    reasoning: ["No malicious patterns identified"],
  };
}

/**
 * Returns a human-readable description of the attack type.
 *
 * @param {string} attackType
 * @returns {string}
 */
export function getAttackTypeDescription(attackType) {
  const descriptions = {
    PHISHING:
      "Phishing attempts to steal credentials or personal information by impersonating legitimate sites.",
    MALWARE:
      "Malware delivery sites host code designed to infect your system with viruses, trojans, or other threats.",
    SOCIAL_ENGINEERING:
      "Social engineering exploits human psychology using urgency, fear, or authority to bypass security.",
    OBFUSCATED_URL:
      "Obfuscated URLs hide their true destination, making it impossible to verify where you're being sent.",
    SAFE: "This site shows no known malicious characteristics.",
  };

  return descriptions[attackType] || descriptions.SAFE;
}

/**
 * Maps severity level to a color code and icon.
 *
 * @param {string} severity
 * @returns {{ color: string, icon: string, label: string }}
 */
export function getSeverityMeta(severity) {
  const meta = {
    CRITICAL: { color: "#d32f2f", icon: "🚨", label: "CRITICAL" },
    HIGH: { color: "#f57c00", icon: "⚠️", label: "HIGH" },
    MEDIUM: { color: "#fbc02d", icon: "⚠️", label: "MEDIUM" },
    LOW: { color: "#388e3c", icon: "ℹ️", label: "LOW" },
    INFO: { color: "#1976d2", icon: "ℹ️", label: "INFO" },
  };

  return meta[severity] || meta.INFO;
}
