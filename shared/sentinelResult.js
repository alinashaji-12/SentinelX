"use strict";

globalThis.SentinelStatus = {
  SAFE: "safe",
  SUSPICIOUS: "suspicious",
  MALICIOUS: "malicious"
};

function resolveStatus(score, signals = [], confidence = 100) {
  // Guard 1: if confidence is critically low, never call anything "suspicious"
  // on a mid-range score — return uncertain instead
  if (confidence < 25 && score >= 15 && score < 65) return "uncertain";

  // Guard 2: trust signal only zeroes out when score is genuinely zero
  const hasTrustSignal = signals.some((s) => {
    if (typeof s === "string") return s.toLowerCase().includes("trusted");
    return s?.type === "trust";
  });
  if (hasTrustSignal && score === 0) return "safe";

  // Guard 3: existing score bands
  if (score >= 65) return "malicious";
  if (score >= 30) return "suspicious";
  if (score >= 15) return "suspicious";
  return "safe";
}

function isGovernmentOrAcademic(hostname) {
  const h = String(hostname || "").toLowerCase();
  return (
    h.endsWith(".gov.in") || h.endsWith(".nic.in") || h.endsWith(".edu.in") ||
    h.endsWith(".ac.in") || h.endsWith(".gov") || h.endsWith(".edu")
  );
}

function applyConfidenceFloor(result, hostname) {
  if (!result || typeof result !== "object") return result;
  if (typeof globalThis.isHighReputationDomain === "function" && globalThis.isHighReputationDomain(hostname)) {
    // Never show very low confidence for known high-reputation domains.
    result.confidence = Math.max(Number(result.confidence || 0), 80);

    // If no strong threat signals on high-rep domains, keep SAFE.
    const hasStrongThreats = Array.isArray(result.signals) && result.signals.some((s) => {
      if (s && typeof s === "object") return Number(s.weight || 0) > 0.6;
      return /malware|phish|credential|keylogger|trojan|dataset|threat intel/i.test(String(s || ""));
    });
    if (!hasStrongThreats && Number(result.score || 0) < 40) {
      result.status = "safe";
      result.confidence = Math.max(Number(result.confidence || 0), 92);
    }
  }

  if (isGovernmentOrAcademic(hostname)) {
    result.confidence = Math.max(Number(result.confidence || 0), 90);
    if (Number(result.score || 0) < 30) result.status = "safe";
  }

  return result;
}

function getDomainCategory(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (!h) return null;
  if (h.endsWith(".gov.in") || h.endsWith(".nic.in") || h.endsWith(".gov")) return "government service";
  if (h.endsWith(".edu") || h.endsWith(".edu.in") || h.endsWith(".ac.in")) return "academic institution";
  if (/nykaa|myntra|ajio|meesho|flipkart|amazon\.in/.test(h)) return "Indian e-commerce platform";
  if (/pharmeasy|1mg|netmeds|apollopharmacy|practo/.test(h)) return "healthcare portal";
  if (/cerave|laroche|mamaearth|plum|dotandkey|minimalist/.test(h)) return "beauty and skincare brand";
  if (/cult\.fit|healthifyme|fittr/.test(h)) return "fitness and wellness platform";
  return "trusted website";
}

function generateVerdictSentence(result, hostname, category) {
  const r = result || {};
  if (r.status === "safe" && typeof globalThis.isHighReputationDomain === "function" && globalThis.isHighReputationDomain(hostname)) {
    return `${hostname} is a verified ${category || "trusted website"}.`;
  }
  if (r.status === "safe") {
    return "No threats detected on this page.";
  }
  if (r.status === "uncertain") {
    const topReason = r.reasons?.[0];
    if (topReason) return `This site has an unusual signal: ${String(topReason).toLowerCase()}.`;
    return "This site is unfamiliar to us. Browse carefully.";
  }
  if (r.status === "blocked" || r.status === "danger" || r.status === "malicious") {
    const topReason = r.reasons?.[0];
    if (topReason) return `Blocked: ${topReason}.`;
    return "This site shows multiple signals associated with phishing.";
  }
  return "Scan complete.";
}

globalThis.normalizeSentinelResult = function (raw) {
  const src = raw || {};
  const baseShape = {
    status: "safe",
    score: 0,
    confidence: 50,
    url: src.url || src.rawUrl || "",
    domain: src.domain || "",
    reasons: [],
    signals: [],
    categories: Array.isArray(src.categories) ? src.categories : [],
    behaviorEvents: Array.isArray(src.behaviorEvents) ? src.behaviorEvents : [],
    ssl: src.ssl || src.sslValid || null,
    sslIssuer: src.sslIssuer || null,
    redirectCount: Number(src.redirectCount) || 0,
    timestamp: src.timestamp || Date.now(),
    policySource: src.policySource || null,
    sensitivityMode: src.sensitivityMode || "medium",
  };

  if (typeof globalThis.isTrustedDomain === "function") {
    const trustKey = src.domain || src.url || src.rawUrl || "";
    const srcScore = Math.round(Math.min(100, Math.max(0, Number(src.score) || 0)));
    if (globalThis.isTrustedDomain(trustKey) && srcScore < 25) {
      return {
        ...baseShape,
        status: "safe",
        score: 0,
        confidence: 95,
        reasons: ["Verified trusted domain"],
        signals: [{ type: "trust", label: "Trusted domain", weight: 1 }]
      };
    }
  }

  let confidence = typeof src.confidence === "number"
    ? src.confidence
    : (typeof src.aiConfidence === "number" ? src.aiConfidence : 50);
  if (confidence > 0 && confidence <= 1) confidence = Math.round(confidence * 100);
  confidence = Math.round(Math.min(100, Math.max(0, confidence)));

  const score = Math.round(Math.min(100, Math.max(0, Number(src.score) || 0)));
  const reasonSignals = Array.isArray(src.reasons) ? src.reasons : [];
  const rawSignals = Array.isArray(src.signals) ? src.signals : [];
  const normalizedSignalObjects = [...rawSignals, ...reasonSignals].map((s) =>
    typeof s === "string" ? { type: "signal", label: s } : s
  );
  const status = resolveStatus(score, normalizedSignalObjects, confidence);

  const translationMap = {
    "signals below malicious correlation threshold": "No strong threat signals found for this page.",
    "Insufficient confidence to confirm safe — flagged for review": "We couldn't gather enough data to fully verify this page.",
    "Subdomain of trusted parent — score reduced by 30": "This appears to be a subdomain of a trusted website.",
    "Education/government domain — threat cap applied": "This is an education or government domain — treated with higher trust.",
    "Known security test domain — treat as suspicious": "This website is used to simulate cyber attacks for testing purposes.",
    "login_page_unverified_domain": "This appears to be a login page on a domain we haven't verified before. Avoid entering passwords unless you trust this site.",
    trusted_domain: "Verified safe domain",
    "Unencrypted HTTP connection": "Page loaded over unencrypted HTTP (not HTTPS)",
    "HTTP on non-root subdomain": "Unencrypted connection on a nested subdomain",
    "Unusually long subdomain": "Domain name has an abnormally long subdomain",
    "Subdomain looks algorithmically generated": "Subdomain pattern looks randomly generated",
    "Unusual multi-word subdomain pattern": "Subdomain uses an unusual multi-word structure",
    "Deeply nested subdomain": "URL has many nested subdomain levels",
    "Non-standard port": "Site uses a non-standard network port",
  };
  const simplifyReason = (item) => {
    const txt = String(item || "");
    if (translationMap[txt]) return translationMap[txt];
    if (/threshold|correlation|heuristic|pipeline|cap applied/i.test(txt)) {
      return "No strong threat signals found for this page.";
    }
    return txt;
  };
  let reasons = reasonSignals.map(simplifyReason).filter((r) => r && String(r).trim());
  reasons = reasons.filter((r, _, arr) => {
    if (
      (/insufficient data/i.test(r) ||
        /gather enough data to fully verify/i.test(r)) &&
      arr.some((x) => /no strong threat/i.test(x))
    ) {
      return false;
    }
    return true;
  });
  const seen = new Set();
  reasons = reasons
    .filter((r) => {
      const t = String(r).trim();
      if (!t) return false;
      if (seen.has(t)) return false;
      seen.add(t);
      return true;
    })
    .slice(0, 3);
  const signals = rawSignals.map((s) => (String(s) === "trusted_domain" ? "Verified safe domain" : s)).filter(Boolean);

  const out = {
    ...baseShape,
    status,
    score,
    confidence,
    url: src.url || src.rawUrl || "",
    domain: src.domain || baseShape.domain,
    reasons,
    signals,
  };
  if (src.sxExtendedRescanLowConfidence === true) {
    out.sxExtendedRescanLowConfidence = true;
  }

  // Domain-class-aware confidence/status floors.
  const hostForFloor = out.domain || out.url || "";
  applyConfidenceFloor(out, hostForFloor);
  const category = getDomainCategory(hostForFloor);
  out.verdictSentence = generateVerdictSentence(out, hostForFloor, category);

  return out;
};

globalThis.resolveStatus = resolveStatus;
