(function initThreatIntelService(global) {
  "use strict";

  const state = {
    phishingDomains: new Set([
      "secure-paypal-login.com",
      "microsoft-security-check.net",
      "verify-wallet-security.io",
      "appleid-verify-login.com"
    ]),
    blacklistDomains: new Set([
      "free-crypto-claim.xyz",
      "urgent-bank-reset.net",
      "gift-card-fastpayout.ru"
    ]),
    scamKeywords: new Set([])
  };

  function normalizeHost(host) {
    return String(host || "").trim().toLowerCase().replace(/^www\./, "");
  }

  function hostVariants(host) {
    const h = normalizeHost(host);
    if (!h) return [];
    const parts = h.split(".").filter(Boolean);
    const out = [h];
    if (parts.length > 2) out.push(parts.slice(-2).join("."));
    return [...new Set(out)];
  }

  function hashInt(input) {
    let h = 2166136261;
    const str = String(input || "");
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h >>> 0;
  }

  function getMockDomainProfile(domain) {
    const host = normalizeHost(domain);
    const seed = hashInt(host || "sentinel");
    const ageDays = 14 + (seed % 5200);
    const locations = ["US", "DE", "SG", "IN", "NL", "GB", "CA", "JP", "AU", "FR"];
    const serverLocation = locations[seed % locations.length];
    return { domainAgeDays: ageDays, serverLocation };
  }

  function hydrate(data) {
    if (!data || typeof data !== "object") return;

    const phish = Array.isArray(data.phishingDomains) ? data.phishingDomains : [];
    const black = Array.isArray(data.blacklistDomains) ? data.blacklistDomains : [];
    const scam = Array.isArray(data.scamKeywords) ? data.scamKeywords : [];

    phish.forEach((d) => state.phishingDomains.add(normalizeHost(d)));
    black.forEach((d) => state.blacklistDomains.add(normalizeHost(d)));
    scam.forEach((k) => state.scamKeywords.add(String(k || "").toLowerCase()));
  }

  function checkDomainReputation(domain) {
    const variants = hostVariants(domain);

    let matched = "";
    let source = "none";

    for (const v of variants) {
      if (state.blacklistDomains.has(v)) {
        matched = v;
        source = "domain_blacklist";
        break;
      }
      if (state.phishingDomains.has(v)) {
        matched = v;
        source = "phishing_database";
        break;
      }
    }

    const seed = hashInt(variants[0] || domain);
    const reports = source === "none" ? (seed % 4) : 12 + (seed % 40);
    const confidence = source === "domain_blacklist"
      ? 96
      : source === "phishing_database"
      ? 88
      : Math.min(35, reports * 8);

    const { domainAgeDays, serverLocation } = getMockDomainProfile(domain);

    return {
      isMalicious: source !== "none",
      reports,
      confidence,
      source,
      matchedDomain: matched,
      domainAgeDays,
      serverLocation
    };
  }

  global.SentinelThreatIntelService = {
    hydrate,
    checkDomainReputation,
    getMockDomainProfile
  };
})(globalThis);