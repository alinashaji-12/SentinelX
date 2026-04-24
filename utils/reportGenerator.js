function normalizeStatus(value) {
  const status = String(value || "").toLowerCase();

  if (status === "malicious" || status === "suspicious" || status === "safe") {
    return status;
  }

  return "safe";
}

function getHostname(url) {
  try {
    return new URL(String(url || "")).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function getMostFrequentEntry(counts) {
  let selectedKey = "none";
  let selectedCount = 0;

  for (const [key, count] of counts.entries()) {
    if (count > selectedCount) {
      selectedKey = key;
      selectedCount = count;
    }
  }

  return {
    value: selectedKey,
    count: selectedCount
  };
}

export function generateReport(history) {
  const items = Array.isArray(history) ? history : [];
  const statusCounts = new Map([
    ["malicious", 0],
    ["suspicious", 0],
    ["safe", 0]
  ]);
  const threatTypeCounts = new Map();
  const maliciousDomainCounts = new Map();

  for (const item of items) {
    const status = normalizeStatus(item?.status);
    statusCounts.set(status, (statusCounts.get(status) || 0) + 1);

    if (status === "malicious" || status === "suspicious") {
      const threatType = String(item?.source || "unknown");
      threatTypeCounts.set(threatType, (threatTypeCounts.get(threatType) || 0) + 1);
    }

    if (status === "malicious") {
      const domain = item?.domain || getHostname(item?.url);
      if (domain) {
        maliciousDomainCounts.set(domain, (maliciousDomainCounts.get(domain) || 0) + 1);
      }
    }
  }

  const topThreatType = getMostFrequentEntry(threatTypeCounts);
  const topMaliciousDomain = getMostFrequentEntry(maliciousDomainCounts);
  const generatedAt = new Date().toISOString();

  return {
    generatedAt,
    totalUrlsScanned: items.length,
    maliciousCount: statusCounts.get("malicious") || 0,
    suspiciousCount: statusCounts.get("suspicious") || 0,
    safeCount: statusCounts.get("safe") || 0,
    mostCommonThreatType: topThreatType.value,
    mostCommonThreatTypeCount: topThreatType.count,
    mostFrequentMaliciousDomain: topMaliciousDomain.value,
    mostFrequentMaliciousDomainCount: topMaliciousDomain.count
  };
}
