const SAFE_BROWSING_API_URL =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY";
const SAFE_BROWSING_TIMEOUT_MS = 3000;

function normalizeUrl(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || ""));
    parsed.hash = "";

    let normalizedPath = parsed.pathname.replace(/\/+$/, "");
    if (normalizedPath === "/") {
      normalizedPath = "";
    }

    return `${parsed.origin}${normalizedPath}${parsed.search}`;
  } catch {
    return String(rawUrl || "");
  }
}

function getStorageLocal(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => {
      resolve(result || {});
    });
  });
}

function setStorageLocal(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => {
      resolve();
    });
  });
}

export async function checkWithSafeBrowsing(url) {
  const normalizedUrl = normalizeUrl(url);

  if (!normalizedUrl) {
    return {
      flag: false,
      isMalicious: false,
      error: true,
      source: "fallback",
      reason: "Safe Browsing unavailable"
    };
  }

  const cacheKey = `safeBrowsing:${normalizedUrl}`;
  const cached = await getStorageLocal([cacheKey]);
  if (cached[cacheKey]) {
    return cached[cacheKey];
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, SAFE_BROWSING_TIMEOUT_MS);

  try {
    const response = await fetch(SAFE_BROWSING_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "sentinel-browse-extension",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: normalizedUrl }]
        }
      }),
      signal: controller.signal
    });

    let result;

    if (!response.ok) {
      result = {
        flag: false,
        isMalicious: false,
        error: true,
        source: "fallback",
        reason: "Safe Browsing unavailable"
      };
    } else {
      const data = await response.json();
      const hasMatches = Array.isArray(data?.matches) && data.matches.length > 0;

      result = hasMatches
        ? {
            flag: true,
            isMalicious: true,
            source: "Google Safe Browsing",
            reason: "Threat detected by Safe Browsing"
          }
        : {
            flag: false,
            isMalicious: false,
            source: "Google Safe Browsing",
            reason: "No Safe Browsing threats detected"
          };
    }

    await setStorageLocal({ [cacheKey]: result });
    return result;
  } catch {
    const fallbackResult = {
      flag: false,
      isMalicious: false,
      error: true,
      source: "fallback",
      reason: "Safe Browsing unavailable"
    };
    await setStorageLocal({ [cacheKey]: fallbackResult });
    return fallbackResult;
  } finally {
    clearTimeout(timeoutId);
  }
}
