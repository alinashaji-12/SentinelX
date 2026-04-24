const KNOWN_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"];

function getHostname(value) {
  try {
    return new URL(String(value || "")).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isKnownShortener(hostname) {
  return KNOWN_SHORTENERS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

export async function expandUrl(shortUrl) {
  const originalUrl = String(shortUrl || "");
  const hostname = getHostname(originalUrl);
  const isShortened = Boolean(hostname) && isKnownShortener(hostname);

  if (!isShortened) {
    return {
      expandedUrl: originalUrl,
      isShortened: false
    };
  }

  try {
    const response = await fetch(originalUrl, {
      method: "HEAD",
      redirect: "follow"
    });

    return {
      expandedUrl: response?.url || originalUrl,
      isShortened: true
    };
  } catch {
    return {
      expandedUrl: originalUrl,
      isShortened: true
    };
  }
}
