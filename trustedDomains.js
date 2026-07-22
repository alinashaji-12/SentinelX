// trustedDomains.js — SentinelX Trusted Domains Whitelist
// CHANGED: New comprehensive whitelist for top safe sites

const TRUSTED_APEX_DOMAINS = new Set([
  "google.com", "youtube.com", "github.com", "microsoft.com",
  "apple.com", "cloudflare.com", "amazon.com", "anthropic.com",
  "claude.ai", "wikipedia.org", "mozilla.org", "stripe.com",
]);

const TRUSTED_FULL_DOMAINS = new Set([
  "www.google.com", "mail.google.com", "docs.google.com",
  "www.github.com", "api.github.com", "github.com",
  "www.youtube.com", "www.microsoft.com", "claude.ai",
]);

function isRandomSubdomain(subdomain) {
  if (!subdomain) return false;
  if (subdomain.length > 20) return true;
  const vowels = (subdomain.match(/[aeiou]/gi) || []).length;
  const ratio = vowels / Math.max(1, subdomain.length);
  if (ratio < 0.15 && subdomain.length > 8) return true;
  if (/[^aeiou]{5,}/i.test(subdomain)) return true;
  if ((subdomain.match(/-/g) || []).length >= 3) return true;
  return false;
}

function isDeepSubdomain(parts) {
  return Array.isArray(parts) && parts.length > 4;
}

function isTrustedDomain(urlOrDomain) {
  let hostname;
  try {
    const raw = String(urlOrDomain || "");
    hostname = raw.startsWith("http") ? new URL(raw).hostname : raw;
  } catch {
    return false;
  }
  hostname = String(hostname || "").toLowerCase();
  if (!hostname) return false;

  if (TRUSTED_FULL_DOMAINS.has(hostname)) return true;

  const parts = hostname.split(".").filter(Boolean);
  const apex = parts.slice(-2).join(".");
  if (!TRUSTED_APEX_DOMAINS.has(apex)) return false;

  if (parts.length > 2) {
    const subdomain = parts.slice(0, -2).join(".");
    if (isRandomSubdomain(subdomain)) return false;
    if (isDeepSubdomain(parts)) return false;
  }
  return true;
}

// CHANGED: Expose globally for background/content scripts
try {
  globalThis.isTrustedDomain = isTrustedDomain;
  globalThis.isRandomSubdomain = isRandomSubdomain;
  globalThis.isDeepSubdomain = isDeepSubdomain;
  globalThis.TRUSTED_APEX_DOMAINS = TRUSTED_APEX_DOMAINS;
} catch (e) {}

