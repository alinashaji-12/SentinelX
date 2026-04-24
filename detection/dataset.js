/**
 * dataset.js — Sentinel Browse Extension
 *
 * Local phishing / malware domain dataset.
 * Matching uses root-domain extraction to prevent both false positives
 * (legitimate subdomains of safe brands) and false negatives.
 */

import { getRootDomain, getHostname } from "./domainWhitelist.js";

/**
 * Known phishing / malware root domains.
 * Entries are root domains (eTLD+1) — subdomains are matched automatically.
 */
const PHISHING_DOMAINS = new Set([
  // Financial phishing
  "paypal-login-secure.com",
  "paypa1-account.com",
  "paypal-update-required.net",
  "paypal-secure-login.xyz",
  "amazon-update-account.xyz",
  "amazon-account-alert.net",
  "amazon-prime-verify.com",
  "amazon-security-notice.com",
  "banking-verify-now.com",
  "secure-bankofamerica.com",
  "bankofamerica-alert.net",
  "chase-security-alert.com",
  "wells-fargo-verify.net",

  // Social media phishing
  "facebook-verification.net",
  "facebook-login-secure.com",
  "instagram-verify-account.com",
  "twitter-support-team.com",
  "linkedin-security-notice.net",

  // Tech / crypto phishing
  "apple-id-verify.com",
  "apple-account-locked.net",
  "microsoft-support-alert.com",
  "google-account-recovery.xyz",
  "metamask-security.net",
  "coinbase-verify.net",
  "binance-secure-login.com",
  "crypto-wallet-recover.xyz",
  "nft-mint-free.xyz",

  // Generic phishing templates
  "malicious.com",
  "phishing-site.net",
  "secure-verify-login.com",
  "account-suspended-alert.com",
  "free-gift-claim.xyz",
  "prize-winner-claim.net",
  "urgent-action-required.com",
  "click-here-reward.xyz",
  "yourpackage-pending.com",
  "parcel-delivery-failed.net",
  "login-secure-update.com",
  "verify-account-now.xyz",
]);

/**
 * Checks whether a URL matches any known phishing domain.
 *
 * Matching strategy:
 *  - Extracts root domain (eTLD+1) from the URL
 *  - Checks it against the dataset (exact root match)
 *  - Prevents false positives: "paypal.com" ≠ "paypal-login-secure.com"
 *  - Prevents false negatives: "sub.phishing-site.net" matches "phishing-site.net"
 *
 * @param {string} url
 * @returns {{ flag: boolean, isMalicious: boolean, source: string, reason: string }}
 */
export function checkDataset(url) {
  const hostname = getHostname(url);

  if (!hostname) {
    return {
      flag: false,
      isMalicious: false,
      source: "dataset",
      reason: "No hostname found in URL",
    };
  }

  const rootDomain = getRootDomain(hostname);

  // Check root domain against dataset
  const matchedRoot = PHISHING_DOMAINS.has(rootDomain);

  // Also check full hostname in case dataset has specific subdomain entries
  const matchedFull = PHISHING_DOMAINS.has(hostname);

  const matched = matchedRoot || matchedFull;
  const matchedDomain = matchedRoot ? rootDomain : hostname;

  return {
    flag: matched,
    isMalicious: matched,
    source: "dataset",
    reason: matched
      ? `Domain "${matchedDomain}" matched phishing/malware dataset`
      : "No match in phishing dataset",
  };
}
