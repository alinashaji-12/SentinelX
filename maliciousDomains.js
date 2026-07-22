// maliciousDomains.js — SentinelX Malicious Domains Blocklist
// CHANGED: New comprehensive blocklist for critical domains (score 100)

// Known malicious / test domains — auto score 100
const MALICIOUS_DOMAINS = new Set([
  // SSL test / intentionally broken SSL
  'neverssl.com',
  'expired.badssl.com',
  'wrong.host.badssl.com',
  'self-signed.badssl.com',
  'untrusted-root.badssl.com',
  'revoked.badssl.com',
  'pinning-test.badssl.com',
  'sha1-intermediate.badssl.com',
  'superfish.badssl.com',
  'edellroot.badssl.com',
  'dsdtestprovider.badssl.com',
  'preact-cms.badssl.com',

  // Known phishing / malware domains (public threat intel lists)
  'secure-paypal-login.com','paypal-secure-login.net',
  'amazon-security-alert.com','amazon-login-verify.net',
  'appleid-verification.com','apple-account-locked.net',
  'microsoft-alert-security.com','windows-defender-alert.net',
  'google-account-alert.com','gmail-security-check.net',
  'netflix-billing-update.com','netflix-account-suspended.net',
  'bank-secure-login.com','sbi-secure-banking.net',
  'hdfc-account-verify.com','icici-bank-login.net',

  // Crypto scams
  'bitcoin-doubler.com','eth-giveaway.net',
  'crypto-profit-bot.com','binance-airdrop.net',
  'coinbase-verify.com','metamask-security.net',

  // Tech support scams
  'windows-error-fix.com','virus-detected-call-now.net',
  'microsoft-tech-support.com','apple-support-helpline.net',
  'pc-error-repair.com','free-virus-removal.net',

  // Fake government
  'irs-refund-claim.com','gov-stimulus-check.net',
  'uidai-verify-aadhar.com','pan-card-update.net',
  'income-tax-refund-claim.com',

  // Known malware distribution
  'malware-traffic-analysis.net', // test only, real ones rotate

  // Typosquat examples
  'gooogle.com','micosoft.com','faceb00k.com',
  'paypa1.com','amaz0n.com','netfl1x.com',
  'g00gle.com','micros0ft.com','linkedln.com',
  'twltter.com','lnstagram.com','whatsaap.com'
]);

function isMaliciousDomain(hostname) {
  if (!hostname) return false;
  hostname = hostname.toLowerCase().replace(/^www\./, '');
  return MALICIOUS_DOMAINS.has(hostname);
}

// CHANGED: Expose globally for background/content scripts
try { globalThis.isMaliciousDomain = isMaliciousDomain; } catch (e) {}

