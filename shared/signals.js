var SIG = {
  HARD_BLOCKLIST:    "hard_blocklist",
  TYPOSQUATTING:     "typosquatting",
  PHISHING_DATASET:  "phishing_dataset",
  CREDENTIAL_FORM:   "credential_form",
  NEW_DOMAIN:        "new_domain",
  SSL_INVALID:       "ssl_invalid",
  SSL_EXPIRED:       "ssl_expired",
  SSL_MISMATCH:      "ssl_mismatch",
  CLIPBOARD_HIJACK:  "clipboard_hijack",
  HIDDEN_IFRAME:     "hidden_iframe",
  AUTO_DOWNLOAD:     "auto_download",
  BEHAVIOR_REDIRECT: "behavior_redirect",
  MALWARE_HOST:      "malware_host",
  BULLETPROOF_HOST:  "bulletproof_host",
  HIGH_ENTROPY:      "high_entropy",
  IP_ADDRESS_URL:    "ip_address_url",
  PUNYCODE:          "punycode",
  KNOWN_SAFE:        "known_safe",
  EDUCATION_DOMAIN:  "education_domain"
};

var SIG_META = {
  hard_blocklist:    { name: "Blocklist match",        category: "phishing",    description: "Exact match in SentinelX known-malicious database" },
  typosquatting:     { name: "Typosquatting",          category: "phishing",    description: "Domain imitates trusted brand via character swap" },
  credential_form:   { name: "Credential form",        category: "phishing",    description: "Login or payment form with suspicious POST target" },
  new_domain:        { name: "New domain",             category: "reputation",  description: "Registered very recently — common phishing tactic" },
  ssl_invalid:       { name: "Invalid TLS",            category: "ssl",         description: "Certificate is self-signed or unverifiable" },
  clipboard_hijack:  { name: "Clipboard hijack",       category: "behavior",    description: "Page overwrote clipboard without user action" },
  malware_host:      { name: "Malware host",           category: "malware",     description: "Server distributes known malware payloads" },
  bulletproof_host:  { name: "Bulletproof hosting",    category: "reputation",  description: "Hosted on abuse-resistant criminal infrastructure" }
};

if (typeof globalThis !== "undefined") {
  globalThis.SIG = SIG;
  globalThis.SIG_META = SIG_META;
}
