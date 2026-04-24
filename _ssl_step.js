
  // ── Step 5.5: Inject SSL/TLS signals ─────────────────────────────────────
  // consumeSSLSignals() drains the webRequest.onHeadersReceived cache for
  // this URL. For HTTP pages it calls analyzeSSL() directly.
  // Signals are de-duplicated and merged before adaptive scoring so the ML
  // model and threat evaluator both see the full signal set.
  try {
    const sslSignals = consumeSSLSignals(normalizedUrl, tabId);
    if (sslSignals.length > 0) {
      result.signals = [...new Set([...(result.signals || []), ...sslSignals])];

      // Build human-readable reasons for SSL issues (shown in overlay)
      const SSL_REASON_MAP = {
        insecure_http:    "Page loaded over plain HTTP — no encryption",
        invalid_ssl:      "SSL certificate could not be validated",
        expired_cert:     "SSL certificate has expired",
        self_signed_cert: "SSL certificate is self-signed (no trusted CA)",
        domain_mismatch:  "SSL certificate domain does not match the site",
        weak_encryption:  "Site uses deprecated/weak encryption (SHA-1/TLS 1.0)",
        mixed_content:    "Page loads insecure HTTP sub-resources (mixed content)",
      };
      const sslReasons = sslSignals
        .map(s => SSL_REASON_MAP[s] || s)
        .filter(Boolean);

      result.reasons = [...new Set([...(result.reasons || []), ...sslReasons])].slice(0, 6);

      // Upgrade status if critical SSL signal present
      const CRITICAL_SSL = ["invalid_ssl", "expired_cert", "domain_mismatch"];
      const hasCriticalSSL = sslSignals.some(s => CRITICAL_SSL.includes(s));
      if (hasCriticalSSL && result.status === "safe") {
        result.status = "suspicious";
        console.log("[Sentinel-SSL] Status upgraded to suspicious due to:", sslSignals);
      }

      console.log("[Sentinel AI] SSL signals merged:", sslSignals);
    }
  } catch (sslErr) {
    // Fail-open: SSL analysis never blocks the detection flow
    console.warn("[Sentinel-SSL] analyzeSSL error:", sslErr?.message);
  }

