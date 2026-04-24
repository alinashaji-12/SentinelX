/**
 * hardBlockStrategy.js — Sentinel Browse Extension
 *
 * ═════════════════════════════════════════════════════════════════════════════
 * PHASE 5: HARD BLOCK STRATEGY
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * Implements aggressive blocking for high-confidence threats:
 *
 * IF confidence > 85% OR IP OR dataset match
 *   → HARD BLOCK (prevent navigation entirely)
 * ELSE
 *   → WARNING PAGE (user can choose to proceed with warning)
 *
 * Integration with chrome.webNavigation.onBeforeNavigate:
 * Returns chrome.webRequest.BlockingResponse
 *
 * ═════════════════════════════════════════════════════════════════════════════
 */

/**
 * Determines blocking action based on analysis result.
 *
 * @param {object} analysisResult — from analyzeUrlAdvanced()
 * @param {string} url — the original URL
 * @returns {object} { action: "block" | "warn" | "allow", mode: "hard" | "soft" | "none" }
 */
export function decideBlockingAction(analysisResult, url) {
  const {
    status = "safe",
    confidence = 0,
    score = 0,
    signalGroups = {},
    attackType = "SAFE",
  } = analysisResult;

  // ─── HARD BLOCK CONDITIONS ─────────────────────────────────────────────────
  // If ANY of these are true → HARD_BLOCK (chrome will show error page)

  // 1. Very high confidence malicious
  if (confidence >= 85) {
    return {
      action: "block",
      mode: "hard",
      reason: `HIGH CONFIDENCE MALICIOUS (${confidence}%)`,
      severity: "CRITICAL",
    };
  }

  // 2. Dataset hit (known malicious domain)
  if (signalGroups.hasDataset) {
    return {
      action: "block",
      mode: "hard",
      reason: "PHISHING/MALWARE DATASET MATCH",
      severity: "CRITICAL",
    };
  }

  // 3. Safe Browsing hit (Google's verdict)
  if (signalGroups.hasSafeBrowsing) {
    return {
      action: "block",
      mode: "hard",
      reason: "GOOGLE SAFE BROWSING FLAGGED",
      severity: "CRITICAL",
    };
  }

  // 4. Public IP + strong signals = infrastructure-level phishing
  if (signalGroups.hasIpAddress) {
    // IP address is always suspicious, but hard-block only if HIGH confidence
    if (confidence >= 75) {
      return {
        action: "block",
        mode: "hard",
        reason: `PUBLIC IP PHISHING INFRASTRUCTURE (${confidence}%)`,
        severity: "CRITICAL",
      };
    }
  }

  // 5. Brand spoof + intent + domain anomaly (triangle of malice)
  if (
    signalGroups.hasBrandSpoof &&
    signalGroups.hasIntent &&
    signalGroups.hasDomainAnomaly
  ) {
    return {
      action: "block",
      mode: "hard",
      reason: "BRAND SPOOF + INTENT + DOMAIN ANOMALY (phishing infrastructure)",
      severity: "CRITICAL",
    };
  }

  // 6. Redirect abuse (trusted site hijacked for phishing)
  if (signalGroups.hasRedirectAbuse && signalGroups.hasIntent) {
    return {
      action: "block",
      mode: "hard",
      reason: "REDIRECT PARAMETER ABUSE (trusted site hijack attempt)",
      severity: "CRITICAL",
    };
  }

  // ─── SOFT BLOCK CONDITIONS ────────────────────────────────────────────────
  // If status is "malicious" OR confidence >= 70 → WARNING PAGE

  if (status === "malicious" || confidence >= 70) {
    return {
      action: "warn",
      mode: "soft",
      reason: `MALICIOUS INDICATORS DETECTED (${confidence}%)`,
      severity: "HIGH",
    };
  }

  // ─── SUSPICIOUS → WARNING PAGE
  if (status === "suspicious" || confidence >= 50) {
    return {
      action: "warn",
      mode: "soft",
      reason: `SUSPICIOUS INDICATORS DETECTED (confidence: ${confidence}%)`,
      severity: "MEDIUM",
    };
  }

  // ─── SAFE → ALLOW (default)
  return {
    action: "allow",
    mode: "none",
    reason: "No malicious indicators detected",
    severity: "INFO",
  };
}

/**
 * ═════════════════════════════════════════════════════════════════════════════
 * CHROME INTEGRATION CODE
 * ═════════════════════════════════════════════════════════════════════════════
 *
 * Add this to background.js:
 */

/**
 * Hard block implementation using chrome.webNavigation API (MV3-safe)
 *
 * For HARD BLOCK: Use webRequest.onBeforeRequest with BlockingResponse
 * For SOFT WARN: Redirect to internal warning page
 */

// ─────────────────────────────────────────────────────────────────────────────
// IMPLEMENTATION A: Using webNavigation (simpler, MV3-native)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Call this in background.js onBeforeNavigate handler
 * Returns a blocking response for hard blocks
 */
export function createBlockingResponse(analysisResult, url) {
  const blockAction = decideBlockingAction(analysisResult, url);

  // Hard block: show browser error page
  if (blockAction.mode === "hard") {
    return {
      cancel: true, // Prevent the navigation
      blocked: true,
      reason: blockAction.reason,
      severity: blockAction.severity,
      // Note: WebNavigation doesn't directly show error; combine with content script warn
    };
  }

  // Soft block: redirect to warning page
  if (blockAction.mode === "soft") {
    const warningUrl = chrome.runtime.getURL("warning.html");
    const encodedUrl = encodeURIComponent(url);
    const encodedReason = encodeURIComponent(blockAction.reason);

    return {
      redirectUrl: `${warningUrl}?target=${encodedUrl}&reason=${encodedReason}&severity=${blockAction.severity}`,
    };
  }

  // Allow (no block)
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION PATTERN: background.js modifications
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Add to background.js:
 *
 * import { decideBlockingAction, createBlockingResponse } from "./hardBlockStrategy.js";
 *
 * chrome.webNavigation.onBeforeNavigate.addListener(
 *   (details) => {
 *     const url = details.url;
 *     const analysisResult = analyzeUrlAdvancedUpgraded(url, {}, {});
 *
 *     const blockAction = decideBlockingAction(analysisResult, url);
 *
 *     if (blockAction.mode === "hard") {
 *       // Log the hard block
 *       console.log(`[HARD BLOCK] ${url} - ${blockAction.reason}`);
 *
 *       // OPTION 1: Cancel navigation (requires webRequest API)
 *       // return { cancel: true };
 *
 *       // OPTION 2: Redirect to error page (MV3-safe)
 *       // This requires setting up an error page
 *       chrome.tabs.update(details.tabId, {
 *         url: chrome.runtime.getURL("error.html") +
 *              "?url=" + encodeURIComponent(url) +
 *              "&reason=" + encodeURIComponent(blockAction.reason)
 *       });
 *     } else if (blockAction.mode === "soft") {
 *       // Log the warning
 *       console.log(`[WARNING] ${url} - ${blockAction.reason}`);
 *
 *       // Show warning page
 *       const warningUrl = chrome.runtime.getURL("warning.html") +
 *                          "?target=" + encodeURIComponent(url) +
 *                          "&reason=" + encodeURIComponent(blockAction.reason) +
 *                          "&severity=" + blockAction.severity;
 *       chrome.tabs.update(details.tabId, { url: warningUrl });
 *     }
 *   }
 * );
 */

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE SCORE THRESHOLDS (Tunable for production)
// ─────────────────────────────────────────────────────────────────────────────

export const HARD_BLOCK_THRESHOLDS = {
  confidence: 85, // Hard block if confidence >= 85%
  score: 10, // Hard block if composite score >= 10
  multipleHardSignals: true, // Hard block if 2+ hard signals present
};

export const WARNING_PAGE_THRESHOLDS = {
  confidence: 50, // Show warning if confidence >= 50%
  score: 4, // Show warning if score >= 4
};

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTION NOTES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 1. HARD BLOCK uses chrome.tabs.update() to redirect to error page
 *    - This is MV3-compliant (no webRequest API required)
 *    - Error page shows "This site is blocked by Sentinel Browse"
 *    - No user override possible (true hard block)
 *
 * 2. SOFT BLOCK (warning page) allows user to:
 *    - Review the threat details
 *    - Choose "Proceed with caution" (bypass warning)
 *    - Report false positive (future feature)
 *
 * 3. THRESHOLDS:
 *    - Adjust confidence thresholds based on false positive rates
 *    - Log all blocks to storage for review
 *    - Monitor dataset hits vs. algorithmic detections
 *
 * 4. BYPASS PREVENTION:
 *    - Hard blocks are final (no UI button to bypass)
 *    - Warning pages show "Proceed at own risk" not "Safe to proceed"
 *    - Track user overrides for adaptive learning
 */
