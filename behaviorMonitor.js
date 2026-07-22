/**
 * behaviorMonitor.js — Sentinel Browse v3.0
 *
 * BEHAVIORAL DETECTION MODULE
 * ══════════════════════════════════════════════════════════════════════
 *
 * Runs at document_start (before page JS) to intercept dangerous APIs
 * at the earliest possible moment.
 *
 * Architecture:
 *   ┌─────────────────────┐      postMessage       ┌──────────────────────┐
 *   │  MAIN world (probe) │ ──────────────────────> │  Isolated world      │
 *   │  - location.href    │                         │  (this file)         │
 *   │  - history.push/rep │                         │  - MutationObserver  │
 *   │  - clipboard.write  │                         │  - click capture     │
 *   │  - URL.createObj    │                         │  - copy event        │
 *   └─────────────────────┘                         └──────────┬───────────┘
 *                                                              │ sendMessage
 *                                                   ┌──────────▼───────────┐
 *                                                   │  background.js       │
 *                                                   │  BEHAVIOR_ALERT      │
 *                                                   └──────────────────────┘
 *
 * BEHAVIOR_ALERT message schema (v2.0 with Confidence System):
 *   {
 *     type: "BEHAVIOR_ALERT",
 *     event,
 *     severity: "low" | "medium" | "high",
 *     confidence: "LOW" | "MEDIUM" | "HIGH",
 *     userInitiated: boolean,
 *     url,
 *     details,
 *     timestamp
 *   }
 *
 * Severity (behavioral): how suspicious the raw event is
 *   "low"    — informational, no immediate overlay
 *   "medium" — suspicious, accumulates toward overlay at 30/100
 *   "high"   — immediate overlay trigger
 *
 * Confidence: how certain we are this is malicious (affects scoring weight)
 *   "LOW"    — 0.2x weight, often false positives (user-triggered, common on legitimate sites)
 *   "MEDIUM" — 0.6x weight, moderate confidence (ambiguous timing, multiple factors)
 *   "HIGH"   — 1.0x weight, very likely malicious (multiple high-risk factors)
 */

"use strict";

// ══════════════════════════════════════════════════════════════════════
// SECTION 1 — CONSTANTS & STATE
// ══════════════════════════════════════════════════════════════════════

/**
 * Internal token used to validate postMessages from the injected probe.
 * Randomised per page load so a page script cannot forge alerts.
 */
const PROBE_TOKEN = `sentinel-probe-${Math.random().toString(36).slice(2)}`;

// ══════════════════════════════════════════════════════════════════════
// GLOBAL SAFE DOMAIN HARD-BLOCK (Rule 1)
// ══════════════════════════════════════════════════════════════════════
//
// These domains NEVER produce behavior alerts, regardless of what the
// detectors observe.  Matching uses endsWith() so all subdomains are
// covered (e.g. accounts.google.com, mail.google.com, etc.).
//
/**
 * Returns true if the current page hostname is a known-safe domain.
 * Checked inside reportBehavior() — the single chokepoint for all signals.
 * @param {string} hostname
 * @returns {boolean}
 */
function isSafeDomain(hostname) {
  if (typeof globalThis.isTrustedDomain === "function") {
    return globalThis.isTrustedDomain(String(hostname || "").toLowerCase());
  }
  return false;
}

// ══════════════════════════════════════════════════════════════════════
// ANALYTICS / NETWORK DOMAIN FILTER (Rule 3)
// ══════════════════════════════════════════════════════════════════════
//
// Used to suppress signals triggered by analytics/CDN network requests
// before they reach reportBehavior().  Also checked inside reportBehavior
// via the requestUrl detail field when present.

const ANALYTICS_DOMAINS = new Set([
  "google-analytics.com",
  "googletagmanager.com",
  "doubleclick.net",
  "googletagservices.com",
  "analytics.google.com",
  "stats.g.doubleclick.net",
  "adservice.google.com",
  "hotjar.com",
  "segment.com",
  "mixpanel.com",
  "amplitude.com",
]);

/**
 * Returns true if a request URL belongs to a known analytics/CDN domain.
 * Used to suppress network-level false positives.
 * @param {string} requestUrl
 * @returns {boolean}
 */
function isAnalyticsDomain(requestUrl) {
  try {
    const hostname = new URL(requestUrl).hostname.toLowerCase();
    return ANALYTICS_DOMAINS.has(hostname) ||
      [...ANALYTICS_DOMAINS].some(d => hostname.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

/** Max alerts per signal category per page load (prevents flooding). */
const RATE_LIMITS = {
  redirect:   3,
  download:   3,
  clipboard:  2,
  pushState:  1, // only one "abuse" alert per page, not per call
  metaRefresh:2,
};

const alertCounts = Object.create(null);

/**
 * Returns true if the given type has exceeded its rate limit.
 * Increments the counter as a side-effect.
 * @param {string} type
 * @returns {boolean}
 */
function rateLimited(type) {
  alertCounts[type] = (alertCounts[type] || 0) + 1;
  return alertCounts[type] > (RATE_LIMITS[type] ?? 3);
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 2 — BACKGROUND REPORTER (v2.0: Confidence System)
// ══════════════════════════════════════════════════════════════════════

/**
 * Sends a BEHAVIOR_ALERT to background.js with confidence levels.
 *
 * GLOBAL GUARDS (applied here so no individual detector needs to repeat them):
 *   1. Safe domain hard-block — SAFE_DOMAINS never produce alerts (Rule 1)
 *   2. Analytics network filter — suppress if details.requestUrl is analytics (Rule 3)
 *   3. Debug logging — always log disposition for traceability (Rule 8)
 *
 * @param {string} event     — machine-readable signal identifier
 * @param {"low"|"medium"|"high"} severity — behavioral severity
 * @param {string} confidence — "LOW" | "MEDIUM" | "HIGH" (affects scoring weight)
 * @param {boolean} userInitiated — true if user action triggered this
 * @param {object} [details] — optional signal-specific metadata
 */
function reportBehavior(event, severity, confidence = "MEDIUM", userInitiated = false, details = {}) {
  const currentHostname = location.hostname.toLowerCase();

  // ── RULE 1: Safe domain hard-block ──────────────────────────────────────
  // NEVER send behavior signals for known-safe domains.
  if (isSafeDomain(currentHostname)) {
    console.debug(`[Sentinel FIX] 🚫 Signal blocked — safe domain: ${currentHostname} | event: ${event}`);
    return;
  }

  // ── RULE 3: Analytics network filter ────────────────────────────────────
  // Suppress signals whose requestUrl is an analytics/CDN endpoint.
  if (details && details.requestUrl && isAnalyticsDomain(details.requestUrl)) {
    console.debug(`[Sentinel FIX] 🚫 Signal blocked — analytics URL: ${details.requestUrl} | event: ${event}`);
    return;
  }

  // ── RULE 8: Debug logging ────────────────────────────────────────────────
  console.debug(
    `[Sentinel FIX] 📡 Reporting behavior signal | Domain: ${currentHostname} | Event: ${event} | Severity: ${severity} | Confidence: ${confidence} | Signals:`, details
  );

  try {
    chrome.runtime.sendMessage({
      type:          "BEHAVIOR_ALERT",
      event,
      severity,
      confidence,
      userInitiated,
      url:           location.href,
      details,
      timestamp:     Date.now(), // FIX: Date.now() returns a number, NOT a Promise
    }, () => {
      // Callback form avoids MV3 unhandled-rejection noise.
      // chrome.runtime.lastError is consumed implicitly.
      void chrome.runtime.lastError;
    });
  } catch {
    // chrome.runtime unavailable (e.g. extension context invalidated).
  }
}


// ══════════════════════════════════════════════════════════════════════
// SECTION 3 — MAIN WORLD PROBE INJECTION
// ══════════════════════════════════════════════════════════════════════
//
// We inject a <script> directly into the page's MAIN world so we can
// intercept native API setters/methods BEFORE page scripts run.
//
// The probe communicates back to this isolated-world script via
// window.postMessage using a randomised token so the page cannot spoof it.

(function injectProbe() {
  // Inline the probe code as a string to avoid needing web_accessible_resources.
  // The token is baked in at injection time.
  const probeCode = `
(function(TOKEN) {
  "use strict";
  function post(type, details) {
    try { window.postMessage({ _sentinel: TOKEN, type, details }, "*"); } catch {}
  }

  // ── 1. window.location.href setter ─────────────────────────────────
  try {
    const desc = Object.getOwnPropertyDescriptor(window.Location.prototype, "href");
    if (desc && desc.set) {
      const orig = desc.set;
      Object.defineProperty(window.Location.prototype, "href", {
        configurable: true,
        enumerable:   true,
        get: desc.get,
        set(value) {
          post("redirect", { to: String(value).slice(0, 200), method: "location.href" });
          return orig.call(this, value);
        },
      });
    }
  } catch {}

  // ── 2. history.pushState / replaceState ─────────────────────────────
  ["pushState", "replaceState"].forEach(name => {
    const orig = history[name];
    if (typeof orig !== "function") return;
    history[name] = function(state, title, url) {
      if (url) post("pushState", { url: String(url).slice(0, 200), method: name });
      return orig.apply(this, arguments);
    };
    history[name].toString = () => orig.toString(); // stealth
  });

  // ── 3. navigator.clipboard.writeText ────────────────────────────────
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function(text) {
        post("clipboard", { preview: String(text || "").slice(0, 80) });
        return orig(text);
      };
    }
  } catch {}

  // ── 4. URL.createObjectURL — detect drive-by blob downloads ─────────
  try {
    const origCreate = URL.createObjectURL;
    URL.createObjectURL = function(obj) {
      if (obj instanceof Blob) {
        post("blobUrl", { mimeType: obj.type || "unknown", size: obj.size });
      }
      return origCreate.call(URL, obj);
    };
  } catch {}

})(${JSON.stringify(PROBE_TOKEN)});
`.trim();

  try {
    const script = document.createElement("script");
    script.textContent = probeCode;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
  } catch {
    // CSP blocks inline scripts on this origin — probe unavailable.
    // Isolated-world detections (Sections 4–5) still function.
  }
})();

// ══════════════════════════════════════════════════════════════════════
// SECTION 4 — PROBE MESSAGE RELAY (v2.0: Confidence & Context)
// ══════════════════════════════════════════════════════════════════════

/** Tracks recent user events (click, copy, paste) to correlate with APIs */
let lastUserEventTime = 0;
const USER_EVENT_WINDOW_MS = 500; // clipboard/redirect within 500ms of user action = likely initiated
let programmaticClipboardCount = 0;
let lastProgrammaticClipboardAt = 0;

// ── Explicit user-initiated flag (Rule 2) ──────────────────────────────────
// Tracks whether a genuine user gesture occurred within the last second.
// Distinct from lastUserEventTime: this is a boolean cleared by a timer,
// making the intent check self-documenting in the clipboard handler.
let userInitiated = false;
let _userInitiatedResetTimer = null;

function _markUserInitiated() {
  userInitiated = true;
  clearTimeout(_userInitiatedResetTimer);
  _userInitiatedResetTimer = setTimeout(() => { userInitiated = false; }, 1000);
}

/**
 * STRICT CLIPBOARD DETECTION (v3.0)
 * Track clipboard events within a 3-second window to detect repeated access.
 * Only flag if:
 *   - MORE THAN 2 events within 3 seconds (repeated behavior)
 *   - AND NOT user-initiated
 *   - AND NOT on a trusted domain
 */
let clipboardEventTimestamps = [];
const CLIPBOARD_WINDOW_MS = 3000;       // 3-second sliding window
const CLIPBOARD_EVENT_THRESHOLD = 3;   // require MORE THAN 2 events (>2 = >=3)

/** Counts rapid pushState calls to detect abuse */
let pushStateCount    = 0;
let pushStateResetTimer = null;
const PUSH_STATE_ABUSE_THRESHOLD = 8;
const PUSH_STATE_WINDOW_MS       = 4000;

// ── Track user interactions ────────────────────────────────────────────────
// Update both the raw timestamp (for 500 ms correlation window used by redirects)
// AND the explicit boolean flag (for the 1 s clipboard guard — Rule 2).
try { document.addEventListener("click",   () => { lastUserEventTime = Date.now(); _markUserInitiated(); }, { capture: true, passive: true }); } catch (e) { console.warn("[Sentinel] Click listener failed:", e); }
document.addEventListener("keydown", () => { lastUserEventTime = Date.now(); _markUserInitiated(); }, { capture: true, passive: true });
document.addEventListener("input",   () => { lastUserEventTime = Date.now(); _markUserInitiated(); }, { capture: true, passive: true });
document.addEventListener("copy",    () => { lastUserEventTime = Date.now(); }, { capture: true, passive: true });
document.addEventListener("cut",     () => { lastUserEventTime = Date.now(); }, { capture: true, passive: true });
document.addEventListener("paste",   () => { lastUserEventTime = Date.now(); }, { capture: true, passive: true });

/**
 * Determines confidence level based on timing and context.
 * If user interaction occurred recently, LOW confidence.
 * If no interaction, MEDIUM/HIGH depending on context.
 */
function getConfidenceForSignal(eventType, timeSinceLastEvent) {
  // User-initiated events within 500ms window = LOW confidence
  if (timeSinceLastEvent < USER_EVENT_WINDOW_MS) {
    return "LOW";
  }
  
  // Beyond user interaction window = MEDIUM by default
  // Context-specific assignments happen in message handler
  return "MEDIUM";
}

window.addEventListener("message", (event) => {
  // Only accept messages from our own probe running in the same window.
  if (event.source !== window) return;
  if (!event.data || event.data._sentinel !== PROBE_TOKEN) return;

  const { type, details } = event.data;
  const timeSinceLastEvent = Date.now() - lastUserEventTime;

  switch (type) {

    case "redirect": {
      if (rateLimited("redirect")) return;
      const userInitiated = timeSinceLastEvent < USER_EVENT_WINDOW_MS;
      const confidence = userInitiated ? "LOW" : "MEDIUM";
      reportBehavior("suspicious_redirect", "medium", confidence, userInitiated, details);
      break;
    }

    case "pushState": {
      pushStateCount++;
      clearTimeout(pushStateResetTimer);
      pushStateResetTimer = setTimeout(() => { pushStateCount = 0; }, PUSH_STATE_WINDOW_MS);

      if (pushStateCount >= PUSH_STATE_ABUSE_THRESHOLD) {
        if (!rateLimited("pushState")) {
          // Multiple rapid pushStates = HIGH confidence
          reportBehavior("pushstate_abuse", "medium", "HIGH", false, {
            count: pushStateCount,
            lastUrl: details?.url,
          });
        }
      }
      break;
    }

    case "clipboard": {
      // ══════════════════════════════════════════════════════════════════════
      // STRICT CLIPBOARD DETECTION (v3.1 — All 5 Rules Applied)
      // Only flag REAL clipboard attacks — not legitimate use on safe domains
      // ══════════════════════════════════════════════════════════════════════

      // RULE 4 (first — cheapest check): Trusted domain early-exit.
      // If the current page is a known-safe domain, clipboard access is benign.
      const currentHostname = location.hostname.toLowerCase();
      const isTrustedClipboardDomain = typeof globalThis.isTrustedDomain === "function"
        ? globalThis.isTrustedDomain(currentHostname)
        : false;
      if (isTrustedClipboardDomain) {
        console.debug(`[Sentinel] ✅ Clipboard suppressed: trusted domain (${currentHostname})`);
        return;
      }

      // RULE 1 + 2: User interaction check — suppress if triggered by user gesture.
      // Checks BOTH the explicit boolean flag (1 s window — Rule 2)
      // AND the raw timestamp window (500 ms — tighter guard for immediate clicks).
      const clipboardUserInitiated = userInitiated || (timeSinceLastEvent < USER_EVENT_WINDOW_MS);
      if (clipboardUserInitiated) {
        console.debug(`[Sentinel] ✅ Clipboard suppressed: user-initiated (flag=${userInitiated}, ${timeSinceLastEvent}ms since last event)`);
        return;
      }

      // Rate limiting check (after cheap guards to avoid counting suppressed events)
      if (rateLimited("clipboard")) return;

      // RULE 5: Frequency threshold — only flag if clipboard is modified MORE THAN
      // 2 times (i.e. >= 3 events) within the 3-second sliding window.
      const now = Date.now();
      clipboardEventTimestamps = clipboardEventTimestamps.filter(t => now - t < CLIPBOARD_WINDOW_MS);
      clipboardEventTimestamps.push(now);

      const eventCount = clipboardEventTimestamps.length;
      if (eventCount < CLIPBOARD_EVENT_THRESHOLD) {
        console.debug(`[Sentinel] ℹ️ Clipboard: ${eventCount} event(s) logged (need >${CLIPBOARD_EVENT_THRESHOLD - 1} within ${CLIPBOARD_WINDOW_MS}ms)`);
        return;
      }

      // RULE 3 (original): navigator.clipboard.writeText was called AND is not
      // user-initiated — confirmed by the probe (MAIN world intercept) which only
      // posts "clipboard" when writeText() is invoked programmatically.

      // All rules passed — this is a real clipboard hijack attempt.
      console.warn(`[Sentinel] 🚨 Clipboard hijack detected: ${eventCount} programmatic writes in ${CLIPBOARD_WINDOW_MS}ms on untrusted domain (${currentHostname})`);
      reportBehavior("clipboard_hijack", "medium", "MEDIUM", false, {
        ...details,
        eventCount,
        windowMs: CLIPBOARD_WINDOW_MS,
        domain: currentHostname,
        suppressed: false,
      });
      break;
    }

    case "blobUrl": {
      if (rateLimited("download")) return;
      // Executable MIME types are inherently suspicious = HIGH confidence
      const HIGH_RISK_MIME = new Set([
        "application/x-msdownload", "application/x-executable",
        "application/x-msdos-program", "application/x-sh",
        "application/x-bat", "application/vnd.microsoft.portable-executable",
      ]);
      const isExecutable = HIGH_RISK_MIME.has(details?.mimeType);
      const confidence = isExecutable ? "HIGH" : "MEDIUM";
      reportBehavior("blob_download", isExecutable ? "high" : "medium", confidence, false, details);
      break;
    }
  }
}, { passive: true });

// ══════════════════════════════════════════════════════════════════════
// SECTION 5 — ISOLATED-WORLD DOM DETECTION
// ══════════════════════════════════════════════════════════════════════
// These detections work purely in the isolated world without the probe.

// ── 5a. MutationObserver — detect injected meta-refresh and hidden anchors

function checkMetaRefresh(node) {
  if (!(node instanceof Element)) return;
  const metas = node.tagName === "META"
    ? [node]
    : (typeof node.querySelectorAll === "function"
        ? node.querySelectorAll('meta[http-equiv="refresh"]')
        : []);

  for (const meta of metas) {
    if (meta.httpEquiv?.toLowerCase() === "refresh") {
      if (rateLimited("metaRefresh")) continue;
      const delay = parseInt(meta.content) || 0;
      // Immediate redirect (0 delay) = HIGH confidence, delayed = MEDIUM
      const confidence = delay === 0 ? "HIGH" : "MEDIUM";
      const severity = delay === 0 ? "high" : "medium";
      reportBehavior("meta_refresh", severity, confidence, false, {
        content: (meta.content || "").slice(0, 100),
        immediate: delay === 0,
      });
    }
  }
}

function checkHiddenDownloadAnchor(node) {
  if (!(node instanceof Element)) return;
  const anchors = node.hasAttribute?.("download")
    ? [node]
    : (typeof node.querySelectorAll === "function"
        ? node.querySelectorAll("a[download]")
        : []);

  for (const a of anchors) {
    // Only flag hidden anchors (auto-click download pattern)
    const style = window.getComputedStyle?.(a) || a.style;
    const isHidden = style.display === "none"
                  || style.visibility === "hidden"
                  || style.opacity   === "0"
                  || (a.offsetWidth === 0 && a.offsetHeight === 0);
    if (isHidden && a.href) {
      if (rateLimited("download")) return;
      // Hidden download anchor = HIGH confidence
      reportBehavior("hidden_download_anchor", "high", "HIGH", false, {
        href: a.href.slice(0, 100),
        filename: String(a.download || "").slice(0, 60),
      });
    }
  }
}

const domObserver = new MutationObserver((mutations) => {
  for (const { addedNodes } of mutations) {
    for (const node of addedNodes) {
      checkMetaRefresh(node);
      checkHiddenDownloadAnchor(node);
    }
  }
});

// documentElement always exists at document_start; body may not yet
domObserver.observe(document.documentElement, { childList: true, subtree: true });

// Scan what's already in the DOM (unlikely at document_start, but safe)
checkMetaRefresh(document.documentElement);
checkHiddenDownloadAnchor(document.documentElement);

// ── 5b. Click capture — intercept download link clicks

document.addEventListener("click", (event) => {
  const anchor = event.target?.closest?.("a[download]");
  if (!anchor || !anchor.href) return;
  if (rateLimited("download")) return;

  // User-initiated click on download = LOW confidence
  reportBehavior("download_click", "medium", "LOW", true, {
    href:     anchor.href.slice(0, 100),
    filename: String(anchor.download || "unknown").slice(0, 60),
  });
}, { capture: true, passive: true });

// ── 5c. document copy event — detect programmatic clipboard copy
//       (only flag if there is no user text selection — indicates JS-triggered copy)

document.addEventListener("copy", (_event) => {
  const selection = window.getSelection?.()?.toString?.() ?? "";
  if (selection.length > 0) return; // user-initiated copy — safe

  if (rateLimited("clipboard")) return;
  // Programmatic copy (no selection) = MEDIUM confidence
  reportBehavior("programmatic_copy", "medium", "MEDIUM", false, {
    note: "copy event fired with no user text selection",
  });
}, { capture: true, passive: true });

// ══════════════════════════════════════════════════════════════════════
// SECTION 6 — IFRAME ABUSE DETECTION
// ══════════════════════════════════════════════════════════════════════
// Detect suspicious invisible iframes (common in clickjacking + credential
// harvesting attacks — phishing pages embed the real bank login in a 0×0 frame).
// 
// CRITICAL (v2.1): Trusted iframe sources are NOT flagged.
// Legitimate services embed trusted ads/analytics in invisible frames:
//   - google.com (analytics)
//   - youtube.com (embeds)
//   - doubleclick.net (Google ads)
//   - gstatic.com (Google static assets)
//   - facebook.com (Like button)

const TRUSTED_IFRAME_SOURCES = new Set([
  "google.com", "www.google.com",
  "youtube.com", "www.youtube.com", "youtu.be",
  "doubleclick.net", "www.doubleclick.net",
  "gstatic.com", "www.gstatic.com",
  "facebook.com", "www.facebook.com",
  "instagram.com", "www.instagram.com",
  "connect.facebook.net",
  "analytics.google.com",
  "googletagmanager.com",
]);

function isTrustedIframeSource(src) {
  try {
    const url = new URL(src);
    const hostname = url.hostname.toLowerCase();
    // Check exact domain and root domain
    if (TRUSTED_IFRAME_SOURCES.has(hostname)) return true;
    // Check root domain (e.g., cdn.gstatic.com → gstatic.com)
    const parts = hostname.split(".");
    if (parts.length >= 2) {
      const rootDomain = parts.slice(-2).join(".");
      return TRUSTED_IFRAME_SOURCES.has(rootDomain);
    }
    return false;
  } catch {
    return false;
  }
}

function checkSuspiciousIframe(node) {
  if (!(node instanceof Element)) return;
  const iframes = node.tagName === "IFRAME"
    ? [node]
    : (typeof node.querySelectorAll === "function"
        ? node.querySelectorAll("iframe")
        : []);

  for (const iframe of iframes) {
    const src = iframe.src || "";
    if (!src || src.startsWith("about:") || src.startsWith("javascript:")) continue;

    // ── TRUSTED DOMAIN BYPASS: Skip trusted iframe sources ──────────────
    if (isTrustedIframeSource(src)) {
      console.debug(`[Sentinel] ✅ iframe allowed: trusted source (${src.slice(0, 80)})`);
      continue;
    }

    const computed = window.getComputedStyle?.(iframe);
    const w = parseInt(iframe.width  || iframe.style.width)  || iframe.offsetWidth;
    const h = parseInt(iframe.height || iframe.style.height) || iframe.offsetHeight;
    const hiddenByStyle = computed?.display === "none";
    const hiddenBySize = w <= 0 || h <= 0;

    if ((hiddenByStyle || hiddenBySize) && src.startsWith("http")) {
      if (rateLimited("redirect")) return; // reuse redirect limit for iframe
      // Hidden iframe with HTTP URL = HIGH confidence
      console.warn(`[Sentinel] ⚠️ Suspicious iframe detected: ${src.slice(0, 80)} (${w}x${h})`);
      reportBehavior("hidden_iframe", "medium", "HIGH", false, {
        src:  src.slice(0, 100),
        size: `${w}x${h}`,
        hiddenByStyle,
        hiddenBySize,
      });
    }
  }
}

// Wire into existing domObserver — add check inside (recreate with updated callback)
// Since domObserver is already observing, we add a second observer specifically for iframes
const iframeObserver = new MutationObserver((mutations) => {
  for (const { addedNodes } of mutations) {
    for (const node of addedNodes) checkSuspiciousIframe(node);
  }
});
iframeObserver.observe(document.documentElement, { childList: true, subtree: true });
checkSuspiciousIframe(document.documentElement);

console.debug("[Sentinel] 🔍 Behavior monitor active on:", location.hostname || location.href);
