/**
 * content.js — Sentinel Browse Extension
 *
 * Injected into every page. Handles:
 *  - Overlay rendering (safe / suspicious / malicious)
 *  - Alert sound playback (one per page load)
 *  - Dismiss button for non-safe overlays
 */

let hasPlayedAlertForPage = false;
let overlayElement = null;
let overlayHideTimeoutId = null;
let _devModeEnabled = false;

console.log("[Sentinel] Content script ACTIVE on:", location.href);

// ══════════════════════════════════════════════════════════════════
// REAL-TIME LOCAL DETECTION ENGINE (content-side)
// ══════════════════════════════════════════════════════════════════

const _SENTINEL_TRUSTED = new Set([
  "google.com", "youtube.com", "github.com", "microsoft.com",
  "apple.com", "amazon.com", "stackoverflow.com", "mozilla.org",
  "wikipedia.org", "linkedin.com", "twitter.com", "x.com",
  "reddit.com", "openai.com", "chatgpt.com", "cloudflare.com",
  "netflix.com", "instagram.com", "facebook.com", "bing.com",
  "yahoo.com", "duckduckgo.com", "office.com", "live.com",
]);

function _sentinelRootDomain(hostname) {
  const parts = (hostname || "").replace(/^www\./, "").split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

function evaluateThreat() {
  let risk = 0;
  const signals = [];
  const hostname = location.hostname.toLowerCase();
  const rootDomain = _sentinelRootDomain(hostname);
  const isTrusted = _SENTINEL_TRUSTED.has(rootDomain) || _SENTINEL_TRUSTED.has(hostname);

  // ── Signal 1: Insecure connection ────────────────────────────────
  if (location.protocol !== "https:") {
    risk += 40;
    signals.push("insecure_connection");
  }

  // ── Signal 2: Password / login form ──────────────────────────────
  if (document.querySelector("input[type='password']")) {
    risk += 25;
    signals.push("login_form_detected");
  }

  // ── Signal 3: External cross-origin iframe ────────────────────────
  const iframes = Array.from(document.querySelectorAll("iframe"));
  const hasExtIframe = iframes.some(f => {
    try { return f.src && !new URL(f.src).hostname.endsWith(hostname); } catch { return false; }
  });
  if (hasExtIframe) {
    risk += 20;
    signals.push("external_iframe");
  }

  // ── Trust modifier: reduce risk 30% for known-safe domains ───────
  if (isTrusted) {
    risk = Math.round(risk * 0.7);
  }

  console.log("[Sentinel] Risk Score:", risk);
  console.log("[Sentinel] Signals:", signals);

  if (isTrusted && risk < 50) {
    console.log("[Sentinel] Decision: IGNORE (trusted domain)");
    return null;
  }
  if (risk >= 50) {
    console.log("[Sentinel] Decision: SHOW — danger");
    return { risk, signals, level: "danger" };
  }
  if (risk >= 25) {
    console.log("[Sentinel] Decision: SHOW — warning");
    return { risk, signals, level: "warning" };
  }
  console.log("[Sentinel] Decision: IGNORE");
  return null;
}

// ══════════════════════════════════════════════════════════════════
// PROFESSIONAL CYBER UI OVERLAY
// ══════════════════════════════════════════════════════════════════

function showSentinelAlert(data) {
  if (!data) return;
  if (document.getElementById("sentinel-security-overlay")) return;

  const { risk, signals, level } = data;
  const domain    = location.hostname || "unknown";
  const isSecure  = location.protocol === "https:";

  // ── Colour palette per severity ──────────────────────────────────
  const threatColor  = level === "danger" ? "#ff1a1a" : "#ff9500";
  const glowColor    = level === "danger" ? "rgba(255,26,26,0.6)"  : "rgba(255,149,0,0.5)";
  const threatLabel  = level === "danger" ? "HIGH RISK" : "MEDIUM RISK";

  // ── SSL tri-state indicator ───────────────────────────────────────
  let connLabel, sslIcon, sslColor;
  if (isSecure && level !== "danger") {
    sslIcon = "🔒"; sslColor = "#00ff88";
    connLabel = `<span style='color:${sslColor};font-weight:700;'>${sslIcon} SECURE (HTTPS)</span>`;
  } else if (!isSecure && level === "danger") {
    sslIcon = "❌"; sslColor = "#ff1a1a";
    connLabel = `<span style='color:${sslColor};font-weight:700;'>${sslIcon} HIGH RISK — NO ENCRYPTION</span>`;
  } else {
    sslIcon = "⚠"; sslColor = "#ff9500";
    connLabel = `<span style='color:${sslColor};font-weight:700;'>${sslIcon} NOT SECURE (HTTP)</span>`;
  }

  // ── Signals list HTML ────────────────────────────────────────────
  const signalsHtml = signals.length
    ? signals.map(s =>
        `<li style="margin:6px 0;color:#cbd5e1;display:flex;align-items:center;gap:8px;">
           <span style="color:${threatColor};font-size:10px;">▶</span>
           ${s.replace(/_/g, " ").toUpperCase()}
         </li>`
      ).join("")
    : `<li style="color:#475569;">No specific signals detected</li>`;

  // ── Inject keyframe CSS once per page ────────────────────────────
  if (!document.getElementById("sentinel-styles-v3")) {
    const st = document.createElement("style");
    st.id = "sentinel-styles-v3";
    st.textContent = `
      @keyframes _sv3-fadein  { from{opacity:0;transform:translateY(12px) scale(.97)} to{opacity:1;transform:translateY(0) scale(1)} }
      @keyframes _sv3-pulse   {
        0%,100% { box-shadow:0 0 18px ${glowColor},0 0 36px ${glowColor},inset 0 0 12px rgba(0,0,0,0.6); }
        50%      { box-shadow:0 0 40px ${glowColor},0 0 80px ${glowColor},inset 0 0 20px rgba(0,0,0,0.4); }
      }
      @keyframes _sv3-shake   { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-6px)} 40%,80%{transform:translateX(6px)} }
      @keyframes _sv3-scanline { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
      @keyframes _sv3-bar     { from{width:0%} to{width:${Math.min(risk, 100)}%} }
      @keyframes _sv3-blink   { 0%,100%{opacity:1} 50%{opacity:0.3} }
      @keyframes _sv3-typing  {
        from { width:0 }
        to   { width:100% }
      }
      #sentinel-security-overlay { animation: _sv3-fadein .4s cubic-bezier(.22,1,.36,1) forwards; }
      #_sv3-card {
        animation:
          _sv3-pulse 2.4s ease-in-out infinite,
          ${level === "danger" ? "_sv3-shake .6s ease .3s" : "none"};
      }
      #_sv3-risk-bar { animation: _sv3-bar 1.4s cubic-bezier(.22,1,.36,1) .5s both; }
      #_sv3-scanline { animation: _sv3-scanline 4s linear infinite; pointer-events:none; }
      #_sv3-cursor   { animation: _sv3-blink .8s step-end infinite; }
      #_sv3-title    { overflow:hidden;white-space:nowrap; animation: _sv3-typing .6s steps(24,end) .3s both; }
      #sentinel-leave-btn:hover  { filter:brightness(1.15); transform:translateY(-1px); }
      #sentinel-ignore-btn:hover { background:rgba(255,255,255,.07)!important; color:#94a3b8!important; }
      #sentinel-leave-btn, #sentinel-ignore-btn { transition: all 180ms ease; }
    `;
    (document.head || document.documentElement).appendChild(st);
  }

  // ── Build overlay DOM ────────────────────────────────────────────
  const overlay = document.createElement("div");
  overlay.id    = "sentinel-security-overlay";
  overlay.setAttribute("role", "alertdialog");
  overlay.setAttribute("aria-modal", "true");

  overlay.innerHTML = `
  <div style="
    position:fixed;inset:0;
    background:linear-gradient(160deg,#020617 0%,#060d1f 55%,#0a0e1f 100%);
    z-index:2147483647;
    display:flex;align-items:center;justify-content:center;
    font-family:'Courier New',Courier,monospace;
    padding:20px;
    overflow:hidden;
  ">

    <!-- Animated scanline -->
    <div id="_sv3-scanline" style="
      position:absolute;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent,rgba(0,255,140,.12),transparent);
      top:0;
    "></div>

    <!-- Background grid -->
    <div style="
      position:absolute;inset:0;
      background-image:
        linear-gradient(rgba(0,255,140,.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,140,.025) 1px, transparent 1px);
      background-size:40px 40px;
      pointer-events:none;
    "></div>

    <!-- Main card -->
    <div id="_sv3-card" style="
      border:1.5px solid ${threatColor};
      border-radius:12px;
      padding:36px 42px;
      max-width:560px;width:100%;
      background:rgba(2,6,23,.96);
      color:#e2e8f0;
      position:relative;
      backdrop-filter:blur(12px);
    ">

      <!-- Corner decorations -->
      <div style="position:absolute;top:0;left:0;width:16px;height:16px;border-top:2px solid ${threatColor};border-left:2px solid ${threatColor};border-radius:12px 0 0 0;"></div>
      <div style="position:absolute;top:0;right:0;width:16px;height:16px;border-top:2px solid ${threatColor};border-right:2px solid ${threatColor};border-radius:0 12px 0 0;"></div>
      <div style="position:absolute;bottom:0;left:0;width:16px;height:16px;border-bottom:2px solid ${threatColor};border-left:2px solid ${threatColor};border-radius:0 0 0 12px;"></div>
      <div style="position:absolute;bottom:0;right:0;width:16px;height:16px;border-bottom:2px solid ${threatColor};border-right:2px solid ${threatColor};border-radius:0 0 12px 0;"></div>

      <!-- Header -->
      <div style="display:flex;align-items:center;gap:16px;border-bottom:1px solid rgba(255,255,255,.07);padding-bottom:20px;margin-bottom:24px;">
        <div style="font-size:34px;line-height:1;filter:drop-shadow(0 0 8px ${threatColor});">🛡️</div>
        <div style="flex:1;">
          <div id="_sv3-title" style="color:${threatColor};font-size:15px;font-weight:900;letter-spacing:3px;text-transform:uppercase;">SENTINEL SECURITY ALERT<span id="_sv3-cursor" style="margin-left:2px;">█</span></div>
          <div style="color:#334155;font-size:9px;margin-top:5px;letter-spacing:2px;">REAL-TIME THREAT DETECTION SYSTEM v3.0 • ${new Date().toLocaleTimeString()}</div>
        </div>
        <div style="
          padding:4px 10px;border-radius:4px;
          font-size:9px;letter-spacing:2px;font-weight:900;
          background:${threatColor}22;border:1px solid ${threatColor}44;
          color:${threatColor};
        ">LIVE</div>
      </div>

      <!-- Risk bar -->
      <div style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
          <span style="color:#475569;font-size:9px;letter-spacing:2px;">RISK SCORE</span>
          <span style="color:${threatColor};font-size:9px;font-weight:900;letter-spacing:1px;">${risk}/100</span>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:4px;height:6px;overflow:hidden;border:1px solid rgba(255,255,255,.06);">
          <div id="_sv3-risk-bar" style="height:100%;width:0%;background:linear-gradient(90deg,${threatColor}88,${threatColor});border-radius:4px;"></div>
        </div>
      </div>

      <!-- Info grid -->
      <div style="display:grid;grid-template-columns:120px 1fr;gap:12px 16px;font-size:12px;">
        <span style="color:#334155;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;align-self:center;">DOMAIN</span>
        <span style="color:#00ffcc;font-weight:bold;font-size:13px;letter-spacing:.5px;">${domain}</span>

        <span style="color:#334155;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;align-self:center;">CONNECTION</span>
        <span style="font-size:12px;">${connLabel}</span>

        <span style="color:#334155;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;align-self:center;">THREAT LEVEL</span>
        <span style="display:inline-flex;align-items:center;gap:6px;">
          <span style="width:8px;height:8px;border-radius:50%;background:${threatColor};display:inline-block;box-shadow:0 0 6px ${threatColor};"></span>
          <span style="background:${threatColor};color:#000;padding:3px 14px;border-radius:999px;font-size:10px;font-weight:900;letter-spacing:2px;">${threatLabel}</span>
        </span>
      </div>

      <!-- Signals panel -->
      <div style="margin-top:22px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-left:3px solid ${threatColor};border-radius:6px;padding:14px 18px;">
        <div style="color:#334155;font-size:9px;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;">▸ THREAT SIGNALS DETECTED</div>
        <ul style="margin:0;padding:0;list-style:none;">${signalsHtml}</ul>
      </div>

      <!-- Action buttons -->
      <div style="display:flex;gap:12px;margin-top:28px;">
        <button id="sentinel-leave-btn" style="
          flex:1;padding:14px;
          background:${threatColor};color:#000;
          border:none;border-radius:8px;
          font-family:'Courier New',monospace;
          font-size:12px;font-weight:900;
          letter-spacing:2.5px;cursor:pointer;
          text-transform:uppercase;
          box-shadow:0 0 20px ${glowColor};
        ">← LEAVE SITE</button>
        <button id="sentinel-ignore-btn" style="
          flex:1;padding:14px;
          background:transparent;color:#475569;
          border:1px solid rgba(255,255,255,.1);
          border-radius:8px;
          font-family:'Courier New',monospace;
          font-size:12px;font-weight:700;
          letter-spacing:2px;cursor:pointer;
          text-transform:uppercase;
        ">IGNORE</button>
      </div>

      <!-- Footer -->
      <div style="margin-top:20px;text-align:center;color:#1e293b;font-size:9px;letter-spacing:2.5px;">SENTINEL BROWSE v3.0 &bull; REAL-TIME PROTECTION ACTIVE</div>
    </div>
  </div>
  `;

  (document.body || document.documentElement).appendChild(overlay);

  document.getElementById("sentinel-leave-btn")?.addEventListener("click", () => {
    if (document.referrer) window.history.back();
    else window.location.href = "https://www.google.com";
  });
  document.getElementById("sentinel-ignore-btn")?.addEventListener("click", () => {
    overlay.remove();
  });

  // Optional: subtle sound cue for danger level
  if (level === "danger") {
    try { playAlertSound("malicious"); } catch {}
  } else {
    try { playAlertSound("suspicious"); } catch {}
  }
}

// ── Run local detection after page is fully loaded ────────────────
window.addEventListener("load", () => {
  setTimeout(() => {
    const threat = evaluateThreat();
    if (threat) showSentinelAlert(threat);
  }, 1200);
});

console.log("[Sentinel] Content script loaded:", location.href);
let _networkMonitorInstalled = false;
let _pageNetworkBridgeInstalled = false;
let _decodedScriptAlertFired = false;
let _phishingUiAlertSent = false;
const _networkAlertSeen = new Set();
const _MAX_NETWORK_ALERTS = 12;

/**
 * Per-page deduplication guard for overlay messages.
 *
 * sendOverlayWithRetry in background.js retries on delivery failure.
 * If the first send succeeds but the callback fires late (race), the
 * second attempt may also be delivered. We key on status+rounded-risk
 * so legitimate severity escalations (suspicious → malicious) still show.
 */
const _overlayShownKeys = new Set();
const _OVERLAY_COOLDOWN_MS = 5000; // 5 s between same-key overlays

document.addEventListener("DOMContentLoaded", () => {
  console.log("[Sentinel] Content script ready");
});

function triggerSecurityOverlay(data) {
  console.log("[Sentinel] Triggering overlay:", data);

  const overlay = document.createElement("div");
  overlay.id = "sentinel-overlay";
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(255,0,0,0.85);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 28px;
      font-weight: bold;
      text-align: center;
    ">
      ⚠️ DANGER ⚠️<br/>
      ${data.reason}<br/>
      Risk: ${data.risk}/100
    </div>
  `;

  document.body.appendChild(overlay);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "sentinel:play-alert") {
    playAlert(message.alertType);
    sendResponse({ ok: true });
    return;
  }

  if (message?.type === "sentinel:show-overlay") {
    // ── [Sentinel AI] Structured receive log ─────────────────────────
    const _rcvRisk = message.finalScore ?? message.finalRisk ?? message.score ?? 0;
    console.log("[Sentinel AI] Overlay received", {
      status:   message.status,
      risk:     _rcvRisk,
      signals:  message.signals || [],
      decision: message.status === "malicious" ? "FULL_SCREEN" : "CARD",
    });

    // ── Deduplication gate ───────────────────────────────────────────
    // Key: status + risk bucketed to nearest 10 (so 42 and 48 share a key)
    const _dedupeKey = `${message.status}:${Math.round(_rcvRisk / 10) * 10}`;
    const _now = Date.now();
    const _lastShown = _overlayShownKeys.get(_dedupeKey);

    if (_lastShown && (_now - _lastShown) < _OVERLAY_COOLDOWN_MS) {
      console.debug("[Sentinel AI] Overlay deduplicated — cooldown active", _dedupeKey);
      sendResponse({ ok: true, deduplicated: true });
      return;
    }
    _overlayShownKeys.set(_dedupeKey, _now);

    // Cache debug context for dev_mode overlay rendering (best-effort).
    try {
      window.__sentinel_last_overlay_signals = Array.isArray(message.signals) ? message.signals : [];
      window.__sentinel_last_overlay_score = typeof message.score === "number" ? message.score : null;
      window.__sentinel_last_overlay_finalScore = typeof message.finalScore === "number" ? message.finalScore : null;
      window.__sentinel_last_overlay_rule = typeof message.appliedRule === "string" ? message.appliedRule : "";
      window.__sentinel_last_overlay_risk_steps = Array.isArray(message.riskSteps) ? message.riskSteps : [];
      window.__sentinel_last_overlay_api_calls = Array.isArray(message.apiCalls) ? message.apiCalls : [];
    } catch {}

    // Route by severity — use professional Sentinel UI for all threat levels
    const _bgRisk = message.finalScore ?? message.score ?? 0;
    const _bgSignals = Array.isArray(message.signals) ? message.signals : message.reasons || [];
    const _bgLevel = message.status === "malicious" ? "danger" : "warning";

    if (message.status === "malicious" || message.status === "suspicious") {
      showSentinelAlert({ risk: _bgRisk, signals: _bgSignals, level: _bgLevel });
      playAlertSound(message.status);
      sendResponse({ ok: true });
      return;
    }

    // Regular small card overlay for suspicious/safe
    showOverlay(
      message.status,
      message.message,
      message.reasons,  // Structured reasons from threat evaluator
      message.trustScore,
      message.educationTip,
      message.breakdown,
      message.aiReasoning,
      message.finalScore || message.finalRisk,  // Accept both old and new field names
      message.explanation
    );
    sendResponse({ ok: true });
  }
});

// Keep dev_mode in sync (lightweight)
try {
  chrome.storage.local.get(["dev_mode"], (d) => {
    _devModeEnabled = Boolean(d && d.dev_mode);
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.dev_mode) _devModeEnabled = Boolean(changes.dev_mode.newValue);
  });
} catch {}

// ─── Alert Sound ───────────────────────────────────────────────────────────

function playAlert(type) {
  if (hasPlayedAlertForPage) return;

  let fileName = "";
  let volume = 1;

  if (type === "suspicious") {
    fileName = "warning.mp3";
    volume = 0.35;
  } else if (type === "malicious") {
    fileName = "danger.mp3";
    volume = 0.85;
  } else {
    return;
  }

  hasPlayedAlertForPage = true;
  const audio = new Audio(chrome.runtime.getURL(`assets/sounds/${fileName}`));
  audio.volume = volume;
  audio.play().catch((err) => {
    console.warn(`[Sentinel] Failed to play ${type} alert sound:`, err);
  });
}

// ─── Overlay Rendering ────────────────────────────────────────────────────

function showOverlay(
  status,
  message,
  reasons = [],
  trustScore = null,
  educationTip = "",
  breakdown = null,
  aiReasoning = null,
  finalRiskScore = null,
  explanation = ""
) {
  const config = getOverlayConfig(status, message, reasons, trustScore, educationTip);
  if (!config) return;

  const overlay = ensureOverlayElement();
  overlay.innerHTML = "";

  // ── Header row: icon + title ─────────────────────────────────────────────
  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;gap:8px;margin-bottom:8px;";

  const icon = document.createElement("span");
  icon.textContent = config.icon;
  icon.setAttribute("aria-hidden", "true");
  icon.style.cssText = "font-size:18px;line-height:1;flex-shrink:0;";

  const title = document.createElement("div");
  title.textContent = config.text;
  title.style.cssText = "font-weight:700;font-size:14px;flex:1;";

  header.appendChild(icon);
  header.appendChild(title);

  // ── Dismiss button (visible for suspicious and malicious) ────────────────
  if (status !== "safe") {
    const dismissBtn = document.createElement("button");
    dismissBtn.textContent = "×";
    dismissBtn.setAttribute("aria-label", "Dismiss alert");
    dismissBtn.style.cssText = [
      "background:rgba(255,255,255,0.25);border:none;cursor:pointer;",
      "color:inherit;font-size:18px;line-height:1;padding:0 4px;border-radius:5px;",
      "font-weight:700;flex-shrink:0;transition:background 120ms;",
    ].join("");
    dismissBtn.addEventListener("mouseenter", () => {
      dismissBtn.style.background = "rgba(255,255,255,0.45)";
    });
    dismissBtn.addEventListener("mouseleave", () => {
      dismissBtn.style.background = "rgba(255,255,255,0.25)";
    });
    dismissBtn.addEventListener("click", () => hideOverlay(overlay));
    header.appendChild(dismissBtn);
  }

  overlay.appendChild(header);

  // ── Trust score badge ────────────────────────────────────────────────────
  if (typeof trustScore === "number") {
    const scoreBadge = document.createElement("div");
    scoreBadge.textContent = `Trust Score: ${trustScore}/100`;
    scoreBadge.style.cssText = [
      "display:inline-flex;padding:3px 10px;border-radius:999px;",
      `font-size:11px;font-weight:700;margin-bottom:6px;`,
      `background:${config.badgeBackground};color:${config.badgeColor};`,
    ].join("");
    overlay.appendChild(scoreBadge);
  }
  if (typeof finalRiskScore === "number") {
    const riskBadge = document.createElement("div");
    riskBadge.textContent = `Final Risk: ${Math.max(0, Math.min(100, Math.round(finalRiskScore)))}/100`;
    riskBadge.style.cssText = [
      "display:inline-flex;padding:3px 10px;border-radius:999px;margin-left:6px;",
      "font-size:11px;font-weight:700;margin-bottom:6px;",
      "background:rgba(255,255,255,0.16);color:#fff;",
    ].join("");
    overlay.appendChild(riskBadge);
  }

  // ── Reasons list (always shown for suspicious/malicious) ─────────────────
  const displayReasons = Array.isArray(reasons)
    ? reasons.filter((r) => typeof r === "string" && r.trim())
    : [];

  if (displayReasons.length > 0) {
    const list = document.createElement("ul");
    list.style.cssText = "margin:6px 0 0;padding-left:18px;font-size:12px;font-weight:500;";

    for (const reason of displayReasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      item.style.marginBottom = "3px";
      list.appendChild(item);
    }
    overlay.appendChild(list);
  }
  const normalizedAi = typeof aiReasoning === "string" ? aiReasoning.trim() : "";
  const normalizedExplanation = typeof explanation === "string" ? explanation.trim() : "";
  if (normalizedAi || normalizedExplanation) {
    const aiCard = document.createElement("div");
    aiCard.style.cssText = [
      "margin-top:10px;padding:10px 10px;border-radius:10px;",
      "background:rgba(255,255,255,0.10);border:1px solid rgba(255,255,255,0.2);",
    ].join("");
    aiCard.innerHTML = `<div style="font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;opacity:.9;">AI Reasoning</div>`;
    const txt = document.createElement("div");
    txt.textContent = normalizedAi || normalizedExplanation;
    txt.style.cssText = "margin-top:6px;font-size:12px;line-height:1.4;opacity:.96;";
    aiCard.appendChild(txt);
    overlay.appendChild(aiCard);
  }

  // ── Developer mode panel (Part 2) ───────────────────────────────────────
  if (_devModeEnabled) {
    const dev = document.createElement("div");
    dev.style.cssText = [
      "margin-top:10px;padding:10px 10px;border-radius:10px;",
      "background:rgba(0,0,0,0.18);border:1px solid rgba(255,255,255,0.22);",
    ].join("");

    const hdr = document.createElement("div");
    hdr.textContent = "Developer Mode";
    hdr.style.cssText = "font-size:10px;font-weight:900;letter-spacing:0.1em;text-transform:uppercase;opacity:0.95;";
    dev.appendChild(hdr);

    const sigs = Array.isArray(window.__sentinel_last_overlay_signals) ? window.__sentinel_last_overlay_signals : [];
    const score = typeof window.__sentinel_last_overlay_score === "number" ? window.__sentinel_last_overlay_score : null;
    const appliedRule = typeof window.__sentinel_last_overlay_rule === "string" ? window.__sentinel_last_overlay_rule : "";
    const finalScore = typeof window.__sentinel_last_overlay_finalScore === "number" ? window.__sentinel_last_overlay_finalScore : null;
    const riskSteps = Array.isArray(window.__sentinel_last_overlay_risk_steps)
      ? window.__sentinel_last_overlay_risk_steps : [];
    const apiCalls = Array.isArray(window.__sentinel_last_overlay_api_calls)
      ? window.__sentinel_last_overlay_api_calls : [];

    const lines = [];
    if (sigs.length) lines.push("Signals:", ...sigs.slice(0, 12).map(s => `- ${s}`));
    if (breakdown && typeof breakdown === "object") {
      const b = Object.entries(breakdown).filter(([k, v]) => k && v).slice(0, 6);
      if (b.length) lines.push("", "Breakdown:", ...b.map(([k, v]) => `- ${k}: ${v}`));
    }
    if (riskSteps.length) {
      lines.push("", "Risk calculation steps:", ...riskSteps.slice(0, 8).map(s => `- ${s}`));
    }
    if (apiCalls.length) {
      lines.push("", "API/Module calls:", ...apiCalls.slice(0, 8).map(s => `- ${s}`));
    }
    if (score !== null) lines.push("", `Score: ${score}`);
    if (finalScore !== null) lines.push(`Final Score: ${finalScore}`);
    if (appliedRule) lines.push(`Rule: ${appliedRule}`);

    const pre = document.createElement("pre");
    pre.textContent = lines.join("\n") || "No debug data.";
    pre.style.cssText = "margin:8px 0 0;white-space:pre-wrap;font-size:11px;line-height:1.35;opacity:0.95;";
    dev.appendChild(pre);
    overlay.appendChild(dev);
  }

  // ── Structured breakdown (XAI++) ──────────────────────────────────────────
  if (breakdown && typeof breakdown === "object") {
    const entries = Object.entries(breakdown)
      .filter(([k, v]) => k && v)
      .slice(0, 4);

    if (entries.length) {
      const xai = document.createElement("div");
      xai.style.cssText = [
        "margin-top:10px;padding:10px 10px;border-radius:10px;",
        "background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.22);",
      ].join("");

      const hdr = document.createElement("div");
      hdr.textContent = "Why this site was flagged";
      hdr.style.cssText = "font-size:10px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;opacity:0.9;";
      xai.appendChild(hdr);

      for (const [k, v] of entries) {
        const row = document.createElement("div");
        row.style.cssText = "display:flex;gap:8px;margin-top:6px;font-size:12px;line-height:1.35;";

        const kk = document.createElement("div");
        kk.textContent = k;
        kk.style.cssText = "min-width:92px;font-weight:800;opacity:0.95;";

        const vv = document.createElement("div");
        vv.textContent = String(v);
        vv.style.cssText = "flex:1;opacity:0.95;";

        row.appendChild(kk);
        row.appendChild(vv);
        xai.appendChild(row);
      }

      overlay.appendChild(xai);
    }
  }

  // ── Education tip ────────────────────────────────────────────────────────
  const normalizedTip = typeof educationTip === "string" ? educationTip.trim() : "";
  if (normalizedTip) {
    const tipCard = document.createElement("div");
    tipCard.style.cssText = [
      `margin-top:8px;padding:8px 10px;border-radius:8px;`,
      `background:${config.tipBackground};color:${config.tipColor};`,
    ].join("");

    const tipLabel = document.createElement("div");
    tipLabel.textContent = "Safety Tip";
    tipLabel.style.cssText = "font-size:10px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;";

    const tipText = document.createElement("div");
    tipText.textContent = normalizedTip;
    tipText.style.cssText = "margin-top:3px;font-size:12px;font-weight:500;";

    tipCard.appendChild(tipLabel);
    tipCard.appendChild(tipText);
    overlay.appendChild(tipCard);
  }

  // ── Apply theme ───────────────────────────────────────────────────────────
  overlay.style.background = config.background;
  overlay.style.color = config.color;
  overlay.style.boxShadow = config.shadow;
  overlay.style.pointerEvents = status !== "safe" ? "auto" : "none";

  // ── Animate in ────────────────────────────────────────────────────────────
  if (overlayHideTimeoutId) {
    clearTimeout(overlayHideTimeoutId);
    overlayHideTimeoutId = null;
  }

  overlay.style.display = "block";
  overlay.style.opacity = "0";
  overlay.style.transform = "translateY(-10px) scale(0.97)";

  requestAnimationFrame(() => {
    overlay.style.opacity = "1";
    overlay.style.transform = "translateY(0) scale(1)";
  });

  // ── Auto-hide (safe/suspicious only) ─────────────────────────────────────
  if (config.autoHideMs) {
    overlayHideTimeoutId = window.setTimeout(() => hideOverlay(overlay), config.autoHideMs);
  }
}

function hideOverlay(overlay) {
  overlay.style.opacity = "0";
  overlay.style.transform = "translateY(-10px) scale(0.97)";
  window.setTimeout(() => {
    if (overlayElement === overlay) {
      overlay.style.display = "none";
    }
  }, 220);
}

// ─── Danger Overlay (CYBERSECURITY STYLE) ─────────────────────────────────

/**
 * FULL-SCREEN DANGER OVERLAY (v3.1)
 * 
 * Shows an aggressive red terminal-style alert for MALICIOUS verdicts.
 * Features:
 *   • Full-screen red overlay with 95% opacity (blocks interaction)
 *   • Flicker animation (60–120ms pulse)
 *   • Terminal monospace font + text-shadow glow
 *   • Two action buttons: "Leave Site" (primary) + "Proceed Anyway" (risky)
 *   • Risk score display (0-100)
 *   • Audio alert (alarm.mp3)
 * 
 * @param {object} result - Detection result with status, risk, signals
 */
function showDangerOverlay(result) {
  // Create the full-screen container
  const overlay = document.createElement("div");
  overlay.id = "sentinel-danger-overlay";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "sentinel-danger-title");

  // Inject cybersecurity-style CSS if not already present
  if (!document.getElementById("sentinel-danger-styles")) {
    const styleEl = document.createElement("style");
    styleEl.id = "sentinel-danger-styles";
    styleEl.textContent = `
      #sentinel-danger-overlay {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: rgba(0, 0, 0, 0.95) !important;
        color: #ff0000 !important;
        z-index: 2147483647 !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
        align-items: center !important;
        font-family: "Courier New", "Lucida Console", monospace !important;
        text-shadow: 0 0 5px #ff0000, 0 0 10px rgba(255, 0, 0, 0.5) !important;
        animation: sentinel-flicker 0.8s infinite !important;
        padding: 20px !important;
        overflow-y: auto !important;
      }

      @keyframes sentinel-flicker {
        0% { opacity: 1; }
        5% { opacity: 0.8; }
        10% { opacity: 1; }
        15% { opacity: 0.85; }
        20% { opacity: 1; }
        100% { opacity: 1; }
      }

      .sentinel-danger-box {
        border: 3px solid #ff0000 !important;
        padding: 40px !important;
        text-align: center !important;
        max-width: 500px !important;
        background: rgba(0, 0, 0, 0.7) !important;
        border-radius: 8px !important;
        box-shadow: 0 0 20px rgba(255, 0, 0, 0.4), inset 0 0 20px rgba(255, 0, 0, 0.1) !important;
      }

      .sentinel-danger-icon {
        font-size: 60px !important;
        margin-bottom: 20px !important;
        animation: sentinel-pulse 1.2s ease-in-out infinite !important;
      }

      @keyframes sentinel-pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.1); opacity: 0.9; }
      }

      .sentinel-danger-title {
        font-size: 28px !important;
        font-weight: bold !important;
        margin: 0 0 12px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase !important;
      }

      .sentinel-danger-subtitle {
        font-size: 14px !important;
        margin: 0 0 20px !important;
        opacity: 0.9 !important;
        letter-spacing: 1px !important;
      }

      .sentinel-danger-risk {
        font-size: 18px !important;
        font-weight: bold !important;
        margin: 20px 0 !important;
        padding: 12px !important;
        background: rgba(255, 0, 0, 0.1) !important;
        border: 1px solid #ff0000 !important;
        border-radius: 4px !important;
      }

      .sentinel-danger-risk-value {
        font-size: 32px !important;
        color: #ff3333 !important;
        letter-spacing: 3px !important;
      }

      .sentinel-danger-signals {
        font-size: 12px !important;
        margin: 16px 0 !important;
        text-align: left !important;
        background: rgba(0, 0, 0, 0.4) !important;
        padding: 12px !important;
        border-left: 2px solid #ff0000 !important;
        max-height: 120px !important;
        overflow-y: auto !important;
        line-height: 1.6 !important;
      }

      .sentinel-danger-signals strong {
        color: #ff3333 !important;
      }

      .sentinel-danger-actions {
        display: flex !important;
        gap: 12px !important;
        margin-top: 24px !important;
        justify-content: center !important;
        flex-wrap: wrap !important;
      }

      .sentinel-danger-btn {
        padding: 12px 28px !important;
        border: 2px solid #ff0000 !important;
        border-radius: 4px !important;
        background: rgba(255, 0, 0, 0.1) !important;
        color: #ff0000 !important;
        font-family: "Courier New", monospace !important;
        font-size: 14px !important;
        font-weight: bold !important;
        cursor: pointer !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        transition: all 200ms !important;
      }

      .sentinel-danger-btn:hover {
        background: #ff0000 !important;
        color: #000 !important;
        box-shadow: 0 0 10px rgba(255, 0, 0, 0.6) !important;
      }

      .sentinel-danger-btn-primary {
        background: rgba(255, 0, 0, 0.2) !important;
      }

      .sentinel-danger-btn-primary:hover {
        background: #ff0000 !important;
      }

      .sentinel-danger-footer {
        font-size: 10px !important;
        margin-top: 20px !important;
        opacity: 0.6 !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
      }
    `;
    document.head?.appendChild(styleEl) || document.documentElement.appendChild(styleEl);
  }

  // Build the danger box content
  const riskScore = Math.max(0, Math.min(100, Math.round(result.finalRiskScore || result.risk || 0)));
  const signals = Array.isArray(result.signals) ? result.signals.slice(0, 5) : [];

  overlay.innerHTML = `
    <div class="sentinel-danger-box">
      <div class="sentinel-danger-icon">🚨</div>
      <div class="sentinel-danger-title" id="sentinel-danger-title">SECURITY WARNING</div>
      <div class="sentinel-danger-subtitle">DANGEROUS SITE DETECTED</div>
      
      <div class="sentinel-danger-risk">
        RISK LEVEL: <span class="sentinel-danger-risk-value">${riskScore}/100</span>
      </div>

      ${signals.length > 0 ? `
        <div class="sentinel-danger-signals">
          <strong>THREATS DETECTED:</strong><br>
          ${signals.map(s => `• ${String(s).toUpperCase()}`).join('<br>')}
        </div>
      ` : ''}

      <div class="sentinel-danger-subtitle" style="margin-top: 16px;">
        This site is known to be malicious. Proceed at your own risk.
      </div>

      <div class="sentinel-danger-actions">
        <button id="sentinel-leave-site" class="sentinel-danger-btn sentinel-danger-btn-primary">
          ← LEAVE SITE
        </button>
        <button id="sentinel-continue-anyway" class="sentinel-danger-btn">
          PROCEED ANYWAY
        </button>
      </div>

      <div class="sentinel-danger-footer">
        Powered by Sentinel Security Extension
      </div>
    </div>
  `;

  // Attach to DOM
  const root = document.body || document.documentElement;
  root.appendChild(overlay);

  // Button handlers
  const leaveBtn = document.getElementById("sentinel-leave-site");
  if (leaveBtn) {
    leaveBtn.addEventListener("click", () => {
      window.location.href = "https://www.google.com";
    });
  }

  const continueBtn = document.getElementById("sentinel-continue-anyway");
  if (continueBtn) {
    continueBtn.addEventListener("click", () => {
      overlay.style.display = "none";
      // Update bypass in background
      try {
        chrome.runtime.sendMessage({
          type: "sentinel:bypass-url",
          url: window.location.href,
        }).catch(() => {});
      } catch {}
    });
  }

  // Play danger alarm sound
  playAlertSound("malicious");
}

/**
 * Enhanced alert sound playback (v3.1)
 * Supports: malicious (danger.mp3), suspicious (warning.mp3), safe (safe.mp3)
 */
function playAlertSound(level) {
  const volumeMap = {
    malicious: 0.75,
    suspicious: 0.5,
    safe: 0.3,
  };

  const fileMap = {
    malicious: "danger.mp3",
    suspicious: "warning.mp3",
    safe: "safe.mp3",
  };

  const volume = volumeMap[level] || 0.5;
  const fileName = fileMap[level] || "warning.mp3";

  try {
    const audio = new Audio(chrome.runtime.getURL(`assets/sounds/${fileName}`));
    audio.volume = volume;
    audio.play().catch(() => {});
  } catch (e) {
    console.warn(`[Sentinel] Failed to play ${level} sound:`, e);
  }
}

function ensureOverlayElement() {
  if (overlayElement && document.contains(overlayElement)) return overlayElement;

  overlayElement = document.createElement("div");
  overlayElement.id = "sentinel-status-overlay";
  overlayElement.setAttribute("role", "status");
  overlayElement.setAttribute("aria-live", "polite");

  overlayElement.style.cssText = [
    "position:fixed;top:16px;right:16px;z-index:2147483647;",
    "max-width:300px;min-width:270px;padding:12px 14px;",
    "border-radius:14px;",
    'font-family:"Segoe UI",Arial,sans-serif;',
    "font-size:14px;font-weight:600;line-height:1.4;letter-spacing:0.01em;",
    "backdrop-filter:blur(8px);",
    "border:1px solid rgba(255,255,255,0.3);",
    "opacity:0;transform:translateY(-10px) scale(0.97);",
    "transition:opacity 220ms ease,transform 220ms ease;",
    "display:none;",
  ].join("");

  const root = document.body || document.documentElement;
  root.appendChild(overlayElement);
  return overlayElement;
}

// ─── Overlay Config per Status ────────────────────────────────────────────

function getOverlayConfig(status, message, reasons, trustScore, educationTip) {
  if (status === "safe") {
    return {
      icon: "✅",
      text: message || "Safe Website",
      trustScore,
      educationTip: "",
      background: "rgba(16, 120, 64, 0.96)",
      color: "#f0fff4",
      badgeBackground: "rgba(255,255,255,0.2)",
      badgeColor: "#f0fff4",
      tipBackground: "rgba(255,255,255,0.12)",
      tipColor: "#f0fff4",
      shadow: "0 10px 28px rgba(16,120,64,0.28)",
      autoHideMs: 3000,
    };
  }

  if (status === "suspicious") {
    return {
      icon: "⚠️",
      text: message || "Suspicious Activity Detected",
      trustScore,
      educationTip,
      background: "rgba(217, 158, 11, 0.97)",
      color: "#2b1d00",
      badgeBackground: "rgba(255,255,255,0.55)",
      badgeColor: "#2b1d00",
      tipBackground: "rgba(255,255,255,0.6)",
      tipColor: "#3a2b00",
      shadow: "0 10px 28px rgba(180,120,0,0.28)",
      autoHideMs: 7000,
    };
  }

  if (status === "malicious") {
    return {
      icon: "🚫",
      text: message || "Malicious Site Blocked",
      trustScore,
      educationTip,
      background: "rgba(180, 24, 30, 0.97)",
      color: "#fff5f5",
      badgeBackground: "rgba(255,255,255,0.18)",
      badgeColor: "#fff5f5",
      tipBackground: "rgba(255,255,255,0.15)",
      tipColor: "#fff5f5",
      shadow: "0 12px 32px rgba(140,10,14,0.36)",
      autoHideMs: 0, // never auto-hide — user must dismiss
    };
  }

  return null;
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 7 — PHISHING UI SCANNER  (Part 2)
// ══════════════════════════════════════════════════════════════════════
//
// Scans the loaded DOM for password, OTP, and credit-card inputs.
// If found on a suspicious or low-trust domain, shows a ⚠️ overlay.
// Runs once at document_idle; re-runs on SPA route changes.

/**
 * Detects which sensitive input categories are present in the page DOM.
 * @returns {{ hasPassword: boolean, hasOTP: boolean, hasCreditCard: boolean, hasCVV: boolean, hasFakeLogin: boolean }}
 */
function detectSensitiveInputTypes() {
  const inputs = Array.from(document.querySelectorAll("input"));

  const hasPassword = inputs.some(el =>
    el.type === "password" ||
    /pass(word)?/i.test(`${el.name}${el.id}${el.placeholder}`)
  );

  // OTP: explicit autocomplete OR four-plus single-character inputs
  const singleChar = inputs.filter(el => el.maxLength === 1 && el.type !== "hidden");
  const hasOTP = singleChar.length >= 4 || inputs.some(el =>
    el.autocomplete === "one-time-code" ||
    (el.inputMode === "numeric" && /otp|code|verif/i.test(`${el.name}${el.id}`))
  );

  // Credit card: autocomplete cc-* or field name patterns
  const hasCC = inputs.some(el => {
    const hint = `${el.autocomplete}${el.name}${el.id}`.toLowerCase();
    return hint.startsWith("cc-") || /card.?number|creditcard|cc.?num/i.test(hint);
  });
  const hasCVV = inputs.some(el => {
    const hint = `${el.autocomplete}${el.name}${el.id}${el.placeholder}`.toLowerCase();
    return /cvv|cvc|security.?code/.test(hint);
  });
  const hasFakeLogin = (() => {
    const forms = Array.from(document.querySelectorAll("form"));
    return forms.some((f) => {
      const pw = f.querySelector('input[type="password"]');
      const user = f.querySelector('input[type="email"],input[name*="user" i],input[name*="login" i],input[name*="email" i]');
      const urgentCopy = /(verify|suspended|unlock|urgent|confirm|security check)/i.test(f.textContent || "");
      return Boolean(pw && (user || urgentCopy));
    });
  })();

  return { hasPassword, hasOTP, hasCreditCard: hasCC, hasCVV, hasFakeLogin };
}

/**
 * Fetches the background's cached analysis for the current page.
 * Returns null if unavailable (SW sleeping, first visit, etc.).
 * @returns {Promise<object|null>}
 */
function getPageAnalysis() {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ type: "sentinel:get-analysis" }, response => {
        resolve(chrome.runtime.lastError ? null : (response?.result ?? null));
      });
    } catch {
      resolve(null);
    }
  });
}

/**
 * Runs the phishing UI scan and shows an overlay if warranted.
 * 
 * CRITICAL (v2.1): Only flag login forms on untrusted domains with other indicators
 * DO NOT flag on trusted domains (google.com, microsoft.com, etc.)
 * 
 * @param {object|null} [cachedAnalysis] — reuse a previously fetched result
 */
async function runPhishingUIScanner(cachedAnalysis = null) {
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;

  const { hasPassword, hasOTP, hasCreditCard, hasCVV, hasFakeLogin } = detectSensitiveInputTypes();
  if (!hasPassword && !hasOTP && !hasCreditCard && !hasCVV && !hasFakeLogin) return;

  const analysis   = cachedAnalysis ?? await getPageAnalysis();
  if (!analysis) return;

  const host = String(location.hostname || "").toLowerCase();
  const TRUSTED_DOMAINS = ["google.com", "microsoft.com", "apple.com", "amazon.com", "edu", "gov"];
  const isTrustedDomain = TRUSTED_DOMAINS.some(domain => (
    domain === "edu" || domain === "gov"
      ? host.endsWith(`.${domain}`)
      : host === domain || host.endsWith(`.${domain}`)
  ));

  const signalList = Array.isArray(analysis?.signals) ? analysis.signals.map(s => String(s).toLowerCase()) : [];
  const hasBrandMismatch = signalList.some(s => s.includes("brand in subdomain") || s.includes("brandplacement") || s.includes("brand typosquatting"));
  const hasSuspiciousKeyword = signalList.some(s => s.includes("keyword") || s.includes("intent") || s.includes("login") || s.includes("verify") || s.includes("secure") || s.includes("update"));
  const hasHighRiskTLD = signalList.some(s => s.includes("tldriskhigh") || s.includes("high-risk tld"));
  const hasSuspiciousIndicators = hasBrandMismatch || hasSuspiciousKeyword || hasHighRiskTLD;

  // ── CRITICAL: Trusted domains are SAFE — no warning ──────────────────
  if (analysis.status === "safe" || isTrustedDomain) {
    console.log("[Sentinel AI] Signal: login_form");
    console.log("[Sentinel AI] Trusted: true");
    console.log("[Sentinel AI] Action: ignored");
    console.debug(`[Sentinel] ✅ Login form on trusted domain — skipping warning`);
    return;
  }

  const isSuspicious = analysis.status === "suspicious";
  const isLowTrust   = typeof analysis.trustScore === "number" && analysis.trustScore < 45;
  if (!isSuspicious && !isLowTrust) {
    console.log("[Sentinel AI] Signal: login_form");
    console.log(`[Sentinel AI] Trusted: ${isTrustedDomain}`);
    console.log("[Sentinel AI] Action: ignored");
    return;
  }

  if (!(hasPassword && !isTrustedDomain && hasSuspiciousIndicators)) {
    console.log("[Sentinel AI] Signal: login_form");
    console.log(`[Sentinel AI] Trusted: ${isTrustedDomain}`);
    console.log("[Sentinel AI] Action: ignored");
    return;
  }

  const fieldTypes = [
    hasPassword   && "password",
    hasOTP        && "OTP / verification code",
    hasCreditCard && "credit card",
    hasCVV        && "CVV / card security code",
  ].filter(Boolean);

  const fieldList  = fieldTypes.join(", ");
  const trustLabel = typeof analysis.trustScore === "number"
    ? `${analysis.trustScore}/100` : "unverified";

  // ── UPDATED MESSAGE (v2.1): Be specific about what we detected ────────
  let overlayMessage = "⚠️ Sensitive fields detected";
  if (hasPassword && !hasCreditCard && !hasCVV && !hasOTP) {
    // Only password field - use non-alarming message
    overlayMessage = "⚠️ Login form detected — verifying legitimacy...";
  } else if (hasCreditCard || hasCVV) {
    // Financial data - strong warning
    overlayMessage = "🚫 Financial data field on low-trust domain";
  }

  console.warn(`[Sentinel] Phishing UI Scanner: ${overlayMessage} (trust: ${trustLabel})`);
  console.log("[Sentinel AI] Signal: login_form");
  console.log(`[Sentinel AI] Trusted: ${isTrustedDomain}`);
  console.log("[Sentinel AI] Action: alerted");

  showOverlay(
    "suspicious",
    overlayMessage,
    [
      `This page is collecting: ${fieldList}`,
      `Domain trust score: ${trustLabel}`,
      hasFakeLogin ? "⚠️ Login form pattern detected" : "Sensitive field pattern confirmed",
      "Verify this is a legitimate site before submitting any data",
    ],
    analysis.trustScore ?? null,
    `Never enter ${fieldList} data unless certain of this site's identity. Legitimate companies will never ask for passwords via email.`,
    analysis?.breakdown || null,
    analysis?.aiReasoning || null,
    analysis?.finalRiskScore ?? null,
    analysis?.explanation || ""
  );

  // Emit phishing UI signal once per page-load.
  if (!_phishingUiAlertSent) {
    _phishingUiAlertSent = true;
    try {
      chrome.runtime.sendMessage({
        type:      "BEHAVIOR_ALERT",
        event:     "phishing_detected",
        severity:  hasFakeLogin ? "high" : "medium",
        confidence: hasFakeLogin ? "HIGH" : "MEDIUM",
        url:       location.href,
        details:   { hasPassword, hasOTP, hasCreditCard, hasCVV, hasFakeLogin },
        timestamp: Date.now(),
      }).catch(() => {});
    } catch {}
  }
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 8 — PERSONAL DATA PROTECTION  (Part 3)
// ══════════════════════════════════════════════════════════════════════
//
// Monitors actual keystrokes in sensitive fields in real time.
// Only activates on risky domains — silently no-ops on safe sites.
// Fires once per page load to avoid alert fatigue.

/** Matches exactly 16 digits with optional separating spaces or dashes. */
const _CARD_PATTERN = /^[\s\-]*(\d[\s\-]*){16}$/;

let _sensitiveAlertFired = false;
let _cachedPageAnalysis  = null; // shared with phishing scanner below

/**
 * Shows a real-time warning when sensitive data entry is detected.
 * @param {string} fieldType — e.g. "password", "credit card number"
 * @param {object|null} analysis
 */
function fireSensitiveDataAlert(fieldType, analysis) {
  if (_sensitiveAlertFired) return;
  _sensitiveAlertFired = true;

  const trustScore = analysis?.trustScore ?? null;
  const finalRisk = typeof analysis?.finalRiskScore === "number"
    ? analysis.finalRiskScore
    : (typeof trustScore === "number" ? (100 - trustScore) : 0);
  const isHighPriority = finalRisk >= 65 || (typeof trustScore === "number" && trustScore < 35);

  showOverlay(
    isHighPriority ? "malicious" : "suspicious",
    `${isHighPriority ? "HIGH PRIORITY" : "⚠️"} Entering ${fieldType} on a risky site`,
    [
      `You are typing ${fieldType} data on this page`,
      trustScore !== null ? `Domain trust score: ${trustScore}/100` : "Domain trust unverified",
      "Stop — verify this site before continuing",
    ],
    trustScore,
    trustScore !== null && trustScore < 30
      ? "This domain has a very low trust score. Stop immediately."
      : "Pause and verify the URL before submitting.",
    analysis?.breakdown || null,
    analysis?.aiReasoning || null,
    finalRisk,
    analysis?.explanation || ""
  );

  // Report to background — logged to history, contributes to reputation
  try {
    chrome.runtime.sendMessage({
      type:      "BEHAVIOR_ALERT",
      event:     "sensitive_data_entry",
      severity:  "high",
      url:       location.href,
      details:   { fieldType },
      timestamp: Date.now(),
    }).catch(() => {});
  } catch {}
}

/**
 * Attaches a delegated real-time input listener.
 * Only called when domain is already flagged as risky.
 * @param {object|null} analysis
 */
function monitorSensitiveInputs(analysis) {
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;

  const isRisky = analysis?.status === "suspicious" ||
                  (typeof analysis?.trustScore === "number" && analysis.trustScore < 45);
  if (!isRisky) return;

  document.addEventListener("input", (event) => {
    if (_sensitiveAlertFired) return;
    const el = event.target;
    if (!(el instanceof HTMLInputElement)) return;

    if (el.type === "password") {
      fireSensitiveDataAlert("password", analysis);
      return;
    }

    // Card number: 16 contiguous digits (spaces/dashes allowed)
    const raw = (el.value || "").replace(/[\s\-]/g, "");
    if (raw.length >= 16 && /^\d{16}$/.test(raw)) {
      const hint = `${el.autocomplete}${el.name}${el.id}`.toLowerCase();
      if (!/(phone|zip|postal|tel|fax)/.test(hint)) {
        fireSensitiveDataAlert("credit card number", analysis);
      }
    }
  }, { capture: true, passive: true });
}

// ══════════════════════════════════════════════════════════════════════
// SECTION 9 — INITIALIZATION
// ══════════════════════════════════════════════════════════════════════

(function initBehaviorDetection() {
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;

  // Fetch analysis once; share between phishing scanner and input monitor
  getPageAnalysis().then(analysis => {
    _cachedPageAnalysis = analysis;
    runPhishingUIScanner(analysis).catch(() => {});
    monitorSensitiveInputs(analysis);
  }).catch(() => {});

  // SPA re-scan: re-run phishing scanner when DOM changes significantly,
  // debounced to avoid hammering during rapid React/Vue renders.
  // Input monitor uses document-level delegation so it auto-covers new fields.
  let _rescanTimer = null;
  const _rescanObserver = new MutationObserver(() => {
    clearTimeout(_rescanTimer);
    _rescanTimer = setTimeout(() => {
      runPhishingUIScanner(_cachedPageAnalysis).catch(() => {});
    }, 1500);
  });

  const _root = document.body || document.documentElement;
  if (_root) _rescanObserver.observe(_root, { childList: true, subtree: true });
})();

// ══════════════════════════════════════════════════════════════════════
// SECTION 10 — ANTI-SCAM CONTENT SCANNER  (Part 3)
// ══════════════════════════════════════════════════════════════════════
//
// Scans the visible page text for scam/social-engineering keywords.
// Keywords are loaded from chrome.storage.local (placed there by
// background.js when it fetches threatIntel.json at startup).
//
// Fallback: a hardcoded minimal set is always available so the scanner
// works even before the background has written to storage.

/** Minimal built-in scam keywords — always available without storage read. */
const _BUILTIN_SCAM_KEYWORDS = [
  "you have won", "you won", "congratulations you",
  "free reward", "claim your reward",
  "free crypto", "free bitcoin",
  "urgent action required", "act immediately",
  "limited time offer", "offer expires today",
  "your account suspended", "account will be closed",
  "your device has virus", "malware detected",
  "call microsoft", "call apple support",
  // Advanced scam / fake support phrases (Phase 3 upgrade)
  "your system is infected", "your computer is infected",
  "call support now", "call tech support",
  "send bitcoin", "send btc", "pay with bitcoin",
  "wallet address", "crypto wallet",
  "make money fast", "earn from home",
  "lucky winner", "you are the winner",
];

let _scamScanDone = false;

/**
 * Extracts normalized visible text from the page body.
 * Skips script, style, and noscript nodes.
 * @returns {string}
 */
function getVisiblePageText() {
  const walker = document.createTreeWalker(
    document.body || document.documentElement,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        const parent = node.parentElement?.tagName?.toLowerCase();
        if (["script", "style", "noscript", "template"].includes(parent)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  const chunks = [];
  let node;
  while ((node = walker.nextNode())) {
    const t = node.textContent?.trim();
    if (t && t.length > 2) chunks.push(t);
    if (chunks.length > 400) break; // cap at ~400 text nodes for performance
  }
  return chunks.join(" ").toLowerCase();
}

/**
 * Scans page text against the loaded threat intel keyword list.
 * Shows overlay if a keyword is found on a low-trust/suspicious domain.
 *
 * @param {object|null} analysis — cached page analysis from background
 * @param {string[]} keywords  — combined built-in + storage keywords
 */
async function runScamContentScanner(analysis, keywords) {
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;
  if (_scamScanDone) return;

  // "Domain not trusted" = not a hard-override trusted root domain.
  const isTrustedRoot = analysis?.score === -5 && Array.isArray(analysis?.signals) &&
    analysis.signals.includes("Trusted domain");
  if (isTrustedRoot) return;

  // Wait for body to be available (called at document_idle so usually instant)
  if (!document.body) return;

  // Lightweight gating: if the site wasn't already risky, do a fast short scan first.
  const isRisky = analysis?.status === "suspicious" ||
                  (typeof analysis?.trustScore === "number" && analysis.trustScore < 55) ||
                  analysis?.status === "malicious";

  if (!isRisky) {
    const quick = String(document.body.innerText || "").toLowerCase().slice(0, 8000);
    const mustHave = ["you won", "free reward", "urgent action", "limited time"];
    if (!mustHave.some(p => quick.includes(p))) return;
  }

  const pageText = getVisiblePageText();
  if (!pageText) return;

  let matchedKeyword = null;
  for (const kw of keywords) {
    if (pageText.includes(kw.toLowerCase())) {
      matchedKeyword = kw;
      break;
    }
  }

  if (!matchedKeyword) return;
  _scamScanDone = true;

  const trustScore = analysis?.trustScore ?? null;

  showOverlay(
    "suspicious",
    "⚠️ Potential scam detected on this page",
    [
      `Scam phrase found: "${matchedKeyword}"`,
      trustScore !== null ? `Domain trust score: ${trustScore}/100` : "Domain trust unverified",
      "Do not provide personal information or make payments",
    ],
    trustScore,
    "Scam pages often use urgency, prize claims, or threat language to manipulate you. Close this page.",
    analysis?.breakdown || {
      "Domain Trust": "Not a trusted domain",
      "Behavior": "No suspicious behavior",
      "Content": `Scam keywords found: "${matchedKeyword}"`,
      "Technical": "No technical anomalies",
    }
  );

  // Report to background for history logging (Phase 3: scamAdvanced)
  try {
    chrome.runtime.sendMessage({
      type:      "BEHAVIOR_ALERT",
      event:     "scam_content_detected",
      severity:  "high",
      url:       location.href,
      details:   { keyword: matchedKeyword, scamAdvanced: true },
      timestamp: Date.now(),
    }).catch(() => {});
  } catch {}
}

// ── Initialization: load keywords from storage then scan ────────────────

(function initScamScanner() {
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;

  // Load dynamic keywords from storage + merge with built-ins
  chrome.storage.local.get("sentinel_threat_intel_keywords", (stored) => {
    const dynamic = Array.isArray(stored?.sentinel_threat_intel_keywords)
      ? stored.sentinel_threat_intel_keywords
      : [];
    // De-duplicate: built-ins first, then dynamic additions
    const allKeywords = [...new Set([..._BUILTIN_SCAM_KEYWORDS, ...dynamic])];

    // Reuse the cached analysis already fetched by initBehaviorDetection
    // (Section 9). In case it's not ready yet, do a fresh getPageAnalysis().
    const scanFn = (analysis) => runScamContentScanner(analysis, allKeywords).catch(() => {});

    if (_cachedPageAnalysis !== null) {
      scanFn(_cachedPageAnalysis);
    } else {
      getPageAnalysis().then(scanFn).catch(() => {});
    }
  });
})();


// ══════════════════════════════════════════════════════════════════════
// SECTION 10b — BASIC DEOBFUSCATOR FOR INLINE SCRIPTS (Part 3)
// ══════════════════════════════════════════════════════════════════════

function _decodeBase64Token(token) {
  try {
    const decoded = atob(token);
    return typeof decoded === "string" ? decoded.toLowerCase() : "";
  } catch {
    return "";
  }
}

function _decodeHexEscapes(text) {
  try {
    return String(text || "")
      .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .toLowerCase();
  } catch {
    return "";
  }
}

function _detectSuspiciousDecodedText(decodedText) {
  const normalized = String(decodedText || "").toLowerCase();
  if (!normalized) return "";

  const phrases = [
    "login", "verify", "password", "account suspended",
    "your system is infected", "call support now", "call tech support",
    "send bitcoin", "crypto wallet", "wallet address", "urgent action",
    ..._BUILTIN_SCAM_KEYWORDS,
  ];

  for (const p of phrases) {
    if (p && normalized.includes(String(p).toLowerCase())) return p;
  }
  return "";
}

function runScriptDeobfuscationScanner() {
  if (_decodedScriptAlertFired) return;
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;

  const scripts = Array.from(document.querySelectorAll("script")).slice(0, 60);
  let matched = "";

  for (const scriptEl of scripts) {
    const scriptText = String(scriptEl.textContent || "");
    if (!scriptText) continue;

    const base64Regex = /atob\(\s*["'`]([A-Za-z0-9+/=]{8,400})["'`]\s*\)/g;
    let b64;
    while ((b64 = base64Regex.exec(scriptText)) !== null) {
      const decoded = _decodeBase64Token(b64[1]);
      matched = _detectSuspiciousDecodedText(decoded);
      if (matched) break;
    }
    if (matched) break;

    const hexRegex = /(?:\\x[0-9a-fA-F]{2}){4,}/g;
    const hexHits = scriptText.match(hexRegex) || [];
    for (const h of hexHits) {
      const decodedHex = _decodeHexEscapes(h);
      matched = _detectSuspiciousDecodedText(decodedHex);
      if (matched) break;
    }
    if (matched) break;
  }

  if (!matched) return;
  _decodedScriptAlertFired = true;

  try {
    chrome.runtime.sendMessage({
      type: "BEHAVIOR_ALERT",
      event: "decoded_suspicious_content",
      severity: "high",
      url: location.href,
      details: { matchedText: matched },
      timestamp: Date.now(),
    }).catch(() => {});
  } catch {}
}

(function initScriptDeobfuscationScanner() {
  if (document.readyState === "complete" || document.readyState === "interactive") {
    runScriptDeobfuscationScanner();
  } else {
    window.addEventListener("DOMContentLoaded", () => runScriptDeobfuscationScanner(), { once: true });
  }
})();


// ══════════════════════════════════════════════════════════════════════
// SECTION 11 — NETWORK ACTIVITY MONITOR (Part 4)
// ══════════════════════════════════════════════════════════════════════

function _safeParseUrl(u) {
  try { return new URL(u, location.href); } catch { return null; }
}

function _getRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  const DOUBLE_TLDS = new Set([
    "co.uk", "co.in", "co.nz", "co.jp", "co.za",
    "com.au", "com.br", "com.sg", "com.my", "com.hk",
    "gov.uk", "gov.in", "gov.au", "gov.sg",
    "org.uk", "net.uk", "ac.uk", "edu.au",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  if (DOUBLE_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function _isUnknownDomain(requestHost) {
  const pageHost = location.hostname.toLowerCase();
  const pageRoot = _getRootDomain(pageHost);
  const reqRoot = _getRootDomain(String(requestHost || "").toLowerCase());
  return Boolean(reqRoot) && reqRoot !== pageRoot;
}

function _hasSuspiciousEndpoint(urlObj) {
  if (!urlObj) return false;
  const hay = `${urlObj.pathname || ""} ${urlObj.search || ""}`.toLowerCase();
  const markers = [
    "/support", "/tech-support", "/wallet", "/seed",
    "bitcoin", "crypto", "verify", "urgent", "claim", "gift",
  ];
  return markers.some(m => hay.includes(m));
}

function _isSuspiciousNetworkTarget(urlObj) {
  if (!urlObj) return false;
  return _isUnknownDomain(urlObj.hostname) || _hasSuspiciousEndpoint(urlObj);
}

function _sendNetworkAlert(requestUrl, reason = "unknown-domain") {
  if (_networkAlertSeen.size >= _MAX_NETWORK_ALERTS) return;
  const key = String(requestUrl || "").slice(0, 180);
  if (_networkAlertSeen.has(key)) return;
  _networkAlertSeen.add(key);
  try {
    chrome.runtime.sendMessage({
      type: "NETWORK_ALERT",
      url: requestUrl,
      reason,
      pageUrl: location.href,
    }).catch(() => {});
  } catch {}
}

function installPageNetworkBridge() {
  if (_pageNetworkBridgeInstalled) return;
  _pageNetworkBridgeInstalled = true;

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.type !== "SENTINEL_PAGE_NETWORK") return;
    const u = _safeParseUrl(data.url);
    if (!u || !_isSuspiciousNetworkTarget(u)) return;
    const reason = _isUnknownDomain(u.hostname) ? "unknown-domain" : "suspicious-endpoint";
    _sendNetworkAlert(u.href, reason);
  });

  try {
    const script = document.createElement("script");
    script.textContent = `
      (() => {
        if (window.__sentinel_page_net_hook_installed) return;
        window.__sentinel_page_net_hook_installed = true;
        const emit = (url, method) => {
          try {
            if (!url) return;
            const abs = new URL(String(url), location.href).href;
            window.postMessage({ type: "SENTINEL_PAGE_NETWORK", url: abs, method: method || "" }, "*");
          } catch {}
        };
        try {
          const originalFetch = window.fetch;
          if (typeof originalFetch === "function") {
            window.fetch = function(...args) {
              try {
                const req = args[0];
                const u = (typeof req === "string" || req instanceof URL) ? String(req) : (req && req.url ? String(req.url) : "");
                emit(u, "fetch");
              } catch {}
              return originalFetch.apply(this, args);
            };
          }
        } catch {}
        try {
          const xOpen = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            try { emit(url, method || "xhr"); } catch {}
            return xOpen.call(this, method, url, ...rest);
          };
        } catch {}
      })();
    `;
    (document.documentElement || document.head || document.body).appendChild(script);
    script.remove();
  } catch {}
}

function installNetworkMonitor() {
  if (_networkMonitorInstalled) return;
  if (["chrome-extension:", "chrome:", "about:"].includes(location.protocol)) return;
  _networkMonitorInstalled = true;
  installPageNetworkBridge();

  // fetch() monitor
  try {
    const origFetch = window.fetch;
    if (typeof origFetch === "function") {
      window.fetch = function (...args) {
        try {
          const u = _safeParseUrl(args[0]);
          if (u && _isSuspiciousNetworkTarget(u)) {
            const reason = _isUnknownDomain(u.hostname) ? "unknown-domain" : "suspicious-endpoint";
            _sendNetworkAlert(u.href, reason);
          }
        } catch {}
        return origFetch.apply(this, args);
      };
    }
  } catch {}

  // XMLHttpRequest monitor
  try {
    const OrigXHR = window.XMLHttpRequest;
    if (OrigXHR && OrigXHR.prototype) {
      const origOpen = OrigXHR.prototype.open;
      OrigXHR.prototype.open = function (method, url, ...rest) {
        try {
          const u = _safeParseUrl(url);
          if (u && _isSuspiciousNetworkTarget(u)) {
            const reason = _isUnknownDomain(u.hostname) ? "unknown-domain" : "suspicious-endpoint";
            _sendNetworkAlert(u.href, reason);
          }
        } catch {}
        return origOpen.call(this, method, url, ...rest);
      };
    }
  } catch {}

  // Initial external scripts already present on page
  try {
    const initialScripts = Array.from(document.querySelectorAll("script[src]")).slice(0, 50);
    for (const s of initialScripts) {
      const src = s.getAttribute("src");
      const u = _safeParseUrl(src);
      if (u && _isSuspiciousNetworkTarget(u)) {
        const reason = _isUnknownDomain(u.hostname) ? "unknown-domain" : "suspicious-endpoint";
        _sendNetworkAlert(u.href, reason);
      }
    }
  } catch {}

  // external script loads (DOM)
  try {
    const obs = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes || []) {
          if (!(node instanceof HTMLElement)) continue;
          const scripts = node.tagName === "SCRIPT" ? [node] : Array.from(node.querySelectorAll?.("script[src]") || []);
          for (const s of scripts) {
            const src = s.getAttribute("src");
            if (!src) continue;
            const u = _safeParseUrl(src);
            if (u && _isSuspiciousNetworkTarget(u)) {
              const reason = _isUnknownDomain(u.hostname) ? "unknown-domain" : "suspicious-endpoint";
              _sendNetworkAlert(u.href, reason);
            }
          }
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  } catch {}
}

(function initNetworkMonitor() {
  installNetworkMonitor();
})();

// ══════════════════════════════════════════════════════════════════════
// SECTION 12 — RUNTIME SCRIPT SANDBOXING
// ══════════════════════════════════════════════════════════════════════
//
// Intercepts dangerous runtime APIs to detect:
//   1. Obfuscated eval() calls — long code or code using atob()
//   2. External script injection — <script src> pointing off-domain
//   3. Suspicious fetch() targets — URL paths matching attack patterns
//
// Architecture note:
//   The eval hook runs in the MAIN world (injected via <script> tag) so it
//   intercepts the real window.eval before page scripts see it.
//   It communicates back via postMessage using a per-load nonce token,
//   identical to the behaviorMonitor.js probe pattern.
//   All final signal dispatch goes through reportSignal() → BEHAVIOR_ALERT.
//
// False-positive guards:
//   • Safe domains (google.com, christuniversity.in, etc.) skip all hooks
//   • eval size threshold: >1000 chars (minified bundles are common & benign)
//   • External scripts on the same root domain are NOT flagged
//   • Rate limit: max 5 sandboxing alerts per page load

// ── Guard: skip sandboxing on safe/extension pages ────────────────────
if (
  !["chrome-extension:", "chrome:", "about:"].includes(location.protocol) &&
  !["google.com", "youtube.com", "microsoft.com", "christuniversity.in",
    "github.com", "gstatic.com", "doubleclick.net", "googletagmanager.com",
  ].some(d => location.hostname === d || location.hostname.endsWith(`.${d}`))
) {

  // ── Nonce token for MAIN-world ↔ isolated-world postMessage ──────────
  const _SANDBOX_TOKEN = `sentinel-sandbox-${Math.random().toString(36).slice(2)}`;

  // ── Rate limiter ──────────────────────────────────────────────────────
  const _sandboxAlertCounts = Object.create(null);
  const _SANDBOX_RATE_LIMITS = {
    obfuscated_script:        3,
    external_script_injection: 5,
    suspicious_network_call:  4,
  };

  function _sandboxRateLimited(signal) {
    _sandboxAlertCounts[signal] = (_sandboxAlertCounts[signal] || 0) + 1;
    return _sandboxAlertCounts[signal] > (_SANDBOX_RATE_LIMITS[signal] ?? 3);
  }

  /**
   * Reports a runtime sandboxing signal to background.js via BEHAVIOR_ALERT.
   * Mirrors the reportBehavior() API in behaviorMonitor.js.
   *
   * @param {string} signal  — machine-readable signal identifier
   * @param {object} [details] — optional metadata
   */
  function reportSignal(signal, details = {}) {
    if (_sandboxRateLimited(signal)) return;

    console.warn(`[Sentinel-Sandbox] 🚨 Signal detected: ${signal}`, details);

    try {
      chrome.runtime.sendMessage({
        type:       "BEHAVIOR_ALERT",
        event:      signal,
        severity:   signal === "obfuscated_script" ? "high" : "medium",
        confidence: signal === "external_script_injection" ? "HIGH" : "MEDIUM",
        userInitiated: false,
        url:        location.href,
        details:    { ...details, domain: location.hostname },
        timestamp:  Date.now(),
      }).catch(() => {});
    } catch {
      // Extension context invalidated — best effort only.
    }
  }

  // ── 1. EVAL HOOK (MAIN world, via injected <script>) ─────────────────
  // We inject this into the MAIN world so it wraps window.eval before any
  // page script runs.  Communicates back via postMessage with _SANDBOX_TOKEN.
  (function installEvalHook() {
    const probeCode = `
(function(TOKEN) {
  "use strict";
  if (window.__sentinel_eval_hooked) return;
  window.__sentinel_eval_hooked = true;

  const _originalEval = window.eval;
  window.eval = function sentinelEval(code) {
    try {
      const src = String(code || "");
      // Flag if: code is very large (>1000 chars) OR uses atob() for obfuscation
      if (src.length > 1000 || src.includes("atob(")) {
        try {
          window.postMessage({
            _sentinelSandbox: TOKEN,
            signal: "obfuscated_script",
            details: {
              codeLength: src.length,
              hasAtob: src.includes("atob("),
              preview: src.slice(0, 120),
            },
          }, "*");
        } catch {}
      }
    } catch {}
    return _originalEval.call(this, code);
  };
  // Preserve toString() so feature-detection doesn't break
  window.eval.toString = () => _originalEval.toString();
})(${JSON.stringify(_SANDBOX_TOKEN)});
`.trim();

    try {
      const script = document.createElement("script");
      script.textContent = probeCode;
      (document.head || document.documentElement).appendChild(script);
      script.remove();
    } catch {
      // CSP blocks inline script injection — eval hook unavailable on this origin.
      console.debug("[Sentinel-Sandbox] eval hook blocked by CSP");
    }
  })();

  // ── Relay: receive postMessage signals from MAIN world eval hook ──────
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data._sentinelSandbox !== _SANDBOX_TOKEN) return;

    const { signal, details } = event.data;
    if (signal && typeof signal === "string") {
      reportSignal(signal, details || {});
    }
  }, { passive: true });

  // ── 2. EXTERNAL SCRIPT INJECTION OBSERVER ────────────────────────────
  // Watches for dynamically injected <script src="..."> elements where
  // the src points to a different root domain than the current page.
  // This catches post-load script injection (XSS, supply-chain attacks).
  (function installScriptInjectionObserver() {
    const pageRoot = _getRootDomain(location.hostname.toLowerCase());

    function checkScriptNode(node) {
      if (!(node instanceof HTMLScriptElement)) return;
      const src = node.getAttribute("src");
      if (!src) return; // inline scripts are handled by the eval hook

      const u = _safeParseUrl(src);
      if (!u) return;

      const srcRoot = _getRootDomain(u.hostname.toLowerCase());
      // Same root domain → legitimate (CDN subdomains, etc.)
      if (srcRoot && srcRoot === pageRoot) return;
      // Relative URL with no hostname → same origin → safe
      if (!u.hostname) return;

      reportSignal("external_script_injection", {
        src: src.slice(0, 200),
        srcDomain: u.hostname,
        pageDomain: location.hostname,
      });
    }

    const scriptObserver = new MutationObserver((mutations) => {
      for (const { addedNodes } of mutations) {
        for (const node of addedNodes) {
          if (node instanceof HTMLScriptElement) {
            checkScriptNode(node);
          } else if (node instanceof HTMLElement) {
            // Check descendant scripts (e.g., injected document fragment)
            node.querySelectorAll?.("script[src]")
              .forEach(s => checkScriptNode(s));
          }
        }
      }
    });

    scriptObserver.observe(document.documentElement, {
      childList: true,
      subtree:   true,
    });

    // Scan scripts already present at injection time
    document.querySelectorAll("script[src]")
      .forEach(s => checkScriptNode(s));
  })();

  // ── 3. SUSPICIOUS FETCH PATTERN MONITOR ──────────────────────────────
  // Supplements Section 11's network monitor with signal-specific detection:
  // catches fetch() calls whose URL string contains known attack path patterns
  // even when the domain itself looks clean (e.g. exfil via legit CDN).
  (function installSuspiciousFetchMonitor() {
    const _SUSPICIOUS_FETCH_PATTERNS = [
      "bitcoin", "crypto", "wallet", "seed-phrase",
      "exfil", "c2", "beacon",
      "/cmd", "/shell", "/exec",
    ];

    // Operate in isolated world — window.fetch here is the page's real fetch
    // (the MAIN-world hook in Section 11 already exists; this isolated-world
    // wrapper only adds the signal-specific path check without duplicating
    // the base network monitor logic).
    try {
      const _origFetchForSandbox = window.fetch;
      if (typeof _origFetchForSandbox === "function" &&
          !window.__sentinel_sandbox_fetch_hooked) {
        window.__sentinel_sandbox_fetch_hooked = true;

        window.fetch = function (...args) {
          try {
            const rawUrl = typeof args[0] === "string"
              ? args[0]
              : (args[0] instanceof URL ? args[0].href : (args[0]?.url || ""));
            const urlLower = rawUrl.toLowerCase();

            if (_SUSPICIOUS_FETCH_PATTERNS.some(p => urlLower.includes(p))) {
              reportSignal("suspicious_network_call", {
                url:     rawUrl.slice(0, 200),
                pattern: _SUSPICIOUS_FETCH_PATTERNS.find(p => urlLower.includes(p)),
              });
            }
          } catch {}
          return _origFetchForSandbox.apply(this, args);
        };
      }
    } catch {
      // fetch unavailable or already non-writable — skip
    }
  })();

} // end safe-domain guard
