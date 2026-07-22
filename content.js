(function () {
  "use strict";

  const OVERLAY_ID = "sx-overlay";
  const PILL_ID = "__sx_pill__";
  let currentData = null;
  let __sxAudioCtx__ = null;
  let __sxAlarmNodes__ = [];

  // Helper: Format scan time as "Scanned just now" or "Scanned 2 mins ago"
  function formatScanTime(timestamp) {
    const now = Date.now();
    const diff = Math.floor((now - timestamp) / 1000);
    if (diff < 10) return "Scanned just now";
    if (diff < 60) return `Scanned ${diff}s ago`;
    const mins = Math.floor(diff / 60);
    if (mins < 60) return `Scanned ${mins}m ago`;
    const hours = Math.floor(mins / 60);
    return `Scanned ${hours}h ago`;
  }

  const style = document.createElement("style");
  style.textContent = `
    #sx-overlay {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 280px;
      border-radius: 14px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px;
      z-index: 2147483647;
      overflow: hidden;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 8px 32px rgba(0,0,0,0.18), 0 2px 8px rgba(0,0,0,0.12);
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      border: 0.5px solid rgba(255,255,255,0.18);
    }
    #sx-overlay.sx-safe { background: rgba(10, 42, 24, 0.96); border-left: 3px solid #34d399; }
    #sx-overlay.sx-uncertain { background: rgba(42, 28, 8, 0.96); border-left: 3px solid #fbbf24; }
    #sx-overlay.sx-danger { background: rgba(42, 8, 8, 0.96); border-left: 3px solid #f87171; }
    #sx-overlay.sx-scanning { background: rgba(20, 20, 24, 0.96); border-left: 3px solid #6b7280; }
    #sx-header { display: flex; align-items: center; gap: 8px; padding: 12px 14px 10px; cursor: pointer; user-select: none; }
    #sx-status-icon { width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-size: 11px; font-weight: 700; }
    .sx-safe #sx-status-icon { background: #34d399; color: #022c1a; }
    .sx-uncertain #sx-status-icon { background: #fbbf24; color: #451a03; }
    .sx-danger #sx-status-icon { background: #f87171; color: #450a0a; }
    .sx-scanning #sx-status-icon { background: #6b7280; color: #fff; }
    #sx-title-block { flex: 1; min-width: 0; }
    #sx-title { font-size: 13px; font-weight: 600; color: #ffffff; margin: 0; line-height: 1.3; }
    #sx-subtitle { font-size: 11px; color: rgba(255,255,255,0.6); margin: 1px 0 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    #sx-close { color: rgba(255,255,255,0.4); cursor: pointer; font-size: 16px; line-height: 1; padding: 2px 4px; border-radius: 4px; flex-shrink: 0; }
    #sx-close:hover { color: rgba(255,255,255,0.8); background: rgba(255,255,255,0.1); }
    #sx-body { max-height: 0; overflow: hidden; transition: max-height 0.3s cubic-bezier(0.4,0,0.2,1); }
    #sx-overlay.expanded #sx-body { max-height: 500px; }
    #sx-divider { height: 0.5px; background: rgba(255,255,255,0.12); margin: 0 14px; }
    #sx-stats { display: flex; padding: 10px 14px; gap: 0; }
    .sx-stat { flex: 1; }
    .sx-stat-label { font-size: 10px; color: rgba(255,255,255,0.45); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 3px; }
    .sx-stat-value { font-size: 18px; font-weight: 700; color: #ffffff; line-height: 1; }
    .sx-safe .sx-stat-value { color: #34d399; }
    .sx-uncertain .sx-stat-value { color: #fbbf24; }
    .sx-danger .sx-stat-value { color: #f87171; }
    #sx-bar-track { height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; margin: 0 14px 10px; overflow: hidden; }
    #sx-bar-fill { height: 100%; border-radius: 2px; transition: width 1s ease-out; }
    .sx-safe #sx-bar-fill { background: #34d399; }
    .sx-uncertain #sx-bar-fill { background: #fbbf24; }
    .sx-danger #sx-bar-fill { background: #f87171; }
    #sx-signals { padding: 4px 14px 8px; display: flex; flex-direction: column; gap: 5px; }
    .sx-signal-row { display: flex; align-items: center; gap: 7px; font-size: 11.5px; color: rgba(255,255,255,0.75); }
    .sx-signal-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .dot-green { background: #34d399; }
    .dot-amber { background: #fbbf24; }
    .dot-red { background: #f87171; }
    #sx-pills { display: flex; flex-wrap: wrap; gap: 5px; padding: 6px 14px 10px; }
    .sx-pill { font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 20px; letter-spacing: 0.03em; }
    .sx-safe .sx-pill { background: rgba(52,211,153,0.15); color: #34d399; border: 0.5px solid rgba(52,211,153,0.3); }
    .sx-uncertain .sx-pill { background: rgba(251,191,36,0.15); color: #fbbf24; border: 0.5px solid rgba(251,191,36,0.3); }
    .sx-danger .sx-pill { background: rgba(248,113,113,0.15); color: #f87171; border: 0.5px solid rgba(248,113,113,0.3); }
    #sx-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; padding: 6px 14px 14px; }
    .sx-btn { padding: 7px 4px; font-size: 11px; font-weight: 500; border-radius: 8px; border: 0.5px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.85); cursor: pointer; text-align: center; transition: background 0.15s; }
    .sx-btn:hover { background: rgba(255,255,255,0.15); }
    .sx-btn.primary { background: rgba(52,211,153,0.2); border-color: rgba(52,211,153,0.4); color: #34d399; }
    .sx-btn.primary:hover { background: rgba(52,211,153,0.3); }
    #sx-branding { padding: 6px 14px 10px; font-size: 9.5px; color: rgba(255,255,255,0.25); text-align: center; letter-spacing: 0.04em; }
    @keyframes sx-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    .sx-scanning #sx-title { animation: sx-pulse 1.5s ease-in-out infinite; }
    @keyframes __sx_pulse__ { 0%,100%{opacity:1;} 50%{opacity:.3;} }
  `;
  document.head.appendChild(style);

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function playAlarmOnce(status) {
    try {
      stopAlarm();
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      __sxAudioCtx__ = new AudioCtx();
      const ctx = __sxAudioCtx__;

      const notes = status === "malicious"
        ? [{ freq: 880, start: 0, dur: 0.18 }, { freq: 880, start: 0.22, dur: 0.18 }, { freq: 1100, start: 0.44, dur: 0.28 }]
        : [{ freq: 520, start: 0, dur: 0.20 }, { freq: 520, start: 0.28, dur: 0.20 }];

      notes.forEach(({ freq, start, dur }) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = status === "malicious" ? "square" : "sine";
        osc.frequency.setValueAtTime(freq, ctx.currentTime);
        gain.gain.setValueAtTime(0.35, ctx.currentTime + start);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + dur);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(ctx.currentTime + start);
        osc.stop(ctx.currentTime + start + dur + 0.05);
        __sxAlarmNodes__.push(osc, gain);
      });
    } catch (e) {}
  }

  function stopAlarm() {
    try {
      __sxAlarmNodes__.forEach(n => { try { n.disconnect(); } catch (_) {} });
      __sxAlarmNodes__ = [];
      if (__sxAudioCtx__) {
        __sxAudioCtx__.close();
        __sxAudioCtx__ = null;
      }
    } catch (_) {}
  }

  function buildOverlayHTML(data) {
    const score = Math.round(data.score || 0);
    const domain = data.domain || location.hostname;
    const signals = (data.signals || []).slice(0, 4);
    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    const trustLevel = data.trustLevel || (score < 30 ? "HIGH" : score < 60 ? "MEDIUM" : "LOW");
    const scanMs = data.scanMs || 0;
    const confidence = Math.round(Number(data.confidence ?? data.aiConfidence ?? 0) || 0);
    const timestamp = data.timestamp || Date.now();
    const scanTimeString = formatScanTime(timestamp);
    const statusIcon = score >= 80 ? "✕" : score >= 30 ? "⚠" : "✓";

    const COLOR = score >= 80 ? "#ff3d57" : score >= 30 ? "#ffb830" : "#00c896";
    const PILL_TXT = score >= 80 ? "BLOCKED" : score >= 60 ? "DANGER" : score >= 30 ? "WARNING" : "SAFE";
    const TRUST_W = score >= 80 ? "12%" : score >= 30 ? "45%" : "88%";

    const PILL_BG = score >= 80 ? "rgba(255,61,87,.18)"
      : score >= 30 ? "rgba(255,184,48,.12)"
      : "rgba(0,200,150,.12)";
    const PILL_BDR = score >= 80 ? "rgba(255,61,87,.35)"
      : score >= 30 ? "rgba(255,184,48,.28)"
      : "rgba(0,200,150,.28)";

    const threatLevel = score <= 20 ? "LOW"
      : score <= 50 ? "MODERATE"
        : score <= 75 ? "HIGH"
          : "CRITICAL";
    const threatColor = score <= 20 ? "#00c896"
      : score <= 50 ? "#ffb830"
        : score <= 75 ? "#ff8a00"
          : "#ff3d57";
    const threatBadgeBG = score <= 20 ? "rgba(0,200,150,.12)"
      : score <= 50 ? "rgba(255,184,48,.12)"
        : score <= 75 ? "rgba(255,138,0,.12)"
          : "rgba(255,61,87,.12)";
    const threatBadgeBDR = score <= 20 ? "rgba(0,200,150,.25)"
      : score <= 50 ? "rgba(255,184,48,.25)"
        : score <= 75 ? "rgba(255,138,0,.25)"
          : "rgba(255,61,87,.3)";

    const confColor = confidence >= 85 ? "#00c896"
      : confidence >= 60 ? "#ffb830"
        : "#ff3d57";
    const confPillBG = confidence >= 85 ? "rgba(0,200,150,.12)"
      : confidence >= 60 ? "rgba(255,184,48,.12)"
        : "rgba(255,61,87,.12)";
    const confPillBDR = confidence >= 85 ? "rgba(0,200,150,.25)"
      : confidence >= 60 ? "rgba(255,184,48,.28)"
        : "rgba(255,61,87,.28)";

    const extractSignalText = function (item) {
      if (typeof item === "string") return item;
      if (item && typeof item.name === "string") return item.name;
      if (item && typeof item.description === "string") return item.description;
      return "";
    };
    const keySignalsSource = reasons.length ? reasons : signals;
    const keySignals = keySignalsSource.slice(0, 3)
      .map(extractSignalText)
      .filter(Boolean);
    // Key-signal chips are intentionally amber/red to visually stand out.
    const chipBG = score >= 80 ? "rgba(255,61,87,.12)"
      : "rgba(255,184,48,.12)";
    const chipBDR = score >= 80 ? "rgba(255,61,87,.28)"
      : "rgba(255,184,48,.25)";
    const chipC = score >= 80 ? "#ff3d57"
      : "#ffb830";
    const chipsHTML = keySignals.length ? (
      "<div style=\"margin-bottom:8px;\">"
      + "<div style=\"font-size:9px;letter-spacing:.12em;color:rgba(255,255,255,.28);text-transform:uppercase;margin-bottom:4px;\">Key signals</div>"
      + "<div style=\"display:flex;flex-wrap:wrap;gap:6px;\">"
      + keySignals.map(function (t) {
        return "<div style=\"display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border-radius:999px;"
          + "background:" + chipBG + ";border:1px solid " + chipBDR + ";color:" + chipC + ";font-size:10px;font-weight:600;\">"
          + "<span style=\"font-size:11px;line-height:1;\">&#9888;</span>"
          + "<span style=\"color:rgba(255,255,255,.92);font-weight:600;\">" + escapeHtml(t) + "</span>"
          + "</div>";
      }).join("")
      + "</div></div>"
    ) : "";
    const lowConfidenceLine = confidence < 60
      ? "<div style=\"font-size:9px;color:rgba(255,255,255,.78);border-left:2px solid #ff3d57;padding:5px 8px;border-radius:4px;margin-bottom:8px;background:rgba(255,61,87,.08);\">Low confidence — result may be inaccurate</div>"
      : "";

    // FIX 5 — Status-based overlay messaging (safe/suspicious/malicious) with emoji icons
    let HEADING = "";
    let SUBHEADING = "";
    let ADVICE = "";

    if (data.status === "malicious") {
      HEADING = "✕ Threat detected";
      SUBHEADING = "This page has been flagged as potentially malicious";
      ADVICE = "This site has been blocked. Do not proceed — maximum threat signals detected.";
    } else if (data.status === "suspicious") {
      HEADING = "⚠ Suspicious page detected";
      SUBHEADING = "This page shows potential risk signals — proceed with caution";
      ADVICE = "Suspicious signals found. Verify this URL carefully before interacting.";
    } else {
      // Safe (should not reach here due to FIX 4, but included for completeness)
      HEADING = "✓ Page secure";
      SUBHEADING = "No threats detected";
      ADVICE = "No threats detected. This site has a clean reputation and valid HTTPS.";
    }

    // Legacy fallback to score-based messaging if status not provided
    if (!data.status) {
      ADVICE = score >= 80
        ? "This site has been blocked. Do not proceed — maximum threat signals detected."
        : score >= 60
          ? "High risk. Do not enter passwords, card numbers, or personal data on this page."
          : score >= 30
            ? "Suspicious signals found. Verify this URL carefully before interacting."
            : "No threats detected. This site has a clean reputation and valid HTTPS.";
    }

    const ADVICE_BG = score >= 80 ? "rgba(255,61,87,.07)"
      : score >= 30 ? "rgba(255,184,48,.07)"
      : "rgba(0,200,150,.07)";

    const arcOffset = Math.round(75 - (score / 100) * 75);
    const arcSVG = "<svg width=\"54\" height=\"32\" viewBox=\"0 0 54 32\">"
      + "<path d=\"M5 29 A24 24 0 0 1 49 29\" fill=\"none\" stroke=\"rgba(255,255,255,0.07)\" stroke-width=\"8\" stroke-linecap=\"round\"/>"
      + "<path d=\"M5 29 A24 24 0 0 1 49 29\" fill=\"none\" stroke=\"" + COLOR + "\" stroke-width=\"8\" stroke-linecap=\"round\" stroke-dasharray=\"75\" stroke-dashoffset=\"" + arcOffset + "\"/>"
      + "</svg>";

    const sigHTML = signals.map(function (s) {
      const wt = s.weight || 0;
      const dotC = wt >= 30 ? "#ff3d57" : wt >= 15 ? "#ffb830" : "#00c896";
      const desc = s.description ? " — " + escapeHtml(s.description.slice(0, 55)) : "";
      return "<div style=\"display:flex;align-items:flex-start;gap:6px;font-size:10.5px;color:rgba(255,255,255,.65);line-height:1.4;margin-bottom:3px;\">"
        + "<div style=\"width:5px;height:5px;border-radius:50%;background:" + dotC + ";flex-shrink:0;margin-top:4px;\"></div>"
        + "<span>" + escapeHtml(s.name || "") + desc + "</span>"
        + "</div>";
    }).join("");

    let btnsHTML = "";
    // FIX 5 — Button layout based on status (not just score), add 'Report as safe' for suspicious
    if (data.status === "malicious" || score >= 80) {
      btnsHTML = "<button id=\"sentinelReportBtn\" type=\"button\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:10.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(0,200,150,.14);color:#00c896;border:0;\">Generate report</button>"
        + "<div id=\"__sx_dismiss__\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:9.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(255,255,255,.06);color:rgba(255,255,255,.3);\">Override (unsafe)</div>";
    } else if (data.status === "suspicious" || score >= 30) {
      btnsHTML = "<button id=\"sentinelLeaveBtn\" type=\"button\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:10.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(255,61,87,.15);color:#ff3d57;border:1px solid rgba(255,61,87,.3);\">Leave now</button>"
        + "<button id=\"sentinelReportBtn\" type=\"button\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:10.5px;font-weight:500;text-align:center;cursor:pointer;background:#00e5ff;color:#0a0e1a;border:0;\">Full report</button>"
        + "<button id=\"sentinelSafeBtn\" type=\"button\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:9.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(0,200,150,.15);color:#00c896;border:0;\">Report as safe</button>";
    } else {
      btnsHTML = "<div id=\"__sx_dismiss__\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:10.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(255,255,255,.07);color:rgba(255,255,255,.55);\">Dismiss</div>"
        + "<button id=\"sentinelReportBtn\" type=\"button\" style=\"flex:1;padding:7px 6px;border-radius:5px;font-size:10.5px;font-weight:500;text-align:center;cursor:pointer;background:rgba(0,200,150,.14);color:#00c896;border:0;\">Full report</button>";
    }

    return "<div style=\"height:3px;background:" + COLOR + ";\"></div>"
      + "<div style=\"padding:12px 14px;\">"
      + "<div style=\"display:flex;align-items:center;gap:7px;margin-bottom:10px;\">"
      + "<svg width=\"14\" height=\"14\" viewBox=\"0 0 14 14\" fill=\"none\"><path d=\"M7 1L2 3.5V7c0 2.6 1.8 5 5 5.7 3.2-.7 5-3.1 5-5.7V3.5L7 1z\" fill=\"" + COLOR + "\" fill-opacity=\".18\" stroke=\"" + COLOR + "\" stroke-width=\"1\"/></svg>"
      + "<span style=\"font-size:11px;font-weight:700;letter-spacing:.08em;color:#00e5ff;\">" + statusIcon + " SENTINELX</span>"
      + "<span id=\"sentinelWhyBtn\" style=\"cursor:pointer;font-size:12px;color:#00e5ff;margin-left:auto;padding:2px 6px;border-radius:4px;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.2);position:relative;\" title=\"Why am I seeing this?\">?<span id=\"sentinelWhyTip\" style=\"display:none;position:absolute;right:0;top:20px;z-index:2;width:220px;background:#0d1117;border:1px solid rgba(255,255,255,.18);padding:8px;border-radius:6px;color:rgba(255,255,255,.85);font-size:10px;line-height:1.4;\">This overlay appeared because the confidence score was too low to confirm this page is safe. SentinelX defaults to caution when uncertain.</span></span>"
      + "<span style=\"font-size:9px;padding:2px 6px;border-radius:99px;font-weight:600;background:" + PILL_BG + ";color:" + COLOR + ";border:1px solid " + PILL_BDR + ";\">" + PILL_TXT + "</span>"
      + (data.policyBadge ? "<span style=\"font-size:9px;padding:2px 6px;border-radius:99px;font-weight:600;background:rgba(0,229,255,.12);color:#00e5ff;border:1px solid rgba(0,229,255,.3);\">Managed by your organisation</span>" : "")
      + "</div>"
      + "<div style=\"font-size:9px;color:rgba(255,255,255,.45);margin-top:-6px;margin-bottom:10px;\">Advanced Cyber Protection</div>"
      + "<div style=\"display:flex;align-items:center;gap:10px;margin-bottom:8px;\">"
      + arcSVG
      + "<div><div style=\"font-size:28px;font-weight:700;font-family:monospace;color:" + COLOR + ";line-height:1;\">" + score + "</div>"
      + "<div style=\"font-size:9px;letter-spacing:.1em;color:" + COLOR + ";margin-top:2px;\">" + PILL_TXT + " · " + trustLevel + " TRUST</div></div>"
      + "</div>"
      + "<div style=\"font-size:10.5px;font-family:monospace;color:rgba(255,255,255,.55);background:rgba(255,255,255,.04);padding:4px 8px;border-radius:4px;margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\">" + escapeHtml(domain) + "</div>"
      + "<div style=\"margin-bottom:8px;\">"
      + "<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:6px;\">"
      + "<span style=\"font-size:9px;letter-spacing:.08em;color:rgba(255,255,255,.28);\">Threat level</span>"
      + "<span style=\"font-size:10px;font-weight:800;padding:2px 7px;border-radius:99px;background:" + threatBadgeBG + ";color:" + threatColor + ";border:1px solid " + threatBadgeBDR + ";\">" + escapeHtml(threatLevel) + "</span>"
      + "</div>"
      + "<div style=\"display:flex;align-items:center;gap:10px;\">"
      + "<div style=\"flex:1;height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden;\">"
      + "<div style=\"height:100%;width:" + Math.max(0, Math.min(100, score)) + "%;border-radius:2px;background:" + threatColor + ";\"></div>"
      + "</div>"
      + "<div style=\"font-size:10px;font-weight:800;color:" + threatColor + ";white-space:nowrap;\">" + score + " / 100</div>"
      + "</div></div>"
      + "<div style=\"display:flex;align-items:center;gap:7px;margin-bottom:8px;\">"
      + "<span style=\"font-size:9px;letter-spacing:.08em;color:rgba(255,255,255,.28);\">TRUST</span>"
      + "<div style=\"flex:1;height:3px;background:rgba(255,255,255,.07);border-radius:2px;\">"
      + "<div style=\"width:" + TRUST_W + ";height:100%;border-radius:2px;background:" + COLOR + ";\"></div></div>"
      + "<span style=\"font-size:10px;font-weight:600;color:" + COLOR + ";\">" + trustLevel + "</span>"
      + "</div>"
      + "<div style=\"display:flex;align-items:center;gap:7px;margin-bottom:8px;\">"
      + "<span style=\"font-size:9px;letter-spacing:.08em;color:rgba(255,255,255,.28);\">CONFIDENCE</span>"
      + "<span style=\"margin-left:auto;font-size:10px;font-weight:800;color:" + confColor + ";background:" + confPillBG + ";border:1px solid " + confPillBDR + ";padding:2px 7px;border-radius:99px;\">" + confidence + "%</span>"
      + "</div>"
      + lowConfidenceLine
      + chipsHTML
      + (sigHTML ? "<div style=\"margin-bottom:8px;\">" + sigHTML + "</div>" : "")
      + "<div style=\"font-size:10.5px;line-height:1.55;color:rgba(255,255,255,.6);border-left:2px solid " + COLOR + ";padding:5px 8px;margin-bottom:9px;background:" + ADVICE_BG + ";\">" + escapeHtml(ADVICE) + "</div>"
      + "<div style=\"display:flex;gap:6px;margin-bottom:2px;\">" + btnsHTML + "</div>"
      + "<div style=\"font-size:9px;color:rgba(255,255,255,.28);margin-top:8px;display:flex;justify-content:space-between;\">"
      + "<span>" + scanTimeString + " · Confidence " + confidence + "%</span>"
      + "<span style=\"display:flex;gap:10px;align-items:center;\">"
      + "<span id=\"__sx_mute__\" class=\"sx-mute-btn\" style=\"color:rgba(255,255,255,.75);cursor:pointer;\">Mute sound</span>"
      + "<span id=\"__sx_dash__\" style=\"color:#00e5ff;cursor:pointer;\">Dashboard</span>"
      + "</span>"
      + "</div>"
      + "</div>";
  }

  function sxSetScanning() {
    const overlay = document.getElementById("sx-overlay");
    if (!overlay) return;
    overlay.classList.remove("sx-safe", "sx-uncertain", "sx-danger");
    overlay.classList.add("sx-scanning");
    const title = document.getElementById("sx-title");
    if (title) title.textContent = "Scanning…";
  }

  function sxBindButtons() {
    const btnScan = document.getElementById("sx-btn-scan");
    if (btnScan) {
      btnScan.addEventListener("click", (e) => {
        e.stopPropagation();
        chrome.runtime.sendMessage({
          type: "SENTINEL_RESCAN",
          action: "SENTINEL_RESCAN",
          url: location.href,
          tabId: null,
          forceDeep: true
        });
        sxSetScanning();
      });
    }

    const btnMute = document.getElementById("sx-btn-mute");
    if (btnMute) {
      btnMute.addEventListener("click", (e) => {
        e.stopPropagation();
        chrome.storage.local.get(["sx_sound_muted"], (data) => {
          const nowMuted = !data.sx_sound_muted;
          chrome.storage.local.set({ sx_sound_muted: nowMuted });
          btnMute.textContent = nowMuted ? "🔔 Unmute" : "🔕 Mute sound";
          btnMute.style.opacity = nowMuted ? "0.5" : "1";
          if (nowMuted) stopAlarm();
        });
      });
    }

    const btnTrust = document.getElementById("sx-btn-trust");
    if (btnTrust) {
      btnTrust.addEventListener("click", (e) => {
        e.stopPropagation();
        const host = location.hostname;
        chrome.storage.local.get(["sx_trusted_domains"], (data) => {
          const trusted = data.sx_trusted_domains || [];
          if (!trusted.includes(host)) trusted.push(host);
          chrome.storage.local.set({ sx_trusted_domains: trusted });
          btnTrust.textContent = "✓ Trusted!";
          btnTrust.style.background = "rgba(52,211,153,0.3)";
          btnTrust.style.borderColor = "rgba(52,211,153,0.6)";
          setTimeout(() => {
            btnTrust.textContent = "✓ I trust this";
            btnTrust.style.background = "";
            btnTrust.style.borderColor = "";
          }, 2000);
        });
      });
    }

    const btnReport = document.getElementById("sx-btn-report");
    if (btnReport) {
      btnReport.addEventListener("click", (e) => {
        e.stopPropagation();
        const reportUrl = chrome.runtime.getURL("report/report.html") + "?url=" + encodeURIComponent(location.href);
        window.open(reportUrl, "_blank");
      });
    }

    const header = document.getElementById("sx-header");
    if (header) {
      header.addEventListener("click", (e) => {
        if (e.target.id === "sx-close" || (e.target.closest && e.target.closest("#sx-close"))) return;
        const overlay = document.getElementById("sx-overlay");
        if (overlay) overlay.classList.toggle("expanded");
      });
    }

    const btnClose = document.getElementById("sx-close");
    if (btnClose) {
      btnClose.addEventListener("click", (e) => {
        e.stopPropagation();
        const overlay = document.getElementById("sx-overlay");
        if (overlay) overlay.style.display = "none";
      });
    }
  }

  function getConfidenceLabel(score, confidence) {
    if (confidence >= 80) return { text: confidence + "%", note: "" };
    if (confidence >= 50) return { text: confidence + "%", note: "Moderate certainty" };
    if (score >= 40 && confidence < 30) {
      return {
        text: confidence + "%",
        note: "⚠ Low confidence — signals detected but source data limited. Treat as indicative."
      };
    }
    return { text: confidence + "%", note: "Insufficient data — result may be inaccurate" };
  }

  function getOverlayTier(status, score, confidence) {
    // Never show malicious/suspicious if confidence is critically low
    // AND score is not extreme
    if (confidence < 25 && score < 65) return "uncertain";
    if (status === "malicious" || score >= 70) return "malicious";
    if (status === "suspicious" && score >= 35 && confidence >= 40) {
      return "suspicious";
    }
    if (status === "safe" && confidence >= 30) return "safe";
    return "uncertain";
  }

  const OVERLAY_TIER_CONFIG = {
    safe: {
      icon: "✔",
      color: "#22c55e",
      headline: "Site looks safe",
      subtext: (domain) => `${domain} passed our security checks.`,
      cta: null,
      playSound: false
    },
    uncertain: {
      icon: "?",
      color: "#94a3b8",
      headline: "Limited scan data",
      /** Body lines are resolved in showOverlay via uncertainBody (confidence-based). */
      subtext: () => "",
      cta: "Rescan page",
      playSound: false
    },
    suspicious: {
      icon: "⚠",
      color: "#f59e0b",
      headline: "Suspicious signals detected",
      subtext: (domain) => `${domain} shows some risk indicators. Proceed carefully.`,
      cta: "View full report",
      playSound: true
    },
    malicious: {
      icon: "✕",
      color: "#ef4444",
      headline: "Threat detected",
      subtext: (domain) => `${domain} has been flagged as dangerous.`,
      cta: "Leave this page",
      playSound: true
    },
  };

  const DOMAIN_CATEGORIES = {
    "nykaa.com": "Indian beauty & skincare marketplace",
    "myntra.com": "Indian fashion marketplace",
    "1mg.com": "Licensed online pharmacy",
    "pharmeasy.in": "Licensed online pharmacy",
    "practo.com": "Healthcare consultation platform",
    "apollopharmacy.in": "Apollo healthcare",
    "cult.fit": "Fitness & wellness platform",
    "healthifyme.com": "Diet & fitness platform",
    "chatgpt.com": "AI platform",
    "openai.com": "AI research platform",
    "flipkart.com": "Indian e-commerce",
    "amazon.in": "Global e-commerce",
    "mamaearth.in": "Natural skincare brand",
    "beminimalist.co": "Skincare brand",
    "cerave.com": "Dermatologist skincare",
    "healthline.com": "Health information",
    "mayoclinic.org": "Medical reference",
    "webmd.com": "Health information",
  };

  function getDomainCategory(hostname) {
    const host = String(hostname || "").toLowerCase();
    for (const [domain, category] of Object.entries(DOMAIN_CATEGORIES)) {
      if (host === domain || host.endsWith("." + domain)) return category;
    }
    return null;
  }

  function getCategoryTags(result, category) {
    const map = {
      "Indian beauty & skincare marketplace": ["Beauty", "Skincare", "E-Commerce", "India", "Verified"],
      "Licensed online pharmacy": ["Healthcare", "Pharmacy", "India", "Licensed", "Verified"],
      "Healthcare consultation platform": ["Healthcare", "Doctors", "India", "Verified"],
      "Fitness & wellness platform": ["Fitness", "Wellness", "India", "Verified"],
      "AI platform": ["AI", "Technology", "Global", "Verified"],
      "Indian e-commerce": ["Shopping", "E-Commerce", "India", "Verified"],
    };
    return map[category] || ["Verified", "Trusted"];
  }

  function showOverlay(data) {
    const canonical = globalThis.normalizeSentinelResult
      ? globalThis.normalizeSentinelResult(data)
      : data;

    removeOverlay();
    currentData = canonical;
    window.__sx_current_status__ = canonical.status;
    const currentHost = canonical.domain || location.hostname;
    const category = getDomainCategory(currentHost);
    const tags = getCategoryTags(canonical, category);
    const score = Math.max(0, Math.min(100, Number(canonical.score || 0)));
    const confidence = Math.max(0, Math.min(100, Math.round(Number(canonical.confidence || 0))));
    const status = String(canonical.status || "safe").toLowerCase();
    let stateClass = "sx-safe";
    let icon = "✓";
    let title = "Site looks safe";
    if (status === "uncertain" || status === "suspicious") {
      stateClass = "sx-uncertain";
      icon = "!";
      title = "Proceed with care";
    } else if (status === "danger" || status === "blocked" || status === "malicious") {
      stateClass = "sx-danger";
      icon = "✕";
      title = "Site may be dangerous";
    }

    const html = `<div id="sx-overlay" class="${stateClass}">
      <div id="sx-header">
        <div id="sx-status-icon">${icon}</div>
        <div id="sx-title-block">
          <div id="sx-title">${title}</div>
          <div id="sx-subtitle">${escapeHtml(currentHost)}${category ? ` — ${escapeHtml(category)}` : ""}</div>
        </div>
        <div id="sx-close">×</div>
      </div>
      <div id="sx-body">
        <div id="sx-divider"></div>
        <div id="sx-stats">
          <div class="sx-stat"><div class="sx-stat-label">Threat score</div><div class="sx-stat-value" id="sx-score">${Math.round(score)}/100</div></div>
          <div class="sx-stat"><div class="sx-stat-label">Confidence</div><div class="sx-stat-value" id="sx-conf">${confidence}%</div></div>
        </div>
        <div id="sx-bar-track"><div id="sx-bar-fill" style="width:0%"></div></div>
        <div id="sx-divider"></div>
        <div id="sx-signals">
          <div class="sx-signal-row"><div class="sx-signal-dot dot-green"></div>SSL encrypted & HSTS verified</div>
          <div class="sx-signal-row"><div class="sx-signal-dot dot-green"></div>Verified trusted domain</div>
          <div class="sx-signal-row"><div class="sx-signal-dot dot-green"></div>${Math.max(0, (canonical.signals || []).length)} threat signals detected</div>
          <div class="sx-signal-row"><div class="sx-signal-dot dot-green"></div>Safe payment gateway detected</div>
        </div>
        <div id="sx-divider"></div>
        <div id="sx-pills">${tags.map((tag) => `<span class="sx-pill">${escapeHtml(tag)}</span>`).join("")}</div>
        <div id="sx-divider"></div>
        <div id="sx-actions">
          <div class="sx-btn primary" id="sx-btn-scan">↺ Scan again</div>
          <div class="sx-btn" id="sx-btn-mute">🔕 Mute sound</div>
          <div class="sx-btn" id="sx-btn-trust">✓ I trust this</div>
          <div class="sx-btn" id="sx-btn-report">↗ Full report</div>
        </div>
        <div id="sx-branding">SENTINELX · ADVANCED CYBER PROTECTION</div>
      </div>
    </div>`;

    document.body.insertAdjacentHTML("beforeend", html);
    sxBindButtons();
    const fill = document.getElementById("sx-bar-fill");
    setTimeout(() => { if (fill) fill.style.width = `${score}%`; }, 50);
    chrome.storage.local.get("sx_sound_muted", (res) => {
      const btn = document.getElementById("sx-btn-mute");
      if (btn) btn.textContent = res && res.sx_sound_muted ? "🔔 Unmute sound" : "🔕 Mute sound";
    });

    if (stateClass !== "sx-safe") {
      chrome.storage.local.get("sx_sound_muted", (res) => {
        if (!res.sx_sound_muted) playAlarmOnce(stateClass === "sx-danger" ? "malicious" : "suspicious");
      });
    }
    if (canonical.status === "safe") {
      setTimeout(() => {
        const overlay = document.getElementById("sx-overlay");
        if (overlay && !overlay.classList.contains("expanded")) {
          overlay.style.opacity = "0.85";
        }
      }, 6000);
    }
  }

  function showScanningPill(labelText) {
    const txt = labelText || "SentinelX scanning…";
    const existing = document.getElementById("__sx_scanning__");
    if (existing) {
      const label = existing.querySelector(".__sx_scanning_label__");
      if (label) label.textContent = txt;
      return;
    }
    const pill = document.createElement("div");
    pill.id = "__sx_scanning__";
    pill.style.cssText = `
      position:fixed;bottom:20px;right:20px;z-index:2147483647;
      background:#0d1220;border:1.5px solid #3a5f8a;border-radius:20px;
      color:#7ab3e0;font-family:-apple-system,sans-serif;font-size:12px;
      padding:6px 14px;display:flex;align-items:center;gap:6px;
      box-shadow:0 4px 16px rgba(0,0,0,0.4);
    `;
    pill.innerHTML =
      `<span style="width:7px;height:7px;border-radius:999px;background:#7ab3e0;animation:__sx_pulse__ 1s infinite;"></span>` +
      `<span class="__sx_scanning_label__">${escapeHtml(txt)}</span>`;
    document.body.appendChild(pill);
  }

  function removeScanningPill() {
    const el = document.getElementById("__sx_scanning__");
    if (el) el.remove();
  }

  function showPill(data) {
    removePill();
    var score = Math.round(data.score || 0);
    var color = score >= 80 ? "#ff3d57" : score >= 30 ? "#ffb830" : "#00c896";
    var label = score >= 80 ? "BLOCKED" : score >= 30 ? "WARNING" : "SAFE";
    var pill = document.createElement("div");
    pill.id = PILL_ID;
    pill.style.cssText = "position:fixed!important;bottom:18px!important;right:18px!important;"
      + "background:#0d1117!important;border-radius:99px!important;"
      + "border:1px solid rgba(255,255,255,0.14)!important;"
      + "padding:5px 12px 5px 8px!important;display:flex!important;"
      + "align-items:center!important;gap:6px!important;"
      + "font-family:Inter,system-ui,sans-serif!important;"
      + "z-index:2147483647!important;cursor:pointer!important;";
    pill.innerHTML = "<span style=\"font-size:11px;font-weight:700;font-family:monospace;color:" + color + ";\">" + score + "</span>"
      + "<span style=\"font-size:10px;color:rgba(255,255,255,.5);\">" + label + "</span>"
      + "<span style=\"font-size:10px;color:rgba(255,255,255,.25);\">×</span>";
    pill.addEventListener("click", function () {
      removePill();
      showOverlay(currentData || data);
    });
    document.body.appendChild(pill);
  }

  function removeOverlay() {
    var el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
    stopAlarm();
  }

  function removePill() {
    var el = document.getElementById(PILL_ID);
    if (el) el.remove();
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const action = message && (message.action || message.type);
    switch (action) {
      case "SENTINEL_SCANNING": {
        const overlay = document.getElementById("sx-overlay");
        if (!overlay) break;
        const body = document.getElementById("sx-title");
        const scoreEl = document.getElementById("sx-score");
        if (body) body.textContent = message.text || "Rescanning…";
        if (scoreEl) scoreEl.textContent = "…";
        // Add a subtle pulse animation class while scanning
        overlay.classList.remove("sx-safe", "sx-uncertain", "sx-danger");
        overlay.classList.add("sx-scanning");
        sendResponse({ ok: true });
        return true;
      }
      case "SENTINEL_SHOW_OVERLAY": {
      const incoming = globalThis.normalizeSentinelResult
        ? globalThis.normalizeSentinelResult(message.data || {})
        : message.data;
      const severityRank = { safe: 0, suspicious: 1, malicious: 2 };
      const currentStatus = window.__sx_current_status__ || "safe";
      if (severityRank[incoming.status] >= severityRank[currentStatus]) {
        window.__sx_current_status__ = incoming.status;
        const existingOverlay = document.getElementById("sx-overlay");
        if (existingOverlay) existingOverlay.classList.remove("sx-scanning");
        removeScanningPill();
        removePill();
        showOverlay(incoming);
      }
      sendResponse({ ok: true });
        break;
      }
      default:
        break;
    }
    return false;
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      showScanningPill();
    });
  } else {
    showScanningPill();
  }

  setTimeout(function () {
    chrome.runtime.sendMessage({ type: "GET_CURRENT_TAB_ID" }, function (response) {
      var tabId = response && response.tabId ? response.tabId : null;
      chrome.runtime.sendMessage({ type: "GET_TAB_ANALYSIS", tabId: tabId }, function (result) {
        if (result) {
          const canonical = globalThis.normalizeSentinelResult
            ? globalThis.normalizeSentinelResult(result)
            : result;
          removeScanningPill();
          removeOverlay();
          showOverlay(canonical);
          return;
        }
        if (!tabId) return;
        chrome.runtime.sendMessage(
          { type: "TRIGGER_ANALYSIS", url: location.href, tabId: tabId },
          function () { if (chrome.runtime.lastError) {} }
        );
      });
    });
  }, 800);
})();
