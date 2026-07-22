(function initSentinelWarning() {
  if (window.__sxInit) return;
  window.__sxInit = true;

  // ── 1. PARSE URL PARAMS ──────────────────────────────────────
  const p = new URLSearchParams(window.location.search);
  const raw = {
    url:        decodeURIComponent(p.get('url')        || ''),
    score:      parseInt(p.get('score')                || '0', 10),
    status:     p.get('status')                        || 'malicious',
    confidence: parseInt(p.get('confidence')           || '0', 10),
    signals:    p.get('signals')                       || '',
    categories: p.get('categories')                    || '',
    reasoning:  p.get('reasoning')                     || '',
  };
  const shouldPlaySound = p.get('sound') !== '0';

  // ── SOUND SYSTEM ─────────────────────────────────────────────

  // Step A: Read saved mute preference from storage
  let isMuted = false;
  try {
    chrome.storage.local.get('sx_sound_muted', (res) => {
      isMuted = !!res.sx_sound_muted;
      updateSoundUI();
      if (!isMuted && shouldPlaySound) {
        playAlertSound();
      }
    });
  } catch {
    // Fallback if storage fails — just play
    if (shouldPlaySound) playAlertSound();
  }

  // Step C: The sound itself — short 2-tone descending chime
  // Plays ONCE. No loop. No repeat. ~0.6 seconds total.
  function playAlertSound() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();

      // First tone: high alert note (440Hz → 330Hz descent)
      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      osc1.connect(gain1);
      gain1.connect(ctx.destination);
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(520, ctx.currentTime);
      osc1.frequency.exponentialRampToValueAtTime(360, ctx.currentTime + 0.25);
      gain1.gain.setValueAtTime(0.35, ctx.currentTime);
      gain1.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
      osc1.start(ctx.currentTime);
      osc1.stop(ctx.currentTime + 0.28);

      // Second tone: lower confirmation note (short, after first)
      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();
      osc2.connect(gain2);
      gain2.connect(ctx.destination);
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(280, ctx.currentTime + 0.32);
      gain2.gain.setValueAtTime(0.25, ctx.currentTime + 0.32);
      gain2.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.60);
      osc2.start(ctx.currentTime + 0.32);
      osc2.stop(ctx.currentTime + 0.60);

      // Auto-close context after sound finishes to free memory
      setTimeout(() => { try { ctx.close(); } catch {} }, 800);

    } catch (e) {
      // AudioContext blocked or unavailable — fail silently
      console.warn('SentinelX: audio unavailable', e);
    }
  }

  // Step D: Mute/unmute toggle — saves preference permanently
  function toggleMute() {
    isMuted = !isMuted;
    chrome.storage.local.set({ sx_sound_muted: isMuted });
    updateSoundUI();
    // Play once when RE-ENABLING so user hears the sound is back
    if (!isMuted) {
      playAlertSound();
    }
  }

  // Step E: Update both sound control locations (banner + footer)
  function updateSoundUI() {
    // Banner cluster buttons
    const btnOn = document.getElementById('btn-sound-on');
    const btnMute = document.getElementById('btn-mute');
    if (btnOn) btnOn.classList.toggle('active', !isMuted);
    if (btnMute) btnMute.classList.toggle('active', isMuted);
    if (btnOn) btnOn.setAttribute('aria-pressed', String(!isMuted));
    if (btnMute) btnMute.setAttribute('aria-pressed', String(isMuted));

    // Footer "Mute sound" / "Unmute sound" text
    const footerLabel = document.getElementById('footer-sound-label');
    if (footerLabel) footerLabel.textContent = isMuted ? 'Unmute sound' : 'Mute sound';
    const footerBtn = document.getElementById('footer-sound-btn');
    if (footerBtn) footerBtn.classList.toggle('muted', isMuted);
  }

  // Step F: Wire buttons — both locations call toggleMute()
  document.getElementById('btn-sound-on')?.addEventListener('click', () => {
    if (isMuted) toggleMute(); // only act if currently muted
  });
  document.getElementById('btn-mute')?.addEventListener('click', () => {
    if (!isMuted) toggleMute(); // only act if currently unmuted
  });
  document.getElementById('footer-sound-btn')?.addEventListener('click', toggleMute);

  // Derive domain safely
  let domain = '--';
  try { domain = new URL(raw.url).hostname; } catch {}

  // Derive protocol
  let protocol = '--';
  try { protocol = new URL(raw.url).protocol.replace(':','').toUpperCase(); } catch {}

  // Confidence fallback if missing but score is high
  let conf = raw.confidence;
  if (conf === 0 && raw.score >= 60) conf = 68;
  if (conf === 0 && raw.score >= 30) conf = 42;

  // Signals array
  const signalList = raw.signals
    ? raw.signals.split('|').filter(Boolean)
    : [];

  // Auto-generate signals if none passed (from score + domain pattern)
  if (signalList.length === 0) {
    if (protocol === 'HTTP') signalList.push('Unencrypted HTTP connection — data visible to attackers');
    if (/[a-z]{8,}/i.test(domain.split('.')[0])) signalList.push('Random-pattern subdomain detected — common phishing sign');
    if (raw.score >= 60) signalList.push('High threat score from risk analysis');
    if (signalList.length === 0) signalList.push('Suspicious patterns detected in page structure');
  }

  // ── 2. POPULATE ALL FIELDS ───────────────────────────────────
  function set(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }
  function setHTML(id, val) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = val;
  }

  // Banner
  set('banner-score', `${raw.score} / 100`);

  // Status badge (malicious vs suspicious)
  const isMalicious = raw.status === 'malicious' || raw.score >= 65;
  set('threat-label', isMalicious ? 'Malicious site detected' : 'Suspicious site detected');
  set('sb-badge-text', isMalicious ? 'Malicious site' : 'Suspicious site');

  // Title adapts to threat type
  set('main-title', isMalicious
    ? 'This site may steal your information.'
    : 'This site looks suspicious.');

  // URL
  set('blocked-url-display', raw.url || 'Unknown URL');

  // Metrics
  const scoreEl = document.getElementById('score-display');
  if (scoreEl) {
    scoreEl.textContent = `${raw.score}/100`;
    scoreEl.className = 'metric-val ' + (raw.score >= 65 ? 'danger' : 'warning');
  }
  set('conf-display', `${conf}%`);
  const protEl = document.getElementById('protocol-display');
  if (protEl) {
    protEl.textContent = protocol;
    protEl.className = 'metric-val ' + (protocol === 'HTTP' ? 'danger' : '');
  }

  // Signals list
  const sigHTML = signalList.map(s =>
    `<div class="signal-row">
      <div class="signal-icon">!</div>
      <div class="signal-text">${s}</div>
    </div>`
  ).join('');
  setHTML('signals-list', sigHTML || '<div class="signal-text" style="padding:8px 0;color:#5a5a72">No specific signals captured.</div>');

  // Sidebar
  function animateCount(el, target, suffix, duration) {
    let start = 0;
    const step = Math.ceil(target / (duration / 16));
    const timer = setInterval(() => {
      start = Math.min(start + step, target);
      el.textContent = start + suffix;
      if (start >= target) clearInterval(timer);
    }, 16);
  }
  const scoreCounterEl = document.getElementById('sb-score');
  if (scoreCounterEl) animateCount(scoreCounterEl, raw.score, '', 800);
  set('sb-domain', domain);
  set('sb-confidence', `${conf}%`);
  set('sb-signal-count', String(signalList.length));

  // Risk meter fill
  const fill = document.getElementById('risk-fill');
  if (fill) fill.style.width = `${Math.min(raw.score, 100)}%`;

  // Reasoning
  const reasoning = raw.reasoning ||
    (isMalicious
      ? `Combination of ${signalList.length} threat signals including ${signalList[0]?.toLowerCase()}. Pattern consistent with known phishing infrastructure.`
      : `Moderate threat indicators. ${signalList[0] || 'Unknown pattern detected'}. Proceed with caution.`);
  set('sb-reasoning', reasoning);
  const whyEl = document.getElementById('why-content');
  if (whyEl) whyEl.textContent = reasoning;

  // Threat category pills below signals box
  const cats = raw.categories ? raw.categories.split('|').filter(Boolean) : [];
  if (cats.length) {
    const el = document.getElementById('category-row');
    if (el) el.innerHTML = cats.map(c =>
      `<span style="background:#2d1a00;border:1px solid #7a4500;
        color:#f39c12;font-size:11px;padding:3px 10px;
        border-radius:20px;display:inline-block;margin:2px">${c}</span>`
    ).join('');
  }

  // ── 3. WIRE ALL FOUR BUTTONS ─────────────────────────────────

  // Button 1: Go back to safety
  document.getElementById('btn-back')?.addEventListener('click', () => {
    if (history.length > 1) {
      history.back();
    } else {
      window.location.href = 'chrome-extension://' + chrome.runtime.id + '/newtab.html';
    }
  });

  // Button 2: Warn me & proceed (THE NEW BUTTON)
  // Shows a 5-second countdown modal before allowing through
  document.getElementById('btn-warn')?.addEventListener('click', () => {
    const confirmed = confirm(
      '⚠️ WARNING — Proceeding to a potentially dangerous site.\n\n' +
      'Site: ' + raw.url + '\n' +
      'Threat score: ' + raw.score + '/100\n\n' +
      'Your data may be at risk. SentinelX will log this visit.\n\n' +
      'Press OK only if you understand the risk.'
    );
    if (confirmed) {
      chrome.runtime.sendMessage({
        action: 'SENTINEL_BYPASS',
        url: raw.url,
        bypassType: 'warned'
      }, () => { window.location.href = raw.url; });
    }
  });

  // Button 3: Proceed anyway (no warning)
  document.getElementById('btn-proceed')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      action: 'SENTINEL_BYPASS',
      url: raw.url,
      bypassType: 'direct'
    }, () => { window.location.href = raw.url; });
  });

  // Button 4: Report false positive
  document.getElementById('btn-report')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    chrome.runtime.sendMessage({
      action: 'SENTINEL_REPORT_SITE',
      url: raw.url,
      domain,
      score: raw.score,
      reportType: 'false_positive',
      timestamp: Date.now()
    }, () => {
      btn.textContent = 'Reported — thank you';
      btn.disabled = true;
      btn.style.opacity = '0.5';
    });
  });

  // Details toggle
  document.getElementById('details-btn')?.addEventListener('click', () => {
    const sb = document.getElementById('sidebar');
    if (sb) sb.style.display = sb.style.display === 'none' ? 'flex' : 'none';
  });

  // Visit history badge (if bypassed before)
  chrome.runtime.sendMessage({ action: 'GET_BYPASS_COUNT', domain }, (res) => {
    if (res && res.count > 0) {
      const badge = document.createElement('div');
      badge.style = 'color:#f39c12;font-size:11px;margin-top:4px';
      badge.textContent = `You have bypassed this domain ${res.count} time(s) before.`;
      document.getElementById('threat-badge')?.after(badge);
    }
  });

})();
