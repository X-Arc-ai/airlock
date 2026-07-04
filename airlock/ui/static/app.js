/* Airlock UI — live event feed over SSE + TrustLedger read APIs. Vanilla JS. */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const feedEl = $('feed'), feedEmpty = $('feed-empty'), flashEl = $('flash');
  const connEl = $('conn'), connLabel = $('conn-label');
  const qListEl = $('q-list'), qCountEl = $('q-count'), srcListEl = $('src-list');
  const sliderEl = $('replay-slider'), liveBtn = $('live-btn');
  const replayTsEl = $('replay-ts'), asofTagEl = $('asof-tag');
  const srcPanel = $('panel-sources');

  const state = {
    screened: 0,
    quarantined: 0,
    replay: false,
    minTs: null,          // ms epoch — left edge of the replay slider
    flashTimer: null,
    replayDebounce: null,
    replaySeq: 0,
  };

  const FEED_CAP = 120;

  // ------------------------------------------------------------- helpers

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function fmtTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return isNaN(d) ? '' : d.toLocaleTimeString('en-GB');
  }

  function fmtFull(ts) {
    const d = new Date(ts);
    if (isNaN(d)) return String(ts);
    return d.toLocaleDateString('en-GB', { month: 'short', day: 'numeric' })
      + ' ' + d.toLocaleTimeString('en-GB');
  }

  function trunc(s, n) {
    s = String(s ?? '');
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(url + ' -> ' + r.status);
    return r.json();
  }

  // -------------------------------------------------------------- counters

  function bumpCounters(quarantined) {
    state.screened += 1;
    if (quarantined) state.quarantined += 1;
    $('n-screened').textContent = state.screened;
    $('n-quarantined').textContent = state.quarantined;
  }

  // ----------------------------------------------------------------- feed

  // Highlight the exact malicious span inside the content preview.
  function previewHTML(preview, span) {
    if (!preview) return { html: '', spanShown: false };
    if (span && preview.includes(span)) {
      const i = preview.indexOf(span);
      return {
        html: esc(preview.slice(0, i)) + '<mark>' + esc(span) + '</mark>'
          + esc(preview.slice(i + span.length)),
        spanShown: true,
      };
    }
    return { html: esc(preview), spanShown: false };
  }

  function verdictCardHTML(v, ts) {
    const q = String(v.decision || '').toLowerCase() === 'quarantine';
    const preview = v.content_preview ?? v.preview ?? v.content ?? '';
    const span = v.malicious_span || '';
    const { html: prevHtml, spanShown } = previewHTML(preview, span);
    const pct = Math.round(Math.max(0, Math.min(1, Number(v.confidence) || 0)) * 100);
    const family = v.threat_family && v.threat_family !== 'none' ? v.threat_family : '';

    let h = '<div class="card-top">';
    h += `<span class="badge ${q ? 'badge-q' : 'badge-a'}">${q ? 'QUARANTINED' : 'ALLOWED'}</span>`;
    h += `<span class="src">${esc(v.source || 'unknown')}</span>`;
    if (family) h += `<span class="family">${esc(family)}</span>`;
    h += `<span class="time">${fmtTime(ts)}</span></div>`;

    if (v.reason) h += `<p class="reason">${esc(v.reason)}</p>`;
    if (prevHtml) h += `<div class="preview">${prevHtml}</div>`;
    if (span && !spanShown) {
      h += `<div class="evidence"><span class="evidence-k">span</span><mark>${esc(trunc(span, 220))}</mark></div>`;
    }
    h += '<div class="card-meta">';
    h += `<span class="conf"><span class="conf-bar"><i style="width:${pct}%"></i></span>${pct}% confidence</span>`;
    if (v.model) h += `<span class="model">${esc(v.model)}</span>`;
    h += '</div>';
    return { html: h, quarantined: q };
  }

  function genericCardHTML(e) {
    const kind = (e.kind || 'event').toUpperCase();
    const body = e.reason || e.detail || e.message || '';
    let h = '<div class="card-top">';
    h += `<span class="badge badge-e">${esc(kind)}</span>`;
    if (e.source || e.host) h += `<span class="src">${esc(e.source || e.host)}</span>`;
    h += `<span class="time">${fmtTime(e.ts)}</span></div>`;
    if (body) h += `<p class="reason">${esc(body)}</p>`;
    return h;
  }

  function addCard(e, opts) {
    opts = opts || {};

    // Proxy / gateway events nest the Verdict under `verdict` with the body
    // in `preview` — flatten so they render as full verdict cards too.
    if (e.decision === undefined && e.verdict && e.verdict.decision !== undefined) {
      e = Object.assign({}, e.verdict, {
        ts: e.ts ?? e.verdict.ts,
        source: e.verdict.source || e.source,
        content_preview: e.content_preview ?? e.preview ?? e.verdict.content_preview,
      });
    }

    const card = document.createElement('article');
    let quarantined = false;

    if (e.decision !== undefined) {
      const built = verdictCardHTML(e, e.ts);
      card.className = 'card ' + (built.quarantined ? 'card-q' : 'card-a');
      card.innerHTML = built.html;
      quarantined = built.quarantined;
      bumpCounters(quarantined);
    } else {
      card.className = 'card card-e';
      card.innerHTML = genericCardHTML(e);
    }

    if (feedEmpty) feedEmpty.classList.add('hidden');
    feedEl.prepend(card);
    while (feedEl.querySelectorAll('.card').length > FEED_CAP) {
      feedEl.lastElementChild.remove();
    }

    if (quarantined && !opts.backfill) {
      flash(e);
      refreshRail();
    }
  }

  // ---------------------------------------------------------------- flash

  function flash(v) {
    const fam = v.threat_family && v.threat_family !== 'none' ? v.threat_family : '';
    $('flash-family').textContent = fam;
    flashEl.classList.remove('show');
    void flashEl.offsetWidth;  // restart the CSS animation
    flashEl.classList.add('show');
    clearTimeout(state.flashTimer);
    state.flashTimer = setTimeout(() => flashEl.classList.remove('show'), 1600);
  }

  // ----------------------------------------------------------------- rail

  function renderQuarantines(list) {
    qCountEl.textContent = list.length;
    if (!list.length) {
      qListEl.innerHTML = '<div class="empty">Nothing captured.</div>';
      return;
    }
    qListEl.innerHTML = list.slice(0, 30).map((x) => {
      let h = '<div class="q-item"><div class="q-top">';
      h += `<span class="q-family">${esc(x.threat_family || 'unknown')}</span>`;
      h += `<span class="time">${fmtTime(x.ts)}</span></div>`;
      h += `<div class="q-src">${esc(x.source || '')}</div>`;
      if (x.malicious_span) {
        h += `<div class="q-span"><mark>${esc(trunc(x.malicious_span, 110))}</mark></div>`;
      }
      return h + '</div>';
    }).join('');
  }

  function renderSources(list) {
    if (!list.length) {
      srcListEl.innerHTML = '<div class="empty">No sources yet.</div>';
      return;
    }
    srcListEl.innerHTML = list.map((s) => {
      const name = s.name ?? s.source ?? '?';
      const trusted = (s.trust || '') === 'trusted';
      const title = s.reason ? ` title="${esc(s.reason)}"` : '';
      return `<div class="src-item ${trusted ? 'trusted' : 'revoked'}"${title}>`
        + '<span class="src-dot"></span>'
        + `<span class="src-name">${esc(name)}</span>`
        + `<span class="src-state">${trusted ? 'trusted' : 'revoked'}</span></div>`;
    }).join('');
    // Track the earliest first_seen for the replay slider's left edge.
    for (const s of list) {
      const t = Date.parse(s.first_seen || s.since || '');
      if (!isNaN(t) && (state.minTs === null || t < state.minTs)) state.minTs = t;
    }
  }

  async function refreshRail() {
    try {
      renderQuarantines(await getJSON('/api/quarantine'));
      if (!state.replay) renderSources(await getJSON('/api/sources'));
    } catch (err) { /* server briefly away; SSE reconnect will retrigger */ }
  }

  // --------------------------------------------------------------- replay

  function replayBounds() {
    const now = Date.now();
    const min = state.minTs !== null ? Math.min(state.minTs, now - 1000) : now - 3600 * 1000;
    return { min, max: now };
  }

  function onSlider() {
    const val = Number(sliderEl.value);
    if (val >= 1000) { goLive(); return; }
    state.replay = true;
    liveBtn.classList.remove('is-live');
    srcPanel.classList.add('replaying');
    const { min, max } = replayBounds();
    const t = new Date(min + (max - min) * (val / 1000));
    replayTsEl.textContent = fmtFull(t);
    asofTagEl.textContent = 'as of ' + t.toLocaleTimeString('en-GB');
    asofTagEl.classList.remove('hidden');
    clearTimeout(state.replayDebounce);
    state.replayDebounce = setTimeout(async () => {
      const seq = ++state.replaySeq;
      try {
        const rows = await getJSON('/api/asof?ts=' + encodeURIComponent(t.toISOString()));
        if (seq === state.replaySeq && state.replay) renderSources(rows);
      } catch (err) { /* ignore mid-drag errors */ }
    }, 130);
  }

  function goLive() {
    state.replay = false;
    state.replaySeq++;
    sliderEl.value = 1000;
    liveBtn.classList.add('is-live');
    srcPanel.classList.remove('replaying');
    asofTagEl.classList.add('hidden');
    replayTsEl.textContent = 'now';
    getJSON('/api/sources').then(renderSources).catch(() => {});
  }

  sliderEl.addEventListener('input', onSlider);
  liveBtn.addEventListener('click', goLive);

  // --------------------------------------------------------------- policy

  function chips(items, cls) {
    return `<div class="chips">${items.map((x) => `<span class="chip ${cls}">${esc(x)}</span>`).join('')}</div>`;
  }

  async function loadPolicy() {
    try {
      const p = await getJSON('/api/policy');
      $('policy-body').innerHTML =
        `<div class="pol-group"><div class="pol-k">allowed hosts</div>${chips(p.allowlist_hosts || [], 'chip-allow')}</div>`
        + `<div class="pol-group"><div class="pol-k">denied paths</div>${chips(p.deny_paths || [], 'chip-deny')}</div>`
        + `<div class="pol-group"><div class="pol-k">secret filters</div>${chips(p.secret_patterns || [], '')}</div>`;
    } catch (err) {
      $('policy-body').innerHTML = '<div class="empty">Policy unavailable.</div>';
    }
  }

  // -------------------------------------------------------------- backfill

  async function backfill() {
    try {
      const rows = await getJSON('/api/recent?limit=30');
      const screens = rows.filter((r) => r.event === 'screen' && r.verdict);
      screens.reverse(); // newest-first -> oldest-first, so prepend keeps order
      for (const r of screens) {
        const v = Object.assign({}, r.verdict);
        v.ts = r.trust_granted_at;
        addCard(v, { backfill: true });
      }
      const t = Date.parse(screens.length ? screens[0].trust_granted_at : '');
      if (!isNaN(t) && (state.minTs === null || t < state.minTs)) state.minTs = t;
    } catch (err) { /* empty ledger is fine */ }
  }

  // ------------------------------------------------------------------ SSE

  function setConn(mode) {
    connEl.className = 'conn ' + mode;
    connLabel.textContent = mode === 'live' ? 'live' : (mode === 'down' ? 'reconnecting' : 'connecting');
  }

  function connect() {
    const es = new EventSource('/events');
    es.onopen = () => setConn('live');
    es.onerror = () => setConn('down');
    es.onmessage = (m) => {
      let e;
      try { e = JSON.parse(m.data); } catch (err) { return; }
      if (!e || typeof e !== 'object') return;
      if (e.kind === 'hello') { setConn('live'); return; }
      if (!e.ts) e.ts = new Date().toISOString();
      addCard(e);
    };
  }

  // ----------------------------------------------------------------- init

  (async function init() {
    setConn('');
    await Promise.allSettled([loadPolicy(), backfill(), refreshRail()]);
    connect();
  })();
})();
