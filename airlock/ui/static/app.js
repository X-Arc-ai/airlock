/* Airlock UI — "Instrument" skin. Vanilla JS bound to the live TrustLedger API.
 * No framework, no external requests. Ported behavior from the design mockup:
 *   - segmented control: All-clear | Live | Replay
 *   - Live feed backfilled from /api/recent + prepended live via SSE /events
 *   - Sources & Trust Replay scrubber: 100 = live, <100 = as-of a past instant
 *     (mapped across [earliest known event … now]), driving /api/asof
 *   - Quarantine + Policy rail panels
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  // ------------------------------------------------------------- state

  const state = {
    scrub: 100,          // 0-100, 100 == live
    allClear: false,
    events: [],           // verdict-shaped rows, newest first
    quarantines: [],       // quarantine_log rows, newest first
    sourcesCache: [],       // last /api/sources fetch (live trust state)
    asofCache: [],          // last /api/asof fetch (replay trust state)
    domainStart: Date.now() - 3600 * 1000, // left edge of the replay scrubber (ms)
  };

  let debounceTimer = null;
  let replaySeq = 0;

  // ------------------------------------------------------------- helpers

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function fmtHM(ts) {
    const d = new Date(ts);
    if (isNaN(d)) return '--:--';
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    return h + ':' + m;
  }

  async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(url + ' -> ' + r.status);
    return r.json();
  }

  function isLive() { return state.scrub >= 99; }
  function isPast() { return !state.allClear && !isLive(); }

  function computeScrubMs() {
    const now = Date.now();
    const start = Math.min(state.domainStart, now - 1000);
    return start + (now - start) * (state.scrub / 100);
  }

  // Wraps the malicious_span inside the content preview with the .flag
  // highlight; falls back gracefully when the preview/span aren't both known.
  function flaggedReceiptHTML(preview, span) {
    if (preview && span && preview.includes(span)) {
      const i = preview.indexOf(span);
      return esc(preview.slice(0, i)) + '<span class="flag">' + esc(span) + '</span>'
        + esc(preview.slice(i + span.length));
    }
    if (span) return '<span class="flag">' + esc(span) + '</span>';
    if (preview) return esc(preview);
    return '<span style="color:var(--mute-soft)">no content preview captured</span>';
  }

  // ---------------------------------------------------------- row templates

  function feedRowHTML(e, i) {
    const isQ = String(e.decision).toLowerCase() === 'quarantine';
    const reveal = (i === 0 && isQ && e._live) ? ' reveal' : '';
    const badge = isQ
      ? '<span style="display:inline-flex;align-items:center;gap:9px"><span style="width:9px;height:9px;background:var(--ink);display:inline-block"></span><span style="font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink);font-weight:500">Quarantined</span></span>'
      : '<span style="display:inline-flex;align-items:center;gap:9px"><span style="width:9px;height:9px;border:1px solid var(--mute);display:inline-block"></span><span style="font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--mute)">Allowed</span></span>';
    const family = e.threat_family && e.threat_family !== 'none' ? e.threat_family : '';
    const tagChip = family ? `<span class="tag">${esc(family)}</span>` : '';
    const rzClass = isQ ? 'rz-q' : 'rz-a';

    let evidence = '';
    if (isQ) {
      const pct = Math.round(Math.max(0, Math.min(1, Number(e.confidence) || 0)) * 100);
      evidence = `
        <div style="margin-top:13px">
          <div class="metarow" style="font-size:10px;letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px">Evidence · flagged span</div>
          <div class="receipt" style="padding:13px 15px;max-width:66ch">${flaggedReceiptHTML(e.content_preview, e.malicious_span)}</div>
          <div style="margin-top:13px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">
            <span class="seal"><span class="sq"></span>Withheld from the agent</span>
            <span style="font-size:12px;color:var(--mute)">the agent doesn't get a vote</span>
            <span style="flex:1"></span>
            <span class="metarow" style="font-size:10.5px;color:var(--mute-soft)">conf ${pct} · ${esc(e.model || '')}</span>
          </div>
        </div>`;
    }

    return `<div class="feed-row${reveal}" style="padding:16px 0;border-bottom:1px solid var(--hairline)">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px">
        ${badge}
        <span style="font-family:var(--mono);font-size:12.5px;color:var(--ink)">${esc(e.source || 'unknown')}</span>
        ${tagChip}
        <span style="flex:1"></span>
        <span class="metarow" style="font-size:10.5px;color:var(--mute-soft)">${fmtHM(e.ts)}</span>
      </div>
      <div class="reason ${rzClass}">${esc(e.reason || '')}</div>
      ${evidence}
    </div>`;
  }

  function quarantineRowHTML(q) {
    return `<div style="display:flex;gap:10px;align-items:baseline">
      <span style="width:6px;height:6px;background:var(--ink);flex:none;transform:translateY(4px)"></span>
      <div style="min-width:0;flex:1">
        <div style="font-family:var(--mono);font-size:11px;color:var(--ink)">${esc(q.threat_family || 'unknown')}</div>
        <div style="font-family:var(--mono);font-size:10.5px;color:var(--mute-soft);overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${esc(q.source || '')}</div>
      </div>
      <span class="metarow" style="font-size:10px;color:var(--mute-soft)">${fmtHM(q.ts)}</span>
    </div>`;
  }

  function sourceRowHTML(name, trusted) {
    const nameColor = trusted ? 'var(--mute)' : 'var(--ink)';
    const stateColor = trusted ? 'var(--mute-soft)' : 'var(--ink)';
    const label = trusted ? 'trusted' : 'revoked';
    return `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
      <span style="font-family:var(--mono);font-size:11.5px;color:${nameColor};overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${esc(name)}</span>
      <span style="font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:${stateColor};flex:none">${label}</span>
    </div>`;
  }

  // ------------------------------------------------------------- rendering

  function renderTopBar() {
    const past = isPast();
    const live = isLive() && !state.allClear;
    const scrubMs = past ? computeScrubMs() : null;

    const stateLabel = state.allClear ? 'Watching' : live ? 'Live' : ('Replay · ' + fmtHM(scrubMs));
    $('stateLabel').textContent = stateLabel;

    const dot = $('stateDot');
    if (past) {
      dot.style.cssText = 'width:7px;height:7px;border-radius:50%;border:1.5px solid var(--mute);display:inline-block';
    } else {
      dot.style.cssText = 'width:7px;height:7px;border-radius:50%;background:var(--accent);display:inline-block;animation:alkBreath 3s ease-in-out infinite';
    }

    $('segClear').classList.toggle('on', state.allClear);
    $('segLive').classList.toggle('on', live);
    $('segReplay').classList.toggle('on', past);

    $('blockedToday').textContent = state.quarantines.length;

    $('feedSub').textContent = state.allClear ? 'all clear' : past ? ('as of ' + fmtHM(scrubMs)) : 'watching';
    $('feedMeta').textContent = past ? 'replay' : '01 / events';

    const railStateEl = $('railState');
    railStateEl.textContent = past ? ('REPLAY · ' + fmtHM(scrubMs)) : 'LIVE';
    railStateEl.style.color = past ? 'var(--mute)' : 'var(--accent-text)';

    $('scrubLeft').textContent = 'first seen ' + fmtHM(state.domainStart);
    $('scrubHint').textContent = past ? 'viewing the past' : 'drag to rewind · live';
    $('scrubRange').value = state.scrub;
  }

  function renderFeed() {
    const allClearEl = $('feedAllClear'), rowsEl = $('feedRows');

    if (state.allClear) {
      allClearEl.style.display = 'flex';
      rowsEl.style.display = 'none';
      const cleanCount = state.events.filter((e) => String(e.decision).toLowerCase() === 'allow').length;
      const last = state.events[0] ? fmtHM(state.events[0].ts) : '--:--';
      $('allClearMeta').textContent = `last screened ${last} · ${cleanCount} clean today`;
      return;
    }

    allClearEl.style.display = 'none';
    rowsEl.style.display = 'block';

    const past = isPast();
    const scrubMs = past ? computeScrubMs() : null;
    const visible = past
      ? state.events.filter((e) => { const t = Date.parse(e.ts); return !isNaN(t) && t <= scrubMs; })
      : state.events;
    const capped = visible.slice(0, 40);
    rowsEl.innerHTML = capped.length
      ? capped.map((e, i) => feedRowHTML(e, i)).join('')
      : '<div class="metarow" style="padding:20px 0;color:var(--mute-soft)">No events yet — waiting for traffic.</div>';
  }

  function renderQuarantinePanel() {
    const past = isPast();
    const scrubMs = past ? computeScrubMs() : null;
    const list = past
      ? state.quarantines.filter((q) => { const t = Date.parse(q.ts); return !isNaN(t) && t <= scrubMs; })
      : state.quarantines;

    $('qCount').textContent = list.length + ' held';
    const qListEl = $('qList'), qEmptyEl = $('qEmpty');
    if (!list.length) {
      qEmptyEl.style.display = 'block';
      qListEl.innerHTML = '';
      return;
    }
    qEmptyEl.style.display = 'none';
    qListEl.innerHTML = list.slice(0, 30).map(quarantineRowHTML).join('');
  }

  function renderSourcesPanel() {
    const list = isPast() ? state.asofCache : state.sourcesCache;
    const rows = (list || []).map((s) => {
      const name = s.name ?? s.source ?? '?';
      const trusted = (s.trust || '') === 'trusted';
      return sourceRowHTML(name, trusted);
    }).join('');
    $('sourcesList').innerHTML = rows
      || '<div class="metarow" style="color:var(--mute-soft)">No sources yet.</div>';
  }

  function renderAll() {
    renderTopBar();
    renderFeed();
    renderQuarantinePanel();
    renderSourcesPanel();
  }

  // --------------------------------------------------------------- replay

  async function refreshSources() {
    if (isPast()) {
      const ms = computeScrubMs();
      const iso = new Date(ms).toISOString();
      const seq = ++replaySeq;
      try {
        const rows = await getJSON('/api/asof?ts=' + encodeURIComponent(iso));
        if (seq === replaySeq && isPast()) {
          state.asofCache = rows;
          renderSourcesPanel();
        }
      } catch (err) { /* mid-drag network hiccup; ignore */ }
    } else {
      try {
        state.sourcesCache = await getJSON('/api/sources');
        if (!isPast()) renderSourcesPanel();
      } catch (err) { /* server briefly away; SSE reconnect will retrigger */ }
    }
  }

  // ----------------------------------------------------------------- data

  async function loadPolicy() {
    try {
      const p = await getJSON('/api/policy');
      const chips = (p.deny_paths || []).map((x) => `<span class="tag">${esc(x)}</span>`).join('');
      $('policyChips').innerHTML = chips || '<span class="metarow" style="color:var(--mute-soft)">none configured</span>';
    } catch (err) {
      $('policyChips').innerHTML = '<span class="metarow" style="color:var(--mute-soft)">policy unavailable</span>';
    }
  }

  async function loadFeedAndQuarantine() {
    const [recentRows, qRows] = await Promise.all([
      getJSON('/api/recent?limit=40').catch(() => []),
      getJSON('/api/quarantine').catch(() => []),
    ]);

    // /api/recent's verdict_json (Verdict.to_dict()) never carries content_preview
    // — that only lives in quarantine_log. Both rows are written from the same
    // `now` inside TrustLedger.record(), so (source, ts) is an exact join key.
    const qBySourceTs = new Map();
    for (const q of qRows) qBySourceTs.set(q.source + '|' + q.ts, q);

    const events = [];
    for (const row of recentRows) {
      if (row.event !== 'screen' || !row.verdict) continue;
      const v = row.verdict;
      const ts = row.trust_granted_at;
      const source = v.source || row.source;
      const isQ = String(v.decision).toLowerCase() === 'quarantine';
      let content_preview = '';
      if (isQ) {
        const match = qBySourceTs.get(source + '|' + ts);
        if (match) content_preview = match.content_preview || '';
      }
      events.push({
        decision: v.decision, threat_family: v.threat_family, malicious_span: v.malicious_span,
        reason: v.reason, confidence: v.confidence, source, model: v.model,
        ts, content_preview, _live: false,
      });
    }

    state.events = events;       // /api/recent is already newest-first
    state.quarantines = qRows;   // /api/quarantine is already newest-first

    if (events[0] && events[0].model) {
      $('statusModel').textContent = events[0].model + ' · airlock v0.1';
    }
  }

  async function loadSourcesLive() {
    state.sourcesCache = await getJSON('/api/sources').catch(() => []);
  }

  function computeDomainStart() {
    const tsList = [];
    for (const e of state.events) { const t = Date.parse(e.ts); if (!isNaN(t)) tsList.push(t); }
    for (const q of state.quarantines) { const t = Date.parse(q.ts); if (!isNaN(t)) tsList.push(t); }
    for (const s of state.sourcesCache) { const t = Date.parse(s.first_seen); if (!isNaN(t)) tsList.push(t); }
    return tsList.length ? Math.min(...tsList) : Date.now() - 3600 * 1000;
  }

  // ------------------------------------------------------------------ SSE

  function connectSSE() {
    const es = new EventSource('/events');
    es.onmessage = (m) => {
      let e;
      try { e = JSON.parse(m.data); } catch (err) { return; }
      if (!e || typeof e !== 'object') return;
      if (e.kind === 'hello') return;
      if (e.decision === undefined) return; // this feed only renders verdict events
      if (!e.ts) e.ts = new Date().toISOString();

      const isQ = String(e.decision).toLowerCase() === 'quarantine';
      state.events.unshift({
        decision: e.decision, threat_family: e.threat_family, malicious_span: e.malicious_span,
        reason: e.reason, confidence: e.confidence, source: e.source, model: e.model,
        ts: e.ts, content_preview: e.content_preview || '', _live: true,
      });
      if (state.events.length > 200) state.events.length = 200;

      if (isQ) {
        state.quarantines.unshift({
          id: 'live-' + Date.now(), ts: e.ts, source: e.source,
          threat_family: e.threat_family, malicious_span: e.malicious_span,
          confidence: e.confidence, content_preview: e.content_preview || '', reason: e.reason,
        });
        if (state.quarantines.length > 200) state.quarantines.length = 200;
      }

      if (!isPast()) {
        renderAll();
        if (isQ) refreshSources(); // a fresh catch also revokes trust for its source
      }
    };
  }

  // ----------------------------------------------------------------- wiring

  function bindThemeToggle() {
    $('themeToggle').addEventListener('click', () => {
      const html = document.documentElement;
      const next = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      html.setAttribute('data-theme', next);
      try { localStorage.setItem('airlock-theme', next); } catch (e) { /* ignore */ }
    });
  }

  function bindSegmented() {
    $('segClear').addEventListener('click', () => {
      state.allClear = true;
      renderAll();
    });
    $('segLive').addEventListener('click', () => {
      state.allClear = false;
      state.scrub = 100;
      renderAll();
      refreshSources();
    });
    $('segReplay').addEventListener('click', () => {
      state.allClear = false;
      state.scrub = 50;
      renderAll();
      refreshSources();
    });
  }

  function bindScrub() {
    $('scrubRange').addEventListener('input', (ev) => {
      state.allClear = false;
      state.scrub = parseFloat(ev.target.value);
      renderAll();
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(refreshSources, 130);
    });
  }

  // ------------------------------------------------------------------ init

  (async function init() {
    bindThemeToggle();
    bindSegmented();
    bindScrub();
    await Promise.allSettled([loadPolicy(), loadFeedAndQuarantine(), loadSourcesLive()]);
    state.domainStart = computeDomainStart();
    renderAll();
    connectSSE();
  })();
})();
