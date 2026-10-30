/* NabuPay Breach Simulator — application shell, defences, analysis, method, report */
(function () {
  'use strict';
  var D = window.BSData, E = window.BSEngine, C = window.NPCharts;
  var $ = function (id) { return document.getElementById(id); };
  var M = D.MODEL;

  /* ------------------------------------------------------------ formatting */
  function money(v) {
    v = Math.round(v || 0); var a = Math.abs(v);
    if (a >= 1e6) return '$' + (v / 1e6).toFixed(a >= 1e7 ? 1 : 2) + 'M';
    if (a >= 1e3) return '$' + Math.round(v / 1e3) + 'K';
    return '$' + v.toLocaleString('en-US');
  }
  function moneyFull(v) { return '$' + Math.round(v || 0).toLocaleString('en-US'); }
  function pct(v, d) { return (v * 100).toFixed(d === undefined ? 0 : d) + '%'; }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function setText(id, t) { var e = $(id); if (e && e.textContent !== t) { e.textContent = t; e.classList.remove('flash-up'); void e.offsetWidth; e.classList.add('flash-up'); } }

  var SHORT = {
    mfa: 'Second factor on every login, including VPN and email.',
    training: 'Phishing simulations and short lessons for all 180 staff.',
    emailsec: 'Filters malicious links and attachments before the inbox.',
    edr: 'Detects and blocks malicious activity on PCs and servers.',
    patch: 'Closes known vulnerabilities on edge devices and servers.',
    segment: 'Firewalls between network zones; only application traffic crosses.',
    backup: 'Offline copies that cannot be encrypted; restore in 24 hours.',
    fraud: 'Call-back checks and dual approval before money leaves.',
    mdr: 'A 24/7 provider watches alerts and isolates hosts quickly.',
    insurance: 'Pays 70% of each loss above $50K, up to $3M.',
    token: 'Card numbers replaced by tokens that are useless if stolen.',
    novpn: 'Removes remote access entirely; staff work on site.'
  };
  var TREAT = {
    mitigate: ['Mitigate', 'Reduce the likelihood or the impact'],
    transfer: ['Transfer', 'Share the risk with a third party'],
    avoid: ['Avoid', 'Stop the activity that creates the risk']
  };

  /* ------------------------------------------------------------ state */
  var S = {
    selected: new Set(), mode: 'open', appetite: M.appetiteDefault, page: 'simulate',
    idx: null, base: null, cur: null, curKey: null, simCache: new Map(),
    exp: new Map(), sens: null, sensKey: null, dirty: true, firstCharts: true
  };
  var listeners = [];
  function emit() { listeners.forEach(function (f) { try { f(); } catch (e) { console.error(e); } }); }
  function mask() { return E.maskOf(D, S.selected); }
  function ctrlById(id) { return D.CONTROLS.find(function (c) { return c.id === id; }); }
  function bitOf(id) { return 1 << D.CONTROLS.findIndex(function (c) { return c.id === id; }); }

  /* ------------------------------------------------------------ portfolio table */
  function buildIndex(done) {
    var T = window.BSFrontier;
    if (T && T.hash === E.dataHash(D) && T.ale.length === (1 << D.CONTROLS.length)) {
      S.idx = E.portfolioIndex(D, Float64Array.from(T.ale)); done(); return;
    }
    // stale or missing table: rebuild in the browser with fewer runs
    var n = 1 << D.CONTROLS.length, ale = new Float64Array(n), at = 0, runs = 40;
    (function chunk() {
      var end = Math.min(n, at + 48);
      var part = E.frontierRange(D, at, end, runs); ale.set(part, at); at = end;
      var note = $('ledger'); if (note) note.innerHTML = '<div class="stat wide"><span class="k">Preparing portfolio analysis</span><b class="v">' + Math.round(at / n * 100) + '%</b></div>';
      if (at < n) setTimeout(chunk, 0); else { S.idx = E.portfolioIndex(D, ale); done(); }
    })();
  }
  function tcorOf(m) { return S.idx.tcor[m]; }
  function scoreOf(m) { return E.scoreOf(S.idx, m, S.mode === 'budget'); }
  function expectedFor(sel) {
    var key = E.maskOf(D, sel);
    if (!S.exp.has(key)) S.exp.set(key, E.expected(D, Array.from(sel), { runs: M.frontierRuns, seedKey: 'fr' }));
    return S.exp.get(key);
  }

  /* ------------------------------------------------------------ simulations (async) */
  var simTimer = null;
  function scheduleSim() {
    clearTimeout(simTimer);
    simTimer = setTimeout(function () {
      if (!S.base) S.base = E.simulateYears(D, []);
      var key = mask();
      if (!S.simCache.has(key)) {
        S.simCache.set(key, E.simulateYears(D, Array.from(S.selected)));
        if (S.simCache.size > 40) S.simCache.delete(S.simCache.keys().next().value);
      }
      S.cur = S.simCache.get(key); S.curKey = key;
      renderSummary(); renderImpactBar();
      if (S.page === 'analyze') renderAnalyze(); else S.dirty = true;
    }, 90);
  }
  function appetiteStatus() {
    if (!S.cur) return null;
    var p = E.exceedance(S.cur, S.appetite);
    return { p: p, ok: p <= M.appetiteTolerance };
  }

  /* ------------------------------------------------------------ navigation */
  var PAGES = ['simulate', 'defend', 'analyze', 'method', 'report'];
  function go(page, opts) {
    if (PAGES.indexOf(page) < 0) page = 'simulate';
    S.page = page;
    document.querySelectorAll('.page').forEach(function (p) { p.classList.toggle('active', p.getAttribute('data-page') === page); });
    document.querySelectorAll('[data-go]').forEach(function (b) {
      var on = b.getAttribute('data-go') === page;
      if (b.classList.contains('tab') || b.classList.contains('nav-item')) { b.classList.toggle('on', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }
    });
    if (!(opts && opts.keepScroll)) window.scrollTo(0, 0);
    if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
    if (page === 'analyze' && S.idx) { if (S.dirty || S.firstCharts) renderAnalyze(); }
    if (page === 'report') renderLeaderboard();
  }

  /* ------------------------------------------------------------ selection */
  function setSelected(next) {
    S.selected = next;
    renderControls(); renderImpactBar(); renderSuggest(); renderSummary(); renderRunMeta();
    S.sens = null; S.dirty = true;
    scheduleSim(); emit();
  }
  function toggle(id) {
    var next = new Set(S.selected);
    if (next.has(id)) next.delete(id);
    else {
      if (S.mode === 'budget' && E.costOf(D, mask() | bitOf(id)) > M.budget) { bumpBudget(); return; }
      next.add(id);
    }
    setSelected(next);
  }
  function bumpBudget() { var b = $('budget-meter'); b.classList.remove('shake'); void b.offsetWidth; b.classList.add('shake'); }

  /* ------------------------------------------------------------ shared summary */
  function renderSummary() {
    if (!S.idx) return;
    var m = mask(), ale = S.idx.ale[m];
    setText('top-ale', money(ale));
    var st = appetiteStatus();
    $('side-summary').innerHTML =
      '<h2>Your position</h2>' +
      '<div class="ss-row"><span>Expected annual loss</span><b>' + money(ale) + '</b></div>' +
      '<div class="ss-row"><span>Bad year (1 in 20)</span><b>' + (S.cur ? money(S.cur.p95) : '…') + '</b></div>' +
      '<div class="ss-row"><span>Control spend</span><b>' + money(S.idx.cost[m]) + '</b></div>' +
      '<div class="ss-row"><span>Score</span><b>' + scoreOf(m) + ' / 100</b></div>' +
      (st ? '<span class="badge ' + (st.ok ? 'badge-ok' : 'badge-bad') + '">' + (st.ok ? 'Within risk appetite' : 'Outside risk appetite') + '</span>' : '');
  }
  function renderRunMeta() {
    var n = S.selected.size;
    $('run-meta').innerHTML = (n ? n + ' of ' + D.CONTROLS.length + ' defences active. ' : 'No defences active yet. ') +
      '<button class="link-btn" data-go="defend">' + (n ? 'Change defences' : 'Add defences') + '</button>';
  }

  /* ------------------------------------------------------------ defend */
  function renderImpactBar() {
    if (!S.idx) return;
    var m = mask(), ale = S.idx.ale[m], base = S.idx.ale[0], red = base ? 1 - ale / base : 0;
    $('impact-bar').innerHTML =
      '<div class="ib"><span>Loss / yr</span><b>' + money(ale) + '</b><small class="' + (red > 0 ? 'good' : '') + '">' + (red > 0 ? '▼ ' + pct(red) : 'no controls') + '</small></div>' +
      '<div class="ib"><span>Spend / yr</span><b>' + money(S.idx.cost[m]) + '</b><small>' + (S.mode === 'budget' ? money(Math.max(0, M.budget - S.idx.cost[m])) + ' left' : 'total ' + money(tcorOf(m))) + '</small></div>' +
      '<div class="ib"><span>Score</span><b>' + scoreOf(m) + '<span style="display:inline;font-size:13px;color:#aab4c3"> /100</span></b><small>' + (S.cur ? 'bad year ' + money(S.cur.p95) : 'simulating…') + '</small></div>';
    var bm = $('budget-meter');
    bm.hidden = S.mode !== 'budget';
    if (S.mode === 'budget') {
      var c = S.idx.cost[m];
      bm.innerHTML = '<div class="bm-track"><div class="bm-fill' + (c >= M.budget ? ' full' : '') + '" style="width:' + Math.min(100, c / M.budget * 100) + '%"></div></div>' +
        '<div class="bm-row"><span>' + moneyFull(c) + ' committed</span><span>budget ' + moneyFull(M.budget) + '</span></div>';
    }
  }

  function bestMove() {
    var m = mask(), cur = tcorOf(m), best = null;
    D.CONTROLS.forEach(function (c, i) {
      var nm = m ^ (1 << i);
      if (S.mode === 'budget' && S.idx.cost[nm] > M.budget) return;
      var gain = cur - tcorOf(nm);
      if (gain > 1000 && (!best || gain > best.gain)) best = { id: c.id, add: !(m & (1 << i)), gain: gain };
    });
    return best;
  }
  function renderSuggest() {
    if (!S.idx) return;
    var b = bestMove(), host = $('suggest');
    if (!b) {
      host.innerHTML = '<div class="suggest done"><p><b>No single change lowers your total cost of risk.</b> Compare your position with the optimum on the efficient frontier.</p><button class="btn btn-secondary btn-sm" data-go="analyze">Open analysis</button></div>';
      return;
    }
    var c = ctrlById(b.id);
    host.innerHTML = '<div class="suggest"><p><b>Best next move:</b> ' + (b.add ? 'add ' : 'remove ') + esc(c.name.toLowerCase()) +
      '. Total cost of risk falls by ' + money(b.gain) + ' a year.</p><button class="btn btn-primary btn-sm" id="apply-move">' + (b.add ? 'Add it' : 'Remove it') + '</button></div>';
    $('apply-move').onclick = function () { toggle(b.id); };
  }

  function renderControls() {
    if (!S.idx) return;
    var m = mask(), host = $('controls'), openSet = {};
    host.querySelectorAll('.ctl-more[aria-expanded="true"]').forEach(function (b) { openSet[b.getAttribute('data-id')] = 1; });
    var html = '';
    Object.keys(TREAT).forEach(function (tr) {
      var list = D.CONTROLS.filter(function (c) { return c.treatment === tr; });
      if (!list.length) return;
      html += '<div class="ctl-group"><h3>' + TREAT[tr][0] + '</h3><p>' + TREAT[tr][1] + '</p><div class="ctl-list">';
      list.forEach(function (c) {
        var i = D.CONTROLS.indexOf(c), bit = 1 << i, on = !!(m & bit);
        var saves = on ? S.idx.ale[m & ~bit] - S.idx.ale[m] : S.idx.ale[m] - S.idx.ale[m | bit];
        var net = saves - c.cost, cls, txt;
        if (saves < 500) { cls = 'none'; txt = on ? 'Adds little on top of your other defences' : 'Would add little on top of your other defences'; }
        else if (net >= 0) { cls = 'good'; txt = (on ? 'Saves ≈ ' : 'Would save ≈ ') + money(saves) + ' / yr'; }
        else { cls = 'weak'; txt = (on ? 'Saves ' : 'Would save ') + money(saves) + ', less than it costs'; }
        var blocked = !on && S.mode === 'budget' && S.idx.cost[m | bit] > M.budget;
        var src = (c.src || []).map(function (k) { var s = D.SOURCES[k]; return s ? '<a href="' + s.url + '" target="_blank" rel="noopener">' + esc(s.title) + '</a>' : ''; }).join('<br>');
        var r = c.effRange || [1, 1, 1];
        html += '<div class="ctl' + (on ? ' on' : '') + (blocked ? ' blocked' : '') + '">' +
          '<button class="ctl-top" role="switch" aria-checked="' + on + '" data-toggle="' + c.id + '">' +
            '<span class="switch" aria-hidden="true"></span>' +
            '<span><span class="ctl-name">' + esc(c.name) + '</span><span class="ctl-desc">' + esc(SHORT[c.id] || '') + '</span>' +
            '<span class="ctl-impact ' + cls + '">' + txt + '</span></span>' +
            '<span class="ctl-cost">' + money(c.cost) + '<small>per year</small></span>' +
          '</button>' +
          '<button class="ctl-more" data-id="' + c.id + '" aria-expanded="' + (openSet[c.id] ? 'true' : 'false') + '">Evidence<svg><use href="#i-down"/></svg></button>' +
          '<div class="ctl-evidence"' + (openSet[c.id] ? '' : ' hidden') + '><span>' + esc(c.why) + '</span>' +
            (r[0] !== r[2] ? '<span class="muted">Realised effectiveness modelled as ' + pct(r[0]) + '–' + pct(r[2]) + ' of the stated effect (most likely ' + pct(r[1]) + ').</span>' : '') +
            '<span class="muted">Cost basis: ' + esc(c.costWhy) + '</span>' + (src ? '<span>' + src + '</span>' : '<span class="badge badge-asm" style="justify-self:start">Stated assumption</span>') +
          '</div></div>';
      });
      html += '</div></div>';
    });
    host.innerHTML = html;
    host.querySelectorAll('[data-toggle]').forEach(function (b) { b.addEventListener('click', function () { toggle(b.getAttribute('data-toggle')); }); });
    host.querySelectorAll('.ctl-more').forEach(function (b) {
      b.addEventListener('click', function () {
        var open = b.getAttribute('aria-expanded') !== 'true';
        b.setAttribute('aria-expanded', open); b.nextElementSibling.hidden = !open;
      });
    });
  }

  /* ------------------------------------------------------------ analyze */
  function appetiteToSlider(v) { return Math.round((Math.log10(v) - 5) / 2 * 100); }
  function sliderToAppetite(s) { var v = Math.pow(10, 5 + s / 100 * 2); var p = Math.pow(10, Math.floor(Math.log10(v)) - 1); return Math.round(v / p) * p; }

  function renderLedger() {
    var m = mask(), ale = S.idx.ale[m], base = S.idx.ale[0], cost = S.idx.cost[m];
    var rosi = cost ? (base - ale - cost) / cost : null, st = appetiteStatus(), opt = S.idx.optimum;
    var stat = function (k, v, d, cls, wide) { return '<div class="stat' + (wide ? ' wide' : '') + '"><span class="k">' + k + '</span><b class="v ' + (cls || '') + '">' + v + '</b><span class="d">' + d + '</span></div>'; };
    $('ledger').innerHTML =
      stat('Expected annual loss', money(ale), 'inherent ' + money(base) + (base > ale ? ' · ▼ ' + pct(1 - ale / base) : ''), '') +
      stat('Bad year (1 in 20)', S.cur ? money(S.cur.p95) : '…', '95th percentile of 2,000 years') +
      stat('Chance of any loss', S.cur ? pct(S.cur.pAny) : '…', 'in a given year') +
      stat('Risk appetite', st ? (st.ok ? 'Within' : 'Outside') : '…', st ? pct(st.p, 1) + ' chance of > ' + money(S.appetite) : '', st ? (st.ok ? 'good' : 'bad') : '') +
      stat('Control spend', money(cost), S.selected.size + ' of ' + D.CONTROLS.length + ' controls') +
      stat('Total cost of risk', money(S.idx.tcor[m]), 'optimum ' + money(S.idx.tcor[opt])) +
      stat('Return on security investment', rosi === null ? '—' : pct(rosi), 'measured against inherent risk', rosi !== null && rosi < 0 ? 'bad' : '') +
      stat('Score', scoreOf(m) + ' / 100', S.mode === 'budget' ? '100 = best portfolio within $120K' : '100 = best of 4,096 portfolios');
  }

  function renderLEC(animate) {
    var out = $('appetite-out'), st = appetiteStatus();
    out.textContent = moneyFull(S.appetite);
    if (!S.cur || !S.base) { $('lec').innerHTML = '<div class="empty">Simulating 2,000 years…</div>'; return; }
    C.lec($('lec'), {
      inherent: S.base, current: S.cur, exceed: E.exceedance, appetite: S.appetite, tol: M.appetiteTolerance, animate: animate,
      onRead: function (x, pc, pb) {
        $('lec-readout').innerHTML = 'Chance of losing more than <b>' + money(x) + '</b> in a year: <b>' + pct(pc, 1) + '</b> with your defences, ' + pct(pb, 1) + ' with none.';
      }
    });
    $('appetite-status').innerHTML = '<div class="appetite-status ' + (st.ok ? 'ok' : 'bad') + '"><svg><use href="#' + (st.ok ? 'i-check' : 'i-alert') + '"/></svg><span>' +
      (st.ok ? '<b>Within appetite.</b> ' : '<b>Outside appetite.</b> ') + 'The chance of losing more than ' + money(S.appetite) + ' in a year is ' + pct(st.p, 1) +
      ' (limit ' + pct(M.appetiteTolerance) + '). ' + (st.ok ? 'The residual risk can be accepted.' : 'Add or change controls, or transfer part of the tail with insurance.') + '</span></div>';
  }

  function renderFrontier(animate) {
    var m = mask(), idx = S.idx, opt = S.mode === 'budget' ? idx.optimumBudget : idx.optimum;
    C.frontier($('frontier'), { idx: idx, you: m, optimum: opt, budget: S.mode === 'budget' ? M.budget : null, animate: animate });
    var gap = idx.tcor[m] - idx.tcor[opt];
    var onFront = idx.pareto.indexOf(m) >= 0;
    var list = E.idsOf(D, opt).map(function (id) { return '<li>' + esc(ctrlById(id).name) + '</li>'; }).join('');
    $('opt-box').innerHTML =
      '<p>Your total cost of risk is <b>' + money(idx.tcor[m]) + '</b>' + (gap > 500 ? ', ' + money(gap) + ' above the lowest achievable (' + money(idx.tcor[opt]) + ').' : ', the lowest achievable.') +
      (onFront ? ' Your portfolio is on the efficient frontier: no cheaper portfolio has a lower expected loss.' : ' A cheaper portfolio exists with the same or lower expected loss, so part of your spend is inefficient.') + '</p>' +
      '<details><summary>Show the optimal portfolio</summary><p style="margin-top:8px">' + money(idx.cost[opt]) + ' per year, expected loss ' + money(idx.ale[opt]) + ':</p><ul>' + list + '</ul></details>';
  }

  function renderTornado(animate) {
    var key = mask();
    if (S.sensKey !== key) { S.sens = E.sensitivity(D, Array.from(S.selected), { runs: 160 }); S.sensKey = key; }
    var rows = S.sens.params.slice(0, 7);
    C.tornado($('tornado'), { base: S.sens.base, rows: rows, animate: animate });
    var top = rows[0];
    $('tornado-note').innerHTML = top ? 'Light bars: input at its minimum. Dark bars: input at its maximum. The biggest driver is <b>' + esc(top.label.toLowerCase()) +
      '</b>, which moves the expected loss between ' + money(Math.min(top.low, top.high)) + ' and ' + money(Math.max(top.low, top.high)) + '. Inputs at the bottom barely matter, so errors in them do not change the decision.' : '';
  }

  function renderFair() {
    var b = expectedFor(new Set()), n = expectedFor(S.selected);
    var bands = function (p) { return [E.likelihoodBand(p.lef), E.impactBand(D, p.lm)]; };
    $('fair').innerHTML = b.per.map(function (p, i) {
      var q = n.per[i], bb = bands(p), nb = bands(q);
      var row = function (k, a, c, f) { return '<div><dt>' + k + '</dt><dd><s>' + f(a) + '</s>' + f(c) + '</dd></div>'; };
      return '<div class="panel fair-card"><h3>' + esc(p.name) + '<span class="badge ' + (nb[0] * nb[1] >= 15 ? 'badge-bad' : nb[0] * nb[1] >= 6 ? 'badge-asm' : 'badge-ok') + '">Risk ' + bb[0] * bb[1] + ' → ' + nb[0] * nb[1] + '</span></h3><dl>' +
        '<div><dt>Attempts per year (TEF)</dt><dd>' + p.tef.toFixed(2) + '</dd></div>' +
        row('Success rate (vulnerability)', p.vuln, q.vuln, function (v) { return pct(v, v < .1 && v > 0 ? 1 : 0); }) +
        row('Loss events per year (LEF)', p.lef, q.lef, function (v) { return v.toFixed(v < .1 ? 3 : 2); }) +
        row('Loss per event (LM)', p.lm, q.lm, money) +
        '<div class="ale-row">' + '<dt>Expected annual loss</dt><dd><s>' + money(p.ale) + '</s>' + money(q.ale) + '</dd></div>' +
        '</dl></div>';
    }).join('');
  }

  function renderMatrix() {
    var b = expectedFor(new Set()), n = expectedFor(S.selected), pins = {};
    function add(p, cls, num) { var k = E.likelihoodBand(p.lef) + '-' + E.impactBand(D, p.lm); (pins[k] = pins[k] || []).push('<span class="pin ' + cls + '" title="' + esc(p.name) + '">' + num + '</span>'); }
    b.per.forEach(function (p, i) { add(p, 'inh', i + 1); });
    n.per.forEach(function (p, i) { if (p.lef > 0) add(p, 'res', i + 1); });
    var cells = '';
    for (var l = 5; l >= 1; l--) for (var im = 1; im <= 5; im++) {
      var s = l * im, bg = s >= 15 ? 'var(--r-crit-soft)' : s >= 8 ? 'var(--r-high-soft)' : s >= 4 ? 'var(--r-mid-soft)' : 'var(--r-low-soft)';
      cells += '<div class="cell" style="background:' + bg + '" title="Likelihood ' + l + ' × impact ' + im + ' = ' + s + '">' + (pins[l + '-' + im] || []).join('') + '</div>';
    }
    $('matrix').innerHTML = '<div class="matrix-layout"><div class="matrix-y">Likelihood (loss events / yr)</div><div class="matrix">' + cells + '</div><div class="matrix-x">Impact (loss per event vs. revenue)</div></div>' +
      '<div class="legend-row">' + b.per.map(function (p, i) { return '<span><span class="pin res">' + (i + 1) + '</span>' + esc(p.name) + '</span>'; }).join('') + '<span><span class="pin inh">#</span>Dashed = inherent</span></div>';
  }

  function renderBIA() {
    var n = expectedFor(S.selected), rw = n.per.find(function (p) { return p.id === 'ransomware'; });
    var rto = rw && rw.rto ? rw.rto : (S.selected.has('backup') ? 24 : M.restoreHoursBackup);
    var rows = D.ASSETS.filter(function (a) { return a.mtd; }).sort(function (a, b) { return a.mtd - b.mtd; });
    var meets = rows.filter(function (a) { return rto <= a.mtd; }).length;
    $('bia').innerHTML = '<p class="small" style="margin-bottom:10px">Expected recovery time after a ransomware incident with your defences: <b>' + Math.round(rto) + ' hours</b>. It meets the maximum tolerable downtime for <b>' + meets + ' of ' + rows.length + '</b> critical services.</p>' +
      '<table class="tbl"><thead><tr><th>Service</th><th class="r">MTD</th><th class="r">Met?</th></tr></thead><tbody>' +
      rows.map(function (a) { var ok = rto <= a.mtd; return '<tr><td>' + esc(a.name) + '</td><td class="r">' + a.mtd + ' h</td><td class="r"><span class="badge ' + (ok ? 'badge-ok' : 'badge-bad') + '">' + (ok ? 'Yes' : 'No') + '</span></td></tr>'; }).join('') +
      '</tbody></table><p class="small muted" style="margin-top:10px">Outage cost ' + money(D.COMPANY.outageCostPerHour) + ' per hour (best estimate). MTDs are BIA assumptions per ISO 22301.</p>';
  }

  function renderCalib() {
    var b = expectedFor(new Set()), rw = b.per[0], ix = b.per[1];
    var max = Math.max(rw.lm, ix.lm, 5.56e6);
    var bar = function (label, v, color) { return '<div class="cbar"><span>' + label + '</span><div class="trk"><div class="fl" style="width:' + (v / max * 100) + '%;background:' + color + '"></div></div><b>' + money(v) + '</b></div>'; };
    $('calib').innerHTML = '<div class="calib">' +
      '<div class="calib-row"><h4>Ransomware: loss per incident <span class="muted" style="font-weight:400">(Sophos: mean recovery cost)</span></h4>' + bar('This model', rw.lm, 'var(--brand)') + bar('Sophos 2025, finance', 1.74e6, 'var(--inherent)') + '</div>' +
      '<div class="calib-row"><h4>Data breach: loss per incident <span class="muted" style="font-weight:400">(IBM: average breach cost)</span></h4>' + bar('This model', ix.lm, 'var(--brand)') + bar('IBM 2025, finance', 5.56e6, 'var(--inherent)') + bar('IBM 2025, global', 4.44e6, 'var(--inherent)') + '</div>' +
      '</div><p class="section-note">The model sits in the published range. Ransomware is higher than Sophos because the model adds lost revenue during the outage and the 31% chance that data is also stolen; the data breach is below IBM\'s financial-sector average, which is driven by larger firms than NabuPay.</p>';
  }

  function renderAnalyze() {
    if (!S.idx) return;
    var animate = S.firstCharts;
    renderLedger(); renderFair(); renderMatrix(); renderBIA(); renderCalib();
    renderFrontier(animate); renderLEC(animate);
    setTimeout(function () { if (S.page === 'analyze') renderTornado(animate); }, 30);
    if (S.cur) { S.dirty = false; S.firstCharts = false; }
  }

  /* ------------------------------------------------------------ method */
  function range3(r, f) { return r[0] === r[2] ? f(r[1]) : f(r[0]) + ' – <b>' + f(r[1]) + '</b> – ' + f(r[2]); }
  function renderMethod() {
    var pub = '<span class="badge badge-pub">Published</span>', asm = '<span class="badge badge-asm">Assumption</span>';
    var rows = [];
    D.ATTACKS.forEach(function (a) { rows.push([a.name + ' attempts per year', 'TEF', range3(a.tefRange, function (v) { return v.toFixed(1); }), a.aroWhy, asm]); });
    rows.push(['Outage cost per hour', 'all critical services down', range3(D.COMPANY.outageCostRange, money), D.COMPANY.outageCostWhy, asm]);
    rows.push(['Cost per breached record', 'first 5,000 records', range3(M.recordCostHighRange, money), D.SOURCES.ibm2026rec.note, pub]);
    rows.push(['Cost per record beyond 5,000', 'large-breach marginal rate', range3(M.recordCostLowRange, money), 'Per-record cost falls in large breaches; marginal rate is an assumption.', asm]);
    rows.push(['Data also stolen in ransomware', '', pct(M.ransomExfilProb), D.SOURCES.sophosFin2025.note, pub]);
    rows.push(['Recovery without usable backups', '', M.restoreHoursNoBackup + ' h', 'Sophos 2025: 47% of financial firms recovered within a week.', pub]);
    rows.push(['Recovery with untested backups', '', M.restoreHoursBackup + ' h', 'Three days to restore and validate.', asm]);
    rows.push(['Phishing click rate (untrained)', '', '33.1%', D.SOURCES.knowbe42025.note, pub]);
    rows.push(['Loss per business email compromise', '', money(130000), D.SOURCES.ic32024.note, pub]);
    rows.push(['Spread between connected assets', 'per 6-hour round', pct(M.lateralBase) + ' / ' + pct(M.lateralToServer) + ' / ' + pct(M.lateralFromDC) + ' × ' + range3(M.spreadScaleRange, function (v) { return v.toFixed(1); }), 'Workstation→workstation / →server / from the directory server. Assumption, tested in the sensitivity analysis.', asm]);
    rows.push(['Detection without security tooling', 'per 6-hour round', range3(M.detectBaseRange, function (v) { return pct(v, 1); }), 'Someone notices unusual behaviour.', asm]);
    D.CONTROLS.forEach(function (c) {
      rows.push([c.name, money(c.cost) + ' per year', (c.effRange[0] === c.effRange[2] ? 'as stated' : range3(c.effRange, function (v) { return pct(v); })), c.why, (c.src && c.src.length) ? pub : asm]);
    });
    var sources = Object.keys(D.SOURCES).map(function (k) { var s = D.SOURCES[k]; return '<li><a href="' + s.url + '" target="_blank" rel="noopener">' + esc(s.title) + '</a><small>' + esc(s.note) + '</small></li>'; }).join('');
    $('method').innerHTML =
      '<div class="section" style="margin-top:0"><div class="section-head"><h2>The FAIR model</h2><p class="section-sub">Open Group Risk Taxonomy</p></div>' +
      '<div class="panel panel-pad"><div class="fair-tree">' +
        '<div class="ft-node root"><b>Risk</b><span>expected annual loss (ALE)</span></div><div class="ft-op">=</div>' +
        '<div class="ft-row"><div class="ft-col"><div class="ft-node mid"><b>Loss event frequency</b><span>loss events per year</span></div><div class="ft-pair"><div class="ft-node"><b>Threat events</b><span>attempts / yr (TEF)</span></div><div class="ft-node"><b>Vulnerability</b><span>P(attempt succeeds)</span></div></div></div>' +
        '<div class="ft-col"><div class="ft-node mid"><b>Loss magnitude</b><span>dollars per loss event</span></div><div class="ft-pair"><div class="ft-node"><b>Primary</b><span>response, rebuild, outage, fraud</span></div><div class="ft-node"><b>Secondary</b><span>records breached, net of insurance</span></div></div></div></div>' +
      '</div></div></div>' +
      '<div class="section"><div class="section-head"><h2>Equations</h2></div><div class="eq">' +
        '<div><b>LEF</b> = TEF × Vulnerability &nbsp;·&nbsp; <b>ALE</b> = LEF × LM (equivalently ARO × SLE)</div>' +
        '<div><b>Loss per event</b> = response + rebuild + outage hours × cost/hour + records × cost/record − insurance recovery</div>' +
        '<div><b>Total cost of risk</b> = annual control spend + residual ALE &nbsp;·&nbsp; <b>ROSI</b> = (ALE<sub>inherent</sub> − ALE<sub>residual</sub> − spend) ÷ spend</div>' +
        '<div><b>Risk score</b> = likelihood band (1–5) × impact band (1–5), NIST SP 800-30. Likelihood from LEF; impact from loss per event as a share of annual revenue (' + money(D.COMPANY.annualRevenueUSD) + ').</div>' +
        '<div><b>Score</b> = 100 × ln(TCoR<sub>none</sub> ÷ TCoR<sub>you</sub>) ÷ ln(TCoR<sub>none</sub> ÷ TCoR<sub>optimum</sub>), where the optimum is the best of all 4,096 portfolios.</div>' +
      '</div></div>' +
      '<div class="section"><div class="section-head"><h2>One simulated year</h2><p class="section-sub">Repeated 2,000 times per portfolio</p></div><div class="panel panel-pad"><ol class="steps">' +
        '<li>Draw a value for every uncertain input from its PERT distribution (minimum, most likely, maximum).</li>' +
        '<li>Draw the number of attempts for each scenario from a Poisson distribution with that year\'s TEF.</li>' +
        '<li>For each attempt, test every entry vector against the active controls. If one succeeds, exposure spreads between connected assets every six hours until detection and containment.</li>' +
        '<li>Price the impact: response, rebuild, outage hours, breached records and fraud, then apply cyber insurance.</li>' +
        '<li>Sum the year\'s losses. Sorting 2,000 years gives the loss exceedance curve, the percentiles and the risk-appetite test.</li>' +
      '</ol><p class="section-note">The efficient frontier and the per-control savings use the best-estimate (PERT mean) inputs and the same 300 simulated incidents per scenario for every portfolio (common random numbers), so differences between portfolios reflect the controls rather than random noise. All runs are seeded and reproducible.</p></div></div>' +
      '<div class="section"><div class="section-head"><h2>Inputs and assumptions</h2><p class="section-sub">min – <b>most likely</b> – max</p></div><div class="panel panel-pad"><table class="tbl assump"><thead><tr><th>Input</th><th class="r">Estimate</th><th>Basis</th><th>Type</th></tr></thead><tbody>' +
        rows.map(function (r) { return '<tr><td>' + esc(r[0]) + (r[1] ? '<span class="muted">' + esc(r[1]) + '</span>' : '') + '</td><td class="r">' + r[2] + '</td><td>' + esc(r[3]) + '</td><td>' + r[4] + '</td></tr>'; }).join('') +
      '</tbody></table></div></div>' +
      '<div class="section"><div class="section-head"><h2>Limitations</h2></div><div class="panel panel-pad"><ul class="limits">' +
        '<li>Scenarios are independent; a single campaign that triggers several scenarios at once is not modelled.</li>' +
        '<li>The network is static and abstracted to 12 asset groups; a group of PCs is treated as one asset.</li>' +
        '<li>Control effectiveness for EDR, email filtering and fraud checks is an expert assumption with a wide range, tested in the sensitivity analysis.</li>' +
        '<li>Ransom payments, regulatory fines specific to Iraq and long-term brand damage are not priced separately.</li>' +
        '<li>Controls are assumed to be independent and fully deployed; real deployments have gaps.</li>' +
        '<li>Monetary values are 2025 US dollars and are not discounted.</li>' +
      '</ul></div></div>' +
      '<div class="section"><div class="section-head"><h2>Sources</h2></div><div class="panel panel-pad"><ol class="sources">' + sources + '</ol></div></div>';
  }

  /* ------------------------------------------------------------ leaderboard */
  var LB = 'nabupay_lb_v2';
  function lbLoad() { try { return JSON.parse(localStorage.getItem(LB)) || []; } catch (e) { return []; } }
  function lbSave(l) { try { localStorage.setItem(LB, JSON.stringify(l)); } catch (e) {} }
  function renderLeaderboard() {
    if (!S.idx) return;
    var m = mask(), sc = scoreOf(m), list = lbLoad().sort(function (a, b) { return b.score - a.score || a.cost - b.cost; }).slice(0, 10);
    $('leaderboard').innerHTML = (list.length ? '<table class="lb"><tbody>' + list.map(function (r, i) {
      return '<tr class="' + (r.you ? 'you' : '') + '"><td class="rk">' + (i + 1) + '</td><td>' + esc(r.name) + '<small>' + (r.mode === 'budget' ? 'Budget' : 'Free') + ' · spend ' + money(r.cost) + ' · total cost ' + money(r.tcor) + '</small></td><td class="sc">' + r.score + '</td></tr>';
    }).join('') + '</tbody></table>' : '<p class="muted">No scores yet. Yours can be the first.</p>') +
      '<div class="name-row"><input class="text-input" id="lb-name" maxlength="24" placeholder="Your name" autocomplete="nickname"><button class="btn btn-primary" id="lb-add">Submit score ' + sc + '</button></div>' +
      '<p class="small muted" style="margin-top:8px">Scores are stored on this device only.</p>';
    $('lb-add').onclick = function () {
      var nm = $('lb-name').value.trim(); if (!nm) { $('lb-name').focus(); return; }
      var l = lbLoad().map(function (r) { r.you = false; return r; });
      l.push({ name: nm, score: sc, cost: S.idx.cost[m], tcor: S.idx.tcor[m], mode: S.mode, you: true, ts: Date.now() });
      lbSave(l); renderLeaderboard();
    };
  }

  /* ------------------------------------------------------------ report */
  function openReport() {
    if (!S.idx || !S.cur) return;
    var m = mask(), idx = S.idx, ale = idx.ale[m], base = idx.ale[0], cost = idx.cost[m], st = appetiteStatus();
    var b = expectedFor(new Set()), n = expectedFor(S.selected);
    if (S.sensKey !== m) { S.sens = E.sensitivity(D, Array.from(S.selected), { runs: 160 }); S.sensKey = m; }
    var sel = D.CONTROLS.filter(function (c) { return S.selected.has(c.id); });
    var rest = D.CONTROLS.filter(function (c) { return !S.selected.has(c.id); });
    var saveOf = function (c) { var bit = bitOf(c.id); return S.selected.has(c.id) ? idx.ale[m & ~bit] - idx.ale[m] : idx.ale[m] - idx.ale[m | bit]; };
    var opt = idx.optimum;
    var srcs = Object.keys(D.SOURCES).map(function (k) { var s = D.SOURCES[k]; return '<li>' + esc(s.title) + '. ' + esc(s.url) + '</li>'; }).join('');
    $('rv-doc').innerHTML =
      '<h1>NabuPay — Cyber Risk &amp; Incident Report</h1>' +
      '<p class="muted">Fictional payment company, Baghdad · ' + D.COMPANY.customers.toLocaleString('en-US') + ' customers · ' + money(D.COMPANY.annualRevenueUSD) + ' annual revenue · generated ' + new Date().toISOString().slice(0, 10) + '</p>' +
      '<h2>1. Executive summary</h2>' +
      '<p>With no controls NabuPay can expect to lose <b>' + moneyFull(base) + '</b> a year to the three modelled scenarios. The selected portfolio of ' + sel.length + ' controls costs <b>' + moneyFull(cost) + '</b> a year and reduces the expected loss to <b>' + moneyFull(ale) + '</b>' + (base ? ' (−' + pct(1 - ale / base) + ')' : '') + '. In a bad year (1 in 20) losses would exceed <b>' + moneyFull(S.cur.p95) + '</b>. The residual risk is <b>' + (st.ok ? 'within' : 'outside') + '</b> the risk appetite of ' + moneyFull(S.appetite) + ' at a 5% tolerance.</p>' +
      '<div class="rv-kpis"><div><span>Inherent ALE</span><b>' + money(base) + '</b></div><div><span>Residual ALE</span><b>' + money(ale) + '</b></div><div><span>Control spend</span><b>' + money(cost) + '</b></div><div><span>Total cost of risk</span><b>' + money(idx.tcor[m]) + '</b></div>' +
      '<div><span>ROSI</span><b>' + (cost ? pct((base - ale - cost) / cost) : '—') + '</b></div><div><span>Bad year (P95)</span><b>' + money(S.cur.p95) + '</b></div><div><span>Chance of any loss</span><b>' + pct(S.cur.pAny) + '</b></div><div><span>Score</span><b>' + scoreOf(m) + '/100</b></div></div>' +
      '<h2>2. Annual loss distribution</h2><p>2,000 simulated years with PERT-distributed inputs and Poisson attempt counts. Median ' + money(S.cur.p50) + ', 90th percentile ' + money(S.cur.p90) + ', 95th ' + money(S.cur.p95) + ', 99th ' + money(S.cur.p99) + ' (inherent: median ' + money(S.base.p50) + ', 95th ' + money(S.base.p95) + '). Probability of exceeding the appetite: ' + pct(st.p, 1) + '.</p>' +
      '<h2>3. Risk register</h2><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Scenario</th><th class="r">TEF</th><th class="r">Vulnerability</th><th class="r">LEF</th><th class="r">Loss per event</th><th class="r">ALE</th><th class="r">Risk</th></tr></thead><tbody>' +
        b.per.map(function (p, i) { var q = n.per[i]; return '<tr><td>' + esc(p.name) + '</td><td class="r">' + p.tef.toFixed(2) + '</td><td class="r">' + pct(p.vuln) + ' → ' + pct(q.vuln, 1) + '</td><td class="r">' + p.lef.toFixed(2) + ' → ' + q.lef.toFixed(3) + '</td><td class="r">' + money(p.lm) + ' → ' + money(q.lm) + '</td><td class="r">' + money(p.ale) + ' → ' + money(q.ale) + '</td><td class="r">' + E.likelihoodBand(p.lef) * E.impactBand(D, p.lm) + ' → ' + E.likelihoodBand(q.lef) * E.impactBand(D, q.lm) + '</td></tr>'; }).join('') +
      '</tbody></table></div>' +
      '<h2>4. Risk treatment plan</h2><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Control</th><th>Strategy</th><th class="r">Cost / yr</th><th class="r">Saves ≈ / yr</th></tr></thead><tbody>' +
        (sel.length ? sel.map(function (c) { return '<tr><td>' + esc(c.name) + '</td><td>' + c.treatment + '</td><td class="r">' + money(c.cost) + '</td><td class="r">' + money(saveOf(c)) + '</td></tr>'; }).join('') : '<tr><td colspan="4">No controls selected: all risk is retained (accepted).</td></tr>') +
      '</tbody></table></div>' +
      '<p>Not selected (risk accepted for these): ' + (rest.length ? rest.map(function (c) { return esc(c.name) + ' (would save ≈ ' + money(saveOf(c)) + ' for ' + money(c.cost) + ')'; }).join('; ') : 'none') + '.</p>' +
      '<p>Lowest total cost of risk among all 4,096 portfolios: ' + money(idx.tcor[opt]) + ' with ' + E.idsOf(D, opt).map(function (id) { return esc(ctrlById(id).name); }).join(', ') + '.</p>' +
      '<h2>5. Sensitivity</h2><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Input (min → max)</th><th class="r">ALE range</th></tr></thead><tbody>' +
        S.sens.params.slice(0, 6).map(function (p) { return '<tr><td>' + esc(p.label) + '</td><td class="r">' + money(Math.min(p.low, p.high)) + ' – ' + money(Math.max(p.low, p.high)) + '</td></tr>'; }).join('') +
      '</tbody></table></div>' +
      '<h2>6. Incident response</h2><p>Detection and containment follow the NIST SP 800-61 Rev. 3 lifecycle. Expected recovery after ransomware with this portfolio: ' + Math.round((n.per[0].rto || 0)) + ' hours; maximum tolerable downtime for the payment API is ' + D.ASSETS.find(function (a) { return a.id === 'api'; }).mtd + ' hours (ISO 22301 BIA).</p>' +
      '<h2>7. Method</h2><p>Quantitative risk model following the Open Group FAIR taxonomy: LEF = TEF × vulnerability, ALE = LEF × loss magnitude. Uncertain inputs use three-point PERT estimates (Vose 2008); likelihood and impact bands follow NIST SP 800-30. Scenarios are classified against MITRE ATT&amp;CK for reference only; the model contains no attack procedures.</p>' +
      '<h2>Sources</h2><ol>' + srcs + '</ol>';
    $('report-view').hidden = false; document.body.style.overflow = 'hidden'; $('report-view').scrollTop = 0;
  }
  function closeReport() { $('report-view').hidden = true; document.body.style.overflow = ''; }

  /* ------------------------------------------------------------ wiring */
  function init() {
    document.addEventListener('click', function (e) {
      var t = e.target.closest('[data-go]');
      if (t) { e.preventDefault(); go(t.getAttribute('data-go')); }
    });
    $('modes').querySelectorAll('button').forEach(function (b) {
      b.addEventListener('click', function () {
        S.mode = b.getAttribute('data-mode');
        $('modes').querySelectorAll('button').forEach(function (x) { x.classList.toggle('on', x === b); x.setAttribute('aria-checked', x === b); });
        if (S.mode === 'budget' && S.idx && S.idx.cost[mask()] > M.budget) {
          var keep = new Set(), spent = 0;
          D.CONTROLS.slice().sort(function (a, c) { return a.cost - c.cost; }).forEach(function (c) { if (S.selected.has(c.id) && spent + c.cost <= M.budget) { keep.add(c.id); spent += c.cost; } });
          setSelected(keep);
        } else { renderControls(); renderImpactBar(); renderSuggest(); renderSummary(); S.dirty = true; if (S.page === 'analyze') renderAnalyze(); }
      });
    });
    var ap = $('appetite');
    ap.value = appetiteToSlider(S.appetite);
    ap.addEventListener('input', function () { S.appetite = sliderToAppetite(+ap.value); renderLEC(false); renderLedger(); renderSummary(); });
    $('open-report').addEventListener('click', openReport);
    $('close-report').addEventListener('click', closeReport);
    $('print-report').addEventListener('click', function () { document.body.classList.add('printing'); window.print(); });
    window.addEventListener('afterprint', function () { document.body.classList.remove('printing'); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('report-view').hidden) closeReport(); });

    var rt, lastW = window.innerWidth;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () {
        if (window.innerWidth === lastW) return; lastW = window.innerWidth;
        if (S.page === 'analyze' && S.idx && S.cur) { renderFrontier(false); renderLEC(false); renderTornado(false); } else S.dirty = true;
      }, 180);
    });

    renderMethod(); renderRunMeta();
    buildIndex(function () {
      renderControls(); renderImpactBar(); renderSuggest(); renderSummary(); renderLeaderboard();
      scheduleSim(); emit();
      var h = (location.hash || '').slice(1); if (h && h !== 'simulate') go(h, { keepScroll: true });
    });
  }

  window.NP = { D: D, E: E, S: S, money: money, moneyFull: moneyFull, go: go, on: function (f) { listeners.push(f); } };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
