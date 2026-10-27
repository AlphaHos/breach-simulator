/* NabuPay Breach Simulator — UI layer */
(function () {
  'use strict';
  var D = window.BSData, E = window.BSEngine;

  var state = {
    selected: new Set(),
    mode: 'open',          // 'open' | 'budget'
    attack: 'ransomware',
    running: false,
    lastAssess: null
  };

  var COLORS = {
    secure: '#f4f1e8', exposed: '#b5771d', impacted: '#9a2f2a',
    contained: '#2f6f8f', protected: '#1f6f5c', edge: '#e7e0cc', external: '#dfd7c2'
  };
  var $ = function (id) { return document.getElementById(id); };
  var money = function (v) {
    v = Math.round(v);
    if (Math.abs(v) >= 1e6) return '$' + (v / 1e6).toFixed(2) + 'M';
    if (Math.abs(v) >= 1e3) return '$' + Math.round(v / 1e3) + 'K';
    return '$' + v.toLocaleString();
  };
  var moneyFull = function (v) { return '$' + Math.round(v).toLocaleString(); };

  /* ---------------- controls ---------------- */
  var TREAT = { mitigate: 'Mitigate (reduce)', transfer: 'Transfer (share)', avoid: 'Avoid (eliminate)', accept: 'Accept (retain)' };

  function renderControls() {
    var host = $('controls'); host.innerHTML = '';
    var groups = {};
    D.CONTROLS.forEach(function (c) { (groups[c.treatment] = groups[c.treatment] || []).push(c); });
    Object.keys(TREAT).forEach(function (tr) {
      if (!groups[tr]) return;
      var g = document.createElement('div'); g.className = 'treat-group';
      g.innerHTML = '<p class="legend">' + TREAT[tr] + '</p>';
      groups[tr].forEach(function (c) {
        var on = state.selected.has(c.id);
        var row = document.createElement('label');
        row.className = 'control' + (on ? ' on' : '');
        row.innerHTML =
          '<input type="checkbox" ' + (on ? 'checked' : '') + ' data-id="' + c.id + '">' +
          '<span><span class="nm">' + c.name + '</span>' +
          '<span class="q">' + c.why + '</span></span>' +
          '<span class="cost">' + money(c.cost) + '<br><span class="meta">/yr</span></span>';
        g.appendChild(row);
      });
      host.appendChild(g);
    });
    host.querySelectorAll('input[type=checkbox]').forEach(function (cb) {
      cb.addEventListener('change', function () {
        var id = cb.getAttribute('data-id');
        if (cb.checked) {
          if (state.mode === 'budget' && projectedCost(id) > D.MODEL.budget) {
            cb.checked = false; flashBudget(); return;
          }
          state.selected.add(id);
        } else state.selected.delete(id);
        renderControls(); recompute();
      });
    });
  }
  function projectedCost(addId) {
    var c = 0; state.selected.forEach(function (id) { c += ctrl(id).cost; });
    if (addId && !state.selected.has(addId)) c += ctrl(addId).cost;
    return c;
  }
  function ctrl(id) { for (var i = 0; i < D.CONTROLS.length; i++) if (D.CONTROLS[i].id === id) return D.CONTROLS[i]; }

  function renderBudget() {
    var bar = $('budgetbar');
    bar.hidden = state.mode !== 'budget';
    if (state.mode !== 'budget') return;
    var spent = projectedCost();
    var pct = Math.min(100, spent / D.MODEL.budget * 100);
    var fill = $('budgetfill');
    fill.style.width = pct + '%';
    fill.classList.toggle('over', spent > D.MODEL.budget);
    $('budgetspent').textContent = moneyFull(spent) + ' committed';
    $('budgetcap').textContent = 'cap ' + moneyFull(D.MODEL.budget);
  }
  function flashBudget() {
    var bar = $('budgetbar'); if (!bar) return;
    bar.style.transition = 'none'; bar.style.outline = '2px solid var(--seal)';
    setTimeout(function () { bar.style.outline = 'none'; }, 350);
  }

  /* ---------------- scenarios ---------------- */
  function renderScenarios() {
    var host = $('scenarios'); host.innerHTML = '';
    D.ATTACKS.forEach(function (a) {
      var b = document.createElement('button');
      b.className = 'scn' + (a.id === state.attack ? ' on' : '');
      b.innerHTML = '<div class="t">' + a.name + '</div><div class="d">' + a.short + '</div>';
      b.addEventListener('click', function () { state.attack = a.id; renderScenarios(); resetMap(); });
      host.appendChild(b);
    });
  }

  /* ---------------- map ---------------- */
  var SVGNS = 'http://www.w3.org/2000/svg';
  var mapEls = {};
  function layout() {
    return window.innerWidth < 700
      ? { vb: '0 0 400 720', key: 'm', w: 150, h: 40, fs: 9 }
      : { vb: '0 0 1000 560', key: 'd', w: 150, h: 54, fs: 10 };
  }
  function el(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function renderMap() {
    var svg = $('map'); svg.innerHTML = ''; mapEls = {};
    var L = layout(); svg.setAttribute('viewBox', L.vb);
    var pos = {}; D.ASSETS.forEach(function (a) { pos[a.id] = a[L.key]; });

    // zone bands (desktop only, subtle)
    if (L.key === 'd') {
      var bands = [['dmz', 180, 360], ['staff', 400, 360], ['core', 630, 360], ['vault', 850, 360]];
      bands.forEach(function (b) {
        svg.appendChild(el('text', { x: b[1] + 75, y: 24, 'text-anchor': 'middle', class: 'zone-label' })).textContent = D.ZONES[b[0]].label;
      });
    }

    // links
    D.LINKS.forEach(function (lk) {
      var u = pos[lk[0]], v = pos[lk[1]]; if (!u || !v) return;
      var ux = u[0] + L.w / 2, uy = u[1] + L.h / 2, vx = v[0] + L.w / 2, vy = v[1] + L.h / 2;
      var line = el('path', { d: 'M' + ux + ',' + uy + ' L' + vx + ',' + vy, class: 'edge-line' + (lk[2] ? ' legit' : '') });
      line.setAttribute('data-u', lk[0]); line.setAttribute('data-v', lk[1]);
      svg.appendChild(line);
    });

    // assets
    D.ASSETS.forEach(function (a) {
      var p = pos[a.id]; if (!p) return;
      var g = el('g', { transform: 'translate(' + p[0] + ',' + p[1] + ')' });
      var isExt = a.kind === 'external';
      var rect = el('rect', {
        class: 'asset-rect', x: 0, y: 0, width: L.w, height: L.h, rx: isExt ? 20 : 3,
        fill: a.kind === 'external' ? COLORS.external : (a.kind === 'edge' ? COLORS.edge : COLORS.secure),
        stroke: a.critical ? '#15233b' : '#c9bfa6', 'stroke-width': a.critical ? 1.6 : 1
      });
      g.appendChild(rect);
      var nm = el('text', { x: 8, y: 19, class: 'asset-name', 'font-size': L.fs });
      nm.textContent = a.name; g.appendChild(nm);
      var sub = el('text', { x: 8, y: L.h - 8, class: 'asset-sub' });
      sub.textContent = a.critical ? 'critical service' : (a.records ? a.records.toLocaleString() + ' records' : (a.count ? a.count + ' hosts' : D.ZONES[a.zone] ? D.ZONES[a.zone].label : ''));
      g.appendChild(sub);
      svg.appendChild(g);
      mapEls[a.id] = { rect: rect, g: g };
    });
    $('company-hint').textContent = D.COMPANY.employees + ' staff · ' + D.COMPANY.customers.toLocaleString() + ' customers · $' + (D.COMPANY.dailyVolumeUSD / 1e6) + 'M/day';
  }
  function paint(id, stateName) {
    var m = mapEls[id]; if (!m) return;
    m.rect.setAttribute('fill', COLORS[stateName] || COLORS.secure);
    if (stateName === 'impacted' || stateName === 'exposed') m.rect.setAttribute('stroke', '#15233b');
  }
  function resetMap() {
    D.ASSETS.forEach(function (a) {
      var base = a.kind === 'external' ? 'external' : (a.kind === 'edge' ? 'edge' : 'secure');
      if (mapEls[a.id]) mapEls[a.id].rect.setAttribute('fill', COLORS[base]);
    });
    // mark protected assets (those shielded by selected controls) with a green hint
    if (state.selected.has('novpn')) paint('vpn', 'protected');
    $('log').innerHTML = '<div class="muted" style="padding:6px 0">Launch the attack to see the incident unfold.</div>';
    setPhases(-1);
    $('runstatus').textContent = '';
  }

  /* ---------------- phases (NIST IR lifecycle) ---------------- */
  var PHASES = ['Preparation', 'Detection', 'Containment', 'Eradication', 'Recovery'];
  function renderPhaseTrack() {
    var t = $('phasetrack'); t.innerHTML = '';
    PHASES.forEach(function (p) {
      var d = document.createElement('div'); d.className = 'phase';
      d.innerHTML = '<div class="bar"></div><div class="nm">' + p + '</div>';
      t.appendChild(d);
    });
  }
  function setPhases(upto) {
    var ch = $('phasetrack').children;
    for (var i = 0; i < ch.length; i++) ch[i].classList.toggle('active', i <= upto);
  }

  /* ---------------- run / animate ---------------- */
  function tagClass(tactic) {
    if (!tactic) return '';
    if (tactic.indexOf('Initial') === 0) return 'access';
    if (tactic.indexOf('Lateral') === 0) return 'lateral';
    if (tactic === 'Detection') return 'detect';
    if (tactic === 'Containment') return 'contain';
    if (tactic === 'Impact') return 'impact';
    if (tactic === 'Exfiltration') return 'impact';
    if (tactic === 'Recovery') return 'recover';
    return '';
  }
  function logRow(ev) {
    var row = document.createElement('div'); row.className = 'row';
    var tag = ev.tactic ? '<span class="tag ' + tagClass(ev.tactic) + '">' + ev.tactic + '</span>' : '';
    row.innerHTML = '<span class="h">' + (ev.hour != null ? ev.hour + 'h' : '—') + '</span>' +
      '<span class="tx">' + tag + ev.text + '</span>';
    return row;
  }

  function run() {
    if (state.running) return;
    resetMap();
    state.running = true; $('runbtn').disabled = true; $('resetbtn').disabled = true;
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    var trace = E.demoRun(D, Array.from(state.selected), state.attack);
    var log = $('log'); log.innerHTML = '';
    var assetState = {};

    // group events by step (hour); null-hour impact/recovery events form the final step
    var steps = {}; var order = [];
    trace.events.forEach(function (ev) {
      var key = ev.hour == null ? 'final' : ev.hour;
      if (!steps[key]) { steps[key] = []; order.push(key); }
      steps[key].push(ev);
    });
    // ensure 'final' is last
    order = order.filter(function (k) { return k !== 'final'; }).sort(function (a, b) { return a - b; });
    if (steps['final']) order.push('final');

    var i = 0;
    var stepDelay = reduced ? 0 : 520;
    var phaseSeen = 0;   // highest NIST phase reached so far (monotonic)

    function step() {
      if (i >= order.length) { finishRun(trace); return; }
      var key = order[i], evs = steps[key];
      evs.forEach(function (ev) {
        log.appendChild(logRow(ev));
        // NIST phase mapping (monotonic)
        if (ev.tactic === 'Detection') phaseSeen = Math.max(phaseSeen, 1);
        else if (ev.tactic === 'Containment') phaseSeen = Math.max(phaseSeen, 2);
        else if (ev.tactic === 'Impact' || ev.tactic === 'Exfiltration') phaseSeen = Math.max(phaseSeen, 3);
        else if (ev.tactic === 'Recovery') phaseSeen = Math.max(phaseSeen, 4);
        // asset colouring
        if (ev.asset && ev.state) {
          var s = (ev.state === 'offline' || ev.state === 'safe') ? 'protected' :
            ev.state === 'held' ? 'secure' : ev.state;
          if (s === 'exposed' && assetState[ev.asset] === 'impacted') s = 'impacted';
          assetState[ev.asset] = s; paint(ev.asset, s);
        }
      });
      setPhases(phaseSeen);
      log.scrollTop = log.scrollHeight;
      i++;
      setTimeout(step, stepDelay);
    }

    setPhases(0);   // preparation lit as the incident opens
    step();
  }

  function finishRun(trace) {
    // mark impacted assets firmly
    trace.impactedIds.forEach(function (id) { paint(id, 'impacted'); });
    if (!trace.breached) { $('runstatus').textContent = 'Attack contained at the perimeter.'; setPhases(2); }
    else {
      var l = trace.loss;
      $('runstatus').innerHTML = 'Incident net loss: <strong>' + moneyFull(l.net) + '</strong>' +
        (l.insured > 0 ? ' (insurance recovered ' + money(l.insured) + ')' : '') +
        (trace.outageHours ? ' · ' + trace.outageHours + 'h outage' : '');
      setPhases(trace.containHour ? 4 : 3);
    }
    state.running = false; $('runbtn').disabled = false; $('resetbtn').disabled = false;
  }

  /* ---------------- metrics / counters ---------------- */
  function recompute() {
    renderBudget();
    var a = E.assess(D, Array.from(state.selected));
    state.lastAssess = a;
    renderCounters(a); renderHeat(a); renderMasthead(a);
    // reflect protection hints on the (idle) map
    if (!state.running) {
      if (state.selected.has('novpn')) paint('vpn', 'protected'); else {
        var vpn = D.ASSETS.find(function (x) { return x.id === 'vpn'; });
        if (mapEls.vpn) mapEls.vpn.rect.setAttribute('fill', COLORS.edge);
      }
    }
  }
  function renderMasthead(a) {
    $('mast-ale').textContent = money(a.aleNow);
    $('mast-red').textContent = a.cost > 0 ? Math.round(a.reduction * 100) + '%' : '0%';
  }
  function scoreRing(score) {
    var r = 26, c = 2 * Math.PI * r, off = c * (1 - score / 100);
    var col = score >= 80 ? '#1f6f5c' : score >= 55 ? '#a9832f' : '#9a2f2a';
    return '<svg viewBox="0 0 64 64" width="64" height="64">' +
      '<circle cx="32" cy="32" r="' + r + '" fill="none" stroke="#ddd5c0" stroke-width="7"/>' +
      '<circle cx="32" cy="32" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="7" stroke-linecap="round" ' +
      'stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + off.toFixed(1) + '" transform="rotate(-90 32 32)"/></svg>';
  }
  function renderCounters(a) {
    var host = $('counters');
    var rosi = a.cost > 0 ? Math.round(a.rosi * 100) + '%' : '—';
    var effNote = a.cost > 0 ? ('$' + a.efficiency.toFixed(1) + ' risk averted per $1 spent') : 'no controls selected';
    host.innerHTML =
      '<div class="counter hero"><div class="k">Annual expected loss (ALE)</div>' +
        '<div class="v danger">' + moneyFull(a.aleNow) + '</div>' +
        '<div class="note">inherent ' + money(a.aleBase) + ' · ' +
        '<span class="delta ' + (a.aleNow < a.aleBase ? 'down' : 'up') + '">▼ ' + Math.round(a.reduction * 100) + '%</span></div></div>' +

      '<div class="counter"><div class="k">Control spend</div>' +
        '<div class="v">' + moneyFull(a.cost) + '<span class="note" style="font-size:11px">/yr</span></div>' +
        '<div class="note">' + a.selected.length + ' controls selected</div></div>' +

      '<div class="counter"><div class="k">Total cost of risk</div>' +
        '<div class="v">' + moneyFull(a.tcorNow) + '</div>' +
        '<div class="note">spend + residual ALE · was ' + money(a.tcorBase) + '</div></div>' +

      '<div class="counter"><div class="k">Return on security investment</div>' +
        '<div class="v ' + (a.rosi >= 0 ? 'safe' : 'danger') + '">' + rosi + '</div>' +
        '<div class="note">' + effNote + '</div></div>' +

      '<div class="counter"><div class="k">Security score</div>' +
        '<div class="score-ring">' + scoreRing(a.score) +
        '<div class="lbl"><div class="n">' + a.score + '</div><div class="c">out of 100' +
        (a.overBudget > 0 ? ' · over budget' : '') + '</div></div></div></div>';
  }

  /* ---------------- heat map ---------------- */
  function heatColor(score) {
    // score = like × imp (1..25)
    if (score >= 15) return '#9a2f2a';
    if (score >= 9) return '#b5771d';
    if (score >= 4) return '#a9832f';
    return '#1f6f5c';
  }
  function renderHeat(a) {
    var host = $('heatwrap');
    var rows = a.scenarios.map(function (s) {
      var bi = s.likeBase * s.impBase, ni = s.likeNow * s.impNow;
      return '<tr><td style="text-align:left;font-weight:600">' + s.name + '</td>' +
        '<td class="cell"><span class="tok" style="background:' + heatColor(bi) + '">' + bi + '</span></td>' +
        '<td style="color:#8795a8">→</td>' +
        '<td class="cell"><span class="tok" style="background:' + heatColor(ni) + '">' + ni + '</span></td>' +
        '<td style="text-align:right;font-family:var(--mono);font-size:10.5px">' + money(s.aleBase) + ' → <strong>' + money(s.aleNow) + '</strong></td></tr>';
    }).join('');
    host.innerHTML = '<table class="heat"><thead><tr><th style="text-align:left">Scenario</th><th>Inherent</th><th></th><th>Residual</th><th style="text-align:right">Annual loss</th></tr></thead><tbody>' +
      rows + '</tbody></table>' +
      '<p class="muted" style="margin-top:8px">Risk score = likelihood (1–5) × impact (1–5). Inherent = before controls; residual = after your selected controls.</p>';
  }

  /* ---------------- sources ---------------- */
  function renderSources() {
    var host = $('sources');
    host.innerHTML = Object.keys(D.SOURCES).map(function (k) {
      var s = D.SOURCES[k];
      return '<li><span class="n">' + s.title + '</span> — <a href="' + s.url + '" target="_blank" rel="noopener">link</a>' +
        '<span class="note">' + s.note + '</span></li>';
    }).join('');
  }

  /* ---------------- leaderboard (local; server-ranked in phase 2) ---------------- */
  var LB_KEY = 'nabupay_lb_v1';
  function loadLB() { try { return JSON.parse(localStorage.getItem(LB_KEY)) || []; } catch (e) { return []; } }
  function saveLB(list) { try { localStorage.setItem(LB_KEY, JSON.stringify(list)); } catch (e) {} }
  function renderLeaderboard() {
    var host = $('leaderboard');
    var list = loadLB().sort(function (x, y) { return y.score - x.score || x.cost - y.cost; }).slice(0, 8);
    var a = state.lastAssess;
    var rows = list.map(function (r, i) {
      return '<tr class="' + (r.you ? 'you' : '') + '"><td class="rank">' + (i + 1) + '</td><td>' + escapeHtml(r.name) +
        '<div class="muted">' + r.mode + ' · ' + money(r.cost) + '/yr</div></td><td class="sc">' + r.score + '</td></tr>';
    }).join('');
    host.innerHTML = '<p class="legend" style="font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#8795a8;border-bottom:1px solid #ddd5c0;padding-bottom:4px">Leaderboard · lowest cost, highest score</p>' +
      '<table class="lb"><tbody>' + (rows || '<tr><td class="muted" style="padding:10px 0">No scores yet. Submit yours.</td></tr>') + '</tbody></table>' +
      '<div class="name-entry"><input id="lbname" maxlength="24" placeholder="Your name or nickname">' +
      '<button class="btn" id="lbsubmit">Submit score ' + (a ? a.score : 0) + '</button></div>' +
      '<p class="muted" style="margin-top:6px">Scores are saved on this device. In the online version, ranking is verified on the server from your chosen controls, so the board cannot be gamed.</p>';
    var btn = $('lbsubmit');
    if (btn) btn.addEventListener('click', function () {
      var nm = ($('lbname').value || '').trim(); if (!nm) { $('lbname').focus(); return; }
      var cur = state.lastAssess; if (!cur) return;
      var list = loadLB().map(function (r) { r.you = false; return r; });
      list.push({ name: nm, score: cur.score, cost: cur.cost, mode: state.mode, you: true, ts: Date.now() });
      saveLB(list); renderLeaderboard();
    });
  }
  function escapeHtml(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

  /* ---------------- report ---------------- */
  function buildReport() {
    var a = state.lastAssess || E.assess(D, Array.from(state.selected));
    var selCtrls = D.CONTROLS.filter(function (c) { return state.selected.has(c.id); });
    var srcHtml = Object.keys(D.SOURCES).map(function (k, i) {
      var s = D.SOURCES[k]; return '<li id="src-' + k + '">' + s.title + '. <a href="' + s.url + '">' + s.url + '</a></li>';
    }).join('');
    var regRows = a.scenarios.map(function (s) {
      return '<tr><td>' + s.name + '</td><td>' + s.aro + '/yr</td>' +
        '<td>' + (s.likeBase) + '×' + (s.impBase) + ' = <b>' + (s.likeBase * s.impBase) + '</b></td>' +
        '<td>' + moneyFull(s.aleBase) + '</td>' +
        '<td>' + (s.likeNow) + '×' + (s.impNow) + ' = <b>' + (s.likeNow * s.impNow) + '</b></td>' +
        '<td>' + moneyFull(s.aleNow) + '</td></tr>';
    }).join('');
    var ctrlRows = selCtrls.map(function (c) {
      return '<tr><td>' + c.name + '</td><td>' + c.treatment + '</td><td>' + moneyFull(c.cost) + '</td><td>' + c.why + '</td></tr>';
    }).join('') || '<tr><td colspan="4" style="color:#888">No controls selected — inherent risk only.</td></tr>';
    var attackTactics = D.ATTACKS.map(function (at) {
      var techs = {};
      at.entry.forEach(function (e) { if (e.technique) techs[e.technique] = D.TECHNIQUES[e.technique] || e.technique; });
      var list = Object.keys(techs).map(function (t) { return t + ' (' + techs[t] + ')'; }).join('; ');
      return '<tr><td>' + at.name + '</td><td>' + list + '</td></tr>';
    }).join('');

    var w = window.open('', '_blank');
    if (!w) { alert('Allow pop-ups to open the report.'); return; }
    var css = 'body{font:13px/1.5 Georgia,serif;color:#15233b;max-width:820px;margin:28px auto;padding:0 20px}' +
      'h1{font-size:24px;border-bottom:2px solid #15233b;padding-bottom:6px;margin-bottom:2px}' +
      'h2{font-size:15px;margin-top:26px;border-bottom:1px solid #c9bfa6;padding-bottom:3px}' +
      '.sub{color:#666;font-size:12px}table{width:100%;border-collapse:collapse;margin-top:8px;font-size:11.5px}' +
      'th,td{border:1px solid #c9bfa6;padding:5px 7px;text-align:left;vertical-align:top}th{background:#ebe6d6}' +
      '.kpi{display:flex;gap:18px;margin-top:10px;flex-wrap:wrap}.kpi div{flex:1;min-width:120px;border:1px solid #c9bfa6;padding:8px}' +
      '.kpi .n{font-size:20px;font-weight:bold}.kpi .l{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#666}' +
      'ol{font-size:11px}a{color:#0f4538}@media print{body{margin:0}.noprint{display:none}}' +
      '.btn{background:#15233b;color:#fff;border:0;padding:8px 14px;border-radius:2px;cursor:pointer;font:600 12px sans-serif}';
    w.document.write('<!doctype html><html><head><meta charset="utf-8"><title>NabuPay — Risk & Incident Report</title><style>' + css + '</style></head><body>' +
      '<div class="noprint" style="text-align:right"><button class="btn" onclick="window.print()">Print / Save PDF</button></div>' +
      '<h1>NabuPay — Cyber Risk &amp; Incident Report</h1>' +
      '<div class="sub">Fictional payment company · ' + D.COMPANY.customers.toLocaleString() + ' customers · $' + (D.COMPANY.dailyVolumeUSD / 1e6) + 'M daily volume · generated ' + new Date().toISOString().slice(0, 10) + '</div>' +

      '<div class="kpi">' +
        '<div><div class="l">Inherent ALE</div><div class="n">' + moneyFull(a.aleBase) + '</div></div>' +
        '<div><div class="l">Residual ALE</div><div class="n">' + moneyFull(a.aleNow) + '</div></div>' +
        '<div><div class="l">Control spend</div><div class="n">' + moneyFull(a.cost) + '</div></div>' +
        '<div><div class="l">ROSI</div><div class="n">' + (a.cost > 0 ? Math.round(a.rosi * 100) + '%' : '—') + '</div></div>' +
        '<div><div class="l">Score</div><div class="n">' + a.score + '/100</div></div>' +
      '</div>' +

      '<h2>1. Risk register (inherent → residual)</h2>' +
      '<table><thead><tr><th>Scenario</th><th>ARO</th><th>Inherent risk</th><th>Inherent ALE</th><th>Residual risk</th><th>Residual ALE</th></tr></thead><tbody>' + regRows + '</tbody></table>' +
      '<p class="sub">Risk = likelihood(1–5) × impact(1–5). ALE = ARO × SLE, SLE estimated by Monte Carlo (1,200 runs). Methodology follows NIST SP 800-30 and FAIR.</p>' +

      '<h2>2. Risk treatment &amp; cost-benefit</h2>' +
      '<table><thead><tr><th>Control</th><th>Treatment</th><th>Annual cost</th><th>Basis</th></tr></thead><tbody>' + ctrlRows + '</tbody></table>' +
      '<p class="sub">Total cost of risk = control spend + residual ALE = ' + moneyFull(a.cost) + ' + ' + moneyFull(a.aleNow) + ' = <b>' + moneyFull(a.tcorNow) + '</b> (inherent ' + moneyFull(a.tcorBase) + ').</p>' +

      '<h2>3. Threat scenarios — MITRE ATT&CK mapping</h2>' +
      '<table><thead><tr><th>Scenario</th><th>Initial-access techniques (classification)</th></tr></thead><tbody>' + attackTactics + '</tbody></table>' +
      '<p class="sub">Scenarios are classified against the MITRE ATT&CK Enterprise matrix for reference; this is a risk model and contains no attack procedures.</p>' +

      '<h2>4. Incident response</h2>' +
      '<p>Detection and containment follow the NIST SP 800-61r3 lifecycle: Preparation → Detection &amp; Analysis → Containment, Eradication &amp; Recovery → Post-incident. Stronger detection controls (EDR, 24/7 SOC) shorten time-to-contain, which the model converts directly into lower outage hours and lower loss.</p>' +

      '<h2>Sources</h2><ol>' + srcHtml + '</ol>' +
      '<p class="sub">NabuPay is fictional and this report is an academic risk-modelling exercise. All figures are modelled from the sources above.</p>' +
      '</body></html>');
    w.document.close();
  }

  /* ---------------- wire up ---------------- */
  function init() {
    renderControls(); renderScenarios(); renderPhaseTrack(); renderMap(); renderSources();
    recompute(); renderLeaderboard(); resetMap();

    $('runbtn').addEventListener('click', run);
    $('resetbtn').addEventListener('click', function () { if (!state.running) resetMap(); });
    $('reportbtn').addEventListener('click', buildReport);
    $('printbtn').addEventListener('click', buildReport);

    $('modes').querySelectorAll('button').forEach(function (b) {
      b.addEventListener('click', function () {
        state.mode = b.getAttribute('data-mode');
        $('modes').querySelectorAll('button').forEach(function (x) { x.classList.toggle('on', x === b); });
        if (state.mode === 'budget' && projectedCost() > D.MODEL.budget) {
          // trim to fit budget, cheapest-first keep
          var keep = new Set(), spent = 0;
          D.CONTROLS.slice().sort(function (x, y) { return x.cost - y.cost; }).forEach(function (c) {
            if (state.selected.has(c.id) && spent + c.cost <= D.MODEL.budget) { keep.add(c.id); spent += c.cost; }
          });
          state.selected = keep; renderControls();
        }
        renderBudget(); recompute(); renderLeaderboard();
      });
    });

    var rt;
    window.addEventListener('resize', function () { clearTimeout(rt); rt = setTimeout(function () { renderMap(); recompute(); if (!state.running) resetMap(); }, 200); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
