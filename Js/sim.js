/* NabuPay Breach Simulator — incident replay on the asset map (defender view) */
(function () {
  'use strict';
  var NP = window.NP, D = NP.D, E = NP.E, S = NP.S, money = NP.money;
  var $ = function (id) { return document.getElementById(id); };
  var SVG = 'http://www.w3.org/2000/svg';

  var sim = { attack: 'ransomware', running: false, nodes: {}, layout: null, timer: null };
  var SHORT = {
    attacker: ['Threat source', 'Internet'], mail: ['Email gateway', 'Edge'], vpn: ['VPN gateway', 'Edge'], api: ['Payment API', 'Edge · critical'],
    support: ['Support PCs', '60 PCs'], finance: ['Finance PCs', '8 PCs'], dev: ['Engineering PCs', '25 PCs'], app: ['Wallet backend', 'critical'],
    dc: ['Domain controller', 'critical'], txdb: ['Transaction DB', '180K records'], vault: ['Card vault', '60K cards'], 'switch': ['Bank link', 'critical'],
    backup: ['Backup server', 'Backup']
  };
  var SCN = {
    ransomware: { t: 'Ransomware', d: 'Malware spreads from a phishing email and encrypts payment systems.' },
    intrusion: { t: 'Intrusion', d: 'An outsider gets in through an internet-facing system and reaches customer data.' },
    bec: { t: 'Phishing & BEC', d: 'A finance mailbox is taken over and used to request a fraudulent transfer.' }
  };
  var PHASES = ['Prepare', 'Detect', 'Contain', 'Eradicate', 'Recover'];   // NIST SP 800-61 lifecycle

  /* ------------------------------------------------ scenario picker */
  function renderScenarios() {
    var host = $('scenarios');
    host.innerHTML = D.ATTACKS.map(function (a) {
      var on = a.id === sim.attack;
      return '<button role="radio" aria-checked="' + on + '" class="' + (on ? 'on' : '') + '" data-scn="' + a.id + '">' + SCN[a.id].t + '</button>';
    }).join('');
    host.querySelectorAll('[data-scn]').forEach(function (b) {
      b.addEventListener('click', function () { if (sim.running) return; sim.attack = b.getAttribute('data-scn'); renderScenarios(); reset(); });
    });
    $('scn-desc').textContent = SCN[sim.attack].d;
  }

  /* ------------------------------------------------ map */
  function mk(tag, attrs, parent) {
    var e = document.createElementNS(SVG, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  // Phone labels: shorter names so the type can stay large on a 320px screen.
  var PHONE = {
    attacker: ['Threat source', 'Internet'], mail: ['Email', 'edge'], vpn: ['VPN', 'edge'], api: ['Payment API', 'critical'],
    support: ['Support', '60 PCs'], finance: ['Finance', '8 PCs'], dev: ['Engineering', '25 PCs'], app: ['Wallet app', 'critical'],
    dc: ['Domain ctrl.', 'critical'], txdb: ['Transactions', '180K records'], vault: ['Card vault', '60K cards'], 'switch': ['Bank link', 'critical'],
    backup: ['Backups', 'backup zone']
  };
  function chooseLayout() {
    var w = $('map-wrap').clientWidth || window.innerWidth;
    return w < 680
      ? { key: 'm', vb: [0, 0, 400, 730], w: 120, h: 56, fs: 16.5, sub: 15, zone: 0, names: PHONE }
      : { key: 'd', vb: [-40, -10, 1080, 580], w: 168, h: 62, fs: 18.5, sub: 16, zone: 17, names: SHORT };
  }
  function renderMap() {
    var svg = $('map'), L = chooseLayout();
    sim.layout = L; sim.nodes = {};
    svg.innerHTML = '';
    svg.setAttribute('viewBox', L.vb.join(' '));
    var pos = {}; D.ASSETS.forEach(function (a) { pos[a.id] = a[L.key]; });
    if (L.key === 'd') {
      [['Internet', 70], ['Edge (DMZ)', 250], ['Staff network', 470], ['Payment core', 700], ['Backup', 890]].forEach(function (z) {
        mk('text', { x: z[1], y: 22, 'text-anchor': 'middle', class: 'zone-label', style: 'font-size:' + L.zone + 'px' }, svg).textContent = z[0];
      });
    }
    var links = mk('g', {}, svg);
    D.LINKS.forEach(function (l) {
      var u = pos[l[0]], v = pos[l[1]];
      mk('line', { x1: u[0], y1: u[1], x2: v[0], y2: v[1], class: 'link' + (l[2] ? ' app' : '') }, links);
    });
    D.ASSETS.forEach(function (a) {
      var p = pos[a.id], lab = L.names[a.id] || [a.name, ''];
      var g = mk('g', { class: 'node' + (a.critical ? ' critical' : '') + (a.kind === 'external' ? ' source' : ''), transform: 'translate(' + p[0] + ',' + p[1] + ')' }, svg);
      var core = mk('g', { class: 'node-core' }, g);
      var rx = a.kind === 'external' ? L.h / 2 : 10;
      mk('rect', { class: 'node-ring', x: -L.w / 2, y: -L.h / 2, width: L.w, height: L.h, rx: rx }, core);
      mk('rect', { class: 'node-box', x: -L.w / 2, y: -L.h / 2, width: L.w, height: L.h, rx: rx }, core);
      var name = mk('text', { class: 'node-name', y: -3, style: 'font-size:' + L.fs + 'px' }, core); name.textContent = lab[0];
      var sub = mk('text', { class: 'node-sub', y: L.h * 0.33, style: 'font-size:' + L.sub + 'px' }, core); sub.textContent = lab[1];
      try { if (name.getComputedTextLength() > L.w - 14) { name.setAttribute('textLength', L.w - 14); name.setAttribute('lengthAdjust', 'spacingAndGlyphs'); } } catch (e) {}
      sim.nodes[a.id] = g;
    });
    restingStates();
  }
  function setState(id, st, bump) {
    var g = sim.nodes[id]; if (!g) return;
    if (st) g.setAttribute('data-state', st); else g.removeAttribute('data-state');
    if (bump) { g.classList.remove('bump'); void g.getBBox(); g.classList.add('bump'); }
  }
  function restingStates() {
    Object.keys(sim.nodes).forEach(function (id) { setState(id, null); });
    if (S.selected.has('novpn')) setState('vpn', 'protected');
    if (S.selected.has('backup')) setState('backup', 'protected');
    if (S.selected.has('token')) setState('vault', 'protected');
  }

  /* ------------------------------------------------ stepper, HUD */
  function renderStepper() { $('stepper').innerHTML = PHASES.map(function (p) { return '<div class="step"><i></i><span>' + p + '</span></div>'; }).join(''); }
  function setStep(n) { var s = $('stepper').children; for (var i = 0; i < s.length; i++) s[i].classList.toggle('done', i <= n); }
  function setPhase(key, label) { var h = $('hud-phase'); h.setAttribute('data-p', key); h.textContent = label; }
  function tween(el, from, to, ms, fmt) {
    var t0 = performance.now(), reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced || ms <= 0) { el.textContent = fmt(to); return; }
    (function f(t) {
      var k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3);
      el.textContent = fmt(from + (to - from) * e);
      if (k < 1) requestAnimationFrame(f);
    })(t0);
  }

  /* ------------------------------------------------ log */
  var KIND = { entry: 'access', spread: 'spread', detect: 'detect', contain: 'contain', impact: 'impact', recover: 'recover', prep: 'held' };
  var TAG = { access: 'Initial access', spread: 'Spread', detect: 'Detection', contain: 'Containment', impact: 'Impact', recover: 'Recovery', held: 'Defence' };
  function addLog(ev, lastHour) {
    var k = ev.tactic === 'Containment' ? 'contain' : ev.tactic === 'Exfiltration' ? 'impact' : (KIND[ev.phase] || 'held');
    var li = document.createElement('li'); li.className = 'tl-item'; li.setAttribute('data-k', k);
    li.innerHTML = '<span class="tl-time">' + (ev.hour == null ? lastHour : ev.hour) + 'h</span><span class="tl-rail"><i class="tl-dot"></i></span>' +
      '<div class="tl-body"><span class="tl-tag">' + TAG[k] + '</span><span class="tl-text"></span></div>';
    li.querySelector('.tl-text').textContent = ev.text;
    $('timeline').appendChild(li);
    $('timeline-empty').hidden = true;
  }

  /* ------------------------------------------------ run */
  function reset() {
    clearTimeout(sim.timer); sim.running = false;
    restingStates(); setStep(-1); setPhase('ready', 'Ready');
    $('hud-clock').textContent = '0 h'; $('hud-loss').textContent = '$0';
    $('timeline').innerHTML = ''; $('timeline-empty').hidden = false; $('result').innerHTML = '';
    var b = $('run'); b.disabled = false; b.classList.remove('busy'); $('reset').disabled = false;
  }

  function run() {
    if (sim.running) return;
    reset();
    sim.running = true;
    var btn = $('run'); btn.disabled = true; btn.classList.add('busy'); $('reset').disabled = true;
    var reduced = matchMedia('(prefers-reduced-motion: reduce)').matches, gap = reduced ? 0 : 650;
    var tr = E.demoRun(D, Array.from(S.selected), sim.attack);

    // group events into steps by hour; impact and recovery close the incident
    var steps = [], byHour = {}, tail = [];
    tr.events.forEach(function (ev) {
      if (ev.hour == null) { tail.push(ev); return; }
      if (!byHour[ev.hour]) { byHour[ev.hour] = []; steps.push(ev.hour); }
      byHour[ev.hour].push(ev);
    });
    steps.sort(function (a, b) { return a - b; });
    var seq = steps.map(function (h) { return { hour: h, evs: byHour[h] }; });
    var lastHour = steps.length ? steps[steps.length - 1] : 0;
    if (tail.length) seq.push({ hour: null, evs: tail });

    var stepN = 0, phaseN = 0, clock = 0;
    setStep(0); setPhase('attack', 'Incident open');
    function next() {
      if (!sim.running) return;
      if (stepN >= seq.length) { finish(tr, lastHour); return; }
      var s = seq[stepN++];
      if (s.hour != null) { tween($('hud-clock'), clock, s.hour, gap * .8, function (v) { return Math.round(v) + ' h'; }); clock = s.hour; }
      s.evs.forEach(function (ev) {
        addLog(ev, lastHour);
        if (ev.phase === 'detect') { phaseN = Math.max(phaseN, 1); setPhase('detect', 'Detected'); var sw = $('map-sweep'); sw.classList.remove('go'); void sw.offsetWidth; sw.classList.add('go'); }
        else if (ev.phase === 'contain' || ev.tactic === 'Containment') { phaseN = Math.max(phaseN, 2); setPhase('contain', 'Containing'); }
        else if (ev.phase === 'impact') { setPhase('impact', 'Business impact'); var w = $('map-wrap'); w.classList.remove('alarm'); void w.offsetWidth; w.classList.add('alarm'); }
        else if (ev.phase === 'recover') { phaseN = 4; setPhase('recover', 'Recovering'); }
        else if (ev.phase === 'prep') setPhase('held', 'Perimeter held');
        else setPhase('attack', 'Spreading');
        if (ev.asset && ev.state) {
          var st = ev.state === 'offline' || ev.state === 'safe' ? 'protected' : ev.state === 'held' ? null : ev.state;
          var cur = sim.nodes[ev.asset] && sim.nodes[ev.asset].getAttribute('data-state');
          if (!(cur === 'impacted' && st === 'exposed')) setState(ev.asset, st, true);
        }
      });
      setStep(phaseN);
      sim.timer = setTimeout(next, gap);
    }
    sim.timer = setTimeout(next, reduced ? 0 : 250);
  }

  function finish(tr, lastHour) {
    var contained = tr.containHour != null;
    if (contained) tr.exposedIds.forEach(function (id) {
      var g = sim.nodes[id]; if (g && g.getAttribute('data-state') === 'exposed') setState(id, 'contained', true);
    });
    tr.impactedIds.forEach(function (id) { if (D.ASSETS.find(function (a) { return a.id === id; }).critical || tr.attack === 'bec') setState(id, 'impacted'); });
    if (tr.breached) setStep(4);
    tween($('hud-loss'), 0, tr.loss.net, 1100, money);
    setPhase(tr.breached ? 'recover' : 'held', tr.breached ? 'Incident closed' : 'Perimeter held');
    renderResult(tr);
    sim.running = false;
    var b = $('run'); b.disabled = false; b.classList.remove('busy'); $('reset').disabled = false;
  }

  /* ------------------------------------------------ result */
  function renderResult(tr) {
    var L = tr.loss, affected = tr.exposedIds.length;
    var title, sub, good;
    if (!tr.breached) { good = true; title = 'Perimeter held'; sub = 'No NabuPay asset was exposed. Defences stopped every entry attempt.'; }
    else if (tr.attack === 'bec') { good = L.fraud === 0; title = good ? 'Fraud stopped' : 'Fraudulent transfer paid'; sub = 'A finance mailbox was compromised. Net loss ' + NP.moneyFull(L.net) + '.'; }
    else {
      good = L.net < 250000;
      if (tr.containHour != null) title = 'Contained after ' + tr.containHour + ' hours';
      else if (tr.attack === 'ransomware') title = tr.outageHours ? 'Systems encrypted, restored in ' + tr.outageHours + ' h' : 'Workstations encrypted, services kept running';
      else title = tr.dataStolen ? 'Customer data stolen before detection' : 'Intruder found no data';
      sub = affected + ' asset groups affected · net loss ' + NP.moneyFull(L.net) + '.';
    }
    var parts = [['Response', L.response, '#667085'], ['Rebuild', L.rebuild, '#98a2b3'], ['Outage', L.outage, '#e8762d'], ['Data', L.data, '#d3383f'], ['Fraud', L.fraud, '#7a2e98']].filter(function (p) { return p[1] > 0; });
    var gross = L.gross || 1;
    var aleNow = S.idx ? S.idx.ale[E.maskOf(D, S.selected)] : 0;
    $('result').innerHTML = '<div class="panel panel-pad result">' +
      '<div class="result-head"><div class="result-icon ' + (good ? 'good' : 'bad') + '"><svg><use href="#' + (good ? 'i-check' : 'i-alert') + '"/></svg></div><div><h3>' + title + '</h3><p>' + sub + '</p></div></div>' +
      (parts.length ? '<div class="stackbar">' + parts.map(function (p, i) { return '<span style="width:' + (p[1] / gross * 100) + '%;background:' + p[2] + ';animation-delay:' + (i * 90) + 'ms"></span>'; }).join('') + '</div>' +
        '<div class="stack-legend">' + parts.map(function (p) { return '<span><i style="background:' + p[2] + '"></i>' + p[0] + ' ' + money(p[1]) + '</span>'; }).join('') +
        (L.insured > 0 ? '<span><i style="background:#1f9d6b"></i>Insurance paid ' + money(L.insured) + '</span>' : '') + '</div>' : '') +
      '<dl class="facts">' +
        '<div><dt>Assets affected</dt><dd>' + affected + '</dd></div>' +
        '<div><dt>Detected</dt><dd>' + (tr.detectHour != null ? 'at ' + tr.detectHour + ' h' : !tr.breached ? '—' : tr.attack === 'bec' ? 'at payment' : tr.attack === 'ransomware' ? 'at encryption' : 'after the fact') + '</dd></div>' +
        '<div><dt>Outage</dt><dd>' + (tr.outageHours ? tr.outageHours + ' h' : '—') + '</dd></div>' +
        '<div><dt>Data stolen</dt><dd>' + (tr.dataStolen ? 'Yes' : 'No') + '</dd></div>' +
      '</dl>' +
      '<p class="section-note">This is one incident. Across all scenarios and their frequencies, your expected loss is ' + money(aleNow) + ' a year. <button class="link-btn" data-go="analyze">See the full distribution</button></p>' +
      '</div>';
  }

  /* ------------------------------------------------ wiring */
  function init() {
    renderScenarios(); renderStepper(); renderMap(); reset();
    $('run').addEventListener('click', run);
    $('reset').addEventListener('click', function () { if (!sim.running) reset(); });
    NP.on(function () { if (!sim.running) reset(); });
    var lastKey = sim.layout && sim.layout.key, rt;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () {
        var k = chooseLayout().key;
        if (k !== lastKey && !sim.running) { lastKey = k; renderMap(); reset(); }
      }, 180);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
