/*
 * Small dependency-free SVG charts. Each chart is drawn at the container's
 * real pixel width, so text stays 12–13px on every screen. Re-render on resize.
 */
(function (root) {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';

  function money(v) {
    var a = Math.abs(v);
    if (a >= 1e6) return '$' + (v / 1e6).toFixed(a >= 1e7 ? 0 : 1).replace(/\.0$/, '') + 'M';
    if (a >= 1e3) return '$' + Math.round(v / 1e3) + 'K';
    return '$' + Math.round(v);
  }
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, str, cls, anchor) {
    var t = el('text', { x: x, y: y, class: cls || 'ax-label', 'text-anchor': anchor || 'start' }, parent);
    t.textContent = str;
    return t;
  }
  function svgFor(host, h) {
    host.innerHTML = '';
    var w = Math.max(260, Math.floor(host.clientWidth || host.getBoundingClientRect().width || 320));
    var s = el('svg', { viewBox: '0 0 ' + w + ' ' + h, width: w, height: h, role: 'img' }, host);
    return { svg: s, w: w, h: h };
  }
  function logScale(d0, d1, r0, r1) {
    var a = Math.log10(d0), b = Math.log10(d1);
    var f = function (v) { return r0 + (Math.log10(Math.max(v, d0)) - a) / (b - a) * (r1 - r0); };
    f.invert = function (p) { return Math.pow(10, a + (p - r0) / (r1 - r0) * (b - a)); };
    return f;
  }
  function linScale(d0, d1, r0, r1) {
    var f = function (v) { return r0 + (v - d0) / (d1 - d0) * (r1 - r0); };
    f.invert = function (p) { return d0 + (p - r0) / (r1 - r0) * (d1 - d0); };
    return f;
  }
  function animatePath(p, on) {
    if (!on || !p.getTotalLength) return;
    var len = p.getTotalLength();
    p.style.setProperty('--len', len);
    p.classList.add('chart-draw');
  }

  /* ------------------------------------------------ loss exceedance curve */
  function lec(host, o) {
    var narrow = (host.clientWidth || 320) < 520;
    var c = svgFor(host, narrow ? 250 : 300), svg = c.svg, W = c.w, H = c.h;
    var m = { l: 44, r: 14, t: 12, b: 42 };
    var x0 = 1e4, x1 = 3e7;
    var X = logScale(x0, x1, m.l, W - m.r), Y = linScale(0, 1, H - m.b, m.t);
    var g = el('g', {}, svg);
    [0, .25, .5, .75, 1].forEach(function (p) {
      el('line', { x1: m.l, x2: W - m.r, y1: Y(p), y2: Y(p), class: 'ax', 'stroke-dasharray': p ? '2 4' : null }, g);
      text(g, m.l - 8, Y(p) + 4, Math.round(p * 100) + '%', 'ax-label', 'end');
    });
    var ticks = narrow ? [1e4, 1e5, 1e6, 1e7] : [1e4, 3e4, 1e5, 3e5, 1e6, 3e6, 1e7, 3e7];
    ticks.forEach(function (t) {
      el('line', { x1: X(t), x2: X(t), y1: H - m.b, y2: H - m.b + 5, class: 'ax' }, g);
      text(g, X(t), H - m.b + 18, money(t), 'ax-label', 'middle');
    });
    text(g, (m.l + W - m.r) / 2, H - 4, 'Annual loss (log scale)', 'ax-title', 'middle');

    var xs = []; for (var i = 0; i <= 90; i++) xs.push(Math.pow(10, Math.log10(x0) + i / 90 * (Math.log10(x1) - Math.log10(x0))));
    function pathFor(sim) { return xs.map(function (x, k) { return (k ? 'L' : 'M') + X(x).toFixed(1) + ',' + Y(o.exceed(sim, x)).toFixed(1); }).join(''); }
    if (o.current) {
      el('path', { d: pathFor(o.current) + 'L' + X(x1) + ',' + Y(0) + 'L' + X(x0) + ',' + Y(0) + 'Z', fill: 'rgba(35,71,201,.08)', class: o.animate ? 'chart-fade' : null }, svg);
    }
    if (o.inherent) {
      var pi = el('path', { d: pathFor(o.inherent), fill: 'none', stroke: '#98a2b3', 'stroke-width': 2.2, 'stroke-dasharray': '6 5' }, svg);
      if (o.animate) pi.classList.add('chart-fade');
    }
    if (o.current) animatePath(el('path', { d: pathFor(o.current), fill: 'none', stroke: '#2347c9', 'stroke-width': 3, 'stroke-linejoin': 'round' }, svg), o.animate);

    if (o.appetite) {
      var ax = X(o.appetite), ay = Y(o.tol);
      el('line', { x1: ax, x2: ax, y1: Y(1), y2: Y(0), stroke: '#d3383f', 'stroke-width': 1.6, 'stroke-dasharray': '4 4' }, svg);
      el('line', { x1: ax, x2: W - m.r, y1: ay, y2: ay, stroke: '#d3383f', 'stroke-width': 1.6 }, svg);
      el('rect', { x: ax, y: Y(1), width: Math.max(0, W - m.r - ax), height: Math.max(0, ay - Y(1)), fill: 'rgba(211,56,63,.05)' }, svg);
      el('circle', { cx: ax, cy: ay, r: 4.5, fill: '#fff', stroke: '#d3383f', 'stroke-width': 2 }, svg);
      var lbl = text(svg, ax + (ax > W * .7 ? -6 : 6), Y(1) + 14, 'Appetite', 'ax-title', ax > W * .7 ? 'end' : 'start');
      lbl.style.fill = '#b0262c';
    }

    // readout
    var guide = el('line', { y1: Y(1), y2: Y(0), stroke: '#101828', 'stroke-width': 1, opacity: 0 }, svg);
    var d1 = el('circle', { r: 4.5, fill: '#2347c9', opacity: 0 }, svg), d0 = el('circle', { r: 4, fill: '#98a2b3', opacity: 0 }, svg);
    var hit = el('rect', { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, fill: 'transparent' }, svg);
    function move(evt) {
      var r = svg.getBoundingClientRect(), px = (evt.clientX - r.left) * (W / r.width);
      px = Math.max(m.l, Math.min(W - m.r, px));
      var x = X.invert(px), pc = o.current ? o.exceed(o.current, x) : 0, pb = o.inherent ? o.exceed(o.inherent, x) : 0;
      guide.setAttribute('x1', px); guide.setAttribute('x2', px); guide.setAttribute('opacity', .35);
      d1.setAttribute('cx', px); d1.setAttribute('cy', Y(pc)); d1.setAttribute('opacity', 1);
      d0.setAttribute('cx', px); d0.setAttribute('cy', Y(pb)); d0.setAttribute('opacity', 1);
      if (o.onRead) o.onRead(x, pc, pb);
    }
    hit.addEventListener('pointermove', move);
    hit.addEventListener('pointerdown', move);
  }

  /* ------------------------------------------------ efficient frontier */
  function frontier(host, o) {
    var narrow = (host.clientWidth || 320) < 520;
    var c = svgFor(host, narrow ? 260 : 320), svg = c.svg, W = c.w, H = c.h;
    var m = { l: 50, r: 16, t: 14, b: 42 };
    var idx = o.idx, n = idx.ale.length, maxC = 0, minA = Infinity, maxA = 0;
    for (var i = 0; i < n; i++) { if (idx.cost[i] > maxC) maxC = idx.cost[i]; if (idx.ale[i] > 0 && idx.ale[i] < minA) minA = idx.ale[i]; if (idx.ale[i] > maxA) maxA = idx.ale[i]; }
    var y0 = Math.pow(10, Math.floor(Math.log10(Math.max(1000, minA)))), y1 = Math.pow(10, Math.ceil(Math.log10(maxA)));
    var X = linScale(0, Math.ceil(maxC / 50000) * 50000, m.l, W - m.r), Y = logScale(y0, y1, H - m.b, m.t);
    var g = el('g', {}, svg);
    for (var t = y0; t <= y1; t *= 10) {
      el('line', { x1: m.l, x2: W - m.r, y1: Y(t), y2: Y(t), class: 'ax', 'stroke-dasharray': '2 4' }, g);
      text(g, m.l - 8, Y(t) + 4, money(t), 'ax-label', 'end');
    }
    var step = narrow ? 100000 : 50000;
    for (var xv = 0; xv <= maxC + 1; xv += step) {
      el('line', { x1: X(xv), x2: X(xv), y1: H - m.b, y2: H - m.b + 5, class: 'ax' }, g);
      text(g, X(xv), H - m.b + 18, money(xv), 'ax-label', 'middle');
    }
    text(g, (m.l + W - m.r) / 2, H - 4, 'Annual control spend', 'ax-title', 'middle');

    if (o.budget) {
      var bx = X(o.budget);
      el('rect', { x: bx, y: m.t, width: Math.max(0, W - m.r - bx), height: H - m.t - m.b, fill: 'rgba(16,24,40,.04)' }, svg);
      el('line', { x1: bx, x2: bx, y1: m.t, y2: H - m.b, stroke: '#667085', 'stroke-width': 1.4, 'stroke-dasharray': '5 4' }, svg);
      text(svg, bx + 5, m.t + 12, 'Over budget', 'ax-label');
    }
    var d = '';
    for (var k = 0; k < n; k++) d += 'M' + X(idx.cost[k]).toFixed(1) + ',' + Y(Math.max(idx.ale[k], y0)).toFixed(1) + 'h0';
    el('path', { d: d, stroke: '#b9c1ce', 'stroke-width': narrow ? 3.2 : 4, 'stroke-linecap': 'round', opacity: .6, class: o.animate ? 'chart-fade' : null }, svg);
    var pd = idx.pareto.map(function (mk, j) { return (j ? 'L' : 'M') + X(idx.cost[mk]).toFixed(1) + ',' + Y(Math.max(idx.ale[mk], y0)).toFixed(1); }).join('');
    animatePath(el('path', { d: pd, fill: 'none', stroke: '#2347c9', 'stroke-width': 2.4, 'stroke-linejoin': 'round' }, svg), o.animate);

    function marker(mk, fill, ring, label, dy) {
      var cx = X(idx.cost[mk]), cy = Y(Math.max(idx.ale[mk], y0));
      el('circle', { cx: cx, cy: cy, r: 11, fill: ring }, svg);
      el('circle', { cx: cx, cy: cy, r: 6.5, fill: fill, stroke: '#fff', 'stroke-width': 2 }, svg);
      var right = cx < W * .62;
      var tl = text(svg, cx + (right ? 14 : -14), cy + dy, label, 'ax-title', right ? 'start' : 'end');
      tl.setAttribute('paint-order', 'stroke'); tl.setAttribute('stroke', '#fff'); tl.setAttribute('stroke-width', 4);
    }
    marker(o.optimum, '#b98a2e', 'rgba(185,138,46,.22)', 'Optimum', -10);
    marker(o.you, '#101828', 'rgba(35,71,201,.22)', 'You', o.you === o.optimum ? 14 : 4);
  }

  /* ------------------------------------------------ tornado (sensitivity) */
  function tornado(host, o) {
    var rows = o.rows, rowH = 50, top = 8;
    var c = svgFor(host, top + rows.length * rowH + 26), svg = c.svg, W = c.w;
    var m = { l: 8, r: 8 };
    var lo = o.base, hi = o.base;
    rows.forEach(function (r) { lo = Math.min(lo, r.low, r.high); hi = Math.max(hi, r.low, r.high); });
    var pad = (hi - lo) * .14 || 1;
    var X = linScale(Math.max(0, lo - pad), hi + pad, m.l, W - m.r), bx = X(o.base);
    rows.forEach(function (r, i) {
      var y = top + i * rowH;
      var lt = text(svg, m.l, y + 13, r.label, 'ax-title'); lt.setAttribute('paint-order', 'stroke'); lt.setAttribute('stroke', '#fff'); lt.setAttribute('stroke-width', 4);
      el('line', { x1: bx, x2: bx, y1: y + 17, y2: y + 37, stroke: '#101828', 'stroke-width': 1.4 }, svg);
      var a = Math.min(r.low, r.high), b = Math.max(r.low, r.high), by = y + 20;
      // segment between base and the value at the input's minimum / maximum
      el('rect', { x: X(Math.min(r.low, o.base)), y: by, width: Math.max(1, Math.abs(X(r.low) - bx)), height: 14, rx: 3, fill: '#a9b8e8' }, svg);
      el('rect', { x: X(Math.min(r.high, o.base)), y: by, width: Math.max(1, Math.abs(X(r.high) - bx)), height: 14, rx: 3, fill: '#2347c9' }, svg);
      var la = text(svg, X(a) - 6, by + 11.5, money(a), 'ax-label', 'end');
      var lb = text(svg, X(b) + 6, by + 11.5, money(b), 'ax-label', 'start');
      if (X(a) - 6 < m.l + 34) { la.setAttribute('x', X(a) + 4); la.setAttribute('text-anchor', 'start'); la.style.fill = '#fff'; }
      if (X(b) + 40 > W) { lb.setAttribute('x', X(b) - 4); lb.setAttribute('text-anchor', 'end'); lb.style.fill = '#fff'; }
    });
    var bl = top + rows.length * rowH;
    text(svg, bx, bl + 16, 'Best estimate ' + money(o.base), 'ax-title', 'middle');
  }

  root.NPCharts = { lec: lec, frontier: frontier, tornado: tornado, money: money };
})(typeof self !== 'undefined' ? self : this);
