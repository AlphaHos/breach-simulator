/*
 * NabuPay Breach Simulator — risk engine v2
 *
 * Pure functions, no DOM. Runs in the browser and in Node (the same file
 * precomputes the portfolio frontier and can re-verify any score).
 *
 * This is a quantitative RISK model in the FAIR style (Open Group O-RT),
 * not an attacker playbook. It works in terms of event frequency, the
 * probability that an attempt becomes a loss (vulnerability), the spread of
 * exposure between assets, defensive response, and financial impact.
 *
 *   LEF (loss events / yr) = TEF (attempts / yr) × Vulnerability
 *   ALE = LEF × LM (mean loss per loss event) = E[annual loss]
 *   Total Cost of Risk = control spend + residual ALE
 *   ROSI = (ALE_inherent − ALE_residual − spend) / spend
 *
 * Uncertainty: every uncertain input is a three-point PERT estimate. The
 * annual simulation samples a fresh "world" of inputs for every simulated
 * year, draws the number of attempts from a Poisson distribution, and runs
 * each attempt through the asset model. The sorted annual losses give the
 * loss exceedance curve and percentiles.
 */
(function (root) {
  'use strict';

  /* ---------------- randomness ---------------- */
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function hashSeed() {
    let h = 2166136261;
    for (let n = 0; n < arguments.length; n++) {
      const s = String(arguments[n]);
      for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
      h ^= 0x9e37; h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }
  function normal(rand) {
    let u = 0; while (u === 0) u = rand();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rand());
  }
  function gamma(rand, k) {              // Marsaglia & Tsang (2000)
    if (k < 1) return gamma(rand, k + 1) * Math.pow(rand() || 1e-12, 1 / k);
    const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d);
    for (;;) {
      let x, v;
      do { x = normal(rand); v = 1 + c * x; } while (v <= 0);
      v = v * v * v;
      const u = rand();
      if (u < 1 - 0.0331 * x * x * x * x) return d * v;
      if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
    }
  }
  /* Beta-PERT, λ = 4 (Vose 2008) */
  function pert(rand, r) {
    const a = r[0], m = r[1], b = r[2];
    if (!(b > a)) return m;
    const al = 1 + 4 * (m - a) / (b - a), be = 1 + 4 * (b - m) / (b - a);
    const x = gamma(rand, al), y = gamma(rand, be);
    return a + (b - a) * x / (x + y);
  }
  function pertMean(r) { return (r[0] + 4 * r[1] + r[2]) / 6; }
  function poisson(rand, lam) {          // Knuth; λ is small here
    const L = Math.exp(-lam); let k = 0, p = 1;
    do { k++; p *= rand(); } while (p > L);
    return k - 1;
  }

  /* ---------------- worlds: one set of input values ---------------- */
  function rangeOf(v, r) { return r || [v, v, v]; }
  function makeWorld(D, pick) {
    const M = D.MODEL, w = { tef: {}, eff: {} };
    D.ATTACKS.forEach(function (a) { w.tef[a.id] = pick(rangeOf(a.aro, a.tefRange)); });
    w.outage = pick(rangeOf(D.COMPANY.outageCostPerHour, D.COMPANY.outageCostRange));
    w.recHigh = pick(rangeOf(M.recordCostHigh, M.recordCostHighRange));
    w.recLow = pick(rangeOf(M.recordCostLow, M.recordCostLowRange));
    w.spread = pick(rangeOf(1, M.spreadScaleRange));
    w.detectBase = pick(rangeOf(M.detectBase, M.detectBaseRange));
    D.CONTROLS.forEach(function (c) { w.eff[c.id] = pick(c.effRange || [1, 1, 1]); });
    return w;
  }
  function meanWorld(D) {
    if (!D._meanWorld) D._meanWorld = makeWorld(D, pertMean);
    return D._meanWorld;
  }
  function sampleWorld(D, rand) { return makeWorld(D, function (r) { return pert(rand, r); }); }
  function cloneWorld(w) {
    return { tef: Object.assign({}, w.tef), eff: Object.assign({}, w.eff), outage: w.outage,
      recHigh: w.recHigh, recLow: w.recLow, spread: w.spread, detectBase: w.detectBase };
  }

  /* ---------------- controls → effect context ---------------- */
  const MULT = ['phishDelivery', 'phishClick', 'credLogin', 'phishCredReuse', 'exploitEdge',
    'exploitInternal', 'lateralCross', 'execBlock', 'cardValue', 'fraudTransfer'];
  function shrink(m, f) { return Math.max(0, Math.min(1, 1 - (1 - m) * f)); }

  function buildContext(D, selected, world) {
    world = world || meanWorld(D);
    const sel = selected instanceof Set ? selected : new Set(selected || []);
    const ctx = {
      phishDelivery: 1, phishClick: 1, credLogin: 1, phishCredReuse: 1,
      exploitEdge: 1, exploitInternal: 1, lateralCross: 1, execBlock: 1,
      detectEdr: 0, detectSoc: 0, containRounds: D.MODEL.containRoundsDefault,
      backupImmutable: false, restoreHours: D.MODEL.restoreHoursBackup,
      cardValue: 1, fraudTransfer: 1, insurance: null, removed: new Set(),
      cost: 0, selected: sel,
      outageCost: world.outage, recHigh: world.recHigh, recLow: world.recLow,
      spread: world.spread, detectBase: world.detectBase
    };
    for (let i = 0; i < D.CONTROLS.length; i++) {
      const c = D.CONTROLS[i];
      if (!sel.has(c.id)) continue;
      const e = c.effects, f = world.eff[c.id] === undefined ? 1 : world.eff[c.id];
      ctx.cost += c.cost;
      for (let m = 0; m < MULT.length; m++) { const k = MULT[m]; if (e[k] !== undefined) ctx[k] *= shrink(e[k], f); }
      if (e.detect) { if (c.id === 'edr') ctx.detectEdr += e.detect * f; else ctx.detectSoc += e.detect * f; }
      if (e.containRounds !== undefined) ctx.containRounds = Math.min(ctx.containRounds, e.containRounds);
      if (e.backupImmutable) ctx.backupImmutable = true;
      if (e.restoreHours !== undefined) ctx.restoreHours = Math.min(ctx.restoreHours, e.restoreHours);
      if (e.insurance) ctx.insurance = e.insurance;
      if (e.removeAsset) ctx.removed.add(e.removeAsset);
    }
    return ctx;
  }

  /* ---------------- static asset graph ---------------- */
  function graph(D) {
    if (D._graph) return D._graph;
    const byId = {}, adj = {};
    D.ASSETS.forEach(function (a) { byId[a.id] = a; adj[a.id] = []; });
    D.LINKS.forEach(function (l) {
      adj[l[0]].push({ to: l[1], legit: !!l[2] });
      adj[l[1]].push({ to: l[0], legit: !!l[2] });
    });
    D._graph = { byId: byId, adj: adj };
    return D._graph;
  }

  function applyInsurance(gross, ins) {
    if (!ins || gross <= ins.deductible) return { net: gross, recovered: 0 };
    const recovered = Math.min(ins.limit, (gross - ins.deductible) * ins.share);
    return { net: gross - recovered, recovered: recovered };
  }
  /* tiered cost per breached record (IBM: per-record cost falls in large breaches) */
  function dataCost(D, ctx, records, mult) {
    const brk = D.MODEL.recordTierBreak;
    const high = Math.min(records, brk) * ctx.recHigh;
    const low = Math.max(0, records - brk) * ctx.recLow;
    return (high + low) * (mult === undefined ? 1 : mult);
  }
  function emptyResult(atk, events) {
    return { attack: atk.id, breached: false, exposedIds: [], impactedIds: [], dataAtRisk: {},
      detectHour: null, containHour: null, outageHours: 0, dataStolen: false, events: events,
      loss: { response: 0, rebuild: 0, outage: 0, data: 0, fraud: 0, gross: 0, insured: 0, net: 0 } };
  }

  /* ---------------- one attempt: network scenarios ---------------- */
  function runNetwork(D, atk, ctx, rand, trace) {
    const g = graph(D), byId = g.byId, adj = g.adj, M = D.MODEL;
    const exposed = new Map();
    const events = trace ? [] : null;
    function log(hour, phase, tactic, assetId, state, text) {
      events.push({ hour: hour, phase: phase, tactic: tactic, asset: assetId || null, state: state || null, text: text });
    }

    for (let i = 0; i < atk.entry.length; i++) {
      const en = atk.entry[i];
      if (ctx.removed.has(en.via)) {
        if (events) log(0, 'prep', 'Initial Access', en.via, 'offline', byId[en.via].name + ' is offline — vector unavailable');
        continue;
      }
      if (en.type === 'phish' || en.type === 'phishCred') {
        const groups = en.to || [];
        const usable = en.type === 'phishCred' ? ctx.phishCredReuse : ctx.execBlock;
        const p = Math.min(0.99, en.base.deliver * ctx.phishDelivery * en.base.click * ctx.phishClick * usable);
        for (let t = 0; t < groups.length; t++) {
          if (rand() < p) {
            if (!exposed.has(groups[t])) exposed.set(groups[t], 0);
            if (events) log(0, 'entry', 'Initial Access', groups[t], 'exposed', 'Email vector reached ' + byId[groups[t]].name);
          }
        }
      } else {
        const p = Math.min(0.99, en.base * (en.type === 'cred' ? ctx.credLogin : ctx.exploitEdge));
        if (rand() < p) {
          if (!exposed.has(en.via)) exposed.set(en.via, 0);
          if (events) log(0, 'entry', 'Initial Access', en.via, 'exposed', en.label + ' — ' + byId[en.via].name + ' exposed');
        }
      }
    }

    const out = emptyResult(atk, events);
    out.breached = exposed.size > 0;
    if (!exposed.size) { if (events) log(0, 'prep', null, null, 'held', 'Perimeter held — no asset exposed'); return out; }

    let detect = null, contain = null;
    const blockedZones = new Set();
    const dwell = atk.dwellRounds || 1;
    for (let r = 1; r <= dwell; r++) {
      const hour = r * M.roundHours;
      if (detect === null) {
        let internal = 0;
        exposed.forEach(function (_, id) { if (byId[id].kind !== 'edge') internal++; });
        internal = Math.min(3, internal);
        const miss = (1 - ctx.detectBase) * (1 - ctx.detectSoc) * Math.pow(1 - ctx.detectEdr, internal);
        if (rand() > miss) {
          detect = hour; contain = hour + ctx.containRounds * M.roundHours;
          out.detectHour = detect; out.containHour = contain;
          if (events) log(hour, 'detect', 'Detection', null, null, (ctx.detectSoc ? 'SOC' : 'Staff') + ' flagged anomalies — investigation opened');
        }
      }
      if (detect !== null && hour >= contain) {
        if (events) log(hour, 'contain', 'Containment', null, 'contained', 'Containment complete — spread halted');
        break;
      }
      const wave = Array.from(exposed.keys());
      for (let f = 0; f < wave.length; f++) {
        const u = wave[f], nbrs = adj[u];
        for (let n = 0; n < nbrs.length; n++) {
          const v = nbrs[n].to, target = byId[v];
          if (exposed.has(v) || ctx.removed.has(v) || target.kind === 'external') continue;
          const sameZone = target.zone === byId[u].zone;
          let p = u === 'dc' ? M.lateralFromDC : (target.kind === 'server' ? M.lateralToServer : M.lateralBase);
          if (!sameZone) p *= nbrs[n].legit ? 0.5 : ctx.lateralCross;
          p *= ctx.exploitInternal * ctx.spread;
          if (target.kind === 'endpoint' || target.kind === 'server') p *= (0.5 + 0.5 * ctx.execBlock);
          if (rand() < Math.min(0.95, p)) {
            exposed.set(v, hour);
            if (events) log(hour, 'spread', 'Lateral Movement', v, 'exposed', 'Exposure reached ' + target.name + ' (' + D.ZONES[target.zone].label + ')');
          } else if (events && !sameZone && !nbrs[n].legit && ctx.selected.has('segment') &&
                     (target.zone === 'core' || target.zone === 'vault') && !blockedZones.has(target.zone)) {
            blockedZones.add(target.zone);
            log(hour, 'spread', 'Containment', v, null, 'Segmentation held — ' + D.ZONES[target.zone].label + ' isolated');
          }
        }
      }
    }

    out.exposedIds = Array.from(exposed.keys());
    out.loss.response = atk.fixedResponse || M.breachFixed;

    if (atk.id === 'ransomware') {
      const backupHit = exposed.has('backup') && !ctx.backupImmutable;
      const stolen = rand() < M.ransomExfilProb;      // Sophos 2025: 31%
      out.dataStolen = stolen;
      let maxOut = 0;
      exposed.forEach(function (_, id) {
        const a = byId[id];
        if (a.kind === 'external' || a.kind === 'edge') return;
        out.impactedIds.push(id);
        out.loss.rebuild += a.rebuild || 0;
        if (a.critical) {
          maxOut = Math.max(maxOut, backupHit ? M.restoreHoursNoBackup : ctx.restoreHours);
          if (events) log(null, 'impact', 'Impact', id, 'impacted', a.name + ' — service encrypted');
        }
        if (a.records && stolen) {
          out.dataAtRisk[id] = a.records;
          out.loss.data += dataCost(D, ctx, a.records, id === 'vault' ? ctx.cardValue : 1);
          if (events) log(null, 'impact', 'Exfiltration', id, 'impacted', 'Data also stolen: ' + a.name + ' (' + a.records.toLocaleString() + ' records)');
        }
      });
      out.outageHours = maxOut;
      out.loss.outage = maxOut * ctx.outageCost;
      if (events) {
        if (backupHit) log(null, 'impact', 'Impact', 'backup', 'impacted', 'Backups reachable — recovery takes ' + M.restoreHoursNoBackup + 'h');
        else if (ctx.backupImmutable) log(null, 'recover', 'Recovery', 'backup', 'safe', 'Immutable backups intact — restored in ' + ctx.restoreHours + 'h');
        else if (maxOut) log(null, 'recover', 'Recovery', null, null, 'Restored from untested backups in ' + maxOut + 'h');
      }
    } else {
      let worst = 0;
      exposed.forEach(function (_, id) {
        const a = byId[id];
        if (a.kind === 'external' || a.kind === 'edge') return;
        out.impactedIds.push(id);
        if (a.records) {
          out.dataAtRisk[id] = a.records;
          out.dataStolen = true;
          out.loss.data += dataCost(D, ctx, a.records, id === 'vault' ? ctx.cardValue : 1);
          if (events) log(null, 'impact', 'Exfiltration', id, 'impacted', 'Data at risk: ' + a.name + ' (' + a.records.toLocaleString() + ' records)');
        }
        if (a.critical) worst = Math.max(worst, 8);
      });
      out.outageHours = worst;
      out.loss.outage = worst * ctx.outageCost;
      if (events && worst) log(null, 'recover', 'Recovery', null, null, 'Affected services rebuilt and validated in ' + worst + 'h');
    }

    const gross = out.loss.response + out.loss.rebuild + out.loss.outage + out.loss.data;
    const ins = applyInsurance(gross, ctx.insurance);
    out.loss.gross = gross; out.loss.insured = ins.recovered; out.loss.net = ins.net;
    return out;
  }

  /* ---------------- one attempt: BEC (no network spread) ---------------- */
  function runBec(D, atk, ctx, rand, trace) {
    const events = trace ? [] : null;
    const out = emptyResult(atk, events);
    function log(phase, tactic, assetId, state, text) { events.push({ hour: 0, phase: phase, tactic: tactic, asset: assetId || null, state: state || null, text: text }); }
    const en = atk.entry[0];
    const p = Math.min(0.99, en.base.deliver * ctx.phishDelivery * en.base.click * ctx.phishClick * ctx.phishCredReuse);
    if (rand() >= p) { if (events) log('prep', null, null, 'held', 'Credential phishing did not succeed'); return out; }
    out.breached = true; out.exposedIds = ['finance']; out.impactedIds = ['finance'];
    if (events) log('entry', 'Initial Access', 'finance', 'exposed', 'Finance mailbox credentials compromised');
    if (rand() < atk.fraudBase * ctx.fraudTransfer) {
      out.loss.fraud = atk.fraudLoss;
      out.loss.response = atk.fixedResponse;
      if (events) log('impact', 'Impact', 'finance', 'impacted', 'Fraudulent transfer paid — $' + atk.fraudLoss.toLocaleString());
    } else {
      out.loss.response = Math.round(atk.fixedResponse * 0.4);
      if (events) log('contain', 'Containment', 'finance', 'contained', 'Transfer verification blocked the payment');
    }
    const gross = out.loss.fraud + out.loss.response;
    const ins = applyInsurance(gross, ctx.insurance);
    out.loss.gross = gross; out.loss.insured = ins.recovered; out.loss.net = ins.net;
    return out;
  }

  function runOnce(D, atk, ctx, rand, trace) {
    return atk.id === 'bec' ? runBec(D, atk, ctx, rand, trace) : runNetwork(D, atk, ctx, rand, trace);
  }

  /* ---------------- expected loss at fixed inputs (common random numbers) ---------------- */
  function expected(D, selected, opts) {
    opts = opts || {};
    const R = opts.runs || D.MODEL.frontierRuns, world = opts.world || meanWorld(D), key = opts.seedKey || 'exp';
    const ctx = buildContext(D, selected, world);
    const per = []; let ale = 0;
    for (let s = 0; s < D.ATTACKS.length; s++) {
      const atk = D.ATTACKS[s];
      let sum = 0, br = 0, outage = 0, outN = 0;
      for (let i = 0; i < R; i++) {
        const r = runOnce(D, atk, ctx, mulberry32(hashSeed(key, atk.id, i)), false);
        sum += r.loss.net; if (r.outageHours > 0) { outage += r.outageHours; outN++; }
        if (r.breached) br++;
      }
      const tef = world.tef[atk.id], vuln = br / R, lm = br ? sum / br : 0;
      per.push({ id: atk.id, name: atk.name, tef: tef, vuln: vuln, lef: tef * vuln, lm: lm,
        ale: tef * sum / R, rto: outN ? outage / outN : 0 });
      ale += tef * sum / R;
    }
    return { ale: ale, per: per, cost: ctx.cost, ctx: ctx };
  }

  /* ---------------- annual Monte Carlo with uncertainty ---------------- */
  function simulateYears(D, selected, opts) {
    opts = opts || {};
    const years = opts.years || D.MODEL.years, key = opts.seedKey || 'yr';
    const sel = new Set(selected || []);
    const losses = new Float64Array(years);
    const per = {}; D.ATTACKS.forEach(function (a) { per[a.id] = 0; });
    for (let y = 0; y < years; y++) {
      const rand = mulberry32(hashSeed(key, y));
      const world = sampleWorld(D, rand);           // inputs for this simulated year
      const ctx = buildContext(D, sel, world);
      let total = 0;
      for (let s = 0; s < D.ATTACKS.length; s++) {
        const atk = D.ATTACKS[s], n = poisson(rand, world.tef[atk.id]);
        for (let k = 0; k < n; k++) { const l = runOnce(D, atk, ctx, rand, false).loss.net; total += l; per[atk.id] += l; }
      }
      losses[y] = total;
    }
    losses.sort();
    let sum = 0, any = 0;
    for (let i = 0; i < years; i++) { sum += losses[i]; if (losses[i] > 0) any++; }
    const q = function (p) { return losses[Math.min(years - 1, Math.floor(p * years))]; };
    Object.keys(per).forEach(function (k) { per[k] /= years; });
    return { losses: losses, years: years, mean: sum / years, pAny: any / years,
      p05: q(0.05), p50: q(0.5), p90: q(0.9), p95: q(0.95), p99: q(0.99), max: losses[years - 1], per: per };
  }
  /* probability that annual loss exceeds x */
  function exceedance(sim, x) {
    const L = sim.losses; let lo = 0, hi = L.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (L[mid] <= x) lo = mid + 1; else hi = mid; }
    return (L.length - lo) / L.length;
  }

  /* ---------------- sensitivity (tornado) ---------------- */
  function sensitivity(D, selected, opts) {
    opts = opts || {};
    const R = opts.runs || 200, base = meanWorld(D);
    const baseAle = expected(D, selected, { runs: R, world: base, seedKey: 'sens' }).ale;
    const M = D.MODEL, sel = new Set(selected || []);
    const params = [];
    D.ATTACKS.forEach(function (a) {
      params.push({ key: 'tef:' + a.id, label: a.name + ' attempts per year', range: a.tefRange, fmt: 'rate',
        set: function (w, v) { w.tef[a.id] = v; } });
    });
    params.push({ key: 'outage', label: 'Outage cost per hour', range: D.COMPANY.outageCostRange, fmt: 'money',
      set: function (w, v) { w.outage = v; } });
    params.push({ key: 'records', label: 'Cost per breached record', range: M.recordCostHighRange, fmt: 'money',
      set: function (w, v, t) { w.recHigh = v; w.recLow = M.recordCostLowRange[t]; } });
    params.push({ key: 'spread', label: 'Spread rate between assets', range: M.spreadScaleRange, fmt: 'x',
      set: function (w, v) { w.spread = v; } });
    params.push({ key: 'detect', label: 'Detection without tooling', range: M.detectBaseRange, fmt: 'pct',
      set: function (w, v) { w.detectBase = v; } });
    D.CONTROLS.forEach(function (c) {
      const r = c.effRange || [1, 1, 1];
      if (!sel.has(c.id) || r[0] === r[2]) return;
      params.push({ key: 'eff:' + c.id, label: c.name + ' effectiveness', range: r, fmt: 'pct',
        set: function (w, v) { w.eff[c.id] = v; } });
    });
    const out = params.map(function (p) {
      const lo = cloneWorld(base), hi = cloneWorld(base);
      p.set(lo, p.range[0], 0); p.set(hi, p.range[2], 2);
      const aLo = expected(D, selected, { runs: R, world: lo, seedKey: 'sens' }).ale;
      const aHi = expected(D, selected, { runs: R, world: hi, seedKey: 'sens' }).ale;
      return { key: p.key, label: p.label, range: p.range, fmt: p.fmt, low: aLo, high: aHi, swing: Math.abs(aHi - aLo) };
    });
    out.sort(function (a, b) { return b.swing - a.swing; });
    return { base: baseAle, params: out };
  }

  /* ---------------- portfolios (all 2^n combinations) ---------------- */
  function maskOf(D, ids) {
    const s = ids instanceof Set ? ids : new Set(ids || []); let m = 0;
    D.CONTROLS.forEach(function (c, i) { if (s.has(c.id)) m |= (1 << i); });
    return m;
  }
  function idsOf(D, mask) { return D.CONTROLS.filter(function (_, i) { return mask & (1 << i); }).map(function (c) { return c.id; }); }
  function costOf(D, mask) { let c = 0; D.CONTROLS.forEach(function (k, i) { if (mask & (1 << i)) c += k.cost; }); return c; }
  function frontierRange(D, from, to, runs) {
    const out = new Float64Array(to - from);
    for (let m = from; m < to; m++) out[m - from] = expected(D, idsOf(D, m), { runs: runs, seedKey: 'fr' }).ale;
    return out;
  }
  /* index the full table: costs, total cost of risk, the optimum per budget */
  function portfolioIndex(D, ale) {
    const n = ale.length, cost = new Float64Array(n), tcor = new Float64Array(n);
    let best = 0, bestB = 0;
    for (let m = 0; m < n; m++) {
      cost[m] = costOf(D, m); tcor[m] = cost[m] + ale[m];
      if (tcor[m] < tcor[best]) best = m;
      if (cost[m] <= D.MODEL.budget && tcor[m] < tcor[bestB]) bestB = m;
    }
    // Pareto frontier: lowest ALE for any spend level
    const order = Array.from({ length: n }, function (_, i) { return i; }).sort(function (a, b) { return cost[a] - cost[b] || ale[a] - ale[b]; });
    const pareto = []; let lowest = Infinity;
    order.forEach(function (m) { if (ale[m] < lowest - 1e-6) { pareto.push(m); lowest = ale[m]; } });
    return { ale: ale, cost: cost, tcor: tcor, optimum: best, optimumBudget: bestB, pareto: pareto };
  }
  /*
   * 0–100: how close the portfolio's total cost of risk is to the best of all
   * 4,096 portfolios, on a log scale (every halving of TCoR counts the same).
   * 0 = no controls, 100 = the optimum (within the budget in budget mode).
   */
  function scoreOf(idx, mask, budgetMode) {
    const base = idx.tcor[0], opt = idx.tcor[budgetMode ? idx.optimumBudget : idx.optimum], you = idx.tcor[mask];
    if (!(base > opt) || !(you > 0)) return 0;
    return Math.max(0, Math.min(100, Math.round(100 * Math.log(base / you) / Math.log(base / opt))));
  }

  /* ---------------- semi-quantitative bands (NIST SP 800-30 style) ---------------- */
  function likelihoodBand(lef) { return lef >= 1 ? 5 : lef >= 0.5 ? 4 : lef >= 0.2 ? 3 : lef >= 0.05 ? 2 : 1; }
  function impactBand(D, lm) {
    const r = lm / D.COMPANY.annualRevenueUSD;
    return r >= 0.2 ? 5 : r >= 0.1 ? 4 : r >= 0.04 ? 3 : r >= 0.01 ? 2 : 1;
  }

  /* ---------------- a single reproducible incident for the replay ---------------- */
  function demoRun(D, selected, attackId, seedKey) {
    const ctx = buildContext(D, selected);
    const atk = D.ATTACKS.find(function (a) { return a.id === attackId; });
    const key = Array.from(ctx.selected).sort().join('|');
    let first = null;
    for (let n = 0; n < 40; n++) {
      const r = runOnce(D, atk, ctx, mulberry32(hashSeed(seedKey || 'demo', attackId, key, n)), true);
      if (n === 0) first = r;
      if (r.breached) { r.seedIndex = n; return r; }
    }
    first.seedIndex = 0;
    return first;
  }

  /* fingerprint of the model inputs, to know whether a precomputed table is current */
  function dataHash(D) {
    const pick = { c: D.COMPANY, a: D.ASSETS, l: D.LINKS, k: D.CONTROLS, t: D.ATTACKS, m: D.MODEL };
    return hashSeed(JSON.stringify(pick)).toString(36);
  }

  const ENGINE = {
    mulberry32: mulberry32, hashSeed: hashSeed, pert: pert, pertMean: pertMean, poisson: poisson,
    meanWorld: meanWorld, sampleWorld: sampleWorld, buildContext: buildContext, runOnce: runOnce,
    expected: expected, simulateYears: simulateYears, exceedance: exceedance, sensitivity: sensitivity,
    maskOf: maskOf, idsOf: idsOf, costOf: costOf, frontierRange: frontierRange, portfolioIndex: portfolioIndex,
    scoreOf: scoreOf, likelihoodBand: likelihoodBand, impactBand: impactBand, demoRun: demoRun,
    dataHash: dataHash, applyInsurance: applyInsurance
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = ENGINE;
  else root.BSEngine = ENGINE;
})(typeof self !== 'undefined' ? self : this);
