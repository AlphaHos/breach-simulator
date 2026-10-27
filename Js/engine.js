/*
 * NabuPay Breach Simulator — risk engine
 *
 * Pure functions, no DOM. Runs in the browser and in Node, so a server can
 * recompute any score from the chosen controls + seed (anti-cheat).
 *
 * This is a RISK model, in the style of FAIR / a GRC tool — not an attacker
 * playbook. It works entirely in terms of likelihood, exposure spread between
 * assets, defensive response (detection + containment) and financial impact.
 * The on-screen log is written from the defender's / consequence point of
 * view (which asset is exposed, when it was contained, what it cost).
 *
 *   ALE = ARO × mean loss per event, estimated by Monte Carlo.
 *   Total Cost of Risk (TCoR) = annual control spend + residual ALE.
 *   ROSI = (ALE_before − ALE_after − control_cost) / control_cost.
 */
(function (root) {
  'use strict';

  /* ---------- seeded RNG (deterministic, reproducible) ---------- */
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

  /* ---------- controls → effect context ---------- */
  function buildContext(D, selected) {
    const sel = new Set(selected || []);
    const ctx = {
      phishDelivery: 1, phishClick: 1, credLogin: 1, phishCredReuse: 1,
      exploitEdge: 1, exploitInternal: 1, lateralCross: 1, execBlock: 1,
      detectEdr: 0, detectSoc: 0, containRounds: D.MODEL.containRoundsDefault,
      backupImmutable: false, restoreHours: D.MODEL.restoreHoursBackup,
      cardValue: 1, fraudTransfer: 1, insurance: null, removed: new Set(),
      cost: 0, selected: sel
    };
    for (let i = 0; i < D.CONTROLS.length; i++) {
      const c = D.CONTROLS[i];
      if (!sel.has(c.id)) continue;
      ctx.cost += c.cost;
      const e = c.effects;
      const mult = ['phishDelivery', 'phishClick', 'credLogin', 'phishCredReuse', 'exploitEdge',
        'exploitInternal', 'lateralCross', 'execBlock', 'cardValue', 'fraudTransfer'];
      for (let m = 0; m < mult.length; m++) { const k = mult[m]; if (e[k] !== undefined) ctx[k] *= e[k]; }
      if (e.detect) { if (c.id === 'edr') ctx.detectEdr += e.detect; else ctx.detectSoc += e.detect; }
      if (e.containRounds !== undefined) ctx.containRounds = Math.min(ctx.containRounds, e.containRounds);
      if (e.backupImmutable) ctx.backupImmutable = true;
      if (e.restoreHours !== undefined) ctx.restoreHours = Math.min(ctx.restoreHours, e.restoreHours);
      if (e.insurance) ctx.insurance = e.insurance;
      if (e.removeAsset) ctx.removed.add(e.removeAsset);
    }
    return ctx;
  }

  /* ---------- static asset graph ---------- */
  function graph(D) {
    if (D._graph) return D._graph;
    const byId = {};
    for (let i = 0; i < D.ASSETS.length; i++) byId[D.ASSETS[i].id] = D.ASSETS[i];
    const adj = {};
    for (let i = 0; i < D.ASSETS.length; i++) adj[D.ASSETS[i].id] = [];
    for (let i = 0; i < D.LINKS.length; i++) {
      const u = D.LINKS[i][0], v = D.LINKS[i][1], legit = !!D.LINKS[i][2];
      adj[u].push({ to: v, legit: legit });
      adj[v].push({ to: u, legit: legit });
    }
    D._graph = { byId: byId, adj: adj };
    return D._graph;
  }

  function applyInsurance(gross, ins) {
    if (!ins || gross <= ins.deductible) return { net: gross, recovered: 0 };
    const recovered = Math.min(ins.limit, (gross - ins.deductible) * ins.share);
    return { net: gross - recovered, recovered: recovered };
  }

  /* data-breach cost for N records, tiered (IBM: per-record cost falls in large breaches) */
  function dataCost(D, records, mult) {
    const M = D.MODEL, brk = M.recordTierBreak;
    const high = Math.min(records, brk) * M.recordCostHigh;
    const low = Math.max(0, records - brk) * M.recordCostLow;
    return (high + low) * (mult === undefined ? 1 : mult);
  }

  /* likelihood that a single threat event reaches at least one asset */
  function entryExposure(atk, ctx) {
    // probability the perimeter is NOT breached by any vector
    let safe = 1;
    for (let i = 0; i < atk.entry.length; i++) {
      const en = atk.entry[i];
      if (ctx.removed.has(en.via)) continue;
      let p;
      if (en.type === 'phish' || en.type === 'phishCred') {
        const reach = en.base.deliver * ctx.phishDelivery;
        const act = en.base.click * ctx.phishClick;
        const usable = en.type === 'phishCred' ? ctx.phishCredReuse : ctx.execBlock;
        // at least one targeted group is affected
        const groups = en.to ? en.to.length : 1;
        const perGroup = reach * act * usable;
        p = 1 - Math.pow(1 - Math.min(0.99, perGroup), groups);
      } else if (en.type === 'cred') {
        p = en.base * ctx.credLogin;
      } else { // exploit
        p = en.base * ctx.exploitEdge;
      }
      safe *= (1 - Math.min(0.99, Math.max(0, p)));
    }
    return 1 - safe;
  }

  /*
   * One Monte-Carlo run of a network-spread scenario (ransomware / intrusion).
   * Returns impact + (optionally) a defender-side event trace for animation.
   */
  function runNetwork(D, atk, ctx, rand, trace) {
    const g = graph(D), byId = g.byId, adj = g.adj, M = D.MODEL;
    const exposed = new Map();                 // assetId -> hour first exposed
    const events = trace ? [] : null;
    function log(hour, phase, tactic, assetId, state, text) {
      if (events) events.push({ hour: hour, phase: phase, tactic: tactic, asset: assetId || null, state: state || null, text: text });
    }

    // --- perimeter: which entry points become exposed ---
    const entries = [];
    for (let i = 0; i < atk.entry.length; i++) {
      const en = atk.entry[i];
      if (ctx.removed.has(en.via)) { log(0, 'prep', 'Initial Access', en.via, 'offline', byId[en.via].name + ' is offline — vector unavailable'); continue; }
      let hit = false;
      if (en.type === 'phish' || en.type === 'phishCred') {
        const groups = en.to || [];
        const usable = en.type === 'phishCred' ? ctx.phishCredReuse : ctx.execBlock;
        for (let t = 0; t < groups.length; t++) {
          const p = Math.min(0.99, en.base.deliver * ctx.phishDelivery * en.base.click * ctx.phishClick * usable);
          if (rand() < p) { if (!exposed.has(groups[t])) exposed.set(groups[t], 0); hit = true; log(0, 'entry', 'Initial Access', groups[t], 'exposed', 'Email vector reached ' + byId[groups[t]].name); }
        }
      } else {
        const p = Math.min(0.99, en.base * (en.type === 'cred' ? ctx.credLogin : ctx.exploitEdge));
        if (rand() < p) { if (!exposed.has(en.via)) exposed.set(en.via, 0); hit = true; log(0, 'entry', 'Initial Access', en.via, 'exposed', en.label + ' — vector open at ' + byId[en.via].name); }
      }
      entries.push({ via: en.via, hit: hit });
    }

    const out = {
      attack: atk.id, breached: exposed.size > 0, exposedIds: [], impactedIds: [], dataAtRisk: {},
      detectHour: null, containHour: null, outageHours: 0, events: events,
      loss: { response: 0, rebuild: 0, outage: 0, data: 0, fraud: 0, gross: 0, insured: 0, net: 0 }
    };
    if (!exposed.size) { log(0, 'prep', null, null, 'held', 'Attack stopped at the perimeter — no asset exposed'); return out; }

    // --- spread of exposure + defensive response, round by round ---
    let detect = null, contain = null;
    const blockedZones = new Set();
    const dwell = atk.dwellRounds || 1;
    for (let r = 1; r <= dwell; r++) {
      const hour = r * M.roundHours;

      // detection hazard rises with the number of exposed internal assets
      if (detect === null) {
        let internal = 0;
        exposed.forEach(function (_, id) { if (byId[id].kind !== 'edge') internal++; });
        internal = Math.min(3, internal);
        const miss = (1 - M.detectBase) * (1 - ctx.detectSoc) * Math.pow(1 - ctx.detectEdr, internal);
        if (rand() > miss) {
          detect = hour; contain = hour + ctx.containRounds * M.roundHours;
          out.detectHour = detect; out.containHour = contain;
          log(hour, 'detect', 'Detection', null, null, (ctx.detectSoc ? 'SOC' : 'Staff') + ' flagged anomalies — investigation opened');
        }
      }
      if (detect !== null && hour >= contain) { log(hour, 'contain', 'Containment', null, 'contained', 'Containment complete — spread halted'); break; }

      // one wave of exposure spread
      const frontier = Array.from(exposed.keys());
      for (let f = 0; f < frontier.length; f++) {
        const u = frontier[f], nbrs = adj[u];
        for (let n = 0; n < nbrs.length; n++) {
          const v = nbrs[n].to;
          if (exposed.has(v) || ctx.removed.has(v)) continue;
          const target = byId[v];
          const sameZone = target.zone === byId[u].zone;
          let p;
          if (byId[u].id === 'dc') p = M.lateralFromDC;                 // domain controller reaches widely
          else if (target.kind === 'server') p = M.lateralToServer;
          else p = M.lateralBase;
          if (!sameZone) { if (nbrs[n].legit) p *= 0.5; else p *= ctx.lateralCross; } // cross-zone needs to defeat segmentation
          p *= ctx.exploitInternal;                                     // patching shrinks the internal attack surface
          if (target.kind === 'endpoint' || target.kind === 'server') p *= (0.5 + 0.5 * ctx.execBlock);
          if (rand() < Math.min(0.95, p)) {
            exposed.set(v, hour);
            const tactic = (target.kind === 'server' && target.critical) ? 'Lateral Movement' : 'Lateral Movement';
            log(hour, 'spread', tactic, v, 'exposed', 'Exposure reached ' + target.name + ' (' + D.ZONES[target.zone].label + ')');
          } else if (!sameZone && !nbrs[n].legit && ctx.selected.has('segment') &&
                     (target.zone === 'core' || target.zone === 'vault') && !blockedZones.has(target.zone)) {
            // note the first blocked crossing into a protected zone, for the narrative
            blockedZones.add(target.zone);
            log(hour, 'spread', 'Containment', v, null, 'Segmentation held — ' + D.ZONES[target.zone].label + ' isolated');
          }
        }
      }
    }

    out.exposedIds = Array.from(exposed.keys());

    // --- financial impact from the set of exposed assets ---
    out.loss.response = atk.fixedResponse || M.breachFixed;

    if (atk.id === 'ransomware') {
      // impact at the moment of containment (or full dwell): exposed assets are encrypted
      const backupHit = exposed.has('backup') && !ctx.backupImmutable;
      let maxOut = 0;
      exposed.forEach(function (_, id) {
        const a = byId[id];
        if (a.kind === 'external' || a.kind === 'edge') return;
        out.impactedIds.push(id);
        out.loss.rebuild += a.rebuild || 0;
        if (a.critical) {
          const rto = backupHit ? M.restoreHoursNoBackup : ctx.restoreHours;
          maxOut = Math.max(maxOut, rto);
          log(null, 'impact', 'Impact', id, 'impacted', a.name + ' — service encrypted');
        }
        if (a.records) { out.dataAtRisk[id] = a.records; out.loss.data += dataCost(D, a.records, id === 'vault' ? ctx.cardValue : 1); }
      });
      out.outageHours = maxOut;
      out.loss.outage = maxOut * D.COMPANY.outageCostPerHour;
      if (backupHit) log(null, 'impact', 'Impact', 'backup', 'impacted', 'Backups reachable — recovery delayed to ' + M.restoreHoursNoBackup + 'h');
      else if (ctx.backupImmutable) log(null, 'recover', 'Recovery', 'backup', 'safe', 'Immutable backups intact — ' + ctx.restoreHours + 'h RTO');

    } else { // network intrusion — exfiltration from reached data stores
      let worstRto = 0;
      exposed.forEach(function (_, id) {
        const a = byId[id];
        if (a.kind === 'external' || a.kind === 'edge') return;
        out.impactedIds.push(id);
        if (a.records) {
          out.dataAtRisk[id] = a.records;
          out.loss.data += dataCost(D, a.records, id === 'vault' ? ctx.cardValue : 1);
          log(null, 'impact', 'Exfiltration', id, 'impacted', 'Data at risk: ' + a.name + ' (' + a.records.toLocaleString() + ' records)');
        }
        if (a.critical) worstRto = Math.max(worstRto, 8);
      });
      out.outageHours = worstRto;
      out.loss.outage = worstRto * D.COMPANY.outageCostPerHour;
    }

    let gross = out.loss.response + out.loss.rebuild + out.loss.outage + out.loss.data;
    const ins = applyInsurance(gross, ctx.insurance);
    out.loss.gross = gross; out.loss.insured = ins.recovered; out.loss.net = ins.net;
    return out;
  }

  /* BEC: no network spread — a fraudulent-transfer risk */
  function runBec(D, atk, ctx, rand, trace) {
    const g = graph(D), byId = g.byId;
    const events = trace ? [] : null;
    const out = { attack: atk.id, breached: false, exposedIds: [], impactedIds: [], dataAtRisk: {},
      detectHour: null, containHour: null, outageHours: 0, events: events,
      loss: { response: 0, rebuild: 0, outage: 0, data: 0, fraud: 0, gross: 0, insured: 0, net: 0 } };
    function log(phase, tactic, assetId, state, text) { if (events) events.push({ hour: 0, phase: phase, tactic: tactic, asset: assetId || null, state: state || null, text: text }); }

    const en = atk.entry[0];
    const usable = en.base.deliver * ctx.phishDelivery * en.base.click * ctx.phishClick * ctx.phishCredReuse;
    if (rand() >= Math.min(0.99, usable)) { log('prep', null, null, 'held', 'Credential phishing did not succeed'); return out; }
    out.breached = true; out.exposedIds = ['finance']; out.impactedIds = ['finance'];
    log('entry', 'Initial Access', 'finance', 'exposed', 'Finance mailbox credentials compromised');

    if (rand() < atk.fraudBase * ctx.fraudTransfer) {
      out.loss.fraud = atk.fraudLoss;
      out.loss.response = atk.fixedResponse;
      log('impact', 'Impact', 'finance', 'impacted', 'Fraudulent transfer paid — $' + atk.fraudLoss.toLocaleString());
    } else {
      out.loss.response = Math.round(atk.fixedResponse * 0.4);
      log('contain', 'Containment', 'finance', 'contained', 'Transfer verification blocked the payout');
    }
    let gross = out.loss.fraud + out.loss.response;
    const ins = applyInsurance(gross, ctx.insurance);
    out.loss.gross = gross; out.loss.insured = ins.recovered; out.loss.net = ins.net;
    return out;
  }

  function runOnce(D, atk, ctx, rand, trace) {
    return atk.id === 'bec' ? runBec(D, atk, ctx, rand, trace) : runNetwork(D, atk, ctx, rand, trace);
  }

  /* Monte Carlo: expected loss per event + percentiles */
  function expectedLoss(D, atk, ctx, runs, seedKey) {
    runs = runs || D.MODEL.runs;
    const rand = mulberry32(hashSeed(seedKey || 'base', atk.id, [...ctx.selected].sort().join('|')));
    let sum = 0, breaches = 0; const losses = new Array(runs);
    for (let i = 0; i < runs; i++) {
      const r = runOnce(D, atk, ctx, rand, false);
      losses[i] = r.loss.net; sum += r.loss.net; if (r.breached) breaches++;
    }
    losses.sort(function (a, b) { return a - b; });
    const mean = sum / runs;
    const pct = function (q) { return losses[Math.min(runs - 1, Math.floor(q * runs))]; };
    return { mean: mean, breachRate: breaches / runs, p50: pct(0.5), p90: pct(0.9), p95: pct(0.95), max: losses[runs - 1], losses: losses };
  }

  /* full assessment across all scenarios for a given set of controls */
  function assess(D, selected, opts) {
    opts = opts || {};
    const ctxBase = buildContext(D, []);
    const ctx = buildContext(D, selected);
    const scenarios = [];
    let aleBase = 0, aleNow = 0;
    for (let i = 0; i < D.ATTACKS.length; i++) {
      const atk = D.ATTACKS[i];
      const base = expectedLoss(D, atk, ctxBase, opts.runs);
      const now = expectedLoss(D, atk, ctx, opts.runs);
      const sBase = atk.aro * base.mean, sNow = atk.aro * now.mean;
      aleBase += sBase; aleNow += sNow;
      scenarios.push({
        id: atk.id, name: atk.name, short: atk.short, aro: atk.aro,
        sleBase: base.mean, sleNow: now.mean, aleBase: sBase, aleNow: sNow,
        breachBase: base.breachRate, breachNow: now.breachRate,
        p90Base: base.p90, p90Now: now.p90, dist: now.losses,
        // qualitative 1..5 likelihood × impact, for the heat map
        likeBase: band5(base.breachRate), likeNow: band5(now.breachRate),
        impBase: bandMoney(base.p90, D), impNow: bandMoney(now.p90, D)
      });
    }
    const cost = ctx.cost;
    const tcorBase = aleBase;
    const tcorNow = aleNow + cost;
    const rosi = cost > 0 ? (aleBase - aleNow - cost) / cost : 0;
    const reduction = aleBase > 0 ? (aleBase - aleNow) / aleBase : 0;

    // Score: risk reduction rewarded, wasted spend and leftover risk penalised.
    // 0..100. Full marks ≈ cut most of the risk cheaply.
    const budget = D.MODEL.budget;
    const efficiency = cost > 0 ? Math.max(0, (aleBase - aleNow) / cost) : 0; // $ saved per $ spent
    let score = 100 * (0.6 * reduction + 0.4 * Math.min(1, efficiency / 6));
    const over = Math.max(0, cost - budget);
    if (over > 0) score -= Math.min(40, 40 * over / budget);
    score = Math.max(0, Math.round(score));

    return {
      selected: Array.from(ctx.selected), scenarios: scenarios,
      aleBase: aleBase, aleNow: aleNow, reduction: reduction,
      cost: cost, tcorBase: tcorBase, tcorNow: tcorNow, rosi: rosi,
      score: score, budget: budget, overBudget: over,
      efficiency: efficiency
    };
  }

  function band5(rate) { return rate >= 0.6 ? 5 : rate >= 0.35 ? 4 : rate >= 0.15 ? 3 : rate >= 0.05 ? 2 : 1; }
  function bandMoney(v, D) {
    const u = D.COMPANY.dailyVolumeUSD;
    return v >= u ? 5 : v >= u * 0.4 ? 4 : v >= u * 0.15 ? 3 : v >= u * 0.04 ? 2 : 1;
  }

  /*
   * A single representative, reproducible run for the on-screen animation.
   * Deterministic in (controls, attack): we scan seed indices in a fixed order
   * and return the first run that breaches, so the demo is meaningful when risk
   * is high yet still shows "held at the perimeter" when controls make breaches
   * genuinely rare. Same inputs always pick the same run (reproducible + fair).
   */
  function demoRun(D, selected, attackId, seedKey) {
    const ctx = buildContext(D, selected);
    const atk = D.ATTACKS.find(function (a) { return a.id === attackId; });
    const key = [...ctx.selected].sort().join('|');
    let first = null;
    for (let n = 0; n < 40; n++) {
      const rand = mulberry32(hashSeed(seedKey || 'demo', attackId, key, n));
      const r = runOnce(D, atk, ctx, rand, true);
      if (n === 0) first = r;
      if (r.breached) { r.seedIndex = n; return r; }
    }
    first.seedIndex = 0;
    return first;
  }

  const ENGINE = { mulberry32: mulberry32, hashSeed: hashSeed, buildContext: buildContext,
    expectedLoss: expectedLoss, assess: assess, demoRun: demoRun, runOnce: runOnce,
    entryExposure: entryExposure, applyInsurance: applyInsurance };
  if (typeof module !== 'undefined' && module.exports) module.exports = ENGINE;
  else root.BSEngine = ENGINE;
})(typeof self !== 'undefined' ? self : this);
