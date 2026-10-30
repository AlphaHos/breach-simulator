# NabuPay Breach Simulator

A quantitative cyber-risk simulator built for the **Risk Management and Incident
Response** module (Al-Shaab University, 2026).

You defend **NabuPay**, a fictional Iraqi payment company. Choose security controls,
run incidents against its network, and see how expected annual loss, tail risk,
total cost of risk and return on security investment change. Every input is either
traced to a published source or labelled as an assumption with an uncertainty range.

**Live:** https://alphahos.github.io/breach-simulator/

> Educational risk model. NabuPay is fictional. The simulator models likelihood,
> impact and defensive response only; it contains no attack tooling and makes no
> network connections beyond loading fonts.

## What it does

| Section | What you get |
|---|---|
| **Simulate** | Replay one incident (ransomware, network intrusion, phishing/BEC) on the asset map with the NIST SP 800-61 lifecycle, an incident log and a loss breakdown. |
| **Defend** | 12 controls grouped by risk treatment (mitigate, transfer, avoid). Each shows its annual cost and the expected loss it removes on top of your other controls. Free or $120K budget mode. |
| **Analyze** | Loss exceedance curve with an adjustable risk appetite, efficient frontier of all 4,096 control portfolios, sensitivity (tornado) analysis, FAIR breakdown per scenario, NIST 800-30 risk matrix, business impact analysis (RTO vs. MTD) and calibration against IBM and Sophos figures. |
| **Method** | The FAIR model, equations, the simulation procedure, every input with its range and basis (published or assumption), limitations and sources. |
| **Report** | A printable risk and incident report, and a local leaderboard. |

## The model

A Monte Carlo risk model following the Open Group **FAIR** taxonomy.

| Quantity | Definition |
|---|---|
| LEF (loss events / yr) | TEF (attempts / yr) × Vulnerability (probability an attempt succeeds) |
| ALE | LEF × LM (mean loss per event), equivalently ARO × SLE |
| Total cost of risk | annual control spend + residual ALE |
| ROSI | (ALE inherent − ALE residual − spend) ÷ spend |
| Risk score | likelihood band × impact band (1–5 each, NIST SP 800-30) |
| Score | 100 × ln(TCoR none ÷ TCoR you) ÷ ln(TCoR none ÷ TCoR optimum) |

**One simulated year:** sample every uncertain input from its PERT distribution →
draw attempts per scenario from a Poisson distribution → run each attempt through the
asset model (entry, spread every six hours, detection, containment) → price response,
rebuild, outage, breached records and fraud → apply insurance. 2,000 years per
portfolio give the loss exceedance curve and percentiles.

The efficient frontier and per-control savings use best-estimate inputs and common
random numbers (the same 300 incidents per scenario for every portfolio), precomputed
by `tools/build-frontier.js`.

## Run and rebuild

Static site, no build step for the page itself:

```bash
python3 -m http.server 8000      # open http://localhost:8000
node tools/build-frontier.js     # re-run after changing Js/data.js (about 10 s)
```

The page checks a hash of the model inputs and recomputes the portfolio table in the
browser if `Js/frontier.js` is stale.

## Files

```
index.html            page structure
css/app.css           design system
Js/data.js            company, assets, controls, scenarios, ranges and sources
Js/engine.js          risk engine (browser and Node)
Js/frontier.js        precomputed expected loss of all 4,096 portfolios
Js/charts.js          SVG charts (loss exceedance, frontier, tornado)
Js/app.js             navigation, defences, analysis, method, report
Js/sim.js             incident replay on the asset map
tools/build-frontier.js
```

## Main sources

IBM Cost of a Data Breach 2025 · Sophos State of Ransomware in Financial Services 2025 ·
Verizon DBIR 2025 · Microsoft Research on MFA (2023) · KnowBe4 Phishing Benchmark 2025 ·
FBI IC3 2024 · ITIC 2024 · NIST SP 800-30 Rev. 1 · NIST SP 800-61 Rev. 3 ·
Open Group O-RT (FAIR) · Vose, *Risk Analysis* (2008) · ISO 22301:2019 · PCI DSS v4.0.1 ·
MITRE ATT&CK. Full list with links on the Method page.

*Hussein Alaa Jaafar — Al-Shaab University — 2026*
