# NabuPay Breach Simulator

An interactive **cyber risk & incident-response simulator** built for the
Risk Management and Incident Response module (Al-Shaab University, 2026).

You run attacks against a fictional Iraqi payment company, **NabuPay**, apply
security controls, and watch the expected annual loss, risk level and return on
security investment change in real time. Every number in the model is traced to
a published source.

**Live demo:** `https://alphahos.github.io/breach-simulator/`

> ⚠️ Educational risk-modelling only. NabuPay is fictional. The simulator
> contains **no attack tooling** and performs **no real network activity** — it
> works entirely in terms of probability, impact and defensive response.

---

## What it does

- **Simulates three threat scenarios** — Ransomware, Network intrusion, and
  Phishing/BEC — as a risk model over NabuPay's asset network.
- **12 security controls** grouped by treatment strategy (mitigate / transfer /
  avoid / accept). Each has a real annual cost and a documented effect.
- **Two modes:** Free (open spend) and Budget (capped at $120K) — both scored on
  *total cost of risk*, so buying everything is not the winning move.
- **Live risk metrics:** ALE (before/after), control spend, Total Cost of Risk,
  ROSI, and a 0–100 security score.
- **Risk heat map** (inherent → residual) and an animated **NIST SP 800-61r3**
  incident timeline.
- **One-click report:** a printable risk register, cost-benefit table, MITRE
  ATT&CK classification and sources.

---

## The model (how the numbers are produced)

The engine (`js/engine.js`) is a Monte-Carlo risk model in the spirit of **FAIR**
and **NIST SP 800-30**. Nothing is hard-coded in the UI; all parameters live in
`js/data.js` with a `why` note and a source next to each one.

| Quantity | Formula |
|---|---|
| **SLE** (single loss expectancy) | mean net loss per event, over 1,200 Monte-Carlo runs |
| **ALE** (annual loss expectancy) | `ARO × SLE` |
| **Risk score** | `likelihood(1–5) × impact(1–5)` → heat map |
| **Total Cost of Risk** | `annual control spend + residual ALE` |
| **ROSI** | `(ALE_before − ALE_after − control_cost) / control_cost` |
| **Security score** | rewards risk reduction and efficiency; penalises wasted spend and going over budget |

Each run: the attack tries its entry vectors; successful entry exposes an asset;
exposure spreads across network links each 6-hour round (segmentation, patching
and EDR reduce the spread); detection and containment follow the defender's
controls; financial impact (outage, data, rebuild, fraud, response) is summed and
insurance applied. The simulation is **seeded**, so the same controls always give
the same result — which also lets a server re-verify any leaderboard score.

Data-breach cost per record is tiered: IBM's full per-record figure applies to the
first 5,000 records and a reduced marginal rate beyond, reflecting IBM's finding
that per-record cost falls sharply in large breaches.

---

## Sources

1. IBM — Cost of a Data Breach Report 2025 / 2026
2. Sophos — The State of Ransomware in Financial Services 2025
3. Verizon — 2025 Data Breach Investigations Report (DBIR)
4. Microsoft Research — How effective is MFA at deterring cyberattacks? (2023)
5. KnowBe4 — Phishing by Industry Benchmarking Report 2025
6. FBI IC3 — 2024 Internet Crime Report
7. ITIC — 2024 Hourly Cost of Downtime Survey
8. NIST SP 800-61 Rev. 3 — Incident Response Recommendations
9. NIST SP 800-30 — Guide for Conducting Risk Assessments
10. MITRE ATT&CK Enterprise Matrix
11. PCI Security Standards Council — PCI DSS v4.0.1

Full titles, URLs and the specific figure used from each are listed in-app and in
`js/data.js`.

---

## Run it

It is a static site — no build, no server.

```bash
# just open the file
open index.html
# or serve locally
python3 -m http.server 8000   # then visit http://localhost:8000
```

### Deploy to GitHub Pages
1. Push these files to the repo.
2. **Settings → Pages → Source: Deploy from a branch → `main` / root → Save.**
3. Wait ~1 minute; the site is live at `https://<user>.github.io/breach-simulator/`.

---

## Project structure

```
breach-simulator/
├── index.html        # layout
├── css/app.css       # security-print visual identity
├── js/data.js        # company, assets, controls, scenarios + sources (all parameters)
├── js/engine.js      # pure risk engine (runs in browser and Node)
├── js/ui.js          # rendering, animation, report, leaderboard
└── README.md
```

The engine is dependency-free and also runs under Node, so the model can be
tested or re-verified on a server:

```bash
node -e "const D=require('./js/data.js'),E=require('./js/engine.js');
console.log(E.assess(D, ['mfa','segment','backup']));"
```

---

*Hussein Alaa Jaafar — Al-Shaab University — Risk Management & Incident Response, 2026.*
