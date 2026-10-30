/*
 * NabuPay Breach Simulator — model data
 *
 * Every number the simulator uses lives in this file. Each one is either
 * taken from a published source (see SOURCES) or is a stated assumption
 * (see the `why` field next to it). Nothing in the engine is hard-coded.
 *
 * Time unit: one simulation round = 6 hours.
 * Money unit: US dollars per year (controls) or per incident (losses).
 */
(function (root) {
  'use strict';

  const SOURCES = {
    ibm2025: {
      title: 'IBM — Cost of a Data Breach Report 2025',
      url: 'https://www.ibm.com/reports/data-breach',
      note: 'Global average breach cost USD 4.44M; financial sector USD 5.56M; mean time to identify and contain 241 days.'
    },
    ibm2026rec: {
      title: 'IBM — Cost of a Data Breach Report 2026 (summarised by Secureframe)',
      url: 'https://secureframe.com/blog/data-breach-statistics',
      note: 'Cost per customer PII record USD 192.'
    },
    sophosFin2025: {
      title: 'Sophos — The State of Ransomware in Financial Services 2025',
      url: 'https://assets.sophos.com/X24WTUEQ/at/749t28qhvtxq93p8gb7wtgz/sophos-state-of-ransomware-in-financial-services-2025.pdf',
      note: 'Root causes: exploited vulnerabilities 40%, compromised credentials 17%, phishing 16%. Data encrypted in 59% of attacks. Mean recovery cost USD 1.74M. Recovery: 47% within a week, 26% within a month, 16% took 1–3 months.'
    },
    dbir2025: {
      title: 'Verizon — 2025 Data Breach Investigations Report',
      url: 'https://www.verizon.com/business/resources/reports/dbir/',
      note: 'Initial access: credential abuse ~22%, vulnerability exploitation 20%, phishing 16%. Edge/VPN exploitation rose to 22%; edge devices took a median of 32 days (all CVEs) and 209 days on average (edge CVEs) to patch.'
    },
    msMfa2023: {
      title: 'Microsoft Research — How effective is multifactor authentication at deterring cyberattacks? (2023)',
      url: 'https://www.microsoft.com/research/publication/how-effective-is-multifactor-authentication-at-deterring-cyberattacks/',
      note: 'MFA reduced the risk of account compromise by 99.22% overall and 98.56% for leaked credentials.'
    },
    knowbe42025: {
      title: 'KnowBe4 — Phishing by Industry Benchmarking Report 2025',
      url: 'https://www.knowbe4.com/press/knowbe4-report-reveals-security-training-reduces-global-phishing-click-rates-by-86',
      note: 'Baseline Phish-prone Percentage 33.1%, falling to 4.1% after 12 months of training (−86%).'
    },
    ic32024: {
      title: 'FBI IC3 — 2024 Internet Crime Report (summarised by Nacha)',
      url: 'https://www.nacha.org/news/fbis-ic3-finds-almost-85-billion-lost-business-email-compromise-last-three-years',
      note: 'Business email compromise: ~USD 2.8B lost across 21,442 complaints (~USD 130K per complaint).'
    },
    itic2024: {
      title: 'ITIC — 2024 Hourly Cost of Downtime Survey',
      url: 'https://calyptix.com/wp-content/uploads/ITIC-2024-Hourly-Cost-of-Downtime-Survey-Results-Part-2.pdf',
      note: 'One hour of downtime exceeds USD 300K for over 90% of mid-size and large enterprises.'
    },
    nist80061: {
      title: 'NIST SP 800-61 Rev. 3 — Incident Response Recommendations',
      url: 'https://csrc.nist.gov/pubs/sp/800/61/r3/final',
      note: 'Incident response lifecycle used for the timeline.'
    },
    attack: {
      title: 'MITRE ATT&CK Enterprise Matrix',
      url: 'https://attack.mitre.org/',
      note: 'Technique IDs attached to every attack step.'
    },
    pcidss: {
      title: 'PCI Security Standards Council — PCI DSS v4.0.1',
      url: 'https://www.pcisecuritystandards.org/',
      note: 'Basis for tokenisation and card-data segmentation.'
    },
    nist80030: {
      title: 'NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments',
      url: 'https://csrc.nist.gov/pubs/sp/800/30/r1/final',
      note: 'Risk = likelihood × impact; likelihood/impact scales used for the heat map.'
    },
    fair: {
      title: 'The Open Group — Risk Taxonomy (O-RT) Standard, v3.0.1 (FAIR)',
      url: 'https://publications.opengroup.org/c20b',
      note: 'Loss event frequency = threat event frequency × vulnerability; risk = LEF × loss magnitude. Basis of the quantitative model.'
    },
    vose: {
      title: 'Vose, D. — Risk Analysis: A Quantitative Guide, 3rd ed. (Wiley, 2008)',
      url: 'https://www.wiley.com/en-us/Risk+Analysis%3A+A+Quantitative+Guide%2C+3rd+Edition-p-9780470512845',
      note: 'PERT distribution for expert three-point estimates (minimum, most likely, maximum).'
    },
    iso22301: {
      title: 'ISO 22301:2019 — Business continuity management systems',
      url: 'https://www.iso.org/standard/75106.html',
      note: 'Business impact analysis: maximum tolerable downtime (MTD) and recovery time objective (RTO).'
    }
  };

  /* The company. Fictional. Sized like a mid-size Iraqi wallet/payments firm. */
  const COMPANY = {
    name: 'NabuPay',
    city: 'Baghdad',
    employees: 180,
    customers: 180000,
    cardsOnFile: 60000,
    dailyVolumeUSD: 5000000,
    // Full payment outage cost per hour. Built bottom-up because ITIC's
    // >$300K/hour figure describes enterprises much larger than NabuPay.
    outageCostPerHour: 12000,
    outageCostRange: [6000, 12000, 25000],
    annualRevenueUSD: 21900000,   // 1.2% fee × $5M/day × 365
    outageCostWhy: 'Lost fees (1.2% × $5M/day ≈ $2.5K/h) + merchant SLA credits (~$3K/h) + customer churn and reputation (~$5.5K/h) + support overtime (~$1K/h). Bottom-up assumption; ITIC 2024 reports >$300K/h for much larger enterprises.'
  };

  const ZONES = {
    internet: { label: 'Internet' },
    dmz: { label: 'Edge (DMZ)' },
    staff: { label: 'Staff network' },
    core: { label: 'Payment core' },
    vault: { label: 'Backup' }
  };

  /*
   * Assets. `kind` drives which controls apply:
   *   endpoint — employee workstations (a node stands for a group of PCs)
   *   server   — servers and services
   *   edge     — internet-facing systems
   * `critical` = payments stop while this asset is down.
   * Coordinates: `d` desktop (1000×560), `m` mobile (400×720).
   */
  const ASSETS = [
    { id: 'attacker', name: 'Threat actor', zone: 'internet', kind: 'external',
      d: [70, 280], m: [200, 40] },

    { id: 'mail', name: 'Email gateway', zone: 'dmz', kind: 'edge',
      rebuild: 8000, d: [250, 110], m: [70, 160] },
    { id: 'vpn', name: 'VPN gateway', zone: 'dmz', kind: 'edge',
      rebuild: 12000, d: [250, 280], m: [200, 160] },
    { id: 'api', name: 'Payment API', zone: 'dmz', kind: 'edge', critical: true,
      rebuild: 30000, d: [250, 450], m: [330, 160] },

    { id: 'support', name: 'Support desk PCs', zone: 'staff', kind: 'endpoint', count: 60,
      rebuild: 18000, d: [470, 90], m: [70, 300] },
    { id: 'finance', name: 'Finance PCs', zone: 'staff', kind: 'endpoint', count: 8,
      rebuild: 6000, d: [470, 220], m: [200, 300] },
    { id: 'dev', name: 'Engineering PCs', zone: 'staff', kind: 'endpoint', count: 25,
      rebuild: 12000, d: [470, 350], m: [330, 300] },
    { id: 'app', name: 'Wallet app backend', zone: 'staff', kind: 'server', critical: true,
      rebuild: 35000, d: [470, 480], m: [330, 420] },

    { id: 'dc', name: 'Domain controller', zone: 'core', kind: 'server', critical: true,
      rebuild: 30000, d: [700, 160], m: [70, 440] },
    { id: 'txdb', name: 'Transaction DB', zone: 'core', kind: 'server', critical: true,
      rebuild: 40000, records: 180000, recordType: 'customer PII', d: [700, 300], m: [200, 540] },
    { id: 'vault', name: 'Card data vault', zone: 'core', kind: 'server', critical: true,
      rebuild: 40000, records: 60000, recordType: 'card data', d: [700, 440], m: [330, 560] },
    { id: 'switch', name: 'Bank settlement link', zone: 'core', kind: 'server', critical: true,
      rebuild: 25000, d: [880, 440], m: [70, 600] },

    { id: 'backup', name: 'Backup server', zone: 'vault', kind: 'server',
      rebuild: 20000, d: [900, 200], m: [200, 670] }
  ];

  /* Network reachability. `legit` paths survive segmentation. */
  const LINKS = [
    ['attacker', 'mail'], ['attacker', 'vpn'], ['attacker', 'api'],
    ['mail', 'support'], ['mail', 'finance'], ['mail', 'dev'],
    ['vpn', 'support'], ['vpn', 'dev'], ['vpn', 'dc'],
    ['api', 'app', 'legit'], ['api', 'vault', 'legit'],
    ['app', 'txdb', 'legit'], ['dev', 'app'],
    ['support', 'dc'], ['finance', 'dc'], ['dev', 'dc'],
    ['support', 'finance'], ['finance', 'dev'],
    ['dev', 'txdb'], ['finance', 'switch'],
    ['dc', 'txdb'], ['dc', 'vault'], ['dc', 'switch'], ['dc', 'backup'], ['dc', 'app'],
    ['txdb', 'backup', 'legit'], ['vault', 'backup', 'legit'], ['txdb', 'switch', 'legit']
  ];

  /*
   * Controls. `effects` are read by the engine:
   *   phishDelivery   × chance a malicious email reaches the inbox
   *   phishClick      × chance a user runs the payload / enters credentials
   *   credLogin       × chance stolen or sprayed credentials work from outside
   *   phishCredReuse  × chance phished credentials are usable (AiTM kits bypass some MFA)
   *   exploitEdge     × chance an internet-facing vulnerability is exploitable
   *   exploitInternal × chance of lateral movement through unpatched hosts
   *   lateralCross    × chance of lateral movement across network zones
   *   execBlock       × chance malware runs on a protected host
   *   detect          + per-round detection hazard
   *   containRounds   rounds from detection to containment
   *   backupImmutable backups cannot be encrypted
   *   cardValue       × loss per stolen card record
   *   fraudTransfer   × chance a fraudulent transfer is paid
   *   insurance       {share, deductible, limit}
   *   removeAsset     asset taken out of the network entirely
   */
  const CONTROLS = [
    { id: 'mfa', name: 'Multi-factor authentication', treatment: 'mitigate', cost: 16000,
      costWhy: '≈ $6 per user per month for 180 staff + rollout.',
      effects: { credLogin: 0.0078, phishCredReuse: 0.2 },
      why: 'Microsoft (2023): MFA cut account compromise by 99.22%. Phishing kits that proxy the login (AiTM) still beat basic MFA, so phished credentials keep 20%.',
      src: ['msMfa2023'] },
    { id: 'training', name: 'Phishing awareness training', treatment: 'mitigate', cost: 9000,
      costWhy: '≈ $50 per user per year incl. simulations.',
      effects: { phishClick: 0.124 },
      why: 'KnowBe4 (2025): phish-prone rate fell from 33.1% to 4.1% after 12 months.',
      src: ['knowbe42025'] },
    { id: 'emailsec', name: 'Email security gateway', treatment: 'mitigate', cost: 14000,
      costWhy: '≈ $6.5 per mailbox per month.',
      effects: { phishDelivery: 0.3 },
      why: 'Assumption: filtering stops about 70% of targeted malicious mail before the inbox.',
      src: [] },
    { id: 'edr', name: 'Endpoint detection & response', treatment: 'mitigate', cost: 32000,
      costWhy: '≈ $60 per endpoint per year for ~250 endpoints and servers + console.',
      effects: { execBlock: 0.5, detect: 0.05 },
      why: 'Assumption: EDR blocks half of commodity payloads and raises an alert on suspicious activity on each compromised host.',
      src: [] },
    { id: 'patch', name: 'Patch management', treatment: 'mitigate', cost: 18000,
      costWhy: 'Tooling + 0.2 FTE of an admin.',
      effects: { exploitEdge: 0.2, exploitInternal: 0.6 },
      why: 'DBIR 2025: exploitation is 20% of initial access and edge CVEs took 209 days on average to patch. A patch programme closes most of that window.',
      src: ['dbir2025'] },
    { id: 'segment', name: 'Network segmentation', treatment: 'mitigate', cost: 45000,
      costWhy: 'Firewall rules, VLAN redesign and jump hosts, amortised over 3 years.',
      effects: { lateralCross: 0.12 },
      why: 'Only application paths may cross zones (PCI DSS scope reduction). Attackers must break through a firewall to move between zones.',
      src: ['pcidss'] },
    { id: 'backup', name: 'Immutable offline backups', treatment: 'mitigate', cost: 24000,
      costWhy: 'Object-lock storage + quarterly restore tests.',
      effects: { backupImmutable: true, restoreHours: 24 },
      why: 'Sophos (2025): only 10% recover within a day. Tested immutable backups are what puts a company in that group.',
      src: ['sophosFin2025'] },
    { id: 'mdr', name: '24/7 SOC monitoring (MDR)', treatment: 'transfer', cost: 70000,
      costWhy: 'Managed detection & response retainer for ~250 assets.',
      effects: { detect: 0.09, containRounds: 1 },
      why: 'Outsourcing detection shares the monitoring risk with a provider. Analysts watch alerts around the clock and isolate hosts within one round.',
      src: ['ibm2025'] },
    { id: 'token', name: 'Card tokenisation', treatment: 'avoid', cost: 30000,
      costWhy: 'Tokenisation service fees + integration.',
      effects: { cardValue: 0.08 },
      why: 'Stops storing real card numbers. A stolen vault holds tokens that are useless outside NabuPay, so only residual handling costs remain.',
      src: ['pcidss'] },
    { id: 'fraud', name: 'Transfer verification & fraud monitoring', treatment: 'mitigate', cost: 22000,
      costWhy: 'Fraud engine licence + call-back verification process.',
      effects: { fraudTransfer: 0.25 },
      why: 'Assumption: call-back on payee changes and dual approval stop three of four fraudulent transfer requests.',
      src: ['ic32024'] },
    { id: 'insurance', name: 'Cyber insurance', treatment: 'transfer', cost: 38000,
      costWhy: 'Annual premium for $3M cover.',
      effects: { insurance: { share: 0.7, deductible: 50000, limit: 3000000 } },
      why: 'Transfers 70% of each loss above a $50K deductible, up to $3M per incident.',
      src: [] },
    { id: 'novpn', name: 'Shut down remote VPN access', treatment: 'avoid', cost: 45000,
      costWhy: 'No licence cost; the figure is lost productivity from no remote work.',
      effects: { removeAsset: 'vpn' },
      why: 'Risk avoidance: removes the edge entry point entirely, at a business cost.',
      src: ['dbir2025'] }
  ];

  /*
   * Attack scenarios.
   * `aro` = targeted attempts reaching NabuPay per year (assumption,
   * weighted by DBIR 2025 initial-access shares for a payments firm).
   */
  const ATTACKS = [
    {
      id: 'ransomware', name: 'Ransomware', short: 'Phishing email → domain takeover → encryption',
      aro: 0.6,
      aroWhy: 'Assumption: roughly one targeted ransomware attempt every ~18 months for a payments firm of this size.',
      entry: [
        { via: 'mail', to: ['support', 'finance', 'dev'], type: 'phish', base: { deliver: 0.9, click: 0.331 },
          technique: 'T1566.001', label: 'Spear-phishing attachment' },
        { via: 'vpn', type: 'cred', base: 0.12, technique: 'T1133', label: 'Login with stolen VPN credentials' },
        { via: 'vpn', type: 'exploit', base: 0.1, technique: 'T1190', label: 'Exploit unpatched VPN appliance' }
      ],
      dwellRounds: 16,
      dwellWhy: 'Assumption: ransomware operators spend about four days moving laterally before encrypting.',
      exfilPerRound: 8000,
      fixedResponse: 60000
    },
    {
      id: 'intrusion', name: 'Network intrusion', short: 'Edge exploit → database theft',
      aro: 0.8,
      aroWhy: 'Assumption: edge and credential attacks are the two largest DBIR 2025 vectors; about one serious attempt a year.',
      entry: [
        { via: 'vpn', type: 'cred', base: 0.25, technique: 'T1110.003', label: 'Password spraying the VPN' },
        { via: 'vpn', type: 'exploit', base: 0.18, technique: 'T1190', label: 'Exploit unpatched VPN appliance' },
        { via: 'api', type: 'exploit', base: 0.1, technique: 'T1190', label: 'Exploit payment API flaw' }
      ],
      dwellRounds: 28,
      exfilPerRound: 20000,
      fixedResponse: 60000
    },
    {
      id: 'bec', name: 'Phishing & BEC', short: 'Credential phish → mailbox takeover → fake transfer',
      aro: 2.0,
      aroWhy: 'Assumption: finance teams receive several targeted lures a year; ~2 credible campaigns.',
      entry: [
        { via: 'mail', to: ['finance'], type: 'phishCred', base: { deliver: 0.9, click: 0.331 },
          technique: 'T1566.002', label: 'Credential phishing link' }
      ],
      fraudBase: 0.6,
      fraudLoss: 130000,
      fraudLossWhy: 'FBI IC3 2024: ~$2.8B across 21,442 BEC complaints ≈ $130K each.',
      fixedResponse: 15000
    }
  ];

  /*
   * Uncertainty. Every uncertain input is a three-point estimate
   * [minimum, most likely, maximum], sampled with a PERT distribution
   * (Vose 2008). Ranges are wider where the input is an assumption and
   * narrower where it comes from a published figure.
   */
  const ATTACK_TEF_RANGE = {          // attempts per year
    ransomware: [0.3, 0.6, 1.0],
    intrusion: [0.4, 0.8, 1.4],
    bec: [1.0, 2.0, 4.0]
  };
  // Realised effectiveness of each control relative to its stated effect.
  // 1 = works exactly as the evidence says; 0.6 = delivers 60% of the reduction.
  const CONTROL_EFF_RANGE = {
    mfa: [0.85, 1, 1],          // sourced (Microsoft 2023); gaps in coverage
    training: [0.6, 0.9, 1],    // sourced (KnowBe4) but needs 12 months
    emailsec: [0.5, 1, 1.15],   // assumption
    edr: [0.5, 1, 1.2],         // assumption
    patch: [0.6, 0.9, 1],       // sourced (DBIR) but patch lag varies
    segment: [0.7, 1, 1.1],     // design control, depends on rule hygiene
    backup: [0.8, 1, 1],
    mdr: [0.6, 1, 1.1],
    token: [0.9, 1, 1],
    fraud: [0.5, 1, 1.15],      // assumption
    insurance: [1, 1, 1],       // contractual terms
    novpn: [1, 1, 1]            // structural removal
  };
  // Business impact analysis: maximum tolerable downtime per critical service (assumption,
  // set by NabuPay's management in the BIA workshop per ISO 22301).
  const BIA_MTD_HOURS = { api: 4, app: 8, txdb: 8, vault: 12, 'switch': 12, dc: 24 };

  const MODEL = {
    roundHours: 6,
    // Spread of exposure between connected assets, per 6-hour round (assumption).
    lateralBase: 0.28,            // workstation to workstation
    lateralToServer: 0.16,        // workstation to server
    lateralFromDC: 0.7,           // from a compromised identity server (directory-wide reach)
    spreadScaleRange: [0.7, 1, 1.3],
    detectBase: 0.01,             // per round with no tooling (someone notices)
    detectBaseRange: [0.005, 0.01, 0.02],
    containRoundsDefault: 3,
    // Sophos (2025): data was also stolen in 31% of financial-services
    // attacks where data was encrypted.
    ransomExfilProb: 0.31,
    ransomExfilSrc: 'sophosFin2025',
    restoreHoursBackup: 72,       // backups exist but are untested
    restoreHoursNoBackup: 168,    // rebuild from scratch, about one week (Sophos modal)
    // Data-breach cost per record. IBM's ~$192/record is an average for
    // typical breaches; IBM also finds per-record cost falls sharply in large
    // ones. We charge the full rate on the first `recordTierBreak` records and
    // a reduced marginal rate beyond, so a full-database breach lands near
    // IBM's financial-sector average instead of an unrealistic linear tower.
    recordCostHigh: 192,
    recordCostHighRange: [150, 192, 240],
    recordCostLow: 10,
    recordCostLowRange: [5, 10, 25],
    recordTierBreak: 5000,
    recordCostSrc: 'ibm2026rec',
    breachFixed: 60000,           // notification, legal, regulator engagement
    years: 2000,                  // simulated years per portfolio (uncertainty Monte Carlo)
    frontierRuns: 300,            // incidents per scenario for the portfolio frontier
    budget: 120000,
    appetiteDefault: 1000000,     // ≈ 5% of annual revenue
    appetiteTolerance: 0.05       // "1 year in 20"
  };

  ATTACKS.forEach(function (a) { a.tefRange = ATTACK_TEF_RANGE[a.id]; });
  CONTROLS.forEach(function (c) { c.effRange = CONTROL_EFF_RANGE[c.id] || [1, 1, 1]; });
  ASSETS.forEach(function (a) { if (BIA_MTD_HOURS[a.id]) a.mtd = BIA_MTD_HOURS[a.id]; });

  const TECHNIQUES = {
    'T1566.001': 'Phishing: spear-phishing attachment',
    'T1566.002': 'Phishing: spear-phishing link',
    'T1133': 'External remote services',
    'T1190': 'Exploit public-facing application',
    'T1110.003': 'Brute force: password spraying',
    'T1486': 'Data encrypted for impact',
    'T1657': 'Financial theft'
  };

  const DATA = { SOURCES, COMPANY, ZONES, ASSETS, LINKS, CONTROLS, ATTACKS, MODEL, TECHNIQUES };
  if (typeof module !== 'undefined' && module.exports) module.exports = DATA;
  else root.BSData = DATA;
})(typeof self !== 'undefined' ? self : this);
