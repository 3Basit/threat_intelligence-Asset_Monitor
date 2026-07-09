# Asset Monitor & Threat Intelligence Pipeline

> **Give it a URL. It tells you exactly what's running, what's vulnerable, how dangerous it is, and how an attacker would exploit it.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-68%20passing-brightgreen)]()
[![Sources](https://img.shields.io/badge/Sources-CISA%20KEV%20%7C%20NVD%20%7C%20EPSS%20%7C%20Exploit--DB-orange)]()
[![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red)]()

---

## What You Get From a Single Run

Point it at any web asset and it returns a **complete threat picture**:

```
[CRITICAL] CVE-2017-12617 | Apache Tomcat → zero.webappsecurity.com
           | rce | TPF: 1.68 | VERSION CONFIRMED (CPE_RANGE) | 2 PUBLIC EXPLOITS
```

Every result includes:

| Data Point | What It Means |
|---|---|
| **Detected Technology** | Vendor + exact version from live HTTP + Nmap |
| **CVE ID** | Specific vulnerability from CISA KEV or NVD |
| **CVSS Score** | Technical severity (0–10) |
| **EPSS Score** | Real-world exploitation probability (ML-based) |
| **KEV Status** | Confirmed actively exploited by US Govt (CISA) |
| **Version Confirmed** | Is *your specific version* actually vulnerable? |
| **CPE Range** | Exact NVD boundary that confirmed the match |
| **Public Exploit** | Is working attack code downloadable right now? |
| **MITRE ATT&CK** | Technique + Tactic — *how* the attacker uses it |
| **CWE Classification** | Root cause weakness type |
| **TPF Score** | Composite priority score (1.0–2.0) across 9 signals |
| **Alert Level** | CRITICAL / HIGH / MEDIUM / LOW |
| **WAF Status** | Is a WAF protecting this asset? |

All of this from running: `python main.py`

---

## Real Output — From Actual Scans

```
Scanning http://zero.webappsecurity.com...
  -> Vendor:         Apache
  -> Product:        Tomcat
  -> Server:         Apache-Coyote/1.1
  -> Tomcat version: 7.0.70 (from error-page probe) ✓
  -> Open ports:     [80, 443, 8080]
  -> Technologies:   jQuery [high] via html_content

[CPE MATCH] CVE-2017-12617 v7.0.70 == cpe_exact: >=7.0.0 <7.0.82

[CRITICAL] CVE-2017-12617 | Tomcat → zero.webappsecurity.com
           | rce | TPF: 1.68 [VERSION CPE_RANGE] [EXPLOIT x2]

[CRITICAL] CVE-2025-24813 | Tomcat → zero.webappsecurity.com
           | rce | TPF: 1.95 [VERSION CPE_RANGE] [EXPLOIT x1]
```

---

## The Pipeline

```
targets.json  (your URLs + criticality)
      │
      ▼
┌──────────────────────────────────────────────┐
│  ASSET MONITOR                               │
│                                              │
│  Phase 1 — HTTP Fingerprinting               │
│    GET request → parse Server/X-Powered-By   │
│    Cookies → PHP/Java/WordPress signals       │
│    HTML → meta generators, JS libraries       │
│                                              │
│    Special: Apache-Coyote detected?          │
│    → probe 404 error page → extract real     │
│      Tomcat version (not connector version)  │
│                                              │
│  Phase 2 — Nmap Service Scan                 │
│    -sV -Pn -n -p 80,443,8080,8443,8000,6868  │
│    → confirms version + emits CPE string     │
│                                              │
│  Phase 3 — Tech & WAF Detection              │
│    Regex signatures on headers/cookies/HTML  │
│    → Cloudflare, Akamai, F5, nginx, jQuery…  │
│                                              │
│  Phase 4 — Change Detection                  │
│    vs. previous scan snapshot                │
│    → NEW_PORT_OPENED / VERSION_CHANGED / …   │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
          CISA KEV  (1,635 confirmed-exploited CVEs)
                   │
                   ▼
          NVD Enrichment
            CVSS score + severity
            CPE version ranges (structured)
            CWE root cause classification
                   │
                   ▼
          EPSS  (30-day ML exploitation probability)
                   │
                   ▼
          Exploit-DB  (public PoC availability)
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  MATCHING ENGINE  (4 stages)                 │
│                                              │
│  Stage 1 — Vendor + Product confidence       │
│    "nginx" == "nginx" AND keyword in CVE     │
│    → HIGH confidence → proceed               │
│    → LOW confidence  → review list           │
│                                              │
│  Stage 2 — CPE Filter                        │
│    Parse CPE string structurally:            │
│    cpe:2.3:a:[vendor]:[product]:version      │
│    Check fields [3] and [4] ONLY             │
│    Skip :o: (OS-type CPEs)                   │
│    → prevents F5/Ubuntu CPEs matching nginx  │
│                                              │
│  Stage 3 — Version Confirmation (two-pass)   │
│    Pass 1: CPE range  → integer tuple math   │
│      (1,18,0) >= (0,6,18) AND < (1,20,1) ✅  │
│    Pass 2: text search → regex word boundary │
│      fallback when NVD has no CPE ranges     │
│                                              │
│  Stage 4 — KEV Sanity Gate                   │
│    Version outside ALL product CPE ranges?   │
│    → route to review (not an alert)          │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
          MITRE ATT&CK Mapping
            vuln_type → Technique ID + Tactic
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  TPF ENGINE  (Threat Pressure Factor)        │
│                                              │
│  TPF = 1.0 + Threat Score  (range 1.0–2.0)  │
│                                              │
│  CVSS ≥ 9.0            → +0.20               │
│  EPSS ≥ 0.70           → +0.20               │
│  KEV confirmed         → +0.13               │
│  vuln_type = rce       → +0.20               │
│  Business criticality  → +0.20 (critical)    │
│  Recency ≤ 30 days     → +0.10               │
│  Public exploit        → +0.10               │
│  Ransomware campaign   → +0.07               │
│  Version CPE_RANGE     → +0.05               │
│                                              │
│  Alert only when NEW or ESCALATED            │
│  (zero duplicate alerts across scans)        │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
     threat_intelligence_output.json
     alerts.json
     asset_changes.json
```

---

## Why Version Confirmation Matters

Most scanners match by product name. This pipeline matches by **proven version**:

```
CVE-2017-7269  →  affects IIS 6.0 ONLY
Detected:          IIS 8.5

❌  Naive scanner:  "IIS found + CVE found = ALERT"
✅  This pipeline:  8.5 ≠ 6.0  →  no alert generated
```

Version confirmation uses NVD's structured CPE boundaries, parsed as integer tuples:

```python
"1.18.0"  →  (1, 18, 0)
"1.20.1"  →  (1, 20, 1)

(1, 18, 0) >= (0, 6, 18)  ✅
(1, 18, 0) <  (1, 20, 1)  ✅
→ version_confirmed = True  [cpe_range]
```

String comparison would silently fail here (`"1.9" > "1.18"` in strings). Integer tuples don't.

---

## What the Output Looks Like

Each record in `threat_intelligence_output.json`:

```json
{
  "asset_id": "ASSET-006",
  "asset_vendor": "Apache",
  "asset_product": "Tomcat",
  "detected_version": "7.0.70",

  "cve_id": "CVE-2017-12617",
  "vuln_type": "rce",
  "cwe_id": "CWE-434",
  "cwe_name": "Unrestricted File Upload",

  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "epss_score": 0.974,
  "epss_percentile": 0.9999,
  "known_ransomware": false,
  "date_added": "2022-03-15",
  "days_since_kev_added": 843,

  "version_confirmed": true,
  "confirmation_method": "cpe_range",
  "cpe_range_matched": ">=7.0.0 <7.0.82",

  "has_public_exploit": true,
  "exploit_count": 2,
  "exploit_ids": "42966,43008",

  "attack_technique_id": "T1190",
  "attack_technique_name": "Exploit Public-Facing Application",
  "attack_tactic": "Initial Access",

  "is_behind_waf": false,
  "waf_name": null,

  "threat_score": 0.68,
  "threat_pressure_factor": 1.68,
  "alert_level": "CRITICAL"
}
```

---

## Threat Pressure Factor (TPF) — 9-Factor Scoring

```
TPF = 1.0 + Threat Score    (Threat Score capped at 1.0)
```

| Factor | Condition | Weight |
|---|---|---|
| CVSS Score | ≥ 9.0 Critical | +0.20 |
| EPSS Score | ≥ 0.70 exploitation probability | +0.20 |
| Vulnerability Type | `rce` | +0.20 |
| Business Criticality | `critical` | +0.20 |
| KEV Presence | Confirmed by CISA (date_added set) | +0.13 |
| Public Exploit | Exploit-DB confirmed | +0.10 |
| Recency | KEV added ≤ 30 days ago | +0.10 |
| Ransomware | Linked to active campaigns | +0.07 |
| Version Confirmed | CPE range match only | +0.05 |

| TPF | Alert Level |
|---|---|
| ≥ 1.7 | 🔴 CRITICAL |
| ≥ 1.5 | 🟠 HIGH |
| ≥ 1.3 | 🟡 MEDIUM |
| < 1.3 | 🟢 LOW |

---

## MITRE ATT&CK Mapping

| vuln_type | Technique | Tactic |
|---|---|---|
| `rce` | T1190 — Exploit Public-Facing App | Initial Access |
| `sqli` | T1190 — Exploit Public-Facing App | Initial Access |
| `auth_bypass` | T1078 — Valid Accounts | Defense Evasion |
| `path_traversal` | T1083 — File & Directory Discovery | Discovery |
| `ssrf` | T1090 — Proxy | Command & Control |
| `xss` | T1059.007 — JavaScript | Execution |

---

## Data Sources

| Source | What It Provides |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 1,635 confirmed actively exploited CVEs — real attacks, not theory |
| [NVD](https://nvd.nist.gov) | CVSS + structured CPE version ranges + CWE root cause |
| [EPSS](https://www.first.org/epss/) | ML-based 30-day exploitation probability |
| [Exploit-DB](https://www.exploit-db.com) | Public proof-of-concept exploit availability |
| [MITRE ATT&CK](https://attack.mitre.org) | Attacker tactic and technique mapping |
| [Nmap](https://nmap.org) | Live service version detection + CPE output |

---

## Setup

### Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download.html) installed and on PATH
- Free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (10× faster enrichment)

### Install

```bash
git clone https://github.com/3Basit/Threat_intelligence-Asset_Monitor.git
cd Threat_intelligence-Asset_Monitor
pip install -r requirements.txt
```

### Configure Targets

Edit `targets.json`:

```json
[
  {
    "target_id": "TARGET-001",
    "url": "https://your-domain.com",
    "business_criticality": "high",
    "internet_facing": true,
    "authorized": true,
    "scan_profile": "default"
  }
]
```

> ⚠️ **Only scan systems you own or have explicit written authorization to test.**
> Targets with `"authorized": false` are silently skipped — the pipeline never touches them.

### Run

```bash
# Windows PowerShell
$env:NVD_API_KEY = "your-key-here"

# Linux / macOS
export NVD_API_KEY="your-key-here"

python main.py
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | — | NVD API key (strongly recommended) |
| `CRD_DB_PATH` | `threat_intelligence.db` | SQLite database path |
| `CRD_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `CRD_SCAN_DELAY_SECONDS` | `2` | Delay between target scans (polite scanning) |

---

## Project Structure

```
Threat_intelligence-Asset_Monitor/
│
├── main.py                 # Pipeline runner (Steps 0–4)
├── config.py               # Centralized config + env var overrides
├── logger.py               # Structured logging
│
├── asset_monitor.py        # HTTP fingerprinting + Nmap + Tech/WAF + Change Detection
├── cisa_kev.py             # CISA KEV fetch (retry + exponential backoff)
├── nvd_fetch.py            # NVD: CVSS + EPSS + CPE ranges + CWE
├── exploit_db.py           # Exploit-DB public exploit lookup
├── mitre_attack.py         # vuln_type → ATT&CK mapping
├── matching.py             # 4-stage CPE version-aware matching engine
├── threat_pressure.py      # TPF computation + alert generation + suppression
├── database.py             # SQLite schema (10 tables) + all DB operations
├── check_db.py             # DB inspection utility
│
├── tests/                  # 68 unit tests
│   ├── test_threat_pressure.py
│   ├── test_matching.py
│   └── test_config.py
│
├── targets.json            # Scan targets
├── requirements.txt
└── THREAT_INTELLIGENCE_OUTPUT_GUIDE.md   # Full output field reference
```

---

## Database Schema (10 Tables)

| Table | Contents |
|---|---|
| `assets` | Live assets: vendor, version, IP, WAF status, confidence |
| `asset_services` | Open ports and services per asset (from Nmap) |
| `asset_technologies` | Detected technologies: CMS, frameworks, JS libraries |
| `asset_waf_info` | WAF name + detection method per asset |
| `cisa_kev` | Full CISA KEV catalog |
| `enriched_cves` | CVEs with CVSS + EPSS + CPE ranges + CWE |
| `exploitdb_cves` | Public exploit IDs per CVE |
| `matched_cves` | CVE-Asset matches with ATT&CK mapping (high confidence) |
| `threat_intelligence` | Final TPF scores per CVE-Asset pair |
| `alerts` | Alert history with suppression log |

---

## Tests

```bash
python -m pytest tests/ -v          # all 68 tests
python -m unittest tests.test_matching -v
```

Covers: TPF computation, CVSS/EPSS thresholds, alert level logic, version parsing, CPE range checks, confidence scoring, text search fallback, alert suppression, None safety.

---

## Output Files

| File | Description |
|---|---|
| `threat_intelligence_output.json` | Full results — one record per CVE-Asset pair |
| `alerts.json` | Active alerts (change-aware, no duplicates) |
| `asset_changes.json` | Infrastructure change log |
| `threat_intelligence.db` | SQLite database (10 tables) |

All output files are in `.gitignore` and recreated on each run.

---

## Legal Notice

Only scan systems you own or have explicit written authorization to test.

The default `targets.json` uses publicly available, legally authorized test environments:
`scanme.nmap.org` (Nmap official), Acunetix demo apps, OWASP Juice Shop, IBM Altoro Mutual, PortSwigger Gin & Juice, bWAPP, HackThisSite.
