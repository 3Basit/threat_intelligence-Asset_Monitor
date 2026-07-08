# Asset Monitor & Threat Intelligence Pipeline

> **Automated asset fingerprinting and vulnerability intelligence — from a URL to a prioritized, evidence-based threat report.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-87%20passing-brightgreen)]()
[![Data Sources](https://img.shields.io/badge/Sources-CISA%20KEV%20%7C%20NVD%20%7C%20EPSS%20%7C%20Exploit--DB-orange)]()

---

## What This Does

Most vulnerability scanners tell you *what* is running. This pipeline tells you *how dangerous it actually is* — and *what the attacker will do with it*.

Starting from a simple target URL, this module:

1. **Discovers** running services, software versions, and technologies (HTTP fingerprinting + Nmap)
2. **Detects** WAF presence and technology stack (regex signature-based)
3. **Monitors** for infrastructure changes across scans (port opens, version upgrades, IP changes)
4. **Fetches** confirmed-exploited vulnerabilities from CISA KEV + enriches with NVD / EPSS / Exploit-DB
5. **Matches** CVEs to assets using CPE version ranges — preventing false positives by version
6. **Maps** each vulnerability to a MITRE ATT&CK tactic and technique
7. **Scores** each CVE-Asset pair with a **Threat Pressure Factor (TPF)** from 9 weighted signals
8. **Alerts** only when something *changes* (new threat, higher score, escalated level) — zero alert fatigue

---

## Pipeline Flow

```
targets.json
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Asset Monitor                                      │
│  Phase 1 → HTTP Fingerprinting                      │
│            Server: nginx/1.18.0 → vendor + version  │
│            Special: Apache-Coyote → Tomcat probe    │
│  Phase 2 → Nmap Scan (-sV -Pn -n)                  │
│            Port 80: nginx 1.18.0 │ cpe:/a:nginx:... │
│  Phase 3 → Tech & WAF Detection (regex patterns)   │
│  Phase 4 → Change Detection vs previous snapshot   │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
    CISA KEV → NVD (CVSS + CPE + CWE) + EPSS → Exploit-DB
                       │
                       ▼
              Matching Engine
              Stage 1: Vendor + Product confidence
              Stage 2: CPE Filter (skip OS/platform CPEs)
              Stage 3: Version Confirmation (two-pass)
              Stage 4: KEV Sanity Gate
                       │
                       ▼
           MITRE ATT&CK Mapping (vuln_type → technique)
                       │
                       ▼
           TPF Scoring (9 factors, capped at 2.0)
                       │
                       ▼
    threat_intelligence_output.json  +  alerts.json
```

---

## Standalone vs. Integrated Use

This module is **designed to work both ways**:

### ✅ Standalone
Run it as a complete threat intelligence pipeline on any target. The output (`threat_intelligence_output.json`) is a self-contained, structured report ready for human review or automated tooling.

```bash
python main.py
```

### 🔗 Integrated (part of a larger platform)
The output schema is designed to feed downstream ML models and LLM-based reporting systems. In the [Cyber Risk & Financial Loss Prediction Platform](https://github.com/), this module is the **first stage** of a 4-model pipeline:

```
Asset Monitor & Threat Intelligence  (this repo)
            │
            ▼  threat_intelligence_output.json
   AI Penetration Testing Module     (RL/PPO agent)
            │
            ▼  pentest results
   Financial Loss Prediction Model   (LightGBM / CatBoost ensemble)
            │
            ▼  EAL estimate
   LLM Intelligent Assistant         (RAG-based report generation)
            │
            ▼  PDF / DOCX / HTML executive report
```

The shared `config.py` and SQLite database allow all modules to operate on the same data store. For multi-module concurrent access, migrate `CRD_DB_PATH` to PostgreSQL.

---

## Key Design Decisions

### False Positive Prevention
A naive system flags every CVE that shares a vendor name with a detected technology. This module rejects that approach entirely:

```
CVE-2017-7269 → affects IIS 6.0 ONLY
Detected:       IIS 8.5

Naive:  "IIS found + CVE found = ALERT"   ← wrong
Ours:   version 8.5 ≠ 6.0  →  NO ALERT   ← correct
```

Version confirmation uses **NVD CPE ranges** parsed structurally (not substring-matched), converted to integer tuples for accurate comparison. A KEV Sanity Gate additionally rejects high-confidence KEV CVEs where the detected version falls definitively outside all published CPE ranges.

### Tomcat Version Extraction
`Server: Apache-Coyote/1.1` reports the Coyote HTTP connector version, not Tomcat's. Using `1.1` for matching would generate false positives across all Tomcat CVEs. The pipeline probes a non-existent path to trigger a 404 error page, which contains the real Tomcat version (e.g., `Apache Tomcat/7.0.70`), and extracts it via regex.

### Smart Alert Suppression
Alerts fire only when:
- A CVE-Asset pair is seen for the first time
- The TPF score increased since the last scan
- The alert level escalated (e.g., MEDIUM → CRITICAL)

Same threat, same score → no duplicate alert.

---

## Threat Pressure Factor (TPF)

TPF is a composite risk multiplier (range: **1.0 → 2.0**):

```
TPF = 1.0 + Threat Score    (Threat Score capped at 1.0)
```

| Factor | Max Weight | Condition |
|---|---|---|
| CVSS Score | +0.20 | ≥ 9.0 Critical |
| EPSS Score | +0.20 | ≥ 0.70 exploitation probability |
| KEV Presence | +0.13 | Confirmed in CISA KEV (`date_added` is set) |
| Vulnerability Type | +0.20 | `rce` > `sqli/auth_bypass` > `traversal/ssrf` > `xss` |
| Business Criticality | +0.20 | `critical` > `high` > `medium` |
| Recency | +0.10 | KEV added ≤ 30 days ago |
| Public Exploit | +0.10 | Exploit-DB confirmed |
| Known Ransomware | +0.07 | Linked to ransomware campaigns |
| Version Confirmed | +0.05 | CPE range match only (not text search) |

| TPF | Alert Level |
|---|---|
| ≥ 1.7 | 🔴 CRITICAL |
| ≥ 1.5 | 🟠 HIGH |
| ≥ 1.3 | 🟡 MEDIUM |
| < 1.3 | 🟢 LOW |

**Example output:**
```
[CRITICAL] CVE-2024-38475 | Apache HTTP Server → scanme.nmap.org
           | rce | TPF: 1.78 | VERSION CPE_RANGE
```

---

## Data Sources

| Source | What it provides |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed actively exploited CVEs (< 1% of all CVEs, 100% real-world) |
| [NVD](https://nvd.nist.gov) | CVSS scores + structured CPE version ranges + CWE classification |
| [EPSS](https://www.first.org/epss/) | ML-based 30-day exploitation probability |
| [Exploit-DB](https://www.exploit-db.com) | Public proof-of-concept exploit availability |
| [MITRE ATT&CK](https://attack.mitre.org) | Tactic + technique mapping per vulnerability type |
| [Nmap](https://nmap.org) | Live service version detection + CPE output |

---

## MITRE ATT&CK Mapping

| vuln_type | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| `rce` | T1190 | Exploit Public-Facing Application | Initial Access |
| `sqli` | T1190 | Exploit Public-Facing Application | Initial Access |
| `auth_bypass` | T1078 | Valid Accounts | Defense Evasion |
| `path_traversal` | T1083 | File and Directory Discovery | Discovery |
| `ssrf` | T1190 | Exploit Public-Facing Application | Initial Access |
| `xss` | T1059.007 | JavaScript | Execution |

---

## Project Structure

```
asset-monitor-threat-intelligence/
│
├── main.py                 # Full pipeline runner (Steps 0–4)
├── config.py               # Centralized config (paths, API keys, env vars)
├── logger.py               # Structured logging (console + rotating file)
│
├── asset_monitor.py        # HTTP fingerprinting + Nmap + Tech/WAF + Change Detection
├── cisa_kev.py             # CISA KEV catalog fetch (with retry + exponential backoff)
├── nvd_fetch.py            # NVD enrichment: CVSS + EPSS + CPE ranges + CWE
├── exploit_db.py           # Exploit-DB public exploit check per CVE
├── mitre_attack.py         # vuln_type → ATT&CK technique mapping
├── matching.py             # CVE-Asset matching (4-stage CPE version-aware)
├── threat_pressure.py      # TPF computation + alert generation + suppression
├── database.py             # SQLite schema + all DB operations (context manager)
├── check_db.py             # DB inspection utility
│
├── tests/                  # 87 unit tests
│   ├── test_threat_pressure.py
│   ├── test_matching.py
│   └── test_config.py
│
├── targets.json            # Scan targets (edit this to add your own)
├── requirements.txt
└── THREAT_INTELLIGENCE_OUTPUT_GUIDE.md
```

---

## Database Schema (10 Tables)

| Table | Contents |
|---|---|
| `assets` | Discovered web assets (vendor, version, IP, WAF status) |
| `asset_services` | Open ports and services from Nmap |
| `asset_technologies` | Detected technologies (CMS, JS frameworks, libraries) |
| `asset_waf_info` | WAF detection per asset |
| `cisa_kev` | Raw CISA KEV catalog |
| `enriched_cves` | CVEs with CVSS + EPSS + CPE ranges + CWE |
| `exploitdb_cves` | Public exploit availability per CVE |
| `matched_cves` | CVE-Asset matches with ATT&CK mapping |
| `threat_intelligence` | Final TPF scores with full context |
| `alerts` | Alert history (deduplication + suppression log) |

---

## Setup

### Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download.html) installed and on PATH
- Free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (recommended — 10× faster enrichment)

### Install

```bash
git clone https://github.com/your-username/asset-monitor-threat-intelligence.git
cd asset-monitor-threat-intelligence
pip install -r requirements.txt
```

### Configure Targets

Edit `targets.json` to add the systems you are authorized to test:

```json
[
  {
    "target_id": "TARGET-001",
    "url": "https://your-target.com",
    "business_criticality": "high",
    "internet_facing": true,
    "authorized": true,
    "scan_profile": "default"
  }
]
```

> ⚠️ **Important:** Only scan systems you own or have explicit written authorization to test. Set `"authorized": false` to skip a target without removing it.

### Run

```bash
# Set NVD API key for faster enrichment
$env:NVD_API_KEY="your-key-here"      # PowerShell
export NVD_API_KEY="your-key-here"    # Linux/Mac

# Run full pipeline
python main.py

# Inspect the database
python check_db.py
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | — | NVD API key (10× rate limit increase) |
| `CRD_DB_PATH` | `threat_intelligence.db` | SQLite database path |
| `CRD_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `CRD_SCAN_DELAY_SECONDS` | `2` | Polite delay between target scans |
| `CRD_TARGETS_FILE` | `targets.json` | Targets file path |

---

## Tests

```bash
# Run all 87 tests
python -m pytest tests/ -v

# Run a specific module
python -m unittest tests.test_matching -v
```

Tests cover TPF computation, version parsing, CPE range checking, confidence scoring, alert suppression, and all edge cases.

---

## Output Files

| File | Description |
|---|---|
| `threat_intelligence_output.json` | Full TPF results per CVE-Asset pair |
| `alerts.json` | Active alerts (suppression-aware) |
| `asset_changes.json` | Infrastructure change log across scans |
| `threat_intelligence.db` | SQLite database (all 10 tables) |

All output files are excluded from the repo via `.gitignore` and recreated on each run.

---

## Legal Notice

Only scan systems you are authorized to test. The default `targets.json` contains publicly available, legally authorized test environments (Nmap's `scanme.nmap.org`, Acunetix demo apps, OWASP Juice Shop, IBM Altoro, PortSwigger Gin & Juice). Do not use this tool against systems without explicit written permission from the system owner.
