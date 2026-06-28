# Threat Intelligence & Asset Monitor

This module is responsible for:

1. Discovering and monitoring web assets (HTTP fingerprinting + Nmap + Tech + WAF detection)
2. Fetching confirmed-exploited vulnerabilities from CISA KEV
3. Enriching CVEs with CVSS scores + CPE version ranges + CWE classification (NVD) and exploitation probability (EPSS)
4. Checking public exploit availability (Exploit-DB)
5. Mapping vulnerabilities to MITRE ATT&CK tactics and techniques
6. Matching CVEs to live assets using vendor, product, and CPE version ranges
7. Computing a Threat Pressure Factor (TPF) per CVE-Asset pair

> **Note:** The FAIR prediction model (financial loss estimation) is maintained separately and not part of this pipeline.

---

## Project Structure

```
Threat_intelligence-Asset_Monitor/
|
|-- main.py                          # Full pipeline runner (Steps 0-4)
|-- config.py                        # Centralized configuration (paths, API keys, settings)
|-- logger.py                        # Structured logging setup (console + file rotation)
|-- asset_monitor.py                 # Phase 1+2+3: HTTP + Nmap + Tech/WAF detection
|-- cisa_kev.py                      # Fetches CISA KEV catalog (with retry + backoff)
|-- nvd_fetch.py                     # Enriches CVEs with NVD + EPSS + CPE ranges + CWE
|-- exploit_db.py                    # Checks public exploit availability per CVE
|-- mitre_attack.py                  # Maps vuln_type to MITRE ATT&CK techniques
|-- matching.py                      # Matches CVEs to assets (CPE version-aware)
|-- threat_pressure.py               # Computes TPF + generates alerts
|-- database.py                      # SQLite schema + all DB functions (context manager)
|-- check_db.py                      # DB inspection utility
|
|-- tests/                           # Unit tests (87 tests)
|   |-- test_threat_pressure.py      # TPF computation, alert levels, edge cases
|   |-- test_matching.py             # Version parsing, CPE ranges, confidence scoring
|   `-- test_config.py               # Config, logging imports, module imports
|
|-- targets.json                     # Scan targets (config — edit this)
|-- requirements.txt
|-- README.md
`-- THREAT_INTELLIGENCE_OUTPUT_GUIDE.md  # TI output field reference
```

> **Note:** Auto-generated files (`assets.json`, `alerts.json`, `asset_changes.json`,
> `threat_intelligence_output.json`, `threat_intelligence.db`) are excluded from the repo
> via `.gitignore` and recreated on each pipeline run.

---

## Database Schema (10 Tables)

| Table | Contents |
|---|---|
| `assets` | Discovered web assets |
| `asset_services` | Open ports and services from Nmap |
| `asset_technologies` | Detected technologies (CMS, frameworks, JS libs) |
| `asset_waf_info` | WAF detection results per asset |
| `cisa_kev` | Raw CISA KEV catalog |
| `enriched_cves` | CVEs enriched with CVSS + EPSS + CPE ranges + CWE |
| `exploitdb_cves` | Public exploit availability per CVE |
| `matched_cves` | CVE-Asset matches with ATT&CK mapping (high confidence only) |
| `threat_intelligence` | Final TPF output with full context |
| `alerts` | Alert history |

---

## Setup

### Requirements

- Python 3.10+
- Nmap installed and on PATH (or at standard Windows location)
- Free NVD API key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure targets

Edit `targets.json`:

```json
[
  {
    "target_id": "TARGET-001",
    "url": "http://your-target.com",
    "business_criticality": "high",
    "internet_facing": true,
    "authorized": true,
    "scan_profile": "default"
  }
]
```

**Field reference:**

| Field | Type | Accepted Values | Description |
|---|---|---|---|
| `target_id` | string | any unique string | Identifier used in output and DB |
| `url` | string | full URL with scheme | Target to scan (http:// or https://) |
| `business_criticality` | string | `critical` / `high` / `medium` / `low` | Affects TPF score |
| `internet_facing` | bool | `true` / `false` | Informational only |
| `authorized` | bool | `true` only | **Must be `true` — targets with `false` are skipped** |
| `scan_profile` | string | any label | Informational label (e.g. `default`, `university`, `hospital`) |

> **Important:** Only scan targets where `"authorized": true`. Never scan systems you do not own or have explicit written permission to test.

### Configure company profile

Edit `company_profile.json`:

```json
{
  "company_name": "Your Company",
  "industry_sector": "healthcare",
  "employee_count_range": "1001 to 10000",
  "estimated_records": 50000,
  "data_sensitivity": "customer_pii",
  "region": "US",
  "annual_revenue_usd": 50000000,
  "has_cyber_insurance": false,
  "business_criticality": "high"
}
```

**Field reference:**

| Field | Accepted Values |
|---|---|
| `industry_sector` | `healthcare`, `financial`, `public_sector`, `retail`, `technology`, `professional_services`, `education`, `industrial`, `transportation`, `energy`, `hospitality`, `entertainment` |
| `employee_count_range` | `"1 to 10"`, `"11 to 100"`, `"101 to 1000"`, `"1001 to 10000"`, `"10001 to 50000"`, `"50001 or more"` |
| `data_sensitivity` | `"ip"` (intellectual property), `"corporate"`, `"customer_pii"`, `"unknown"` |
| `region` | `"US"`, `"EU"`, `"Middle_East"`, `"APAC"`, `"LATAM"`, `"Africa"` |
| `has_cyber_insurance` | `true` / `false` — reduces ALE by ~$750K if true |
| `business_criticality` | `"critical"` / `"high"` / `"medium"` / `"low"` |

### Configuration

All settings are centralized in `config.py` and can be overridden via environment variables with the `CRD_` prefix:

| Environment Variable | Default | Description |
|---|---|---|
| `CRD_DB_PATH` | `threat_intelligence.db` | SQLite database path |
| `NVD_API_KEY` or `CRD_NVD_API_KEY` | (empty) | NVD API key for faster enrichment |
| `CRD_LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `CRD_LOG_FILE` | (empty) | Log file path (empty = console only) |
| `CRD_TARGETS_FILE` | `targets.json` | Scan targets file |
| `CRD_MODEL_DIR` | `prediction_model/saved_model` | Trained model directory |
| `CRD_SCAN_DELAY_SECONDS` | `2` | Delay between target scans |

---

## Running the Pipeline

```bash
# Set NVD API key (recommended — 10x faster enrichment)
# Windows PowerShell:
$env:NVD_API_KEY="your-key-here"
# Linux/Mac:
export NVD_API_KEY="your-key-here"

# Run full pipeline
python main.py

# Inspect database
python check_db.py
```

**Pipeline steps (Steps 0–4):**

```
init_db()           -> creates/migrates SQLite schema (10 tables)
asset_monitor.py    -> scans targets, discovers assets + technologies + WAF
cisa_kev.py         -> fetches ~1500+ confirmed-exploited CVEs (with retry)
nvd_fetch.py        -> enriches CVEs with CVSS + EPSS + CPE ranges + CWE
exploit_db.py       -> checks Exploit-DB for public exploits per CVE
mitre_attack.py     -> maps vuln_type to ATT&CK technique + tactic
matching.py         -> matches CVEs to assets (CPE version-aware + ATT&CK)
threat_pressure.py  -> computes TPF, generates alerts, writes output
```

---

## Running Tests

```bash
# Run all 87 tests
python -m pytest tests/ -q

# Run a specific test file
python -m unittest tests.test_matching -v
```

Tests cover:
- **TPF computation** — CVSS/EPSS thresholds, alert levels, edge cases, None safety
- **CVE matching** — version parsing, CPE range checking, confidence scoring, vuln type detection
- **Configuration** — config/logging imports, module imports

---

## Pipeline Flow

```
targets.json
    |
    v
Asset Monitor
  Phase 1: HTTP fingerprinting (vendor, product, server header)
  Phase 2: Nmap service + version detection
  Phase 3A: Technology detection (HTML, cookies, JS libs, headers)
  Phase 3B: WAF detection (Cloudflare, Akamai, AWS, F5, etc.)
    |
    v
CISA KEV -> NVD (CVSS + CPE + CWE) + EPSS -> Exploit-DB -> ATT&CK Mapping -> Matching -> TPF
    |
    v
threat_intelligence_output.json  <- output of this pipeline
alerts.json
```

---

## Threat Pressure Factor (TPF)

TPF is a multiplier (1.0–2.0):

```
Final Risk = base_probability x threat_pressure_factor
```

**Components:**

| Component | Condition | Weight |
|---|---|---|
| CVSS Score | >=9.0 Critical | +0.20 |
| CVSS Score | >=7.0 High | +0.13 |
| CVSS Score | >=4.0 Medium | +0.07 |
| EPSS Score | >=0.7 | +0.20 |
| EPSS Score | >=0.4 | +0.13 |
| EPSS Score | >=0.1 | +0.07 |
| KEV Presence | Always (all records) | +0.13 |
| Vulnerability Type | RCE | +0.20 |
| Vulnerability Type | SQLi / Auth Bypass | +0.15 |
| Vulnerability Type | Path Traversal / SSRF | +0.12 |
| Vulnerability Type | XSS | +0.08 |
| Business Criticality | Critical | +0.20 |
| Business Criticality | High | +0.13 |
| Business Criticality | Medium | +0.07 |
| Recency | KEV added <=30 days | +0.10 |
| Recency | KEV added <=90 days | +0.06 |
| Recency | KEV added <=365 days | +0.03 |
| Known Ransomware | If true | +0.07 |
| Version Confirmed | CPE range only | +0.05 |
| Public Exploit | Exploit-DB confirmed | +0.10 |

**Alert levels:**

| TPF | Alert Level |
|---|---|
| >= 1.7 | CRITICAL |
| >= 1.5 | HIGH |
| >= 1.3 | MEDIUM |
| < 1.3 | LOW |

---

## Version Confirmation

Two-pass approach to confirm if a detected version is vulnerable:

**Pass 1 — CPE Ranges (High Confidence)**
Uses structured NVD CPE data. Two sub-cases:
- **CPE with version range** (`versionStartIncluding` / `versionEndExcluding`): checks if the Nmap-detected version falls within the vulnerable range.
- **CPE with exact version** (no boundaries): extracts the exact version from the CPE criteria string (e.g. `IIS 6.0`) and requires an exact match with the detected version.
Adds +0.05 to TPF only when confirmed. Reported as `confirmation_method: "cpe_range"`.

**Pass 2 — Text Search (Medium Confidence, fallback)**
When NVD has no structured CPE data, searches the CVE description text for the version string using word-boundary regex. Does NOT add TPF bonus. Reported as `confirmation_method: "text_search"`.

**No Match:** `version_confirmed: false`, `confirmation_method: "none"`. This includes cases where the exact CPE version does not match the detected version.

---

## MITRE ATT&CK Mapping

Each matched CVE is automatically mapped to an ATT&CK technique based on its `vuln_type`:

| vuln_type | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| rce | T1190 | Exploit Public-Facing Application | Initial Access |
| sqli | T1190 | Exploit Public-Facing Application | Initial Access |
| auth_bypass | T1078 | Valid Accounts | Defense Evasion |
| path_traversal | T1083 | File and Directory Discovery | Discovery |
| ssrf | T1090 | Proxy | Command and Control |
| xss | T1059.007 | JavaScript | Execution |
| other | T1190 | Exploit Public-Facing Application | Initial Access |

Fields added to output: `attack_technique_id`, `attack_technique_name`, `attack_tactic`.

---

## Data Sources

| Source | URL | What it provides |
|---|---|---|
| CISA KEV | cisa.gov | Confirmed exploited vulnerabilities |
| NVD | nvd.nist.gov | CVSS + CPE ranges + CWE + published date |
| EPSS | first.org | 30-day exploitation probability |
| Exploit-DB | exploit-db.com | Public exploit availability + IDs |
| MITRE ATT&CK | attack.mitre.org | Tactic + technique mapping |
| Nmap | nmap.org | Live service version detection |

---

## Team Integration

```
Pentest Module  ->  Threat Intelligence Module (Steps 0-4)
                        |
                        v
               threat_intelligence_output.json
               alerts.json
```

**Shared configuration:** All modules use `config.py` for paths and settings. Override via `CRD_*` environment variables to point all modules at the same database and output directory.

**Shared database:** All modules read/write the same SQLite database (`config.DB_PATH`). For concurrent multi-module access, migrate to PostgreSQL and update `CRD_DB_PATH`.

See `THREAT_INTELLIGENCE_OUTPUT_GUIDE.md` for TI output field documentation.

---

## Legal Notice

Only scan systems you are authorized to test. Demo targets (`testphp.vulnweb.com`, `testasp.vulnweb.com`) are Acunetix-provided legal test environments.
