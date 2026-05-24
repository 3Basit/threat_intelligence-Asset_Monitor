# Cyber Risk Dollarizer — Threat Intelligence Module

Part of the **Cyber Risk Dollarizer** graduation project. This module is responsible for:

1. Discovering and monitoring web assets (HTTP fingerprinting + Nmap + Tech + WAF detection)
2. Fetching confirmed-exploited vulnerabilities from CISA KEV
3. Enriching CVEs with CVSS scores + CPE version ranges + CWE classification (NVD) and exploitation probability (EPSS)
4. Checking public exploit availability (Exploit-DB)
5. Mapping vulnerabilities to MITRE ATT&CK tactics and techniques
6. Matching CVEs to live assets using vendor, product, and CPE version ranges
7. Computing a Threat Pressure Factor (TPF) per CVE-Asset pair
8. Sending `threat_intelligence_output.json` to the Prediction Model

---

## Project Structure

```
Threat_intelligence-Asset_Monitor/
|
|-- main.py                          # Full pipeline runner
|-- asset_monitor.py                 # Phase 1+2+3: HTTP + Nmap + Tech/WAF detection
|-- cisa_kev.py                      # Fetches CISA KEV catalog
|-- nvd_fetch.py                     # Enriches CVEs with NVD + EPSS + CPE ranges + CWE
|-- exploit_db.py                    # Checks public exploit availability per CVE
|-- mitre_attack.py                  # Maps vuln_type to MITRE ATT&CK techniques
|-- matching.py                      # Matches CVEs to assets (CPE version-aware)
|-- threat_pressure.py               # Computes TPF + generates alerts
|-- database.py                      # SQLite schema + all DB functions
|-- check_db.py                      # DB inspection utility
|
|-- targets.json                     # Scan targets (config — edit this)
|-- requirements.txt
|-- README.md
`-- THREAT_INTELLIGENCE_OUTPUT_GUIDE.md
```

> **Note:** Auto-generated files (`assets.json`, `alerts.json`, `asset_changes.json`,
> `threat_intelligence_output.json`, `threat_intelligence.db`) are excluded from the repo
> via `.gitignore` and recreated on every pipeline run.

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

- Python 3.13
- Nmap installed at `C:\Program Files (x86)\Nmap\nmap.EXE`
- Free NVD API key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

### Install dependencies

```powershell
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

> **Important:** Only scan targets where `"authorized": true`.

---

## Running the Pipeline

```powershell
$env:NVD_API_KEY="your-key-here"
python main.py
python check_db.py
```

**Pipeline steps:**

```
init_db()           -> creates/migrates SQLite schema (10 tables)
asset_monitor.py    -> scans targets, discovers assets + technologies + WAF
cisa_kev.py         -> fetches ~1500+ confirmed-exploited CVEs
nvd_fetch.py        -> enriches CVEs with CVSS + EPSS + CPE ranges + CWE (with retry)
exploit_db.py       -> checks Exploit-DB for public exploits per CVE
mitre_attack.py     -> maps vuln_type to ATT&CK technique + tactic (static mapping)
matching.py         -> matches CVEs to assets (CPE version-aware + ATT&CK fields)
threat_pressure.py  -> computes TPF, generates alerts, writes output
```

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
threat_intelligence_output.json  <- sent to Prediction Model
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
When NVD has no structured CPE data, searches the CVE description text for the version string. Does NOT add TPF bonus. Reported as `confirmation_method: "text_search"`.

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
Pentest Model  ->  Threat Intelligence Module (this)
                        |
                        v
               threat_intelligence_output.json
                        |
                        v
               Prediction Model  ->  LLM Recommendations
```

See `THREAT_INTELLIGENCE_OUTPUT_GUIDE.md` for complete field documentation.

---

## Legal Notice

Only scan systems you are authorized to test. Demo targets (`testphp.vulnweb.com`, `testasp.vulnweb.com`) are Acunetix-provided legal test environments.
