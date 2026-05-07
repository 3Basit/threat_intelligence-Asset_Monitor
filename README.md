# Cyber Risk Dollarizer — Threat Intelligence Module

Part of the **Cyber Risk Dollarizer** graduation project. This module is responsible for:

1. Discovering and monitoring web assets (HTTP fingerprinting + Nmap)
2. Fetching confirmed-exploited vulnerabilities from CISA KEV
3. Enriching CVEs with CVSS scores (NVD) and exploitation probability (EPSS)
4. Matching CVEs to live assets using vendor, product, and version detection
5. Computing a Threat Pressure Factor (TPF) per CVE-Asset pair
6. Sending `threat_intelligence_output.json` to the Prediction Model

---

## Project Structure

```
grad.project.C/
│
├── main.py                          # Full pipeline runner
├── asset_monitor.py                 # Phase 1+2+3: HTTP + Nmap + Tech/WAF detection
├── cisa_kev.py                      # Fetches CISA KEV catalog
├── nvd_fetch.py                     # Enriches CVEs with NVD + EPSS
├── matching.py                      # Matches CVEs to assets
├── threat_pressure.py               # Computes TPF + generates alerts
├── database.py                      # SQLite schema + all DB functions
├── check_db.py                      # DB inspection utility
│
├── targets.json                     # Scan targets (config — edit this)
├── assets.json                      # Discovered assets (auto-generated)
├── threat_intelligence_output.json  # ← sent to Prediction Model
├── alerts.json                      # New/escalated alerts (auto-generated)
├── asset_changes.json               # Detected infrastructure changes
│
├── threat_intelligence.db           # SQLite database
├── requirements.txt
└── README.md
```

---

## Database Schema (10 Tables)

| Table | Contents |
|---|---|
| `assets` | Discovered web assets |
| `asset_services` | Open ports and services from Nmap |
| `asset_technologies` | Detected technologies (CMS, frameworks, JS libs) |
| `asset_waf_info` | WAF detection results |
| `cisa_kev` | Raw CISA KEV catalog |
| `enriched_cves` | CVEs enriched with CVSS + EPSS |
| `matched_cves` | CVE-Asset matches (high confidence only) |
| `threat_intelligence` | Final TPF output |
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

Edit `targets.json` to add your scan targets:

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

> **Important:** Only scan targets where `"authorized": true`. Never scan systems you do not have explicit permission to test.

---

## Running the Pipeline

```powershell
# Step 1: Set NVD API key
$env:NVD_API_KEY="your-key-here"

# Step 2: Run full pipeline
python main.py

# Step 3: Inspect database
python check_db.py
```

The pipeline runs these steps automatically:

```
init_db()           → creates/migrates SQLite schema
asset_monitor.py    → scans targets, discovers assets
cisa_kev.py         → fetches ~1500+ confirmed-exploited CVEs
nvd_fetch.py        → enriches relevant CVEs with CVSS + EPSS
matching.py         → matches CVEs to assets (version-aware)
threat_pressure.py  → computes TPF, generates alerts, writes output
```

---

## Pipeline Flow

```
targets.json
    │
    ▼
Asset Monitor ──────────────────────────────────────────────┐
  Phase 1: HTTP fingerprinting (vendor, product, server)    │
  Phase 2: Nmap service + version detection                 │
  Phase 3A: Technology detection (HTML, cookies, headers)   │
  Phase 3B: WAF detection (Cloudflare, Akamai, AWS, etc.)  │
    │                                                        │
    ▼                                                        │
assets.json + DB (assets, asset_services,                   │
                  asset_technologies, asset_waf_info)        │
    │                                                        │
    ▼                                                        │
CISA KEV → NVD + EPSS → Matching → TPF Engine              │
    │                                                        │
    ▼                                                        │
threat_intelligence_output.json  ←─── sent to Prediction ──┘
alerts.json
```

---

## Threat Pressure Factor (TPF)

TPF is a multiplier (1.0–2.0) representing how much a vulnerability increases the base risk:

```
Final Risk = base_probability × threat_pressure_factor
```

**Components:**

| Component | Max Weight |
|---|---|
| CVSS Score | +0.20 |
| EPSS Score | +0.20 |
| KEV Presence | +0.13 (always — all CVEs are KEV) |
| Vulnerability Type (RCE, SQLi, etc.) | +0.20 |
| Business Criticality | +0.20 |
| Recency of exploitation | +0.10 |
| Known Ransomware | +0.07 |
| Version Confirmed (Nmap match) | +0.05 |

**Alert levels:**

| TPF | Alert Level |
|---|---|
| ≥ 1.7 | CRITICAL |
| ≥ 1.5 | HIGH |
| ≥ 1.3 | MEDIUM |
| < 1.3 | LOW |

---

## Output Format

See `THREAT_INTELLIGENCE_OUTPUT_GUIDE.md` for complete field-by-field documentation of `threat_intelligence_output.json`.

---

## Data Sources

| Source | URL | What it provides |
|---|---|---|
| CISA KEV | cisa.gov | Confirmed exploited vulnerabilities |
| NVD | nvd.nist.gov | CVSS scores + severity + published date |
| EPSS | first.org | 30-day exploitation probability |
| Nmap | nmap.org | Live service version detection |

---

## Team Integration

This module is part of a 4-component system:

```
Pentest Model  →  Threat Intelligence Module (this)
                        ↓
               threat_intelligence_output.json
                        ↓
               Prediction Model  →  LLM Recommendations
```

The Prediction Model multiplies its base probability by `threat_pressure_factor` from our output to produce the final risk probability used for cyber risk dollarization.

---

## Legal Notice

This tool is for authorized security testing only. The demo targets (`testphp.vulnweb.com`, `testasp.vulnweb.com`) are Acunetix-provided legal test environments. Replace with your authorized targets before deployment.
