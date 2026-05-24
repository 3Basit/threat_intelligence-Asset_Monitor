# Threat Intelligence Output — Documentation for Prediction Model Team

**From:** Threat Intelligence Module
**File:** `threat_intelligence_output.json`
**Format:** JSON Array — one object per (CVE × Asset) pair
**Updated:** Every pipeline run (`python main.py`)

---

## How This File Is Generated

```
targets.json
    |
    v
Asset Monitor       -> discovers live web assets (HTTP + Nmap + Tech + WAF)
    |
    v
CISA KEV            -> 1500+ confirmed-exploited vulnerabilities
    |
    v
NVD + EPSS          -> CVSS + CPE version ranges + CWE + exploitation probability
    |
    v
Exploit-DB          -> checks if a public exploit exists per CVE
    |
    v
MITRE ATT&CK        -> maps vuln_type to tactics and techniques
    |
    v
Matching Engine     -> links CVEs to assets (vendor + product + CPE version)
    |
    v
TPF Engine          -> computes Threat Pressure Factor per CVE-Asset pair
    |
    v
threat_intelligence_output.json
```

---

## Your Integration Point

```
Final Risk Probability = base_probability x threat_pressure_factor
```

`threat_pressure_factor` ranges from **1.0** (no threat) to **2.0** (maximum threat).

---

## Full Field Reference

### Asset Identification

| Field | Type | Example | Description |
|---|---|---|---|
| `asset_id` | string | `"ASSET-002"` | Unique asset identifier. |
| `asset_name` | string | `"acuforum forums"` | Human-readable asset name. |
| `asset_type` | string | `"web_application"` | Always `web_application` in this module. |
| `asset_vendor` | string | `"Microsoft"` | Technology vendor detected on the asset. |
| `asset_product` | string | `"IIS"` | Specific product detected on the asset. |
| `business_criticality` | string | `"high"` | `critical` / `high` / `medium` / `low` |

---

### CVE Identification

| Field | Type | Example | Description |
|---|---|---|---|
| `cve_id` | string | `"CVE-2017-7269"` | Official MITRE CVE identifier. |
| `cve_vendor` | string | `"Microsoft"` | Vendor named in the CVE record. |
| `cve_product` | string | `"IIS"` | Product named in the CVE record. |
| `description` | string | `"...buffer overflow..."` | Full CVE description from NVD. |
| `vuln_type` | string | `"rce"` | Vulnerability category detected from description keywords. |
| `cwe_id` | string | `"CWE-120"` | Common Weakness Enumeration ID from NVD — identifies the root cause weakness class. `null` if NVD has no CWE data. |
| `cwe_name` | string | `"Classic Buffer Overflow"` | Human-readable name of the weakness. `null` if not available. |

**`vuln_type` values:**

| Value | Meaning | TPF Weight |
|---|---|---|
| `rce` | Remote Code Execution | +0.20 |
| `sqli` | SQL Injection | +0.15 |
| `auth_bypass` | Authentication Bypass | +0.15 |
| `path_traversal` | Path/Directory Traversal | +0.12 |
| `ssrf` | Server-Side Request Forgery | +0.12 |
| `xss` | Cross-Site Scripting | +0.08 |
| `other` | Other web vulnerability | +0.05 |
| `unknown` | Could not be determined | +0.00 |

**Common `cwe_id` values:**

| CWE ID | Name |
|---|---|
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-Site Scripting |
| CWE-89 | SQL Injection |
| CWE-119 / CWE-120 | Buffer Overflow |
| CWE-287 | Improper Authentication |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-918 | Server-Side Request Forgery |

> `cwe_id` and `cwe_name` are informational — not used in TPF calculation, but can be used as categorical features in your model.

---

### Risk Scores

| Field | Type | Example | Description |
|---|---|---|---|
| `cvss_score` | float | `9.8` | CVSS v3.1 base score. Range: 0.0–10.0. |
| `severity` | string | `"CRITICAL"` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `epss_score` | float | `0.94411` | 30-day exploitation probability. Range: 0.0–1.0. |
| `epss_percentile` | float | `0.99979` | Ranking among all CVEs. `0.9998` = top 0.02%. |
| `known_ransomware` | bool | `false` | Confirmed use in ransomware campaigns. |

---

### Temporal Features

| Field | Type | Example | Description |
|---|---|---|---|
| `published` | string | `"2017-03-27"` | CVE publication date. |
| `date_added` | string | `"2021-11-03"` | Date CISA confirmed real-world exploitation. |
| `days_since_published` | int | `3336` | Age of the vulnerability in days. |
| `days_since_kev_added` | int | `1654` | Days since CISA confirmation. |

---

### Match Quality Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `match_confidence` | string | `"high"` | Always `"high"` in this file — low confidence excluded. |
| `scope` | string | `"web"` | Always `"web"` — this module covers web assets only. |
| `source` | string | `"CISA_KEV + NVD + EPSS + ExploitDB"` | All data sources used. |

---

### Version Confirmation Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `version_confirmed` | bool | `false` | Whether the detected version is confirmed vulnerable. |
| `detected_version` | string | `"8.5"` | Version string detected by Nmap on the live asset. |
| `confirmation_method` | string | `"cpe_range"` | How the version was confirmed. See table below. |
| `cpe_range_matched` | string\|null | `">=6.0 <7.0"` | The specific NVD CPE range or exact version that confirmed the match. `null` if not confirmed. Formats: `">=X <Y"` for ranges, `"exact:X.Y"` for exact CPE versions. |

**`confirmation_method` values:**

| Value | Meaning | Confidence | TPF Bonus |
|---|---|---|---|
| `cpe_range` | Version falls within NVD structured CPE range, or exactly matches CPE exact version | **High** | +0.05 |
| `text_search` | Version string found in CVE description text (fallback) | **Medium** | +0.00 |
| `none` | Version not confirmed — either no CPE match or exact CPE version mismatch | Low | +0.00 |

> `version_confirmed=true` with `confirmation_method="text_search"` is medium confidence only. Weight it lower than `cpe_range` in your model.
> `cpe_range_matched` shows exactly which NVD range or version confirmed the result — use it for audit and explainability.

---

### WAF Context

| Field | Type | Example | Description |
|---|---|---|---|
| `is_behind_waf` | bool | `false` | WAF detected in front of this asset. |
| `waf_name` | string\|null | `null` | WAF name: `"Cloudflare"`, `"Akamai"`, `"AWS CloudFront"`, `"Sucuri"`, `"Incapsula"`, `"F5 BIG-IP"`, `"ModSecurity"`, `"Fastly"`, or `null`. |

---

### Exploit-DB Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `has_public_exploit` | bool | `true` | A working exploit is publicly available on Exploit-DB. |
| `exploit_count` | int | `2` | Number of public exploits found. |
| `exploit_ids` | string | `"41738,41992"` | Comma-separated Exploit-DB IDs. Look up at `exploit-db.com/exploits/{id}` |

> `has_public_exploit=true` means any attacker — even unskilled — can download and run a working exploit. This is a strong signal for high final risk probability.

---

### MITRE ATT&CK Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `attack_technique_id` | string\|null | `"T1190"` | MITRE ATT&CK Technique ID mapped from `vuln_type`. |
| `attack_technique_name` | string\|null | `"Exploit Public-Facing Application"` | Full name of the ATT&CK technique. |
| `attack_tactic` | string\|null | `"Initial Access"` | The ATT&CK tactic (phase of the attack chain). `null` if `vuln_type=unknown`. |

**Full `vuln_type` → ATT&CK mapping:**

| vuln_type | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| `rce` | T1190 | Exploit Public-Facing Application | Initial Access |
| `sqli` | T1190 | Exploit Public-Facing Application | Initial Access |
| `auth_bypass` | T1078 | Valid Accounts | Defense Evasion |
| `path_traversal` | T1083 | File and Directory Discovery | Discovery |
| `ssrf` | T1090 | Proxy | Command and Control |
| `xss` | T1059.007 | JavaScript | Execution |
| `other` | T1190 | Exploit Public-Facing Application | Initial Access |
| `unknown` | null | null | null |

> `attack_technique_id` and `attack_tactic` are informational context fields. They are not used in TPF calculation but are highly useful for threat reporting, security dashboards, and SOC workflows that align with ATT&CK.

---

### TPF Output

| Field | Type | Example | Description |
|---|---|---|---|
| `threat_score` | float | `1.0` | Raw weighted sum. Range: 0.0–1.0 (capped). |
| `threat_pressure_factor` | **float** | **`2.0`** | **The multiplier your model uses.** Range: 1.0–2.0. |
| `alert_level` | string | `"CRITICAL"` | Pre-computed label based on TPF value. |

**Alert level thresholds:**

| TPF | Alert Level |
|---|---|
| >= 1.7 | `CRITICAL` |
| >= 1.5 | `HIGH` |
| >= 1.3 | `MEDIUM` |
| < 1.3 | `LOW` |

---

## TPF Formula (Complete)

```
threat_score =
    CVSS component          (>=9.0->+0.20 | >=7.0->+0.13 | >=4.0->+0.07)
  + EPSS component          (>=0.7->+0.20 | >=0.4->+0.13 | >=0.1->+0.07)
  + KEV presence            +0.13  (always — all records are KEV confirmed)
  + known_ransomware        +0.07  (if true)
  + vuln_type weight        (rce->+0.20 ... xss->+0.08)
  + business_criticality    (critical->+0.20 ... low->+0.00)
  + recency                 (<=30d->+0.10 | <=90d->+0.06 | <=365d->+0.03)
  + version_confirmed       +0.05  (ONLY if confirmation_method = "cpe_range")
  + has_public_exploit      +0.10  (if true)

threat_score           = min(threat_score, 1.0)
threat_pressure_factor = 1.0 + threat_score
```

---

## Worked Example — CVE-2017-7269 on IIS 8.5

> **Note:** CVE-2017-7269 affects **IIS 6.0** (exact CPE). The detected version is **8.5**.
> The system correctly sets `version_confirmed=false` — this is a potential match, not a confirmed vulnerability.

```
CVSS 9.8  (>=9.0)                         -> +0.20
EPSS 0.944 (>=0.7)                        -> +0.20
KEV presence                              -> +0.13
known_ransomware = false                  -> +0.00
vuln_type = rce                           -> +0.20
business_criticality = high               -> +0.13
days_since_kev_added = 1663 (>365d)       -> +0.00
version_confirmed = false (cpe mismatch)  -> +0.00  (was 8.5, CPE says 6.0)
has_public_exploit = true (2 exploits)    -> +0.10
cwe_id = CWE-120 (informational)          -> +0.00
attack_technique_id = T1190 (informational) -> +0.00
                                        ---------
threat_score (raw)                        = 0.96
threat_score (capped at 1.0)              = 0.96
threat_pressure_factor                    = 1.0 + 0.96 = 1.96
alert_level                               = CRITICAL (>=1.7)
```

> The record remains CRITICAL due to public exploits + EPSS 0.944 + RCE type.
> It is flagged as **potentially affected** (`version_confirmed=false`), not confirmed vulnerable.
> Manual verification or Pentest Module confirmation is required.

---

## Integration Example

```python
import json

with open("threat_intelligence_output.json") as f:
    ti_records = json.load(f)

for record in ti_records:
    tpf    = record["threat_pressure_factor"]   # 1.0-2.0
    cm     = record["confirmation_method"]       # "cpe_range" / "text_search" / "none"
    has_ex = record["has_public_exploit"]        # bool
    cwe    = record["cwe_id"]                    # e.g. "CWE-120" or None
    tactic = record["attack_tactic"]             # e.g. "Initial Access" or None

    # Optional: use confirmation_method as confidence weight
    confidence_weight = {
        "cpe_range":   1.0,
        "text_search": 0.8,
        "none":        0.6
    }.get(cm, 0.6)

    base_probability  = your_model.predict(record)
    final_probability = base_probability * tpf * confidence_weight

    print(
        f"{record['asset_id']} | {record['cve_id']} | "
        f"CWE={cwe} | ATT&CK={tactic} | "
        f"TPF={tpf} | final={final_probability:.3f}"
    )
```

---

## Data Sources

| Source | What It Provides | Update Frequency |
|---|---|---|
| CISA KEV | Confirmed exploited vulnerabilities | Continuously updated |
| NVD | CVSS + CPE ranges + CWE + published date | Within 24-48h of CVE |
| EPSS | 30-day exploitation probability | Daily |
| Exploit-DB | Public exploit availability + exploit IDs | Per pipeline run |
| MITRE ATT&CK | Tactic + technique mapping per vuln_type | Static mapping (updated manually) |
| Nmap | Live service version on asset | Per pipeline run |
| HTTP Fingerprinting | Vendor, product, WAF, technologies | Per pipeline run |

---

## Notes

- Every record has `match_confidence = "high"` — low confidence matches are excluded.
- All records come from CISA KEV — real-world exploitation confirmed by the US government.
- `version_confirmed` must be read together with `confirmation_method` for correct interpretation.
- `cwe_id`, `cwe_name`, `attack_technique_id`, `attack_technique_name`, `attack_tactic` are context fields — not used in TPF but valuable for reporting and model features.
- The file is regenerated on every `python main.py` run. Always use the latest version.
