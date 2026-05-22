import json
from datetime import datetime, timezone
from database import (
    get_matched_cves,
    get_asset_waf_info,
    get_previous_ti_state,
    save_threat_intelligence as db_save_ti,
    save_alerts              as db_save_alerts
)

VULN_TYPE_WEIGHTS = {
    "rce":            0.20,
    "sqli":           0.15,
    "auth_bypass":    0.15,
    "path_traversal": 0.12,
    "ssrf":           0.12,
    "xss":            0.08,
    "other":          0.05,
    "unknown":        0.00
}

CRITICALITY_WEIGHTS = {
    "critical": 0.20,
    "high":     0.13,
    "medium":   0.07,
    "low":      0.00
}

ALERT_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def compute_tpf(record):
    score = 0.0

    cvss = record.get("cvss_score")
    if cvss is not None:
        if cvss >= 9.0:   score += 0.20
        elif cvss >= 7.0: score += 0.13
        elif cvss >= 4.0: score += 0.07

    epss = record.get("epss_score")
    if epss is not None:
        if epss >= 0.7:   score += 0.20
        elif epss >= 0.4: score += 0.13
        elif epss >= 0.1: score += 0.07

    score += 0.13  # KEV presence

    if record.get("known_ransomware"):
        score += 0.07

    score += VULN_TYPE_WEIGHTS.get(record.get("vuln_type", "unknown"), 0.0)
    score += CRITICALITY_WEIGHTS.get(record.get("business_criticality", "low"), 0.0)

    try:
        date_added = datetime.strptime(record["date_added"], "%Y-%m-%d")
        days_since = (datetime.now() - date_added).days
        if days_since <= 30:    score += 0.10
        elif days_since <= 90:  score += 0.06
        elif days_since <= 365: score += 0.03
    except Exception:
        pass

    # Version confirmation bonus — only for CPE-range confirmed (high confidence)
    # text_search confirmation does NOT add bonus (medium confidence only)
    if record.get("version_confirmed") and record.get("confirmation_method") == "cpe_range":
        score += 0.05

    # Public exploit bonus
    if record.get("has_public_exploit"):
        score += 0.10

    threat_score           = round(min(score, 1.0), 2)
    threat_pressure_factor = round(1.0 + threat_score, 2)
    return threat_score, threat_pressure_factor


def get_alert_level(tpf):
    if tpf >= 1.7:   return "CRITICAL"
    elif tpf >= 1.5: return "HIGH"
    elif tpf >= 1.3: return "MEDIUM"
    else:            return "LOW"


def run_threat_pressure():
    matches = get_matched_cves()

    if not matches:
        print("[WARN] matched_cves table is empty — run Step 3 (matching) first.")
        return

    previous_state = get_previous_ti_state()
    output = []
    alerts = []

    for m in matches:
        threat_score, tpf = compute_tpf(m)
        alert_level        = get_alert_level(tpf)

        try:
            days_since_published = (
                datetime.now() - datetime.strptime(m["published"], "%Y-%m-%d")
            ).days
        except Exception:
            days_since_published = None

        try:
            days_since_kev_added = (
                datetime.now() - datetime.strptime(m["date_added"], "%Y-%m-%d")
            ).days
        except Exception:
            days_since_kev_added = None

        waf_info      = get_asset_waf_info(m["asset_id"])
        is_behind_waf = waf_info["is_behind_waf"]
        waf_name      = waf_info["waf_name"]

        record = {
            "cve_id":                 m["cve_id"],
            "cve_vendor":             m["cve_vendor"],
            "cve_product":            m["cve_product"],
            "asset_id":               m["asset_id"],
            "asset_name":             m["asset_name"],
            "asset_type":             m["asset_type"],
            "asset_vendor":           m["asset_vendor"],
            "asset_product":          m["asset_product"],
            "business_criticality":   m["business_criticality"],
            "cvss_score":             m["cvss_score"],
            "severity":               m["severity"],
            "epss_score":             m["epss_score"],
            "epss_percentile":        m["epss_percentile"],
            "published":              m["published"],
            "date_added":             m["date_added"],
            "days_since_published":   days_since_published,
            "days_since_kev_added":   days_since_kev_added,
            "known_ransomware":       m["known_ransomware"],
            "vuln_type":              m["vuln_type"],
            "description":            m["description"],
            "match_confidence":       m["match_confidence"],
            "scope":                  m["scope"],
            "source":                 m["source"],
            "threat_score":           threat_score,
            "threat_pressure_factor": tpf,
            "alert_level":            alert_level,
            "version_confirmed":      m.get("version_confirmed", False),
            "detected_version":       m.get("detected_version"),
            "confirmation_method":    m.get("confirmation_method", "none"),
            "cpe_range_matched":      m.get("cpe_range_matched"),
            "is_behind_waf":          is_behind_waf,
            "waf_name":               waf_name,
            "has_public_exploit":     m.get("has_public_exploit", False),
            "exploit_count":          m.get("exploit_count", 0),
            "exploit_ids":            m.get("exploit_ids", ""),
            "cwe_id":                 m.get("cwe_id"),
            "cwe_name":               m.get("cwe_name"),
            "attack_technique_id":    m.get("attack_technique_id"),
            "attack_technique_name":  m.get("attack_technique_name"),
            "attack_tactic":          m.get("attack_tactic"),
        }

        output.append(record)

        state_key  = f"{m['cve_id']}|{m['asset_id']}"
        is_new     = state_key not in previous_state
        tpf_raised = (not is_new) and tpf > previous_state[state_key]["tpf"]
        lvl_raised = (not is_new) and (
            ALERT_LEVELS.get(alert_level, 0) >
            ALERT_LEVELS.get(previous_state[state_key]["alert_level"], 0)
        )

        if is_new or tpf_raised or lvl_raised:
            alerts.append({
                "timestamp":              datetime.now(timezone.utc).isoformat(),
                "reason":                 "new" if is_new else "escalated",
                "alert_level":            alert_level,
                "cve_id":                 m["cve_id"],
                "cve_vendor":             m["cve_vendor"],
                "cve_product":            m["cve_product"],
                "asset_id":               m["asset_id"],
                "asset_name":             m["asset_name"],
                "vuln_type":              m["vuln_type"],
                "cvss_score":             m["cvss_score"],
                "epss_score":             m["epss_score"],
                "threat_score":           threat_score,
                "threat_pressure_factor": tpf,
                "description":            m["description"],
            })

    db_save_ti(output)
    db_save_alerts(alerts)

    with open("threat_intelligence_output.json", "w") as f:
        json.dump(output, f, indent=2)

    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)

    confirmed     = sum(1 for r in output if r.get("version_confirmed"))
    cpe_count     = sum(1 for r in output if r.get("confirmation_method") == "cpe_range")
    txt_count     = sum(1 for r in output if r.get("confirmation_method") == "text_search")
    waf_count     = sum(1 for r in output if r.get("is_behind_waf"))
    exploit_count = sum(1 for r in output if r.get("has_public_exploit"))

    print(f"Total records:        {len(output)}")
    print(f"Version confirmed:    {confirmed}")
    print(f"  +- cpe_range:       {cpe_count}  (high confidence)")
    print(f"  +- text_search:     {txt_count}  (medium confidence)")
    print(f"Behind WAF:           {waf_count}")
    print(f"With public exploits: {exploit_count}")
    print(f"New/escalated alerts: {len(alerts)}")

    for a in alerts:
        rec     = next((r for r in output
                        if r["cve_id"] == a["cve_id"]
                        and r["asset_id"] == a["asset_id"]), {})
        cm      = rec.get("confirmation_method", "none")
        vc_tag  = f" [VERSION {cm.upper()}]" if rec.get("version_confirmed") else ""
        waf_tag = f" [WAF: {rec['waf_name']}]" if rec.get("is_behind_waf") else ""
        exp_tag = f" [EXPLOIT x{rec.get('exploit_count',0)}]" \
                  if rec.get("has_public_exploit") else ""
        print(
            f"  [{a['alert_level']}] {a['cve_id']} | {a['cve_product']}"
            f" -> {a['asset_name']} | {a['vuln_type']}"
            f" | TPF: {a['threat_pressure_factor']}{vc_tag}{waf_tag}{exp_tag}"
        )


if __name__ == "__main__":
    run_threat_pressure()
