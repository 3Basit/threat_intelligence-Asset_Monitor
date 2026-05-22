import sqlite3

DB_FILE = "threat_intelligence.db"


def print_section(title):
    print("\n" + title)
    print("-" * len(title))


def fetch_rows(cursor, query):
    try:
        return cursor.execute(query).fetchall()
    except sqlite3.Error as exc:
        print(f"  [WARN] {exc}")
        return []


def print_rows(rows):
    if not rows:
        print("  (none)")
        return
    for row in rows:
        values = [f"{key}={row[key]}" for key in row.keys()]
        print("  " + " | ".join(values))


def main():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    sections = [
        (
            "TABLES",
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ),
        (
            "ASSETS",
            """
            SELECT asset_id, asset_name, asset_type, business_criticality, vendor, product
            FROM assets ORDER BY asset_id
            """
        ),
        (
            "ASSET SERVICES",
            """
            SELECT asset_id, port, state, service_name, product, version
            FROM asset_services ORDER BY asset_id, port
            """
        ),
        (
            "ASSET TECHNOLOGIES",
            """
            SELECT asset_id, technology_name, category, version, source, confidence
            FROM asset_technologies ORDER BY asset_id, category
            """
        ),
        (
            "ASSET WAF INFO",
            """
            SELECT asset_id, is_behind_waf, waf_name, detected_by, detected_at
            FROM asset_waf_info ORDER BY asset_id
            """
        ),
        (
            "EXPLOIT-DB",
            """
            SELECT cve_id, has_public_exploit, exploit_count, exploit_ids, checked_at
            FROM exploitdb_cves ORDER BY exploit_count DESC
            """
        ),
        (
            "MATCHED CVES",
            """
            SELECT cve_id, asset_id, asset_name, cve_vendor, cve_product,
                   severity, cvss_score, epss_score, vuln_type, match_confidence,
                   version_confirmed, detected_version, confirmation_method, cpe_range_matched,
                   has_public_exploit, exploit_count, exploit_ids, cwe_id, cwe_name,
                   attack_technique_id, attack_tactic
            FROM matched_cves ORDER BY asset_id, cve_id
            """
        ),
        (
            "THREAT INTELLIGENCE",
            """
            SELECT cve_id, asset_id, asset_name, severity, cvss_score, epss_score,
                   threat_score, threat_pressure_factor, alert_level,
                   version_confirmed, detected_version, confirmation_method, cpe_range_matched,
                   is_behind_waf, waf_name,
                   has_public_exploit, exploit_count, cwe_id, cwe_name,
                   attack_technique_id, attack_tactic
            FROM threat_intelligence ORDER BY threat_pressure_factor DESC
            """
        ),
        (
            "ALERTS (latest 5)",
            """
            SELECT a.timestamp, a.reason, a.alert_level, a.cve_id, a.asset_id,
                   a.vuln_type, a.threat_score, a.threat_pressure_factor
            FROM alerts a
            ORDER BY a.id DESC
            LIMIT 5
            """
        ),
    ]

    for title, query in sections:
        print_section(title)
        print_rows(fetch_rows(cursor, query))

    conn.close()


if __name__ == "__main__":
    main()
