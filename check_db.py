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
            "MATCHED CVES",
            """
            SELECT cve_id, asset_id, asset_name, cve_vendor, cve_product,
                   severity, cvss_score, epss_score, vuln_type, match_confidence,
                   version_confirmed, detected_version
            FROM matched_cves ORDER BY asset_id, cve_id
            """
        ),
        (
            "THREAT INTELLIGENCE",
            """
            SELECT cve_id, asset_id, asset_name, severity, cvss_score, epss_score,
                   threat_score, threat_pressure_factor, alert_level,
                   version_confirmed, detected_version, is_behind_waf, waf_name
            FROM threat_intelligence ORDER BY asset_id, cve_id
            """
        ),
        (
            "ALERTS",
            """
            SELECT a.timestamp, a.reason, a.alert_level, a.cve_id, a.asset_id,
                   a.vuln_type, a.threat_score, a.threat_pressure_factor
            FROM alerts a
            INNER JOIN threat_intelligence ti
                ON ti.cve_id = a.cve_id AND ti.asset_id = a.asset_id
            ORDER BY a.id DESC
            """
        ),
    ]

    for title, query in sections:
        print_section(title)
        print_rows(fetch_rows(cursor, query))

    conn.close()


if __name__ == "__main__":
    main()