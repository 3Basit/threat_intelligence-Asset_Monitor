import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime

DB_FILE = "threat_intelligence.db"


@contextmanager
def get_db():
    """Context manager: auto-commit on success, rollback on error, always closes."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_connection():
    """Legacy helper kept for read-only callers that fetch and close manually."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id             TEXT PRIMARY KEY,
            asset_name           TEXT,
            asset_type           TEXT,
            business_criticality TEXT,
            vendor               TEXT,
            product              TEXT,
            keywords             TEXT,
            created_at           TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cisa_kev (
            cve_id           TEXT PRIMARY KEY,
            vendor           TEXT,
            product          TEXT,
            date_added       TEXT,
            known_ransomware INTEGER,
            description      TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS enriched_cves (
            cve_id           TEXT PRIMARY KEY,
            vendor           TEXT,
            product          TEXT,
            date_added       TEXT,
            known_ransomware INTEGER,
            description      TEXT,
            cvss_score       REAL,
            severity         TEXT,
            published        TEXT,
            epss_score       REAL,
            epss_percentile  REAL,
            cpe_ranges       TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exploitdb_cves (
            cve_id             TEXT PRIMARY KEY,
            has_public_exploit INTEGER DEFAULT 0,
            exploit_count      INTEGER DEFAULT 0,
            exploit_ids        TEXT,
            checked_at         TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS matched_cves (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id               TEXT,
            cve_vendor           TEXT,
            cve_product          TEXT,
            asset_id             TEXT,
            asset_name           TEXT,
            asset_type           TEXT,
            asset_vendor         TEXT,
            asset_product        TEXT,
            business_criticality TEXT,
            cvss_score           REAL,
            severity             TEXT,
            epss_score           REAL,
            epss_percentile      REAL,
            published            TEXT,
            date_added           TEXT,
            known_ransomware     INTEGER,
            vuln_type            TEXT,
            description          TEXT,
            match_confidence     TEXT,
            scope                TEXT,
            source               TEXT,
            version_confirmed    INTEGER DEFAULT 0,
            detected_version     TEXT,
            confirmation_method  TEXT DEFAULT 'none',
            cpe_range_matched    TEXT,
            has_public_exploit      INTEGER DEFAULT 0,
            exploit_count           INTEGER DEFAULT 0,
            exploit_ids             TEXT,
            attack_technique_id     TEXT,
            attack_technique_name   TEXT,
            attack_tactic           TEXT,
            UNIQUE(cve_id, asset_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id                  TEXT,
            cve_vendor              TEXT,
            cve_product             TEXT,
            asset_id                TEXT,
            asset_name              TEXT,
            asset_type              TEXT,
            asset_vendor            TEXT,
            asset_product           TEXT,
            business_criticality    TEXT,
            cvss_score              REAL,
            severity                TEXT,
            epss_score              REAL,
            epss_percentile         REAL,
            published               TEXT,
            date_added              TEXT,
            days_since_published    INTEGER,
            days_since_kev_added    INTEGER,
            known_ransomware        INTEGER,
            vuln_type               TEXT,
            description             TEXT,
            match_confidence        TEXT,
            scope                   TEXT,
            source                  TEXT,
            threat_score            REAL,
            threat_pressure_factor  REAL,
            alert_level             TEXT,
            version_confirmed       INTEGER DEFAULT 0,
            detected_version        TEXT,
            confirmation_method     TEXT DEFAULT 'none',
            cpe_range_matched       TEXT,
            is_behind_waf           INTEGER DEFAULT 0,
            waf_name                TEXT,
            has_public_exploit      INTEGER DEFAULT 0,
            exploit_count           INTEGER DEFAULT 0,
            exploit_ids             TEXT,
            attack_technique_id     TEXT,
            attack_technique_name   TEXT,
            attack_tactic           TEXT,
            last_updated            TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(cve_id, asset_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp               TEXT,
            reason                  TEXT,
            alert_level             TEXT,
            cve_id                  TEXT,
            cve_vendor              TEXT,
            cve_product             TEXT,
            asset_id                TEXT,
            asset_name              TEXT,
            vuln_type               TEXT,
            cvss_score              REAL,
            epss_score              REAL,
            threat_score            REAL,
            threat_pressure_factor  REAL,
            description             TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_services (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id     TEXT,
            port         INTEGER,
            state        TEXT,
            service_name TEXT,
            product      TEXT,
            version      TEXT,
            cpe          TEXT,
            detected_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_technologies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id        TEXT,
            technology_name TEXT,
            category        TEXT,
            version         TEXT,
            source          TEXT,
            confidence      TEXT,
            detected_at     TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_waf_info (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id      TEXT UNIQUE,
            is_behind_waf INTEGER DEFAULT 0,
            waf_name      TEXT,
            detected_by   TEXT,
            detected_at   TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Schema migrations (safe on existing DB) ───────────────
    migrations = [
        "ALTER TABLE matched_cves        ADD COLUMN version_confirmed   INTEGER DEFAULT 0",
        "ALTER TABLE matched_cves        ADD COLUMN detected_version    TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN confirmation_method TEXT DEFAULT 'none'",
        "ALTER TABLE matched_cves        ADD COLUMN has_public_exploit  INTEGER DEFAULT 0",
        "ALTER TABLE matched_cves        ADD COLUMN exploit_count       INTEGER DEFAULT 0",
        "ALTER TABLE matched_cves        ADD COLUMN exploit_ids         TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN cwe_id              TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN cwe_name            TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN version_confirmed   INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN detected_version    TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN confirmation_method TEXT DEFAULT 'none'",
        "ALTER TABLE threat_intelligence ADD COLUMN is_behind_waf       INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN waf_name            TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN has_public_exploit  INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN exploit_count       INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN exploit_ids         TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN cwe_id                TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN cwe_name              TEXT",
        "ALTER TABLE enriched_cves       ADD COLUMN cpe_ranges            TEXT",
        "ALTER TABLE enriched_cves       ADD COLUMN cwe_id                TEXT",
        "ALTER TABLE enriched_cves       ADD COLUMN cwe_name              TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN attack_technique_id   TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN attack_technique_name TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN attack_tactic         TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN attack_technique_id   TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN attack_technique_name TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN attack_tactic         TEXT",
        "ALTER TABLE matched_cves        ADD COLUMN cpe_range_matched     TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN cpe_range_matched     TEXT",
    ]
    for sql in migrations:
        try:
            cursor.execute(sql)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()
    print("Database initialized OK")


# ── Writes ────────────────────────────────────────────────────

def save_assets(assets):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM assets")
        for a in assets:
            cursor.execute("""
                INSERT OR REPLACE INTO assets
                (asset_id, asset_name, asset_type, business_criticality, vendor, product, keywords)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                a["asset_id"], a["asset_name"], a["asset_type"],
                a["business_criticality"], a["vendor"], a["product"],
                json.dumps(a["keywords"])
            ))


def save_cisa_kev(vulns):
    with get_db() as conn:
        cursor = conn.cursor()
        for v in vulns:
            cursor.execute("""
                INSERT OR REPLACE INTO cisa_kev
                (cve_id, vendor, product, date_added, known_ransomware, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                v["cve_id"], v["vendor"], v["product"],
                v["date_added"], int(v["known_ransomware"]), v["description"]
            ))


def save_enriched_cves(cves):
    with get_db() as conn:
        cursor = conn.cursor()
        for c in cves:
            cursor.execute("""
                INSERT OR REPLACE INTO enriched_cves
                (cve_id, vendor, product, date_added, known_ransomware, description,
                 cvss_score, severity, published, epss_score, epss_percentile,
                 cpe_ranges, cwe_id, cwe_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c["cve_id"], c["vendor"], c["product"], c["date_added"],
                int(c["known_ransomware"]), c["description"],
                c.get("cvss_score"), c.get("severity"), c.get("published"),
                c.get("epss_score"), c.get("epss_percentile"),
                json.dumps(c.get("cpe_ranges", [])),
                c.get("cwe_id"), c.get("cwe_name")
            ))


def save_exploitdb_cves(records):
    with get_db() as conn:
        cursor = conn.cursor()
        for r in records:
            cursor.execute("""
                INSERT OR REPLACE INTO exploitdb_cves
                (cve_id, has_public_exploit, exploit_count, exploit_ids)
                VALUES (?, ?, ?, ?)
            """, (
                r["cve_id"], int(r["has_public_exploit"]),
                r["exploit_count"], r["exploit_ids"]
            ))


def save_matched_cves(matches):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM matched_cves")
        for m in matches:
            cursor.execute("""
                INSERT OR IGNORE INTO matched_cves
                (cve_id, cve_vendor, cve_product, asset_id, asset_name, asset_type,
                 asset_vendor, asset_product, business_criticality, cvss_score, severity,
                 epss_score, epss_percentile, published, date_added, known_ransomware,
                 vuln_type, description, match_confidence, scope, source,
                 version_confirmed, detected_version, confirmation_method, cpe_range_matched,
                 has_public_exploit, exploit_count, exploit_ids, cwe_id, cwe_name,
                 attack_technique_id, attack_technique_name, attack_tactic)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                m["cve_id"], m["cve_vendor"], m["cve_product"],
                m["asset_id"], m["asset_name"], m["asset_type"],
                m["asset_vendor"], m["asset_product"], m["business_criticality"],
                m.get("cvss_score"), m.get("severity"),
                m.get("epss_score"), m.get("epss_percentile"),
                m.get("published"), m.get("date_added"),
                int(m.get("known_ransomware", False)),
                m.get("vuln_type"), m.get("description"),
                m.get("match_confidence"), m.get("scope"), m.get("source"),
                int(m.get("version_confirmed", False)),
                m.get("detected_version"),
                m.get("confirmation_method", "none"),
                m.get("cpe_range_matched"),
                int(m.get("has_public_exploit", False)),
                m.get("exploit_count", 0),
                m.get("exploit_ids", ""),
                m.get("cwe_id"), m.get("cwe_name"),
                m.get("attack_technique_id"), m.get("attack_technique_name"),
                m.get("attack_tactic")
            ))


def save_threat_intelligence(records):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_intelligence")
        for r in records:
            cursor.execute("""
                INSERT OR IGNORE INTO threat_intelligence
                (cve_id, cve_vendor, cve_product, asset_id, asset_name, asset_type,
                 asset_vendor, asset_product, business_criticality, cvss_score, severity,
                 epss_score, epss_percentile, published, date_added, days_since_published,
                 days_since_kev_added, known_ransomware, vuln_type, description,
                 match_confidence, scope, source, threat_score, threat_pressure_factor,
                 alert_level, version_confirmed, detected_version, confirmation_method,
                 cpe_range_matched,
                 is_behind_waf, waf_name, has_public_exploit, exploit_count, exploit_ids,
                 cwe_id, cwe_name,
                 attack_technique_id, attack_technique_name, attack_tactic)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["cve_id"], r["cve_vendor"], r["cve_product"],
                r["asset_id"], r["asset_name"], r["asset_type"],
                r["asset_vendor"], r["asset_product"], r["business_criticality"],
                r.get("cvss_score"), r.get("severity"),
                r.get("epss_score"), r.get("epss_percentile"),
                r.get("published"), r.get("date_added"),
                r.get("days_since_published"), r.get("days_since_kev_added"),
                int(r.get("known_ransomware", False)),
                r.get("vuln_type"), r.get("description"),
                r.get("match_confidence"), r.get("scope"), r.get("source"),
                r.get("threat_score"), r.get("threat_pressure_factor"), r.get("alert_level"),
                int(r.get("version_confirmed", False)),
                r.get("detected_version"),
                r.get("confirmation_method", "none"),
                r.get("cpe_range_matched"),
                int(r.get("is_behind_waf", False)),
                r.get("waf_name"),
                int(r.get("has_public_exploit", False)),
                r.get("exploit_count", 0),
                r.get("exploit_ids", ""),
                r.get("cwe_id"), r.get("cwe_name"),
                r.get("attack_technique_id"), r.get("attack_technique_name"),
                r.get("attack_tactic")
            ))


def save_alerts(alerts_list):
    """Insert alerts, skipping duplicates for the same CVE+asset+level on the same day."""
    with get_db() as conn:
        cursor = conn.cursor()
        for a in alerts_list:
            # Deduplicate: one alert per (cve_id, asset_id, alert_level) per calendar day
            today = a["timestamp"][:10]  # e.g. "2026-05-22"
            cursor.execute("""
                SELECT 1 FROM alerts
                WHERE cve_id = ? AND asset_id = ? AND alert_level = ?
                  AND substr(timestamp, 1, 10) = ?
            """, (a["cve_id"], a["asset_id"], a["alert_level"], today))
            if cursor.fetchone():
                continue  # already logged today
            cursor.execute("""
                INSERT INTO alerts
                (timestamp, reason, alert_level, cve_id, cve_vendor, cve_product,
                 asset_id, asset_name, vuln_type, cvss_score, epss_score,
                 threat_score, threat_pressure_factor, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a["timestamp"], a["reason"], a["alert_level"],
                a["cve_id"], a["cve_vendor"], a["cve_product"],
                a["asset_id"], a["asset_name"], a["vuln_type"],
                a.get("cvss_score"), a.get("epss_score"),
                a.get("threat_score"), a.get("threat_pressure_factor"),
                a.get("description")
            ))


def save_asset_services(asset_id, services):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM asset_services WHERE asset_id = ?", (asset_id,))
        for s in services:
            if s.get("state") != "open":
                continue
            cursor.execute("""
                INSERT INTO asset_services
                (asset_id, port, state, service_name, product, version, cpe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                asset_id, s.get("port"), s.get("state"),
                s.get("service_name"), s.get("product"),
                s.get("version"), json.dumps(s.get("cpe", []))
            ))


def save_asset_technologies(asset_id, technologies):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM asset_technologies WHERE asset_id = ?", (asset_id,))
        for t in technologies:
            cursor.execute("""
                INSERT INTO asset_technologies
                (asset_id, technology_name, category, version, source, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                asset_id, t.get("name"), t.get("category"),
                t.get("version"), t.get("source", "signature"),
                t.get("confidence", "medium")
            ))


def save_asset_waf_info(asset_id, is_behind_waf, waf_name, detected_by):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO asset_waf_info
            (asset_id, is_behind_waf, waf_name, detected_by)
            VALUES (?, ?, ?, ?)
        """, (asset_id, int(is_behind_waf), waf_name, detected_by))


# ── Reads ─────────────────────────────────────────────────────

def get_assets():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets")
    rows = cursor.fetchall()
    conn.close()
    assets = []
    for row in rows:
        a = dict(row)
        a["keywords"] = json.loads(a["keywords"])
        assets.append(a)
    return assets


def get_cisa_kev():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cisa_kev")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["known_ransomware"] = bool(d["known_ransomware"])
        result.append(d)
    return result


def get_enriched_cves():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM enriched_cves")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["known_ransomware"] = bool(d["known_ransomware"])
        try:
            d["cpe_ranges"] = json.loads(d.get("cpe_ranges") or "[]")
        except Exception:
            d["cpe_ranges"] = []
        result.append(d)
    return result


def get_exploitdb_info(cve_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT has_public_exploit, exploit_count, exploit_ids "
        "FROM exploitdb_cves WHERE cve_id = ?",
        (cve_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "has_public_exploit": bool(row["has_public_exploit"]),
            "exploit_count":      row["exploit_count"],
            "exploit_ids":        row["exploit_ids"] or "",
        }
    return {"has_public_exploit": False, "exploit_count": 0, "exploit_ids": ""}


def get_matched_cves():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM matched_cves WHERE match_confidence = 'high'")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["known_ransomware"]   = bool(d["known_ransomware"])
        d["version_confirmed"]  = bool(d.get("version_confirmed", 0))
        d["has_public_exploit"] = bool(d.get("has_public_exploit", 0))
        result.append(d)
    return result


def get_asset_services(asset_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM asset_services WHERE asset_id = ? AND state = 'open'",
        (asset_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["cpe"] = json.loads(d.get("cpe", "[]"))
        except Exception:
            d["cpe"] = []
        result.append(d)
    return result


def get_asset_waf_info(asset_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT is_behind_waf, waf_name FROM asset_waf_info WHERE asset_id = ?",
        (asset_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"is_behind_waf": bool(row["is_behind_waf"]), "waf_name": row["waf_name"]}
    return {"is_behind_waf": False, "waf_name": None}


def get_previous_ti_state():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT cve_id, asset_id, threat_pressure_factor, alert_level "
        "FROM threat_intelligence"
    )
    rows = cursor.fetchall()
    conn.close()
    return {
        f"{r['cve_id']}|{r['asset_id']}": {
            "tpf":         r["threat_pressure_factor"],
            "alert_level": r["alert_level"]
        }
        for r in rows
    }


if __name__ == "__main__":
    init_db()
