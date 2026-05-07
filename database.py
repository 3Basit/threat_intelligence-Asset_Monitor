import sqlite3
import json
from datetime import datetime

DB_FILE = "threat_intelligence.db"

def get_connection():
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
            epss_percentile  REAL
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
            is_behind_waf           INTEGER DEFAULT 0,
            waf_name                TEXT,
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
        "ALTER TABLE matched_cves        ADD COLUMN version_confirmed INTEGER DEFAULT 0",
        "ALTER TABLE matched_cves        ADD COLUMN detected_version  TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN version_confirmed INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN detected_version  TEXT",
        "ALTER TABLE threat_intelligence ADD COLUMN is_behind_waf     INTEGER DEFAULT 0",
        "ALTER TABLE threat_intelligence ADD COLUMN waf_name          TEXT",
    ]
    for sql in migrations:
        try:
            cursor.execute(sql)
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.commit()
    conn.close()
    print("Database initialized OK")


# ── Writes ────────────────────────────────────────────────────

def save_assets(assets):
    conn = get_connection()
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
    conn.commit()
    conn.close()

def save_cisa_kev(vulns):
    conn = get_connection()
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
    conn.commit()
    conn.close()

def save_enriched_cves(cves):
    conn = get_connection()
    cursor = conn.cursor()
    for c in cves:
        cursor.execute("""
            INSERT OR REPLACE INTO enriched_cves
            (cve_id, vendor, product, date_added, known_ransomware, description,
             cvss_score, severity, published, epss_score, epss_percentile)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            c["cve_id"], c["vendor"], c["product"], c["date_added"],
            int(c["known_ransomware"]), c["description"],
            c.get("cvss_score"), c.get("severity"), c.get("published"),
            c.get("epss_score"), c.get("epss_percentile")
        ))
    conn.commit()
    conn.close()

def save_matched_cves(matches):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM matched_cves")
    for m in matches:
        cursor.execute("""
            INSERT OR IGNORE INTO matched_cves
            (cve_id, cve_vendor, cve_product, asset_id, asset_name, asset_type,
             asset_vendor, asset_product, business_criticality, cvss_score, severity,
             epss_score, epss_percentile, published, date_added, known_ransomware,
             vuln_type, description, match_confidence, scope, source,
             version_confirmed, detected_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            m.get("detected_version")
        ))
    conn.commit()
    conn.close()

def save_threat_intelligence(records):
    conn = get_connection()
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
             alert_level, version_confirmed, detected_version, is_behind_waf, waf_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            int(r.get("is_behind_waf", False)),
            r.get("waf_name")
        ))
    conn.commit()
    conn.close()

def save_alerts(alerts_list):
    conn = get_connection()
    cursor = conn.cursor()
    for a in alerts_list:
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
    conn.commit()
    conn.close()

def save_asset_services(asset_id, services):
    conn = get_connection()
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
    conn.commit()
    conn.close()

def save_asset_technologies(asset_id, technologies):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM asset_technologies WHERE asset_id = ?", (asset_id,))
    for t in technologies:
        cursor.execute("""
            INSERT INTO asset_technologies
            (asset_id, technology_name, category, version, source, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            asset_id,
            t.get("name"),
            t.get("category"),
            t.get("version"),
            t.get("source", "signature"),
            t.get("confidence", "medium")
        ))
    conn.commit()
    conn.close()

def save_asset_waf_info(asset_id, is_behind_waf, waf_name, detected_by):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO asset_waf_info
        (asset_id, is_behind_waf, waf_name, detected_by)
        VALUES (?, ?, ?, ?)
    """, (asset_id, int(is_behind_waf), waf_name, detected_by))
    conn.commit()
    conn.close()


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
        result.append(d)
    return result

def get_matched_cves():
    """Returns only high-confidence matches that enter the pipeline."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM matched_cves WHERE match_confidence = 'high'")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["known_ransomware"]  = bool(d["known_ransomware"])
        d["version_confirmed"] = bool(d.get("version_confirmed", 0))
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
    """Returns WAF status for an asset."""
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
    """
    Returns last saved TI snapshot keyed by 'cve_id|asset_id'.
    Call BEFORE save_threat_intelligence() clears the table.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT cve_id, asset_id, threat_pressure_factor, alert_level FROM threat_intelligence"
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