import sys
import os
import subprocess

import config
from logger import get_logger
from database        import init_db, get_enriched_cves
from cisa_kev        import fetch_cisa_kev, save_cisa_kev
from nvd_fetch       import enrich_cves
from exploit_db      import run_exploitdb
from matching        import run_matching
from threat_pressure import run_threat_pressure

log = get_logger("main")


def main():
    # ── Step 0: Init DB ───────────────────────────────────────────
    print("=" * 50)
    print("Initializing database...")
    init_db()

    # ── Step 0b: Asset Monitor ────────────────────────────────────
    print("=" * 50)
    print("Step 0: Running Asset Monitor...")
    result = subprocess.run([sys.executable, "asset_monitor.py"], check=False)
    if result.returncode != 0:
        log.warning("Asset Monitor exited with errors — continuing with existing assets in DB")

    # ── Step 1: CISA KEV ─────────────────────────────────────────
    print("=" * 50)
    print("Step 1: Fetching CISA KEV...")
    save_cisa_kev(fetch_cisa_kev())

    # ── Step 2: NVD + EPSS + CPE ranges ──────────────────────────
    print("=" * 50)
    print("Step 2: Enriching from NVD + EPSS (with CPE version ranges)...")
    enrich_cves()

    # ── Step 2b: Exploit-DB ───────────────────────────────────────
    print("=" * 50)
    print("Step 2b: Checking Exploit-DB for public exploits...")
    enriched_cves = get_enriched_cves()
    cve_ids       = [c["cve_id"] for c in enriched_cves]
    run_exploitdb(cve_ids)

    # ── Step 3: Matching (CPE-aware) ──────────────────────────────
    print("=" * 50)
    print("Step 3: Matching CVEs to web assets (CPE version check + Exploit-DB)...")
    run_matching()

    # ── Step 4: TPF + Alerts ──────────────────────────────────────
    print("=" * 50)
    print("Step 4: Computing TPF + Generating alerts...")
    run_threat_pressure()

    print("=" * 50)
    print("Pipeline complete!")





if __name__ == "__main__":
    main()

