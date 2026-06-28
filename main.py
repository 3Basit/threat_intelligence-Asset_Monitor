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

    # ── Step 5: FAIR Prediction (disabled — run separately if needed) ──
    print("=" * 50)
    print("Step 5: FAIR Risk Prediction... [SKIPPED — run prediction_model separately]")
    # To run prediction locally: python -m prediction_model.fair_engine
    # _run_prediction_step()  ← disabled: prediction module excluded from this pipeline

    print("=" * 50)
    print("Pipeline complete!")


def _run_prediction_step():
    """Run FAIR prediction if prerequisites are available.

    Prerequisites:
    - company_profile.json exists (user must create it)
    - prediction_model/saved_model/magnitude_model.joblib exists (must train first)
    - threat_intelligence_output.json exists (produced by Step 4)
    """
    ti_output_file = config.TI_OUTPUT_FILE
    company_profile_file = config.COMPANY_PROFILE_FILE
    model_file = os.path.join(config.MODEL_DIR, "magnitude_model.joblib")

    if not os.path.exists(ti_output_file):
        log.info("No TI output found — run Steps 1-4 first")
        return

    if not os.path.exists(company_profile_file):
        log.info("No company_profile.json found — create one with industry_sector, region, estimated_records (see prediction_model/schema.py)")
        return

    if not os.path.exists(model_file):
        log.info("No trained model found — train first: python -m prediction_model.model_training --compare")
        return

    try:
        from prediction_model.fair_engine import run_prediction
        run_prediction(
            ti_output_file=ti_output_file,
            company_profile_file=company_profile_file,
            output_file=config.PREDICTION_OUTPUT_FILE,
        )
    except Exception as e:
        log.error("Prediction failed: %s", e)
        log.info("The TI pipeline completed successfully. Prediction is optional.")


if __name__ == "__main__":
    main()

