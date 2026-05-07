import sys
import subprocess
from database import init_db
from cisa_kev        import fetch_cisa_kev, save_cisa_kev
from nvd_fetch       import enrich_cves
from matching        import run_matching
from threat_pressure import run_threat_pressure

# ── Step 0: Init DB ───────────────────────────────────────────
print("=" * 50)
print("Initializing database...")
init_db()

# ── Step 0b: Asset Monitor ────────────────────────────────────
print("=" * 50)
print("Step 0: Running Asset Monitor...")
result = subprocess.run([sys.executable, "asset_monitor.py"], check=False)
if result.returncode != 0:
    print("[WARN] Asset Monitor exited with errors — continuing with existing assets in DB")

# ── Step 1: CISA KEV ─────────────────────────────────────────
print("=" * 50)
print("Step 1: Fetching CISA KEV...")
save_cisa_kev(fetch_cisa_kev())

# ── Step 2: NVD + EPSS ───────────────────────────────────────
print("=" * 50)
print("Step 2: Enriching from NVD + EPSS...")
enrich_cves()

# ── Step 3: Matching ──────────────────────────────────────────
print("=" * 50)
print("Step 3: Matching CVEs to web assets (with version check)...")
run_matching()

# ── Step 4: TPF + Alerts ──────────────────────────────────────
print("=" * 50)
print("Step 4: Computing TPF + Generating alerts...")
run_threat_pressure()

print("=" * 50)
print("Pipeline complete!")