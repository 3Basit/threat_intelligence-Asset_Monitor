import requests
import json
import time
import os
from database import get_cisa_kev, get_assets, save_enriched_cves as db_save_enriched_cves

NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def is_relevant(vuln, assets):
    text = f"{vuln['vendor']} {vuln['product']} {vuln['description']}".lower()
    for asset in assets:
        for keyword in asset["keywords"]:
            if keyword.lower() in text:
                return True
    return False

def fetch_nvd_details(cve_id):
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data     = response.json()
        cve      = data["vulnerabilities"][0]["cve"]
        try:
            cvss_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity   = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        except Exception:
            cvss_score = None
            severity   = None
        return {
            "cvss_score": cvss_score,
            "severity":   severity,
            "published":  cve["published"][:10]
        }
    except Exception:
        return {"cvss_score": None, "severity": None, "published": None}

def fetch_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200 or not response.text.strip():
            return {"epss_score": None, "epss_percentile": None}
        data = response.json()
        if not data.get("data"):
            return {"epss_score": None, "epss_percentile": None}
        return {
            "epss_score":      float(data["data"][0]["epss"]),
            "epss_percentile": float(data["data"][0]["percentile"])
        }
    except Exception:
        return {"epss_score": None, "epss_percentile": None}

def enrich_cves():
    cisa_data = get_cisa_kev()
    assets    = get_assets()

    if not cisa_data:
        print("[ERROR] cisa_kev table is empty. Run Step 1 first.")
        return

    if not assets:
        print("[ERROR] assets table is empty. Run Asset Monitor first.")
        return

    relevant = [v for v in cisa_data if is_relevant(v, assets)]
    print(f"Relevant CVEs: {len(relevant)} out of {len(cisa_data)}")

    enriched = []
    for i, vuln in enumerate(relevant):
        print(f"Fetching {i+1}/{len(relevant)} - {vuln['cve_id']}")
        nvd  = fetch_nvd_details(vuln["cve_id"])
        epss = fetch_epss(vuln["cve_id"])
        enriched.append({**vuln, **nvd, **epss})
        time.sleep(0.6)

    db_save_enriched_cves(enriched)
    print(f"Saved {len(enriched)} enriched CVEs to DB")

if __name__ == "__main__":
    enrich_cves()