import requests
import json
from database import save_cisa_kev as db_save_cisa_kev

def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()

    filtered = []
    for vuln in data['vulnerabilities']:
        filtered.append({
            "cve_id":           vuln["cveID"],
            "vendor":           vuln["vendorProject"],
            "product":          vuln["product"],
            "date_added":       vuln["dateAdded"],
            "known_ransomware": vuln["knownRansomwareCampaignUse"] == "Known",
            "description":      vuln["shortDescription"]
        })
    return filtered

def save_cisa_kev(data):
    db_save_cisa_kev(data)
    print(f"Saved {len(data)} CVEs to DB")

if __name__ == "__main__":
    data = fetch_cisa_kev()
    save_cisa_kev(data)