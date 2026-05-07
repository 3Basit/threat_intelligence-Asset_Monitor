import json
from database import (
    get_enriched_cves,
    get_assets,
    get_asset_services,
    save_matched_cves as db_save_matched_cves
)

WEB_VULN_KEYWORDS = {
    "rce": [
        "remote code execution", "rce", "code injection",
        "command injection", "execute code", "code execution",
        "arbitrary code", "arbitrary command", "command execution",
        "upload and execute", "jsp file", "ognl", "deserialization"
    ],
    "sqli":           ["sql injection", "sqli"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "local file"],
    "auth_bypass":    ["authentication bypass", "auth bypass", "improper authentication"],
    "ssrf":           ["server-side request forgery", "ssrf"],
    "xss":            ["cross-site scripting", "xss"],
}

def detect_vuln_type(description):
    if not description:
        return "unknown"
    desc = description.lower()
    for vuln_type, keywords in WEB_VULN_KEYWORDS.items():
        for kw in keywords:
            if kw in desc:
                return vuln_type
    return "other"

def is_web_asset(asset):
    return asset["asset_type"].startswith("web")

def compute_match_confidence(cve, asset):
    cve_vendor  = cve["vendor"].lower()
    cve_product = cve["product"].lower()
    ast_vendor  = asset["vendor"].lower()

    vendor_match  = cve_vendor == ast_vendor
    product_match = any(kw.lower() in cve_product for kw in asset["keywords"])

    if vendor_match and product_match:
        return "high"
    return "low"

def check_version_confirmed(cve, asset_id):
    services = get_asset_services(asset_id)
    if not services:
        return False, None

    desc_and_product = (
        f"{cve.get('description', '')} {cve.get('product', '')}"
    ).lower()

    for svc in services:
        version = svc.get("version") or ""
        if not version:
            continue
        if version.lower() in desc_and_product:
            return True, version
        major_minor = ".".join(version.split(".")[:2])
        if major_minor and major_minor in desc_and_product:
            return True, version

    for svc in services:
        version = svc.get("version") or ""
        if version:
            return False, version

    return False, None

def run_matching():
    cves   = get_enriched_cves()
    assets = get_assets()

    if not cves:
        print("[ERROR] enriched_cves table empty. Run Step 2 first.")
        return

    if not assets:
        print("[ERROR] assets table empty. Run Asset Monitor first.")
        return

    web_assets = [a for a in assets if is_web_asset(a)]

    matched = []
    review  = []
    seen    = set()

    for cve in cves:
        for asset in web_assets:
            key = (cve["cve_id"], asset["asset_id"])
            if key in seen:
                continue

            confidence = compute_match_confidence(cve, asset)

            if confidence == "low":
                seen.add(key)
                review.append(cve["cve_id"])
                continue

            seen.add(key)

            version_confirmed, detected_version = check_version_confirmed(
                cve, asset["asset_id"]
            )

            matched.append({
                "cve_id":               cve["cve_id"],
                "cve_vendor":           cve["vendor"],
                "cve_product":          cve["product"],
                "date_added":           cve["date_added"],
                "known_ransomware":     cve["known_ransomware"],
                "description":          cve["description"],
                "cvss_score":           cve["cvss_score"],
                "severity":             cve["severity"],
                "epss_score":           cve["epss_score"],
                "epss_percentile":      cve["epss_percentile"],
                "published":            cve["published"],
                "asset_id":             asset["asset_id"],
                "asset_name":           asset["asset_name"],
                "asset_type":           asset["asset_type"],
                "asset_vendor":         asset["vendor"],
                "asset_product":        asset["product"],
                "business_criticality": asset["business_criticality"],
                "match_confidence":     confidence,
                "vuln_type":            detect_vuln_type(cve["description"]),
                "scope":                "web",
                "source":               "CISA_KEV + NVD + EPSS",
                "version_confirmed":    version_confirmed,
                "detected_version":     detected_version,
            })

    db_save_matched_cves(matched)

    confirmed_count = sum(1 for m in matched if m["version_confirmed"])
    print(f"Total matched   (high confidence): {len(matched)}")
    print(f"Version confirmed (Nmap verified): {confirmed_count}")
    print(f"Total review    (low confidence):  {len(review)}")

if __name__ == "__main__":
    run_matching()