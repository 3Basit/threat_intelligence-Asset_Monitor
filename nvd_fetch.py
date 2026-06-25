import requests
import time
import os

import config
from logger import get_logger
from database import get_cisa_kev, get_assets, save_enriched_cves as db_save_enriched_cves

log = get_logger("nvd_fetch")

NVD_API_KEY = config.NVD_API_KEY

# Known CWE-ID → human-readable name mapping (common ones)
CWE_NAMES = {
    "CWE-20":   "Improper Input Validation",
    "CWE-22":   "Path Traversal",
    "CWE-74":   "Injection",
    "CWE-77":   "Command Injection",
    "CWE-78":   "OS Command Injection",
    "CWE-79":   "Cross-Site Scripting (XSS)",
    "CWE-89":   "SQL Injection",
    "CWE-94":   "Code Injection",
    "CWE-119":  "Buffer Overflow",
    "CWE-120":  "Classic Buffer Overflow",
    "CWE-121":  "Stack-based Buffer Overflow",
    "CWE-122":  "Heap-based Buffer Overflow",
    "CWE-125":  "Out-of-bounds Read",
    "CWE-190":  "Integer Overflow",
    "CWE-200":  "Exposure of Sensitive Information",
    "CWE-269":  "Improper Privilege Management",
    "CWE-276":  "Incorrect Default Permissions",
    "CWE-284":  "Improper Access Control",
    "CWE-285":  "Improper Authorization",
    "CWE-287":  "Improper Authentication",
    "CWE-306":  "Missing Authentication for Critical Function",
    "CWE-307":  "Brute Force Protection Missing",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-416":  "Use After Free",
    "CWE-434":  "Unrestricted File Upload",
    "CWE-502":  "Deserialization of Untrusted Data",
    "CWE-601":  "URL Redirection to Untrusted Site",
    "CWE-611":  "XML External Entity (XXE)",
    "CWE-787":  "Out-of-bounds Write",
    "CWE-798":  "Use of Hard-coded Credentials",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
}


def is_relevant(vuln, assets):
    text = f"{vuln['vendor']} {vuln['product']} {vuln['description']}".lower()
    for asset in assets:
        for keyword in asset["keywords"]:
            if keyword.lower() in text:
                return True
    return False


def _get_uncovered_keywords(assets, cisa_relevant):
    """Return asset keywords that have no matching CISA KEV CVEs."""
    covered = set()
    for vuln in cisa_relevant:
        text = f"{vuln['vendor']} {vuln['product']} {vuln['description']}".lower()
        for asset in assets:
            for kw in asset["keywords"]:
                if kw.lower() in text:
                    covered.add(kw.lower())
    uncovered = set()
    for asset in assets:
        for kw in asset["keywords"]:
            if kw.lower() not in covered:
                uncovered.add(kw.lower())
    return list(uncovered)


def fetch_nvd_by_keyword(keyword, max_results=20):
    """Search NVD directly for HIGH/CRITICAL CVEs matching a product keyword.

    Used as fallback when a detected technology has no CISA KEV entries.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        results = []
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            cvss, severity = None, None
            try:
                cvss     = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            except Exception:
                try:
                    cvss     = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                except Exception:
                    pass
            if cvss is not None and cvss < 7.0:
                continue  # skip LOW / MEDIUM
            results.append({
                "cve_id":          cve_id,
                "vendor":          keyword,
                "product":         keyword,
                "date_added":      None,
                "known_ransomware": False,
                "description":     desc,
            })
        return results
    except Exception as e:
        log.warning("NVD keyword search '%s' failed: %s", keyword, e)
        return []


def extract_cpe_ranges(cve_data):
    """
    Extract CPE version ranges from NVD API response.
    Returns a list of dicts with version boundary fields.
    Used by matching.py for precise version confirmation.
    """
    ranges = []
    try:
        configurations = cve_data.get("configurations", [])
        for cfg in configurations:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    ranges.append({
                        "criteria":                cpe_match.get("criteria", ""),
                        "version_start_including": cpe_match.get("versionStartIncluding"),
                        "version_start_excluding": cpe_match.get("versionStartExcluding"),
                        "version_end_including":   cpe_match.get("versionEndIncluding"),
                        "version_end_excluding":   cpe_match.get("versionEndExcluding"),
                    })
    except Exception:
        pass
    return ranges


def extract_cwe(cve_data):
    """
    Extract CWE ID and human-readable name from NVD weaknesses field.
    Returns (cwe_id, cwe_name) e.g. ("CWE-119", "Buffer Overflow")
    or (None, None) if not available.
    """
    try:
        weaknesses = cve_data.get("weaknesses", [])
        if not weaknesses:
            return None, None
        value = weaknesses[0]["description"][0]["value"]
        # Skip placeholder values NVD uses when CWE is unknown
        if not value or value.startswith("NVD-CWE"):
            return None, None
        cwe_id   = value                   # e.g. "CWE-119"
        cwe_name = CWE_NAMES.get(cwe_id)  # lookup; None if not in our map
        return cwe_id, cwe_name
    except (KeyError, IndexError, TypeError):
        return None, None


def fetch_nvd_details(cve_id):
    """
    Fetch CVSS, severity, published date, CPE ranges, and CWE from NVD.
    Retries up to 3 times with exponential backoff (2s, 4s) on failure.
    """
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    null_result = {
        "cvss_score": None, "severity":   None,
        "published":  None, "cpe_ranges": [],
        "cwe_id":     None, "cwe_name":   None,
    }

    for attempt in range(1, 4):  # attempts 1, 2, 3
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data     = response.json()
            cve      = data["vulnerabilities"][0]["cve"]

            try:
                cvss_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity   = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            except Exception:
                try:
                    cvss_score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    severity   = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                except Exception:
                    cvss_score = None
                    severity   = None

            cpe_ranges       = extract_cpe_ranges(cve)
            cwe_id, cwe_name = extract_cwe(cve)

            return {
                "cvss_score": cvss_score,
                "severity":   severity,
                "published":  (cve.get("published") or "")[:10] or None,
                "cpe_ranges": cpe_ranges,
                "cwe_id":     cwe_id,
                "cwe_name":   cwe_name,
            }

        except Exception as e:
            if attempt < 3:
                wait = 2 ** attempt  # 2s then 4s
                log.warning("%s attempt %d/3 (waiting %ds): %s", cve_id, attempt + 1, wait, e)
                time.sleep(wait)
            else:
                log.error("%s — all 3 attempts failed: %s", cve_id, e)

    return null_result


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
        log.error("cisa_kev table is empty. Run Step 1 first.")
        return

    if not assets:
        log.error("assets table is empty. Run Asset Monitor first.")
        return

    relevant = [v for v in cisa_data if is_relevant(v, assets)]
    print(f"Relevant CVEs (CISA KEV): {len(relevant)} out of {len(cisa_data)}")

    # For technologies with no CISA KEV coverage, search NVD directly
    uncovered = _get_uncovered_keywords(assets, relevant)
    if uncovered:
        print(f"Technologies not in CISA KEV: {uncovered} — querying NVD directly...")
        existing_ids = {v["cve_id"] for v in relevant}
        for kw in uncovered:
            nvd_hits = fetch_nvd_by_keyword(kw, max_results=100)
            new = [c for c in nvd_hits if c["cve_id"] not in existing_ids]
            if new:
                print(f"  + '{kw}': {len(new)} HIGH/CRITICAL CVEs from NVD")
            else:
                print(f"  + '{kw}': 0 new CVEs")
            relevant.extend(new)
            existing_ids.update(c["cve_id"] for c in new)
            time.sleep(config.NVD_DELAY_WITH_KEY if NVD_API_KEY else 2)

    print(f"Total CVEs to enrich: {len(relevant)}")

    enriched = []
    for i, vuln in enumerate(relevant):
        print(f"Fetching {i+1}/{len(relevant)} - {vuln['cve_id']}")
        nvd  = fetch_nvd_details(vuln["cve_id"])
        epss = fetch_epss(vuln["cve_id"])

        record = {**vuln, **epss,
                  "cvss_score": nvd["cvss_score"],
                  "severity":   nvd["severity"],
                  "published":  nvd["published"],
                  "cpe_ranges": nvd["cpe_ranges"],
                  "cwe_id":     nvd["cwe_id"],
                  "cwe_name":   nvd["cwe_name"]}

        if len(nvd["cpe_ranges"]):
            print(f"  -> {len(nvd['cpe_ranges'])} CPE version range(s) extracted")
        if nvd["cwe_id"]:
            label = f"{nvd['cwe_id']} ({nvd['cwe_name']})" if nvd["cwe_name"] else nvd["cwe_id"]
            print(f"  -> CWE: {label}")

        enriched.append(record)
        time.sleep(config.NVD_DELAY_WITH_KEY if NVD_API_KEY else config.NVD_DELAY_WITHOUT_KEY)

    db_save_enriched_cves(enriched)
    print(f"Saved {len(enriched)} enriched CVEs to DB")


if __name__ == "__main__":
    enrich_cves()
