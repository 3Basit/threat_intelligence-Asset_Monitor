import json
import re

from logger import get_logger
from database import (
    get_enriched_cves,
    get_assets,
    get_asset_services,
    get_exploitdb_info,
    save_matched_cves as db_save_matched_cves
)
from mitre_attack import get_attack_mapping

log = get_logger("matching")

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
    cve_vendor = (cve.get("vendor") or "").lower()
    asset_vendor = (asset.get("vendor") or "").lower()
    cve_product = (cve.get("product") or "").lower()
    vendor_match = cve_vendor and asset_vendor and cve_vendor == asset_vendor
    product_match = any(
        kw.lower() in cve_product
        for kw in asset.get("keywords", [])
        if len(kw) >= 3
    )
    return "high" if (vendor_match and product_match) else "low"


# ── CPE Version Matching ──────────────────────────────────────

def parse_version(version_str):
    """Parse version string into comparable tuple. e.g. '1.20.1' → (1, 20, 1)"""
    if not version_str:
        return None
    try:
        parts = []
        for x in version_str.split(".")[:4]:
            digits = ""
            for ch in x:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if digits:
                parts.append(int(digits))
        return tuple(parts) if parts else None
    except Exception:
        return None


def extract_cpe_version(criteria):
    """
    Extract the version component from a CPE 2.3 string.
    e.g. 'cpe:2.3:a:microsoft:internet_information_services:6.0:*:*:*:*:*:*:*' -> '6.0'
    Returns None if the version field is a wildcard ('*') or absent.
    """
    if not criteria:
        return None
    try:
        parts = criteria.split(":")
        # CPE 2.3 format: cpe : 2.3 : type : vendor : product : version : ...
        #                  [0]   [1]   [2]    [3]       [4]        [5]
        if len(parts) >= 6:
            version = parts[5]
            if version and version not in ("*", "-", ""):
                return version
    except Exception:
        pass
    return None


def version_in_cpe_range(detected_version, cpe_range):
    """
    Return True if detected_version falls within a single CPE range dict.

    Two cases handled:
    1. Range with boundaries (versionStart/versionEnd): standard range check.
    2. No boundaries but a specific version in the criteria string:
       detected version must EXACTLY match the CPE version.
       If the criteria version is a wildcard ('*') or absent: cannot confirm.
    """
    detected = parse_version(detected_version)
    if not detected:
        return False

    has_boundaries = any([
        cpe_range.get("version_start_including"),
        cpe_range.get("version_start_excluding"),
        cpe_range.get("version_end_including"),
        cpe_range.get("version_end_excluding"),
    ])

    if not has_boundaries:
        # No version range -- check the exact version encoded in the CPE criteria.
        # e.g. cpe:2.3:a:microsoft:internet_information_services:6.0:* -> exact 6.0
        cpe_exact = extract_cpe_version(cpe_range.get("criteria", ""))
        if cpe_exact:
            return parse_version(cpe_exact) == detected
        # Wildcard version in CPE and no boundaries -- cannot confirm.
        return False

    start_inc = parse_version(cpe_range.get("version_start_including"))
    if start_inc and detected < start_inc:
        return False

    start_exc = parse_version(cpe_range.get("version_start_excluding"))
    if start_exc and detected <= start_exc:
        return False

    end_inc = parse_version(cpe_range.get("version_end_including"))
    if end_inc and detected > end_inc:
        return False

    end_exc = parse_version(cpe_range.get("version_end_excluding"))
    if end_exc and detected >= end_exc:
        return False

    return True


def check_version_confirmed(cve, asset_id):
    """
    Two-pass version confirmation:

    Pass 1 -- CPE ranges from NVD (structured, high confidence)
               confirmation_method = "cpe_range"

    Pass 2 -- Text search in CVE description (fallback, medium confidence)
               confirmation_method = "text_search"

    No match -> version_confirmed=False, confirmation_method="none"

    Returns (version_confirmed, detected_version, confirmation_method, cpe_range_matched)
    cpe_range_matched is the specific NVD CPE range dict that confirmed the version, or None.
    """
    services = get_asset_services(asset_id)
    if not services:
        return False, None, "none", None

    detected_version = None
    for svc in services:
        if svc.get("version"):
            detected_version = svc["version"]
            break

    if not detected_version:
        return False, None, "none", None

    # -- Pass 1: CPE ranges (high confidence) ---------
    cpe_ranges = cve.get("cpe_ranges", [])
    if cpe_ranges:
        # Only check CPE ranges whose criteria matches the detected product.
        # CVE configurations often bundle OS/platform CPEs (Ubuntu, Debian, Xcode)
        # alongside the actual product CPE. Comparing a software version like
        # nginx 1.20.1 against an Apple Xcode range like <13.0 is a false positive.
        asset_keywords = [
            kw.lower()
            for svc in services
            for kw in ([svc.get("product", ""), svc.get("service_name", "")])
            if kw
        ]
        def _criteria_matches_product(criteria):
            """Return True only if the CPE vendor or product field matches
            the detected asset technology.

            CPE 2.3 format: cpe:2.3:<type>:<vendor>:<product>:<version>:...
            We check fields [3] (vendor) and [4] (product) specifically,
            NOT a substring anywhere in the full criteria string.

            This prevents false positives where a CVE affecting F5 BIG-IP
            (which embeds nginx as a module) has a CPE like:
              cpe:2.3:a:f5:big-ip_...:8.3:...
            that does NOT contain "nginx" in vendor/product fields.
            """
            c = criteria.lower()
            # Skip OS-type CPEs (:o:) entirely
            if ":o:" in c:
                return False
            # Parse CPE: cpe : 2.3 : type : vendor : product : version : ...
            #             [0]   [1]   [2]    [3]       [4]       [5]
            parts = c.split(":")
            if len(parts) >= 5:
                cpe_vendor  = parts[3]
                cpe_product = parts[4]
                return any(
                    kw in cpe_vendor or kw in cpe_product
                    for kw in asset_keywords if len(kw) > 2
                )
            # Fallback for malformed CPE strings
            return any(kw in c for kw in asset_keywords if len(kw) > 2)

        product_ranges = [r for r in cpe_ranges if _criteria_matches_product(r.get("criteria", ""))]

        if not product_ranges:
            # No CPE ranges match this product — cannot confirm via CPE.
            # Do NOT fall back to unrelated CPE ranges (e.g., zzcms, pascom)
            # whose version numbers are incompatible with the detected software.
            # Fall through to Pass 2 (text search) below.
            pass
        else:
            for cpe_range in product_ranges:
                if version_in_cpe_range(detected_version, cpe_range):
                    return True, detected_version, "cpe_range", cpe_range
            # Product-specific CPE ranges exist but version NOT in any range → definitive no
            return False, detected_version, "none", None

    # -- Pass 2: Text search (medium confidence fallback) --
    # Only used when NVD has no structured CPE ranges for this CVE
    desc_text = (
        f"{cve.get('description', '')} {cve.get('product', '')}"
    ).lower()

    escaped = re.escape(detected_version)
    if re.search(r'(?<!\d)' + escaped + r'(?!\d)', desc_text):
        return True, detected_version, "text_search", None

    major_minor = ".".join(detected_version.split(".")[:2])
    if major_minor and len(major_minor) >= 3:
        escaped_mm = re.escape(major_minor)
        if re.search(r'(?<!\d)' + escaped_mm + r'(?!\d)', desc_text):
            return True, detected_version, "text_search", None

    return False, detected_version, "none", None


def run_matching():
    cves   = get_enriched_cves()
    assets = get_assets()

    if not cves:
        log.error("enriched_cves table empty. Run Step 2 first.")
        return
    if not assets:
        log.error("assets table empty. Run Asset Monitor first.")
        return

    web_assets = [a for a in assets if is_web_asset(a)]
    matched    = []
    review     = []
    seen       = set()

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

            # -- Version confirmation (CPE-first) ------
            version_confirmed, detected_version, confirmation_method, cpe_range_matched = (
                check_version_confirmed(cve, asset["asset_id"])
            )

            # NVD keyword-search CVEs (date_added=None, not in CISA KEV) are only
            # included if version is confirmed. Without confirmation they are noise:
            # old CVEs from 2009-2014 match the "nginx" keyword but clearly don't
            # affect nginx 1.18.0 (released 2020).
            in_cisa_kev = cve.get("date_added") is not None
            if not in_cisa_kev and not version_confirmed:
                review.append(cve["cve_id"])
                continue

            # -- Exploit-DB lookup ---------------------
            exploit_info = get_exploitdb_info(cve["cve_id"])
            vuln_type = detect_vuln_type(cve["description"])

            # Build human-readable CPE range summary for transparency
            cpe_range_summary = None
            if cpe_range_matched:
                parts = []
                if cpe_range_matched.get("version_start_including"):
                    parts.append(f">={cpe_range_matched['version_start_including']}")
                if cpe_range_matched.get("version_start_excluding"):
                    parts.append(f">{cpe_range_matched['version_start_excluding']}")
                if cpe_range_matched.get("version_end_including"):
                    parts.append(f"<={cpe_range_matched['version_end_including']}")
                if cpe_range_matched.get("version_end_excluding"):
                    parts.append(f"<{cpe_range_matched['version_end_excluding']}")
                cpe_range_summary = " ".join(parts) if parts else (
                    "exact:" + (extract_cpe_version(cpe_range_matched.get("criteria", "")) or "*")
                )
                print(f"    [CPE MATCH] {cve['cve_id']} v{detected_version} == cpe_exact: {cpe_range_summary}")

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
                "vuln_type":            vuln_type,
                "scope":                "web",
                "source":               "CISA_KEV + NVD + EPSS + ExploitDB",
                "version_confirmed":    version_confirmed,
                "detected_version":     detected_version,
                "confirmation_method":  confirmation_method,
                "cpe_range_matched":    cpe_range_summary,
                "has_public_exploit":   exploit_info["has_public_exploit"],
                "exploit_count":        exploit_info["exploit_count"],
                "exploit_ids":          exploit_info["exploit_ids"],
                "cwe_id":               cve.get("cwe_id"),
                "cwe_name":             cve.get("cwe_name"),
                **{f"attack_{k}": v for k, v in get_attack_mapping(
                    vuln_type
                ).items()},
            })

    db_save_matched_cves(matched)

    confirmed     = sum(1 for m in matched if m["version_confirmed"])
    cpe_confirmed = sum(1 for m in matched if m["confirmation_method"] == "cpe_range")
    txt_confirmed = sum(1 for m in matched if m["confirmation_method"] == "text_search")
    with_exploits = sum(1 for m in matched if m["has_public_exploit"])

    print(f"Total matched   (high confidence):  {len(matched)}")
    print(f"Version confirmed:                  {confirmed}")
    print(f"  +- via CPE ranges (high):         {cpe_confirmed}")
    print(f"  +- via text search (medium):      {txt_confirmed}")
    print(f"With public exploits (Exploit-DB):  {with_exploits}")
    print(f"Total review    (low confidence):   {len(review)}")


if __name__ == "__main__":
    run_matching()
