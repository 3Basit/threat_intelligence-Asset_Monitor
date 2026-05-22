import requests
import requests.adapters
import json
import socket
import subprocess
import shutil
import os
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from datetime import datetime, timezone
from database import (
    save_assets,
    save_asset_services,
    save_asset_technologies,
    save_asset_waf_info
)

NMAP_WEB_PORTS    = "80,443,8080,8443,8000,8888"
SCAN_DELAY_SECONDS = 2  # Polite delay between target scans to avoid crawler detection
USER_AGENT         = "GradProject-AssetMonitor/1.0 (authorized-security-research; contact: security@example.com)"

# ── Phase 3: Technology Signatures ────────────────────────

TECH_SIGNATURES = [
    # ── Web Servers (from Server header) ──────────────────
    {"pattern": r"microsoft-iis/([\d.]+)",     "name": "Microsoft IIS",   "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"apache/([\d.]+)",             "name": "Apache HTTP",     "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"nginx/([\d.]+)",              "name": "nginx",           "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"openresty/([\d.]+)",          "name": "OpenResty",       "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"lighttpd/([\d.]+)",           "name": "Lighttpd",        "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"litespeed",                   "name": "LiteSpeed",       "category": "web_server",           "source": "server_header",  "confidence": "high"},
    {"pattern": r"caddy",                       "name": "Caddy",           "category": "web_server",           "source": "server_header",  "confidence": "high"},

    # ── Languages / Frameworks (from X-Powered-By) ────────
    {"pattern": r"php/([\d.]+)",                "name": "PHP",             "category": "programming_language", "source": "x_powered_by",   "confidence": "high"},
    {"pattern": r"asp\.net",                    "name": "ASP.NET",         "category": "framework",            "source": "x_powered_by",   "confidence": "high"},
    {"pattern": r"express",                     "name": "Express.js",      "category": "framework",            "source": "x_powered_by",   "confidence": "high"},
    {"pattern": r"next\.js",                    "name": "Next.js",         "category": "framework",            "source": "x_powered_by",   "confidence": "high"},

    # ── Frameworks (from extra headers) ───────────────────
    {"pattern": r"laravel",                     "name": "Laravel",         "category": "framework",            "source": "extra_headers",  "confidence": "medium"},
    {"pattern": r"django",                      "name": "Django",          "category": "framework",            "source": "extra_headers",  "confidence": "medium"},
    {"pattern": r"rails",                       "name": "Ruby on Rails",   "category": "framework",            "source": "extra_headers",  "confidence": "medium"},

    # ── CMS (from HTML content) ───────────────────────────
    {"pattern": r"wp-content/",                 "name": "WordPress",       "category": "cms",                  "source": "html_content",   "confidence": "high"},
    {"pattern": r"wp-includes/",                "name": "WordPress",       "category": "cms",                  "source": "html_content",   "confidence": "high"},
    {"pattern": r"/sites/default/files/",       "name": "Drupal",          "category": "cms",                  "source": "html_content",   "confidence": "high"},
    {"pattern": r"drupal\.js",                  "name": "Drupal",          "category": "cms",                  "source": "html_content",   "confidence": "high"},
    {"pattern": r"/media/jui/",                 "name": "Joomla",          "category": "cms",                  "source": "html_content",   "confidence": "high"},
    {"pattern": r"joomla",                      "name": "Joomla",          "category": "cms",                  "source": "html_content",   "confidence": "medium"},

    # ── Meta Generator Tag ────────────────────────────────
    {"pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', "name": None, "category": "cms", "source": "meta_generator", "confidence": "high"},

    # ── JS Libraries (from HTML content) ─────────────────
    {"pattern": r"jquery[./-]([\d.]+)",         "name": "jQuery",          "category": "javascript_library",   "source": "html_content",   "confidence": "high"},
    {"pattern": r"react[./-]([\d.]+)",          "name": "React",           "category": "javascript_library",   "source": "html_content",   "confidence": "medium"},
    {"pattern": r"angular[./-]([\d.]+)",        "name": "Angular",         "category": "javascript_library",   "source": "html_content",   "confidence": "medium"},
    {"pattern": r"vue[./-]([\d.]+)",            "name": "Vue.js",          "category": "javascript_library",   "source": "html_content",   "confidence": "medium"},
    {"pattern": r"bootstrap[./-]([\d.]+)",      "name": "Bootstrap",       "category": "css_framework",        "source": "html_content",   "confidence": "medium"},

    # ── Analytics ─────────────────────────────────────────
    {"pattern": r"google-analytics\.com",       "name": "Google Analytics","category": "analytics",            "source": "html_content",   "confidence": "high"},
    {"pattern": r"gtag\(",                      "name": "Google Tag Manager","category": "analytics",          "source": "html_content",   "confidence": "high"},

    # ── Cookies ───────────────────────────────────────────
    {"pattern": r"phpsessid",                   "name": "PHP",             "category": "programming_language", "source": "cookies",        "confidence": "high"},
    {"pattern": r"asp\.net_sessionid",          "name": "ASP.NET",         "category": "framework",            "source": "cookies",        "confidence": "high"},
    {"pattern": r"jsessionid",                  "name": "Java Servlet",    "category": "framework",            "source": "cookies",        "confidence": "high"},
    {"pattern": r"laravel_session",             "name": "Laravel",         "category": "framework",            "source": "cookies",        "confidence": "high"},
    {"pattern": r"wp-settings",                 "name": "WordPress",       "category": "cms",                  "source": "cookies",        "confidence": "high"},
]

# ── Phase 3: WAF Signatures ────────────────────────────────

WAF_SIGNATURES = [
    {"name": "Cloudflare",    "checks": [
        {"source": "server_header", "pattern": r"cloudflare"},
        {"source": "cookies",       "pattern": r"__cf(uid|_bm|clearance)"},
        {"source": "headers_raw",   "pattern": r"cf-ray"},
        {"source": "html_content",  "pattern": r"cloudflare ray id"},
    ]},
    {"name": "Akamai",        "checks": [
        {"source": "server_header", "pattern": r"akamaighost"},
        {"source": "headers_raw",   "pattern": r"x-akamai"},
        {"source": "headers_raw",   "pattern": r"akamai-grn"},
    ]},
    {"name": "AWS CloudFront","checks": [
        {"source": "headers_raw",   "pattern": r"via.*cloudfront"},
        {"source": "headers_raw",   "pattern": r"x-amz-cf-id"},
    ]},
    {"name": "Sucuri",        "checks": [
        {"source": "headers_raw",   "pattern": r"x-sucuri-id"},
        {"source": "headers_raw",   "pattern": r"x-sucuri-cache"},
    ]},
    {"name": "Incapsula",     "checks": [
        {"source": "headers_raw",   "pattern": r"x-cdn.*incapsula"},
        {"source": "cookies",       "pattern": r"incap_ses|visid_incap"},
    ]},
    {"name": "F5 BIG-IP",     "checks": [
        {"source": "cookies",       "pattern": r"bigipserver"},
        {"source": "server_header", "pattern": r"big-ip"},
    ]},
    {"name": "ModSecurity",   "checks": [
        {"source": "server_header", "pattern": r"mod_security"},
        {"source": "html_content",  "pattern": r"mod_security|modsecurity"},
    ]},
    {"name": "Fastly",        "checks": [
        {"source": "headers_raw",   "pattern": r"x-served-by.*cache"},
        {"source": "headers_raw",   "pattern": r"fastly-restarts"},
    ]},
]

def load_targets():
    with open("targets.json") as f:
        return json.load(f)

def get_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=3)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# ── Phase 1: HTTP Fingerprinting ───────────────────────────

def fingerprint_target(target, session):
    url    = target["url"]
    result = {
        "target_id":          target["target_id"],
        "url":                url,
        "status_code":        None,
        "final_url":          None,
        "title":              None,
        "server":             None,
        "x_powered_by":       None,
        "uses_https":         url.startswith("https"),
        "ip":                 None,
        "response_time_ms":   None,
        "vendor":             None,
        "product":            None,
        "keywords":           [],
        "confidence":         "low",
        "detected_by":        "http_headers",
        "scan_status":        "skipped",
        "error_type":         None,
        "error_message":      None,
        "_response_text":     "",
        "_response_headers":  {},
        "_cookies_str":       "",
        "last_seen":          datetime.now(timezone.utc).isoformat()
    }

    if not target.get("authorized", False):
        print(f"  [SKIP] Skipping {url} - not authorized")
        return result

    headers = {"User-Agent": USER_AGENT}

    try:
        start    = time.time()
        response = session.get(url, headers=headers, timeout=(5, 15), allow_redirects=True)
        elapsed  = round((time.time() - start) * 1000)

        result["scan_status"]       = "success"
        result["status_code"]       = response.status_code
        result["final_url"]         = response.url
        result["server"]            = response.headers.get("Server")
        result["x_powered_by"]      = response.headers.get("X-Powered-By")
        result["uses_https"]        = response.url.startswith("https")
        result["response_time_ms"]  = elapsed
        result["_response_text"]    = response.text[:50000]
        result["_response_headers"] = dict(response.headers)

        cookies_str = " ".join(
            f"{k}={v}" for k, v in response.cookies.items()
        ).lower()
        result["_cookies_str"] = cookies_str

        text = response.text
        if "<title>" in text.lower():
            start_idx = text.lower().find("<title>") + 7
            end_idx   = text.lower().find("</title>")
            if end_idx > start_idx:
                result["title"] = text[start_idx:end_idx].strip()[:100]

        try:
            hostname     = urlparse(url).hostname
            result["ip"] = socket.gethostbyname(hostname)
        except (socket.gaierror, OSError):
            pass  # DNS resolution failed — IP stays None

        server   = result["server"] or ""
        powered  = result["x_powered_by"] or ""
        combined = f"{server} {powered}".lower()

        if "apache" in combined and "tomcat" in combined:
            result["vendor"]     = "Apache"
            result["product"]    = "Tomcat"
            result["keywords"]   = ["tomcat", "apache tomcat"]
            result["confidence"] = "high"
        elif "apache" in combined:
            result["vendor"]     = "Apache"
            result["product"]    = "HTTP Server"
            result["keywords"]   = ["http server", "httpd", "apache httpd"]
            result["confidence"] = "medium"
        elif "nginx" in combined:
            result["vendor"]     = "nginx"
            result["product"]    = "nginx"
            result["keywords"]   = ["nginx"]
            result["confidence"] = "medium"
        elif "iis" in combined or "microsoft" in combined:
            result["vendor"]     = "Microsoft"
            result["product"]    = "IIS"
            result["keywords"]   = ["iis", "microsoft iis"]
            result["confidence"] = "medium"
        elif "php" in combined:
            result["vendor"]     = "PHP"
            result["product"]    = "PHP"
            result["keywords"]   = ["php"]
            result["confidence"] = "low"
        else:
            result["vendor"]     = "Unknown"
            result["product"]    = "Unknown"
            result["keywords"]   = []
            result["confidence"] = "low"

    except requests.exceptions.ConnectTimeout as e:
        result["scan_status"]   = "failed"
        result["error_type"]    = "ConnectTimeout"
        result["error_message"] = str(e)[:200]
        print(f"  [WARN] ConnectTimeout: {url}")

    except requests.exceptions.ConnectionError as e:
        result["scan_status"]   = "failed"
        result["error_type"]    = "ConnectionError"
        result["error_message"] = str(e)[:200]
        print(f"  [WARN] ConnectionError: {url}")

    except Exception as e:
        result["scan_status"]   = "failed"
        result["error_type"]    = type(e).__name__
        result["error_message"] = str(e)[:200]
        print(f"  [WARN] Error: {url} - {e}")

    return result

# ── Phase 2: Nmap Scanning ─────────────────────────────────

def get_nmap_path():
    path = shutil.which("nmap")
    if path:
        return path
    for p in [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.EXE",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.EXE",
    ]:
        if os.path.exists(p):
            return p
    return None

def run_nmap_scan(hostname):
    nmap_path = get_nmap_path()
    print(f"  Using Nmap executable: {nmap_path}")

    if not nmap_path:
        return {"status": "failed", "error": "NmapNotFound", "xml": None}

    try:
        cmd = [nmap_path, "-sV", "-Pn", "-n", "-p", NMAP_WEB_PORTS, hostname, "-oX", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"status": "failed", "error": result.stderr[:200], "xml": None}
        return {"status": "success", "xml": result.stdout}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "NmapTimeout",   "xml": None}
    except FileNotFoundError:
        return {"status": "failed", "error": "NmapNotFound",  "xml": None}
    except Exception as e:
        return {"status": "failed", "error": str(e)[:200],    "xml": None}

def parse_nmap_xml(xml_text):
    empty = {"ip": None, "open_ports": [], "open_services": [], "nmap_ports": [], "services": []}
    if not xml_text:
        return empty
    try:
        root    = ET.fromstring(xml_text)
        host_el = root.find("host")
        if host_el is None:
            return empty

        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break

        open_ports    = []
        open_services = []
        nmap_ports    = []

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_num = int(port_el.get("portid", 0))
                state_el = port_el.find("state")
                state    = state_el.get("state") if state_el is not None else "unknown"

                svc_el   = port_el.find("service")
                svc_name = product = version = ""
                cpe_list = []

                if svc_el is not None:
                    svc_name = svc_el.get("name", "")
                    product  = svc_el.get("product", "")
                    version  = svc_el.get("version", "")
                    cpe_list = [c.text for c in svc_el.findall("cpe") if c.text]

                port_info = {
                    "port": port_num, "state": state,
                    "service_name": svc_name, "product": product,
                    "version": version, "cpe": cpe_list
                }
                nmap_ports.append(port_info)

                if state == "open":
                    open_ports.append(port_num)
                    open_services.append(port_info)

        return {
            "ip":            ip,
            "open_ports":    open_ports,
            "open_services": open_services,
            "nmap_ports":    nmap_ports,
            "services":      open_services
        }
    except ET.ParseError:
        return empty
    except Exception:
        return empty

# ── Phase 3: Technology + WAF Detection ────────────────────

def detect_technologies(result):
    technologies = []
    seen_names   = set()

    def add_tech(name, category, version, source, confidence="medium"):
        key = name.lower() if name else ""
        if key and key not in seen_names:
            seen_names.add(key)
            technologies.append({
                "name":       name,
                "category":   category,
                "version":    version or None,
                "source":     source,
                "confidence": confidence
            })

    server_header  = (result.get("server") or "").lower()
    powered_header = (result.get("x_powered_by") or "").lower()
    html_content   = (result.get("_response_text") or "").lower()
    cookies_str    = result.get("_cookies_str") or ""
    headers_raw    = " ".join(
        f"{k}: {v}" for k, v in (result.get("_response_headers") or {}).items()
    ).lower()
    extra_headers  = headers_raw

    source_map = {
        "server_header": server_header,
        "x_powered_by":  powered_header,
        "html_content":  html_content,
        "cookies":       cookies_str,
        "extra_headers": extra_headers,
        "meta_generator": html_content,
    }

    for sig in TECH_SIGNATURES:
        text    = source_map.get(sig["source"], "")
        pattern = sig["pattern"]
        match   = re.search(pattern, text, re.IGNORECASE)

        if not match:
            continue

        # Meta generator — extract content value as name
        if sig["source"] == "meta_generator":
            raw_name = match.group(1) if match.lastindex else None
            if raw_name:
                name     = raw_name.strip()
                version  = None
                ver_match = re.search(r"([\d.]+)", name)
                if ver_match:
                    version = ver_match.group(1)
                    name    = re.sub(r"\s*[\d.]+.*$", "", name).strip()
                add_tech(name, sig["category"], version, sig["source"], sig["confidence"])
            continue

        name    = sig["name"]
        version = None
        try:
            if match.lastindex and match.group(1):
                version = match.group(1)
        except (IndexError, AttributeError):
            pass  # Regex group not captured — version stays None

        add_tech(name, sig["category"], version, sig["source"], sig["confidence"])

    # Add Nmap open services as technologies
    for svc in result.get("open_services", []):
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product:
            add_tech(product, "network_service", version or None, "nmap", "high")

    return technologies

def detect_waf(result):
    server_header = (result.get("server") or "").lower()
    html_content  = (result.get("_response_text") or "").lower()
    cookies_str   = result.get("_cookies_str") or ""
    headers_raw   = " ".join(
        f"{k}: {v}" for k, v in (result.get("_response_headers") or {}).items()
    ).lower()

    source_map = {
        "server_header": server_header,
        "html_content":  html_content,
        "cookies":       cookies_str,
        "headers_raw":   headers_raw,
    }

    for waf in WAF_SIGNATURES:
        for check in waf["checks"]:
            text = source_map.get(check["source"], "")
            if re.search(check["pattern"], text, re.IGNORECASE):
                return True, waf["name"], check["source"]

    return False, None, None

# ── Snapshot + Change Detection ────────────────────────────

def load_previous_snapshot():
    try:
        with open("previous_assets_snapshot.json") as f:
            return json.load(f)
    except:
        return []

def save_current_snapshot(assets):
    with open("previous_assets_snapshot.json", "w") as f:
        json.dump(assets, f, indent=2)

def detect_service_changes(prev, curr):
    changes = []
    now     = datetime.now(timezone.utc).isoformat()
    url     = curr["url"]
    tid     = curr["target_id"]

    prev_ports = {s["port"]: s for s in prev.get("open_services", [])}
    curr_ports = {s["port"]: s for s in curr.get("open_services", [])}

    for port, svc in curr_ports.items():
        if port not in prev_ports:
            changes.append({"change_type": "NEW_PORT_OPENED", "target_id": tid, "url": url,
                            "old_value": None, "new_value": str(port),
                            "severity": "high", "detected_at": now})
        else:
            prev_svc = prev_ports[port]
            if svc.get("product") != prev_svc.get("product"):
                changes.append({"change_type": "SERVICE_CHANGED", "target_id": tid, "url": url,
                                "old_value": prev_svc.get("product"), "new_value": svc.get("product"),
                                "severity": "high", "detected_at": now})
            elif svc.get("version") != prev_svc.get("version"):
                changes.append({"change_type": "SERVICE_VERSION_CHANGED", "target_id": tid, "url": url,
                                "old_value": prev_svc.get("version"), "new_value": svc.get("version"),
                                "severity": "medium", "detected_at": now})

    for port in prev_ports:
        if port not in curr_ports:
            changes.append({"change_type": "PORT_CLOSED", "target_id": tid, "url": url,
                            "old_value": str(port), "new_value": None,
                            "severity": "medium", "detected_at": now})
    return changes

def detect_changes(previous, current):
    changes  = []
    prev_map = {a["target_id"]: a for a in previous}
    curr_map = {a["target_id"]: a for a in current}
    now      = datetime.now(timezone.utc).isoformat()

    for tid, curr in curr_map.items():
        if curr["scan_status"] == "failed":
            changes.append({"change_type": "SCAN_FAILED", "target_id": tid, "url": curr["url"],
                            "old_value": None, "new_value": curr["error_type"],
                            "severity": "medium", "detected_at": now})
            continue

        if tid not in prev_map:
            changes.append({"change_type": "NEW_ASSET", "target_id": tid, "url": curr["url"],
                            "old_value": None, "new_value": f"{curr['vendor']} {curr['product']}",
                            "severity": "high", "detected_at": now})
            continue

        prev = prev_map[tid]

        if prev.get("scan_status") == "failed" and curr["scan_status"] == "success":
            changes.append({"change_type": "SCAN_RECOVERED", "target_id": tid, "url": curr["url"],
                            "old_value": "failed", "new_value": f"{curr['vendor']} {curr['product']}",
                            "severity": "low", "detected_at": now})

        if curr["vendor"] != prev["vendor"] or curr["product"] != prev["product"]:
            changes.append({"change_type": "TECHNOLOGY_CHANGED", "target_id": tid, "url": curr["url"],
                            "old_value": f"{prev['vendor']} {prev['product']}",
                            "new_value": f"{curr['vendor']} {curr['product']}",
                            "severity": "high", "detected_at": now})

        if curr["status_code"] != prev["status_code"]:
            changes.append({"change_type": "STATUS_CODE_CHANGED", "target_id": tid, "url": curr["url"],
                            "old_value": str(prev["status_code"]), "new_value": str(curr["status_code"]),
                            "severity": "medium", "detected_at": now})

        if curr["server"] != prev["server"]:
            changes.append({"change_type": "SERVER_HEADER_CHANGED", "target_id": tid, "url": curr["url"],
                            "old_value": prev["server"], "new_value": curr["server"],
                            "severity": "medium", "detected_at": now})

        if curr["ip"] != prev["ip"] and prev["ip"] is not None:
            changes.append({"change_type": "IP_CHANGED", "target_id": tid, "url": curr["url"],
                            "old_value": prev["ip"], "new_value": curr["ip"],
                            "severity": "high", "detected_at": now})

        if curr["uses_https"] != prev["uses_https"]:
            changes.append({"change_type": "HTTPS_CHANGED", "target_id": tid, "url": curr["url"],
                            "old_value": str(prev["uses_https"]), "new_value": str(curr["uses_https"]),
                            "severity": "medium", "detected_at": now})

        # Technology-level change detection
        prev_techs = set(t["name"] for t in prev.get("technologies", []))
        curr_techs = set(t["name"] for t in curr.get("technologies", []))

        for added in curr_techs - prev_techs:
            changes.append({"change_type": "TECHNOLOGY_ADDED", "target_id": tid, "url": curr["url"],
                            "old_value": None, "new_value": added,
                            "severity": "medium", "detected_at": now})

        for removed in prev_techs - curr_techs:
            changes.append({"change_type": "TECHNOLOGY_REMOVED", "target_id": tid, "url": curr["url"],
                            "old_value": removed, "new_value": None,
                            "severity": "medium", "detected_at": now})

        changes.extend(detect_service_changes(prev, curr))

    for tid in prev_map:
        if tid not in curr_map:
            changes.append({"change_type": "ASSET_REMOVED", "target_id": tid,
                            "url": prev_map[tid]["url"],
                            "old_value": f"{prev_map[tid]['vendor']} {prev_map[tid]['product']}",
                            "new_value": None, "severity": "critical", "detected_at": now})

    return changes

# ── Export ─────────────────────────────────────────────────

def export_assets_json(current_assets, targets):
    target_map = {t["target_id"]: t for t in targets}
    assets     = []
    failed     = []

    for a in current_assets:
        if a["scan_status"] == "failed":
            failed.append({
                "target_id":     a["target_id"],
                "url":           a["url"],
                "error_type":    a["error_type"],
                "error_message": a["error_message"],
                "last_seen":     a["last_seen"]
            })
            continue

        if a["confidence"] not in {"medium", "high"}:
            continue

        asset_id = a["target_id"].replace("TARGET", "ASSET")

        # Use hostname as asset_name — page titles are unreliable
        # (login pages, error pages, etc. produce meaningless names)
        parsed_url  = urlparse(a["url"])
        asset_label = parsed_url.hostname or a["url"]

        assets.append({
            "asset_id":             asset_id,
            "asset_name":           asset_label,
            "asset_type":           "web_application",
            "business_criticality": target_map.get(a["target_id"], {}).get("business_criticality", "medium"),
            "vendor":               a["vendor"],
            "product":              a["product"],
            "keywords":             a["keywords"],
            "url":                  a["url"],
            "ip":                   a["ip"],
            "open_ports":           a.get("open_ports", []),
            "open_services":        a.get("open_services", []),
            "technologies":         a.get("technologies", []),
            "is_behind_waf":        a.get("is_behind_waf", False),
            "waf_name":             a.get("waf_name"),
            "confidence":           a["confidence"],
            "detected_by":          a["detected_by"]
        })

    with open("assets.json", "w") as f:
        json.dump(assets, f, indent=2)

    with open("failed_targets.json", "w") as f:
        json.dump(failed, f, indent=2)

    save_assets(assets)
    return assets, failed

# ── Main ───────────────────────────────────────────────────

def run_monitor():
    print("=" * 50)
    print("Asset Monitor - Starting scan...")
    print("Note: Only authorized targets will be scanned.")
    print("=" * 50)

    targets        = load_targets()
    previous       = load_previous_snapshot()
    current_assets = []
    session        = get_session()

    for i, target in enumerate(targets):
        if i > 0:
            delay = target.get("scan_delay_seconds", SCAN_DELAY_SECONDS)
            print(f"  [Rate-limit] Waiting {delay}s before next target...")
            time.sleep(delay)
        print(f"\nScanning {target['url']}...")

        # Phase 1 — HTTP Fingerprinting
        result = fingerprint_target(target, session)

        # Phase 2 — Nmap
        result["nmap_scan_status"] = "skipped"
        result["open_ports"]       = []
        result["open_services"]    = []
        result["nmap_ports"]       = []
        result["services"]         = []

        if result["scan_status"] == "success":
            hostname = urlparse(target["url"]).hostname
            print(f"  Running Nmap on {hostname}...")
            nmap_result = run_nmap_scan(hostname)

            if nmap_result["status"] == "success":
                parsed = parse_nmap_xml(nmap_result["xml"])
                result["nmap_scan_status"] = "success"
                result["open_ports"]       = parsed["open_ports"]
                result["open_services"]    = parsed["open_services"]
                result["nmap_ports"]       = parsed["nmap_ports"]
                result["services"]         = parsed["services"]
                if parsed["ip"] and not result["ip"]:
                    result["ip"] = parsed["ip"]
            else:
                result["nmap_scan_status"] = "failed"
                print(f"  [WARN] Nmap failed: {nmap_result['error']}")

        # Phase 3 — Technology + WAF Detection
        result["tech_detection_status"] = "skipped"
        result["technologies"]           = []
        result["is_behind_waf"]          = False
        result["waf_name"]               = None

        if result["scan_status"] == "success":
            result["technologies"]           = detect_technologies(result)
            result["tech_detection_status"]  = "success"

            is_waf, waf_name, waf_detected_by = detect_waf(result)
            result["is_behind_waf"] = is_waf
            result["waf_name"]      = waf_name

        current_assets.append(result)

        open_services = result.get("open_services", [])
        techs         = result.get("technologies", [])

        print(f"  -> Vendor:             {result['vendor']}")
        print(f"  -> Product:            {result['product']}")
        print(f"  -> Status:             {result['status_code']}")
        print(f"  -> IP:                 {result['ip']}")
        print(f"  -> Server:             {result['server']}")
        print(f"  -> Confidence:         {result['confidence']}")
        print(f"  -> Scan status:        {result['scan_status']}")
        print(f"  -> Nmap status:        {result['nmap_scan_status']}")
        print(f"  -> Open ports:         {result['open_ports']}")
        print(f"  -> Open services:      {len(open_services)}")
        if open_services:
            first = open_services[0]
            print(f"  -> First open service: {first.get('product','')} {first.get('version','')} (port {first.get('port','')})")
        print(f"  -> Tech detection:     {result['tech_detection_status']}")
        print(f"  -> Technologies found: {len(techs)}")
        if techs:
            for t in techs[:3]:
                print(f"     • {t['name']} ({t['category']}) [{t['confidence']}] via {t['source']}")
        print(f"  -> WAF detected:       {result['is_behind_waf']} {('(' + result['waf_name'] + ')') if result['waf_name'] else ''}")

    changes = detect_changes(previous, current_assets)

    # Remove internal fields before saving snapshot
    snapshot = []
    for a in current_assets:
        clean = {k: v for k, v in a.items() if not k.startswith("_")}
        snapshot.append(clean)

    with open("current_assets_snapshot.json", "w") as f:
        json.dump(snapshot, f, indent=2)

    with open("asset_changes.json", "w") as f:
        json.dump(changes, f, indent=2)

    save_current_snapshot(snapshot)

    assets, failed = export_assets_json(current_assets, targets)

    # Save to DB
    for a in current_assets:
        asset_id = a["target_id"].replace("TARGET", "ASSET")

        if a["nmap_scan_status"] == "success" and a["open_services"]:
            save_asset_services(asset_id, a["open_services"])

        if a["tech_detection_status"] == "success" and a["technologies"]:
            save_asset_technologies(asset_id, a["technologies"])

        if a["scan_status"] == "success":
            save_asset_waf_info(
                asset_id,
                a["is_behind_waf"],
                a["waf_name"],
                "signature_detection"
            )

    print(f"\n{'=' * 50}")
    print(f"Total scanned:     {len(current_assets)}")
    print(f"Changes detected:  {len(changes)}")
    print(f"Exported assets:   {len(assets)}")
    print(f"Failed targets:    {len(failed)}")

    if changes:
        print("\nChanges:")
        for c in changes:
            print(f"  [{c['severity'].upper()}] {c['change_type']} | {c['url']}")
            print(f"         {c['old_value']} -> {c['new_value']}")

    print("=" * 50)
    print("Asset Monitor - Done!")

if __name__ == "__main__":
    run_monitor()