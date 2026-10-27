#!/usr/bin/env python3
"""
asset-audit — external audit scanner for domains you OWN.

Passive, GET-only external surface review:
  inventory -> fingerprint -> version-confirmed CVE mapping -> config exposure -> report

NO exploitation, NO payloads, NO data dumping. GET requests to check reachability,
headers, and publicly-readable misconfigurations only.

Zero third-party dependencies (stdlib only).

Authorization gate: refuses to run without --authorize "<your attestation>".
"""

import argparse
import concurrent.futures
import datetime
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

UA = "asset-audit/1.0 (+authorized-scan)"
UA_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36"
TIMEOUT = 12

# ----------------------------------------------------------------------------
# CVE knowledge base: manually curated, version-range based.
# Matching rule (0-false-positive discipline):
#   CONFIRMED  -> detected version is inside [affected_from, affected_to]
#   SUSPECTED  -> software detected but version unknown
# Everything else is ignored (never reported).
# ----------------------------------------------------------------------------
CVE_MAP = {
    "wordpress": [
        {"cve": "CVE-2017-5487", "name": "WP REST API user enumeration",
         "from": "1.0", "to": "4.7.1", "sev": "MEDIUM"},
        {"cve": "CVE-2019-8942", "name": "WP core stored XSS via post slugs",
         "from": "1.0", "to": "5.0.0", "sev": "MEDIUM"},
        {"cve": "CVE-2019-8943", "name": "WP core directory traversal (media delete)",
         "from": "1.0", "to": "5.0.0", "sev": "HIGH"},
        {"cve": "CVE-2016-10033", "name": "PHPMailer RCE (bundled < WP 4.7.1)",
         "from": "1.0", "to": "4.7.0", "sev": "CRITICAL"},
        {"cve": "CVE-2015-5714", "name": "WP core XSS via shortcode",
         "from": "1.0", "to": "4.3.1", "sev": "MEDIUM"},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600", "name": "Drupalgeddon2 — RCE",
         "from": "6.0", "to": "8.5.0", "sev": "CRITICAL"},
        {"cve": "CVE-2018-7602", "name": "Drupalgeddon3 — RCE",
         "from": "7.0", "to": "8.5.5", "sev": "CRITICAL"},
        {"cve": "CVE-2019-6340", "name": "Drupal core RCE via REST",
         "from": "8.0", "to": "8.6.9", "sev": "CRITICAL"},
    ],
    "joomla": [
        {"cve": "CVE-2015-8562", "name": "Joomla PHP object injection RCE",
         "from": "1.5", "to": "3.4.5", "sev": "CRITICAL"},
        {"cve": "CVE-2023-23752", "name": "Joomla unauth info disclosure",
         "from": "1.0", "to": "4.2.7", "sev": "HIGH"},
    ],
    "nginx": [
        {"cve": "CVE-2017-7529", "name": "nginx integer overflow info disclosure",
         "from": "1.0", "to": "1.13.2", "sev": "MEDIUM"},
        {"cve": "CVE-2021-23017", "name": "nginx DNS resolver off-by-one RCE",
         "from": "0.6.18", "to": "1.21.0", "sev": "HIGH"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "name": "Apache path traversal/RCE (2.4.49)",
         "from": "2.4.49", "to": "2.4.49", "sev": "CRITICAL"},
        {"cve": "CVE-2021-42013", "name": "Apache path traversal/RCE (2.4.50)",
         "from": "2.4.50", "to": "2.4.50", "sev": "CRITICAL"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "name": "PHP-FPM underflow RCE",
         "from": "7.1", "to": "7.3.10", "sev": "CRITICAL"},
        {"cve": "CVE-2024-4577", "name": "PHP-CGI argument injection RCE",
         "from": "5.0", "to": "8.3.7", "sev": "CRITICAL"},
    ],
    "tomcat": [
        {"cve": "CVE-2017-12615", "name": "Tomcat PUT RCE",
         "from": "7.0.0", "to": "8.5.22", "sev": "CRITICAL"},
        {"cve": "CVE-2020-1938", "name": "Ghostcat — AJP file read",
         "from": "6.0", "to": "9.0.30", "sev": "HIGH"},
    ],
    "express": [
        {"cve": "CVE-2024-29041", "name": "Express open redirect via res.location/res.redirect",
         "from": "4.0.0", "to": "4.19.1", "sev": "MEDIUM"},
        {"cve": "CVE-2024-43796", "name": "Express XSS via response.redirect",
         "from": "4.0.0", "to": "4.20.0", "sev": "MEDIUM"},
    ],
    "nextjs": [
        {"cve": "CVE-2024-34351", "name": "Next.js SSRF via Server Actions",
         "from": "10.0.0", "to": "14.1.1", "sev": "HIGH"},
        {"cve": "CVE-2025-29927", "name": "Next.js middleware auth bypass (x-middleware-subrequest)",
         "from": "10.0.0", "to": "14.2.24", "sev": "HIGH"},
    ],
}

CONFIG_PROBES = [
    ("/.git/HEAD", "exposed .git directory (source disclosure)", lambda b: b.startswith("ref:")),
    ("/.env", "exposed .env file (credential disclosure)", lambda b: "=" in b and ("KEY" in b.upper() or "PASS" in b.upper())),
    ("/wp-config.php.bak", "WordPress config backup exposed", lambda b: "DB_" in b),
    ("/.htaccess.bak", "htaccess backup exposed", lambda b: "Rewrite" in b or "Auth" in b),
    ("/backup.zip", "backup archive in webroot", lambda b: b[:2] == "PK"),
    ("/server-status", "Apache server-status exposed", lambda b: "Apache Status" in b or "<title>Apache" in b),
]

# ------------------------------------------------------- NVD 2.0 enrichment ---
# Optional. --nvd enriches findings with live NVD data (rate-limited, cached).
# Cached per-CVE in nvd-cache.json next to this script; offline-safe (cache-first).

NVD_CACHE_FILE = None  # set in main()


def nvd_lookup(cve_id, cache):
    if cve_id in cache:
        return cache[cve_id]
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT * 2) as r:
            data = json.load(r)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            cache[cve_id] = {"error": "not found in NVD"}
            return cache[cve_id]
        v = vulns[0]["cve"]
        metrics = v.get("metrics", {})
        entry = {
            "published": v.get("published", ""),
            "lastModified": v.get("lastModified", ""),
            "description": next((d["value"] for d in v.get("descriptions", [])
                                 if d["lang"] == "en"), "")[:300],
        }
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                entry["cvss"] = m["cvssData"].get("baseScore")
                entry["cvss_vector"] = m["cvssData"].get("vectorString", "")
                entry["cvss_severity"] = m["cvssData"].get("baseSeverity", "")
                break
        refs = [r["url"] for r in v.get("references", [])][:3]
        entry["references"] = refs
        cache[cve_id] = entry
        return entry
    except Exception as e:
        return {"error": f"NVD lookup failed: {e}"}

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-content-type-options", "x-frame-options",
                    "referrer-policy", "permissions-policy"]

# ---------------------------------------------------------------- helpers ----

def log(msg):
    print(msg, file=sys.stderr, flush=True)


def parse_version(s):
    """'4.2.1' -> (4,2,1); returns None if unparseable."""
    m = re.match(r"(\d+(?:\.\d+){0,3})", s or "")
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def vpad(v, n):
    v = list(v) + [0] * (n - len(v))
    return tuple(v[:n])


def in_range(version, lo, hi):
    v = parse_version(version)
    if v is None:
        return False
    n = max(len(v), 3)
    vlo, vhi = parse_version(lo), parse_version(hi)
    v, vlo, vhi = vpad(v, n), vpad(vlo, n), vpad(vhi, n)
    return vlo <= v <= vhi

# ------------------------------------------------------------------ stages ---

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def fetch(url, method="GET", max_bytes=400_000, browser_ua=False):
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": UA_BROWSER if browser_ua else UA,
                                          "Accept": "*/*"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        body = r.read(max_bytes)
        return r.status, dict(r.headers), body


def probe_host(host):
    """Return best base URL + HTTP info or None. Accepts host or host:port."""
    hostpart, port = host, None
    if ":" in host:
        hostpart, port_s = host.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
            host = hostpart
    ip = resolve(hostpart)
    result = {"host": host, "ip": ip}
    if not ip:
        result["error"] = "DNS resolution failed"
        return result
    schemes = ("https", "http")
    if port:
        urls = [f"{s}://{host}:{port}" for s in schemes]
    else:
        urls = [f"{s}://{host}" for s in schemes]
    for url in urls:
        try:
            status, headers, body = fetch(url)
            result.update(base_url=url, status=status,
                          headers={k.lower(): v for k, v in headers.items()},
                          body_head=body[:20000].decode("utf-8", "replace"),
                          tls=url.startswith("https"))
            return result
        except urllib.error.HTTPError as e:
            # server exists but errored — still usable at 4xx
            result.update(base_url=url, status=e.code,
                          headers={k.lower(): v for k, v in e.headers.items()},
                          body_head=e.read(20000).decode("utf-8", "replace"),
                          tls=url.startswith("https"))
            return result
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError):
            continue
    result["error"] = "no HTTP/HTTPS listener reachable"
    return result


def fingerprint(info):
    """Extract software+version signals from headers/body. Returns dict name->version|None."""
    found = {}
    headers = info.get("headers", {})
    body = info.get("body_head", "")

    # server header
    server = headers.get("server", "")
    for m in re.finditer(r"(nginx|apache|tomcat|jetty|iis)[/-]([\d.]+)?", server, re.I):
        found[m.group(1).lower()] = m.group(2)

    xpowered = headers.get("x-powered-by", "")
    m = re.search(r"PHP[/ ]([\d.]+)", xpowered, re.I)
    if m:
        found["php"] = m.group(1)
    m = re.search(r"ASP\.NET/?([\d.]+)?", xpowered, re.I)
    if m:
        found["aspnet"] = m.group(1)

    # generator meta (CMS)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
    if m:
        gen = m.group(1)
        for name in ("wordpress", "drupal", "joomla"):
            if name in gen.lower():
                vm = re.search(r"([\d.]+)", gen)
                found[name] = vm.group(1) if vm else None

    # node/express family — headers first
    if headers.get("x-powered-by", "").lower().startswith("express"):
        found["express"] = None
    # X-Recruiting is a distinctive Express-app tell (JS apps often set it)
    if "x-recruiting" in headers:
        found.setdefault("express", None)
    # runtime tells: ETag format, x-request-id style
    etag = headers.get("etag", "")
    if re.match(r'^W/"[a-f0-9]{15,}"$', etag) or headers.get("x-runtime"):
        found.setdefault("express", None)

    # SPA frameworks — script/link markers in body
    spa_markers = {
        "angular": (r'(ng-app|ng-version="([\d.]+)"|_nghost|angular\.min\.js)', "angular"),
        "nextjs": (r'(/_next/static|__NEXT_DATA__)', "nextjs"),
        "nuxt": (r'(/_nuxt/|__NUXT__)', "nuxt"),
        "react": (r'(data-reactroot|react(-dom)?\.production\.min\.js|_reactListening)', "react"),
        "vue": (r'(data-v-app|vue\.runtime|vue\.(global|prod))', "vue"),
    }
    for key, (pat, name) in spa_markers.items():
        m = re.search(pat, body, re.I)
        if m:
            ver = None
            for g in reversed(m.groups() or []):
                if g and g[0].isdigit():
                    ver = g
                    break
            found[key] = ver

    # wordpress tells even without generator
    if "wp-content" in body or "wp-json" in body:
        found.setdefault("wordpress", None)

    # RSS feed version (WP discloses there when meta stripped)
    if "wordpress" in found and not found.get("wordpress"):
        try:
            st, hd, bd = fetch(info["base_url"] + "/feed/")
            txt = bd.decode("utf-8", "replace")
            m = re.search(r"<generator>https://wordpress\.org/\?v=([\d.]+)</generator>", txt)
            if m:
                found["wordpress"] = m.group(1)
        except Exception:
            pass

    # WP version fallbacks (added after real-world run 2026-10-26):
    # 1. /readme.html — ships with core, prints "Version X.Y" in big header
    # 2. /wp-links-opml.php — <generator> tag unless muted by header() strip
    # 3. /?feed=rss2 — same generator as /feed/ but different code path
    if "wordpress" in found and not found.get("wordpress"):
        for path, pat in (
            # readme.html: real version sits in the <title>/logo area as "WordPress X.Y";
            # plain "Version" strings appear in upgrade instructions WITHOUT a number.
            # Cloudflare-fronted sites (bondhalbert) 403 the audit UA — use browser UA.
            ("/readme.html", r"<title>WordPress\s+(\d+\.\d+(?:\.\d+)?)"),
            ("/wp-links-opml.php", r"generator=([\d.]+)"),
            ("/?feed=rss2", r"wordpress\.org/\?v=([\d.]+)"),
        ):
            try:
                st, hd, bd = fetch(info["base_url"] + path, max_bytes=60_000, browser_ua=True)
                txt = bd.decode("utf-8", "replace")
                m = re.search(pat, txt)
                if m:
                    found["wordpress"] = m.group(1)
                    break
            except Exception:
                continue
        # fallback 1: readme.html (version in h1/h2)
        if not found.get("wordpress"):
            try:
                st, hd, bd = fetch(info["base_url"] + "/readme.html")
                txt = bd.decode("utf-8", "replace")
                m = re.search(r"Version ([\d.]+)", txt)
                if m:
                    found["wordpress"] = m.group(1)
            except Exception:
                pass
        # fallback 2: wp-links-opml.php (generator attr)
        if not found.get("wordpress"):
            try:
                st, hd, bd = fetch(info["base_url"] + "/wp-links-opml.php")
                txt = bd.decode("utf-8", "replace")
                m = re.search(r'generator="wordpress/([\d.]+)"', txt, re.I)
                if m:
                    found["wordpress"] = m.group(1)
            except Exception:
                pass
        # fallback 3: ?feed=rss2 with different generator format
        if not found.get("wordpress"):
            try:
                st, hd, bd = fetch(info["base_url"] + "/?feed=rss2")
                txt = bd.decode("utf-8", "replace")
                m = re.search(r'v=([\d.]+)</generator>', txt)
                if m:
                    found["wordpress"] = m.group(1)
            except Exception:
                pass

    # Node/Express/SPA fallback: fetch a likely JS bundle and look for framework signatures
    if not any(k in found for k in ("express", "angular", "nextjs", "nuxt", "react", "vue")):
        m = re.search(r'<script[^>]+src=["\']([^"\']+\.js)["\']', body)
        if m:
            try:
                src = m.group(1)
                url = src if src.startswith("http") else info["base_url"] + "/" + src.lstrip("/")
                st, hd, bd = fetch(url, max_bytes=1_500_000)
                txt = bd.decode("utf-8", "replace")[:500_000]
                if re.search(r'AngularJS? v?([\d.]+)|ng version', txt):
                    vm = re.search(r'AngularJS? v?([\d.]+)', txt)
                    found["angular"] = vm.group(1) if vm else None
                if "React" in txt and ("createElement" in txt or "react-dom" in txt):
                    found.setdefault("react", None)
                if "__NEXT_DATA__" in body or "next/dist" in txt:
                    found["nextjs"] = None
                if re.search(r'Vue\.js v([\d.]+)', txt):
                    vm = re.search(r'Vue\.js v([\d.]+)', txt)
                    found["vue"] = vm.group(1) if vm else None
                if re.search(r'X-Powered-By[^\n]*Express', txt, re.I):
                    found.setdefault("express", None)
            except Exception:
                pass

    return found


def map_cves(found):
    confirmed, suspected = [], []
    for name, version in found.items():
        for cve in CVE_MAP.get(name, []):
            entry = dict(cve, software=name, detected_version=version)
            if version and in_range(version, cve["from"], cve["to"]):
                confirmed.append(entry)
            elif version is None:
                suspected.append(entry)
    return confirmed, suspected


def check_config_exposure(base_url):
    hits = []
    for path, desc, validator in CONFIG_PROBES:
        try:
            st, hd, bd = fetch(base_url + path, max_bytes=200_000)
            if st == 200 and validator(bd.decode("utf-8", "replace")):
                hits.append({"path": path, "issue": desc, "severity": "HIGH"})
        except Exception:
            continue
    return hits


def check_headers(info):
    missing = [h for h in SECURITY_HEADERS
               if h not in info.get("headers", {})]
    return missing


def audit_host(host):
    log(f"[*] {host}: probing")
    info = probe_host(host)
    if "base_url" not in info:
        log(f"[-] {host}: {info.get('error')}")
        return info

    info["fingerprint"] = fingerprint(info)
    info["cves_confirmed"], info["cves_suspected"] = map_cves(info["fingerprint"])
    log(f"[+] {host}: {info['fingerprint'] or 'no stack identified'}")

    log(f"[*] {host}: config exposure checks")
    info["config_exposure"] = check_config_exposure(info["base_url"])
    info["missing_security_headers"] = check_headers(info)
    return info

# ------------------------------------------------------------------ report ---

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_report(results, meta):
    lines = []
    a = lines.append
    a("# Asset Audit Report")
    a("")
    a(f"**Generated:** {meta['generated']}  ")
    a(f"**Targets:** {len(meta['targets'])}  ")
    a(f"**Authorization attestation:** {meta['authorization']}")
    a("")
    a("> GET-only passive external review. No exploitation performed. "
      "CVEs listed as CONFIRMED only where a detected version falls inside "
      "the affected range.")
    a("")

    total_conf = sum(len(r.get("cves_confirmed", [])) for r in results)
    total_exp = sum(len(r.get("config_exposure", [])) for r in results)
    a("## Summary")
    a("")
    a(f"- Version-confirmed CVEs: **{total_conf}**")
    a(f"- Config exposures found: **{total_exp}**")
    a("")

    for r in results:
        host_label = r["host"]
        base = r.get("base_url")
        if base and (":" in host_label or base.split("//")[-1] != host_label):
            host_label = base.split("//")[-1]
        a(f"## {host_label}")
        a("")
        if "error" in r:
            a(f"❌ {r['error']}")
            a("")
            continue
        a(f"- Target: `{r['base_url']}`")
        a(f"- IP: `{r['ip']}` · TLS: {'yes' if r['tls'] else 'no'} · HTTP {r['status']}")
        if r.get("fingerprint"):
            stack = ", ".join(f"{k} {v or '(version unknown)'}" for k, v in r["fingerprint"].items())
            a(f"- Stack: {stack}")
        else:
            a("- Stack: not identified from passive signals")

        if r.get("cves_confirmed"):
            a("")
            a("| CVE | Software | Detected | Severity | CVSS |")
            a("|---|---|---|---|---|")
            for c in sorted(r["cves_confirmed"], key=lambda x: SEV_ORDER.get(x["sev"], 9)):
                nvd = c.get("nvd") or {}
                cvss = nvd.get("cvss", "") if isinstance(nvd, dict) and "cvss" in nvd else ""
                a(f"| {c['cve']} | {c['software']} {c['detected_version']} | in {c['from']}–{c['to']} | {c['sev']} | {cvss} |")
        if r.get("cves_suspected"):
            names = ", ".join(sorted({c["cve"] for c in r["cves_suspected"]}))
            a(f"- ⚠️ Suspected (software present, version undetected): {names}")

        if r.get("config_exposure"):
            a("")
            for e in r["config_exposure"]:
                a(f"- 🔴 **{e['severity']}**: {e['issue']} at `{e['path']}`")
        if r.get("missing_security_headers"):
            a(f"- 🟡 Missing security headers: {', '.join(r['missing_security_headers'])}")
        a("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Passive external audit for owned domains (GET-only).")
    ap.add_argument("targets", help="text file with one domain per line")
    ap.add_argument("--authorize", required=True, metavar="STATEMENT",
                    help='required: e.g. --authorize "I own example.com and authorize this audit"')
    ap.add_argument("--out", default="audit-report", help="output basename (default audit-report)")
    ap.add_argument("--zip", action="store_true", help="also bundle report+json into a zip")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--nvd", action="store_true",
                    help="enrich CONFIRMED CVEs with live NVD 2.0 data (cached in nvd-cache.json)")
    args = ap.parse_args()

    global NVD_CACHE_FILE
    nvd_cache = {}
    if args.nvd:
        import os
        NVD_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd-cache.json")
        if os.path.exists(NVD_CACHE_FILE):
            try:
                nvd_cache = json.load(open(NVD_CACHE_FILE))
            except Exception:
                nvd_cache = {}

    try:
        with open(args.targets) as f:
            domains = [ln.strip() for ln in f
                       if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        sys.exit(f"targets file not found: {args.targets}")
    domains = sorted({d.lower().strip("/") for d in domains})
    if not domains:
        sys.exit("no domains in targets file")

    log(f"[*] Authorization on record: \"{args.authorize}\"")
    log(f"[*] Auditing {len(domains)} target(s), GET-only passive checks\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(audit_host, domains))

    if args.nvd:
        import os
        all_confirmed = {(c["cve"]) for r in results for c in r.get("cves_confirmed", [])}
        for cve_id in sorted(all_confirmed):
            if cve_id in nvd_cache:
                continue
            log(f"[*] NVD: {cve_id}")
            nvd_lookup(cve_id, nvd_cache)
        for r in results:
            for c in r.get("cves_confirmed", []):
                c["nvd"] = nvd_cache.get(c["cve"], {})
        os.makedirs(os.path.dirname(NVD_CACHE_FILE) or ".", exist_ok=True)
        with open(NVD_CACHE_FILE, "w") as f:
            json.dump(nvd_cache, f, indent=2)

    meta = {"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "targets": domains, "authorization": args.authorize}
    md = build_report(results, meta)
    md_path = f"{args.out}.md"
    json_path = f"{args.out}.json"
    with open(md_path, "w") as f:
        f.write(md)
    with open(json_path, "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2)

    if args.zip:
        import zipfile
        with zipfile.ZipFile(f"{args.out}.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.write(md_path)
            z.write(json_path)
        log(f"[+] wrote {args.out}.zip")

    log(f"[+] done: {md_path}, {json_path}")


if __name__ == "__main__":
    main()
