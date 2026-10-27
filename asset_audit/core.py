"""Core scanning engine: probe, fingerprint, CVE mapping, exposure checks.
GET-only by design. No exploit logic exists here or will ever be added."""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .knowledge import CVE_MAP, CONFIG_PROBES, SECURITY_HEADERS

DEFAULT_TIMEOUT = 12
UA = "asset-audit/1.0 (+authorized-scan)"
UA_BROWSER = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125 Safari/537.36")


# ---------------------------------------------------------------- dataclasses

@dataclass
class CVEFinding:
    cve: str
    name: str
    software: str
    detected_version: str | None
    affected_from: str
    affected_to: str
    severity: str
    status: str            # "confirmed" | "suspected"
    nvd: dict = field(default_factory=dict)


@dataclass
class ExposureFinding:
    path: str
    issue: str
    severity: str          # currently "HIGH" for all probes


@dataclass
class TargetResult:
    host: str
    ip: str | None = None
    base_url: str | None = None
    status: int | None = None
    tls: bool | None = None
    error: str | None = None
    fingerprint: dict = field(default_factory=dict)
    cves_confirmed: list = field(default_factory=list)
    cves_suspected: list = field(default_factory=list)
    config_exposure: list = field(default_factory=list)
    missing_security_headers: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    body_head: str = ""


# ------------------------------------------------------------------- helpers

def _fetch(url, method="GET", max_bytes=400_000, browser_ua=False, timeout=DEFAULT_TIMEOUT):
    req = urllib.request.Request(
        url, method=method,
        headers={"User-Agent": UA_BROWSER if browser_ua else UA, "Accept": "*/*"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, dict(r.headers), r.read(max_bytes)


def parse_version(s):
    m = re.match(r"(\d+(?:\.\d+){0,3})", s or "")
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _vpad(v, n):
    v = list(v) + [0] * (n - len(v))
    return tuple(v[:n])


def in_range(version, lo, hi):
    v = parse_version(version)
    if v is None:
        return False
    n = max(len(v), 3)
    vlo, vhi = parse_version(lo), parse_version(hi)
    return _vpad(v, n) <= _vpad(vhi, n) and _vpad(v, n) >= _vpad(vlo, n)


# -------------------------------------------------------------------- engine

class Auditor:
    """Passive, GET-only external auditor.

    >>> a = Auditor(authorization="I own example.com")
    >>> result = a.audit_host("example.com")       # single
    >>> results = a.audit(["example.com", "example.org"])  # parallel
    """

    def __init__(self, authorization: str, timeout: int = DEFAULT_TIMEOUT):
        if not authorization or not authorization.strip():
            raise ValueError("authorization statement is required — it is embedded in every report")
        self.authorization = authorization.strip()
        self.timeout = timeout

    # -- public API ------------------------------------------------------

    def audit(self, hosts, workers: int = 4) -> list[TargetResult]:
        hosts = sorted({h.lower().strip("/") for h in hosts if h and h.strip()})
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.audit_host, hosts))

    def audit_host(self, host: str) -> TargetResult:
        info = self._probe(host)
        if info.base_url is None:
            return info
        info.fingerprint = self._fingerprint(info)
        conf, susp = self._map_cves(info.fingerprint)
        info.cves_confirmed, info.cves_suspected = conf, susp
        info.config_exposure = self._check_exposure(info.base_url)
        info.missing_security_headers = self._check_headers(info)
        return info

    # -- stages -----------------------------------------------------------

    def _probe(self, host) -> TargetResult:
        hostpart, port = host, None
        if ":" in host:
            hostpart, port_s = host.rsplit(":", 1)
            if port_s.isdigit():
                port = int(port_s)
                host = hostpart
        try:
            ip = socket.gethostbyname(hostpart)
        except socket.gaierror:
            return TargetResult(host=host, error="DNS resolution failed")
        result = TargetResult(host=host, ip=ip)
        urls = ([f"https://{host}:{port}", f"http://{host}:{port}"] if port
                else ["https://" + host, "http://" + host])
        for url in urls:
            try:
                st, hd, body = _fetch(url, timeout=self.timeout)
                result.base_url, result.status = url, st
                result.headers = {k.lower(): v for k, v in hd.items()}
                result.body_head = body[:20000].decode("utf-8", "replace")
                result.tls = url.startswith("https")
                return result
            except urllib.error.HTTPError as e:
                result.base_url, result.status = url, e.code
                result.headers = {k.lower(): v for k, v in e.headers.items()}
                result.body_head = e.read(20000).decode("utf-8", "replace")
                result.tls = url.startswith("https")
                return result
            except Exception:
                continue
        result.error = "no HTTP/HTTPS listener reachable"
        return result

    def _fingerprint(self, info: TargetResult) -> dict:
        found = {}
        headers, body = info.headers, info.body_head

        server = headers.get("server", "")
        for m in re.finditer(r"(nginx|apache|tomcat|jetty|iis)[/-]([\d.]+)?", server, re.I):
            found[m.group(1).lower()] = m.group(2)

        xp = headers.get("x-powered-by", "")
        m = re.search(r"PHP[/ ]([\d.]+)", xp, re.I)
        if m:
            found["php"] = m.group(1)
        if headers.get("x-powered-by", "").lower().startswith("express"):
            found["express"] = None
        if "x-recruiting" in headers:
            found.setdefault("express", None)
        etag = headers.get("etag", "")
        if re.match(r'^W/"[a-f0-9]{15,}"$', etag) or headers.get("x-runtime"):
            found.setdefault("express", None)

        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        if m:
            gen = m.group(1)
            for name in ("wordpress", "drupal", "joomla"):
                if name in gen.lower():
                    vm = re.search(r"([\d.]+)", gen)
                    found[name] = vm.group(1) if vm else None

        spa_markers = {
            "angular": (r'(ng-app|ng-version="([\d.]+)"|_nghost|angular\.min\.js)', "angular"),
            "nextjs": (r'(/_next/static|__NEXT_DATA__)', "nextjs"),
            "nuxt": (r'(/_nuxt/|__NUXT__)', "nuxt"),
            "react": (r'(data-reactroot|react(-dom)?\.production\.min\.js|_reactListening)', "react"),
            "vue": (r'(data-v-app|vue\.runtime|vue\.(global|prod))', "vue"),
        }
        for key, (pat, _name) in spa_markers.items():
            m = re.search(pat, body, re.I)
            if m:
                ver = None
                for g in reversed(m.groups() or []):
                    if g and g[0].isdigit():
                        ver = g
                        break
                found[key] = ver

        if "wp-content" in body or "wp-json" in body:
            found.setdefault("wordpress", None)

        # WP version fallbacks (v3): feed generator, readme title, opml
        if "wordpress" in found and not found.get("wordpress"):
            for path, pat, browser in (
                ("/feed/", r"wordpress\.org/\?v=([\d.]+)", False),
                ("/readme.html", r"<title>WordPress\s+(\d+\.\d+(?:\.\d+)?)", True),
                ("/wp-links-opml.php", r"generator=([\d.]+)", True),
                ("/?feed=rss2", r"wordpress\.org/\?v=([\d.]+)", False),
            ):
                try:
                    st, hd, bd = _fetch(info.base_url + path, max_bytes=60_000,
                                        browser_ua=browser, timeout=self.timeout)
                    m = re.search(pat, bd.decode("utf-8", "replace"))
                    if m:
                        found["wordpress"] = m.group(1)
                        break
                except Exception:
                    continue
        return found

    def _map_cves(self, found: dict):
        confirmed, suspected = [], []
        for name, version in found.items():
            for cve in CVE_MAP.get(name, []):
                entry = dict(cve, software=name, detected_version=version)
                if version and in_range(version, cve["from"], cve["to"]):
                    entry["status"] = "confirmed"
                    confirmed.append(entry)
                elif version is None:
                    entry["status"] = "suspected"
                    suspected.append(entry)
        return confirmed, suspected

    def _check_exposure(self, base_url: str) -> list:
        hits = []
        for path, desc, validator in CONFIG_PROBES:
            try:
                st, hd, bd = _fetch(base_url + path, max_bytes=200_000, timeout=self.timeout)
                if st == 200 and validator(bd.decode("utf-8", "replace")):
                    hits.append({"path": path, "issue": desc, "severity": "HIGH"})
            except Exception:
                continue
        return hits

    def _check_headers(self, info: TargetResult) -> list:
        return [h for h in SECURITY_HEADERS if h not in info.headers]
