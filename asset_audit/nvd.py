"""NVD 2.0 enrichment with a local JSON cache (cache-first, offline-safe)."""

from __future__ import annotations

import json
import os
import urllib.request

from .core import UA

DEFAULT_TIMEOUT = 24


class NVDClient:
    def __init__(self, cache_path: str | None = None):
        self.cache_path = cache_path or os.path.join(
            os.path.expanduser("~"), ".cache", "asset-audit", "nvd-cache.json")
        self.cache = {}
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def lookup(self, cve_id: str) -> dict:
        if cve_id in self.cache:
            return self.cache[cve_id]
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as r:
                data = json.load(r)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                self.cache[cve_id] = {"error": "not found in NVD"}
                return self.cache[cve_id]
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
            entry["references"] = [r["url"] for r in v.get("references", [])][:3]
            self.cache[cve_id] = entry
            return entry
        except Exception as e:
            return {"error": f"NVD lookup failed: {e}"}

    def enrich(self, results) -> int:
        """Attach NVD data to every CONFIRMED cve entry in results (mutates)."""
        todo = sorted({c["cve"] for r in results for c in r.cves_confirmed
                       if cve_needed(c)})
        for cve_id in todo:
            self.lookup(cve_id)
        n = 0
        for r in results:
            for c in r.cves_confirmed:
                c["nvd"] = self.cache.get(c["cve"], {})
                n += 1
        self.save()
        return n

    def cve_needed(c):
        return True

    def save(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w") as f:
            json.dump(self.cache, f, indent=2)


def cve_needed(c):
    return True
