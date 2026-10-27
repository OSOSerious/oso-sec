"""Report builders: markdown + JSON from TargetResult lists."""

from __future__ import annotations

import datetime
import json

from .knowledge import SEV_ORDER


def build_markdown(results, meta) -> str:
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

    total_conf = sum(len(r.cves_confirmed) for r in results)
    total_exp = sum(len(r.config_exposure) for r in results)
    a("## Summary")
    a("")
    a(f"- Version-confirmed CVEs: **{total_conf}**")
    a(f"- Config exposures found: **{total_exp}**")
    a("")

    for r in results:
        host_label = r.host
        base = r.base_url
        if base and (":" in host_label or base.split("//")[-1] != host_label):
            host_label = base.split("//")[-1]
        a(f"## {host_label}")
        a("")
        if r.error:
            a(f"❌ {r.error}")
            a("")
            continue
        a(f"- Target: `{r.base_url}`")
        a(f"- IP: `{r.ip}` · TLS: {'yes' if r.tls else 'no'} · HTTP {r.status}")
        if r.fingerprint:
            stack = ", ".join(f"{k} {v or '(version unknown)'}" for k, v in r.fingerprint.items())
            a(f"- Stack: {stack}")
        else:
            a("- Stack: not identified from passive signals")

        if r.cves_confirmed:
            a("")
            a("| CVE | Software | Detected | Severity | CVSS |")
            a("|---|---|---|---|---|")
            for c in sorted(r.cves_confirmed, key=lambda x: SEV_ORDER.get(x["sev"], 9)):
                nvd = c.get("nvd") or {}
                cvss = nvd.get("cvss", "") if isinstance(nvd, dict) and "cvss" in nvd else ""
                a(f"| {c['cve']} | {c['software']} {c['detected_version']} | "
                  f"in {c['from']}–{c['to']} | {c['sev']} | {cvss} |")
        if r.cves_suspected:
            names = ", ".join(sorted({c["cve"] for c in r.cves_suspected}))
            a(f"- ⚠️ Suspected (software present, version undetected): {names}")
        if r.config_exposure:
            a("")
            for e in r.config_exposure:
                a(f"- 🔴 **{e['severity']}**: {e['issue']} at `{e['path']}`")
        if r.missing_security_headers:
            a(f"- 🟡 Missing security headers: {', '.join(r.missing_security_headers)}")
        a("")
    return "\n".join(lines)


def build_json(results, meta) -> dict:
    out = {"meta": meta, "results": []}
    for r in results:
        out["results"].append({
            "host": r.host, "ip": r.ip, "base_url": r.base_url,
            "status": r.status, "tls": r.tls, "error": r.error,
            "fingerprint": r.fingerprint,
            "cves_confirmed": r.cves_confirmed,
            "cves_suspected": r.cves_suspected,
            "config_exposure": r.config_exposure,
            "missing_security_headers": r.missing_security_headers,
        })
    return out


def write_reports(results, authorization, out_basename, meta_extra=None):
    meta = {"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "targets": [r.host for r in results],
            "authorization": authorization}
    if meta_extra:
        meta.update(meta_extra)
    md = build_markdown(results, meta)
    data = build_json(results, meta)
    with open(f"{out_basename}.md", "w") as f:
        f.write(md)
    with open(f"{out_basename}.json", "w") as f:
        json.dump(data, f, indent=2)
    return f"{out_basename}.md", f"{out_basename}.json"
