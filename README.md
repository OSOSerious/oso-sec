# asset-audit — SDK for passive external audits of domains you own

A canonical, installable Python package: import it, run it as a CLI, or hand it to an
agent. GET-only by design. No exploit logic exists in this package — the safety model
is structural (see below).

## Install

```bash
cd asset-audit
pip install .          # or: pip install -e . for development
```

Python ≥ 3.9, zero third-party dependencies (stdlib only).

## SDK usage (3 lines)

```python
from asset_audit import Auditor, write_reports

auditor = Auditor(authorization="I own example.com — authorized audit")
results = auditor.audit(["example.com", "example.org"])
write_reports(results, auditor.authorization, "audit-report")
```

`results` is a list of `TargetResult` dataclasses — everything is typed, introspectable
machine data:

```python
r = results[0]
r.host, r.ip, r.base_url, r.tls, r.status
r.fingerprint                   # {"wordpress": "4.2.1", "php": "5.5.9", ...}
r.cves_confirmed                # version-proven CVE dicts (CVSS via NVDClient)
r.cves_suspected               # software present, version unknown — labeled, never mixed
r.config_exposure               # .git/.env/backup probes
r.missing_security_headers
```

Other exports: `NVDClient` (enrich with live CVSS, cached offline-safe), `in_range` /
`parse_version` (reusable version-range logic), `CVE_MAP` / `CONFIG_PROBES` /
`SECURITY_HEADERS` (extensible knowledge base), `build_markdown` / `build_json`.

## CLI usage

```bash
asset-audit domains.txt --authorize "I own these domains" --nvd --zip
# or without installing:
python -m asset_audit domains.txt --authorize "..." --out report --zip
```

Flags: `--out` basename (default `audit-report`), `--nvd` live CVSS enrichment,
`--zip` bundle, `--workers N` (default 4), `--version`.

## What it does

1. **Inventory** — DNS, HTTPS→HTTP probe, IP/TLS/status; `host` or `host:port`
2. **Fingerprint** — Server/X-Powered-By headers, generator meta, wp-content/wp-json
   markers, SPA framework markers (Angular/Next/Nuxt/React/Vue), Express tells
   (X-Powered-By, X-Recruiting, ETag shape), WP version fallbacks (feed generator,
   readme title with browser-UA for CDN-fronted sites, OPML, rss2)
3. **CVE mapping — the 0-false-positive gate**: a CVE is CONFIRMED only when the
   detected version falls inside the affected range. Software-without-version lands
   in a clearly labeled SUSPECTED bucket. Anything unverifiable is not reported.
4. **Exposure probes** — .git/HEAD, .env, wp-config backups, htaccess backups,
   backup.zip, server-status (all with body validators; all GET)
5. **Header review** — six security headers
6. **Reports** — markdown + JSON (+ optional zip), authorization embedded

## Safety model (structural, not advisory)

- **GET-only.** The engine makes no other verb; there is no exploit path in the codebase.
- **Authorization required at construction** — `Auditor(authorization=...)` raises
  without it, and the statement is stamped into every report.
- **No unverified findings.** The confirmed/suspected split is enforced in `_map_cves`,
  not left to the caller's discipline.

## Extending

- Add software/CVEs: append to `CVE_MAP` in `asset_audit/knowledge.py` — entries must
  carry `from`/`to` version ranges (range-less entries break the 0-FP gate and will
  report as suspected).
- Add probes: append `(path, description, body_validator)` to `CONFIG_PROBES`.

## Layout

```
asset-audit/
├── pyproject.toml           # installable package, `asset-audit` console script
├── asset_audit/
│   ├── __init__.py          # public API
│   ├── core.py              # Auditor, TargetResult, probe/fingerprint engine
│   ├── knowledge.py         # CVE ranges, probes, headers
│   ├── report.py            # markdown/json builders
│   ├── nvd.py               # NVD 2.0 client with cache
│   └── cli.py               # CLI + python -m entry
├── examples/quickstart.py   # runnable demo (4 usage patterns)
├── audit.py                 # legacy standalone script (kept; superseded by package)
└── domains.txt              # target list
```

## Verified

- `pip install .` → `asset-audit` console script works (tested in a clean venv)
- Quickstart against the local lab: WP 4.2.1 + PHP 5.5.9 fingerprinted, 6 CVEs
  confirmed, NVD CVSS 9.8 pulled live
- Two bugs found and fixed during SDK extraction: host:port scheme construction
  (tried https twice, never http) and report key names (`from`/`to` vs
  `affected_from`) — the standalone script's logic, faithfully ported, is now
  covered by the same live-lab verification as the original.
