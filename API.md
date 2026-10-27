# API Reference — asset-audit 1.0.0

## `Auditor`

The engine. Passive, GET-only.

```python
from asset_audit import Auditor

auditor = Auditor(authorization="I own example.com — authorized audit")
```

| Parameter | Type | Notes |
|---|---|---|
| `authorization` | `str` | **Required.** Raises `ValueError` if empty/missing. Embedded in every report. |
| `timeout` | `int` | Per-request timeout seconds. Default `12`. |

### Methods

#### `auditor.audit(hosts, workers=4) -> list[TargetResult]`
Audits a list of hosts in parallel. Hosts may be `domain`, `sub.domain`, or
`domain:port`. Lowercased, deduplicated, sorted.

#### `auditor.audit_host(host) -> TargetResult`
Single target, full pipeline: probe → fingerprint → CVE map → exposure → headers.

---

## `TargetResult` (dataclass)

| Field | Type | Meaning |
|---|---|---|
| `host` | `str` | Normalized input host |
| `ip` | `str \| None` | Resolved A record |
| `base_url` | `str \| None` | Winning `https://`/`http://` base (None if unreachable) |
| `status` | `int \| None` | HTTP status of the probe |
| `tls` | `bool \| None` | Whether the winning scheme was https |
| `error` | `str \| None` | `"DNS resolution failed"` / `"no HTTP/HTTPS listener reachable"` |
| `fingerprint` | `dict[str, str \| None]` | e.g. `{"wordpress": "4.2.1", "php": "5.5.9"}`; value `None` = detected, version unknown |
| `cves_confirmed` | `list[dict]` | Version-proven findings. Keys: `cve, name, software, detected_version, from, to, sev, status` (+ `nvd` after enrichment) |
| `cves_suspected` | `list[dict]` | Software present, version undetected — never mixed with confirmed |
| `config_exposure` | `list[dict]` | `{path, issue, severity}` for verified exposure probes |
| `missing_security_headers` | `list[str]` | From the six checked headers |
| `headers` | `dict` | Response headers (lowercased keys) |
| `body_head` | `str` | First 20 KB of the probe response body |

---

## `NVDClient`

```python
from asset_audit import NVDClient
nvd = NVDClient()          # optional: NVDClient(cache_path="/custom/nvd.json")
nvd.enrich(results)        # attaches nvd dict to every confirmed CVE; returns count
nvd.lookup("CVE-2024-4577")  # single dict
```

Enrichment fields: `published`, `lastModified`, `description` (300 chars),
`cvss`, `cvss_vector`, `cvss_severity`, `references` (≤3).
Cache-first: network only on cache miss; cache survives offline runs.

---

## Report functions

```python
from asset_audit import write_reports, build_markdown, build_json

md_path, json_path = write_reports(results, authorization, "audit-report")
md_string  = build_markdown(results, meta)
data       = build_json(results, meta)      # plain dict
```

`meta` requires `generated`, `targets`, `authorization` (write_reports builds it).

---

## Version helpers

```python
from asset_audit import in_range, parse_version

in_range("4.2.1", "1.0", "4.7.0")   # True
in_range("5.0", "1.0", "4.7.0")     # False
in_range(None, "1.0", "4.7.0")      # False (version required)
parse_version("4.2.1")              # (4, 2, 1); None if unparseable
```

---

## Knowledge base (extensible)

```python
from asset_audit import CVE_MAP, CONFIG_PROBES, SECURITY_HEADERS
```

- `CVE_MAP[software]` → list of `{cve, name, from, to, sev}`. **Entries must carry
  version ranges** — range-less entries break the 0-FP gate (they can only report
  as suspected).
- `CONFIG_PROBES` → list of `(path, description, body_validator_callable)`.
  Validators must reject HTML catch-all responses (see CHANGELOG: .env fix).
- `SECURITY_HEADERS` → list of header names checked.

---

## CLI

```bash
asset-audit targets.txt --authorize "I own these domains" [--nvd] [--zip] \
                         [--out audit-report] [--workers 4] [--version]
# equivalent:
python -m asset_audit targets.txt --authorize "..." --nvd --zip
```

Targets file: one host per line, `#` comments allowed.
Outputs `<out>.md` + `<out>.json` (+ `<out>.zip` with `--zip`).

**Exit behavior:** completes with report even if some targets are unreachable
(errors recorded per-target). Missing targets file or empty list → non-zero exit.

---

## Safety contract

1. **GET-only.** The engine builds no other verb. No exploit logic exists in the
   package; PRs adding any will be rejected.
2. **Authorization required** at construction, propagated to every artifact.
3. **No unverified findings.** The confirmed/suspected split is enforced in code.
4. **Intended scope:** domains you own or are contractually authorized to audit.
