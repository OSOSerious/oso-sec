# Agent Integration

`asset-audit` is agent-agnostic by contract: deterministic CLI, machine-readable
output, meaningful exit codes, no interactivity. Any harness that can run a
command and read stdout/stderr or a file can drive it. No specific client,
platform, or SDK is required — and none ever will be.

## The contract

```bash
asset-audit TARGETS --authorize "STATEMENT" [--out BASE] [--nvd] [--zip] [--workers N]
```

| Guarantee | Detail |
|---|---|
| Deterministic | Same inputs → same findings. No randomness, no prompts, no state mutation between runs |
| Non-interactive | Never blocks on input. Missing args → immediate non-zero exit |
| Authorization is an argument | The calling agent *must* supply a scope statement; it is embedded in every artifact produced |
| Output is files | `<out>.md`, `<out>.json` (+ `<out>.zip` with `--zip`). JSON is the machine surface |
| Errors are per-target | Unreachable targets are recorded in results, not fatal |
| Bounded runtime | `--workers N` controls concurrency; requests have fixed timeouts |

## Exit codes (decision surface for the harness)

| Code | Meaning | Agent action |
|---|---|---|
| `0` | Run completed; reports written | Parse `<out>.json`; report/act on findings |
| `1` | Bad invocation: missing targets file, empty list, or missing `--authorize` | Fix arguments; do not retry as-is |
| `2` | Unhandled engine error | Inspect stderr; treat run as invalid |

## JSON result shape (`<out>.json`)

```jsonc
{
  "meta": {
    "generated": "2026-10-27T...",     // UTC ISO timestamp
    "targets": ["example.com"],         // normalized host list
    "authorization": "<the statement>"  // provenance — keep with the report
  },
  "results": [
    {
      "host": "example.com",
      "ip": "1.2.3.4",
      "base_url": "https://example.com",
      "status": 200,
      "tls": true,
      "error": null,                    // or "DNS resolution failed", etc.
      "fingerprint": {"wordpress": "6.4"},   // value null = version unknown
      "cves_confirmed": [               // version-proven ONLY. Empty is a valid, good result
        {"cve": "CVE-...", "software": "wordpress", "detected_version": "6.4",
         "from": "1.0", "to": "6.4.2", "sev": "HIGH", "status": "confirmed",
         "nvd": {"cvss": 7.5, "cvss_severity": "HIGH"}}
      ],
      "cves_suspected": [],             // software present, version undetected — never mixed
      "config_exposure": [],            // verified probes only (.git/.env/backups/...)
      "missing_security_headers": ["permissions-policy"]
    }
  ]
}
```

**Zero-FP guarantee for consumers:** everything in `cves_confirmed` has a detected
version inside the affected range. Anything unverifiable is in `cves_suspected`.
Safe to auto-escalate `cves_confirmed` without re-validation.

## Harness patterns

### Shell-capable agents (bash tool, CI, cron)

```bash
asset-audit domains.txt --authorize "scheduled audit of owned assets" --out run --zip
rc=$?
if [ $rc -eq 0 ]; then jq '.results[] | select(.cves_confirmed|length>0)' run.json; fi
```

### Diff/alerting (change detection)

`monitor.sh` (repo root) implements the pattern: run → diff vs `last-run.json`
baseline → exit `2` with a `+ host: CVE` list on new findings. Wire the exit code
to your harness's alert channel.

### SDK embedding (Python-native agents)

```python
from asset_audit import Auditor
results = Auditor(authorization="scope statement").audit(["example.com"])
for r in results:
    escalate(r.cves_confirmed)      # proven, safe to act
    queue(r.cves_suspected)         # needs version confirmation
```

### MCP / tool-palette clients

Optional. `pip install .[mcp]` exposes the same `Auditor` as standard MCP tools
(`audit_domains(domains, authorization)`, `get_report()`). The `authorization`
parameter is required in the tool schema itself, so the gate survives the wire.
Works with any MCP-compatible client — no particular one is assumed or required.

## Scope rules for agent operators

- Point it only at assets you own or are contracted to audit. The
  `--authorize` statement is provenance, not permission — scope is the operator's
  legal responsibility.
- The tool is GET-only; it cannot and will not exploit anything it finds.
