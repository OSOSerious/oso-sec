# -oso-sec

Security toolkit: a passive audit SDK for assets you own, plus a complete
loopback-only exploit lab with validated detection engineering. Everything
here is defensive or lab-scoped. No exploit logic targets third-party systems —
by structure, not by policy.

## Contents

### `asset_audit/` — external audit SDK (pip-installable)

Passive, GET-only auditing for **domains you own**:

```bash
pip install .
asset-audit domains.txt --authorize "I own these domains" --nvd --zip
```

```python
from asset_audit import Auditor, write_reports
results = Auditor(authorization="I own example.com").audit(["example.com"])
write_reports(results, "I own example.com", "report")
```

- Inventory → fingerprinting (9 stacks: WP/Drupal/Joomla/nginx/Apache/PHP/
  Tomcat/Express/Next.js + SPA markers) → version-confirmed CVE mapping →
  config-exposure probes → security-header review
- **0-false-positive gate**: CONFIRMED only when detected version ∈ affected
  range; unverifiable findings land in a labeled SUSPECTED bucket. Enforced in code.
- NVD 2.0 enrichment (CVSS) with offline-safe cache
- Authorization attestation required at construction; embedded in every report
- Zero third-party dependencies, Python ≥ 3.9
- Docs: [README](README.md) · [API](API.md) · [CHANGELOG](CHANGELOG.md)

### `exploit-lab/` — local, loopback-only practice range + engagement archive

Five deliberately-vulnerable containers on `127.0.0.1` only
(DVWA, Juice Shop, Mutillidae, WordPress, Shellshock) plus WAF and Suricata IDS:

```bash
cd exploit-lab && ./lab.sh start
```

- `exercises/` — 7 guided workbooks: recon → web kill chains → CVE practice →
  blue-team detection mirror
- `engagement/` — full pentest-report archive of a completed lab engagement:
  5/5 kill chains with proof tables, 14 live-validated detection rules (0 FPs),
  WAF deployment, break/fix verification, final attestation
- `suricata/` — working config + 14 production rules validated against real
  attack traffic, with the detection-engineering lessons learned getting there
- `solver/` — registry-driven Juice Shop challenge solver, **hard-pinned to
  127.0.0.1** (it refuses any other target), plus headless-Chrome drivers for
  the browser tiers

## Safety model

| Boundary | Enforcement |
|---|---|
| Audit tool is GET-only | No other verb exists in the engine; no exploit path in the codebase |
| Authorization required | `Auditor(authorization=...)` raises without it |
| Findings must be provable | Confirmed/suspected split enforced in `_map_cves` |
| Solver can't leave the lab | Base URL pinned to 127.0.0.1 in code |
| Lab can't leak to the network | Every container published as `127.0.0.1:<port>` |

Scope: use against your own assets, contracted engagements, or sanctioned labs.
