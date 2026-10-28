"""Optional MCP server exposing asset-audit as standard agent tools.

Any MCP-compatible client/harness can mount this. No particular client is
assumed or required.

Run:
    python -m asset_audit.mcp_server          # stdio transport (default)

Requires the optional extra:  pip install .[mcp]

Safety note: `authorization` is a REQUIRED parameter of every tool below —
the scope gate rides along in the tool schema itself, so no client can invoke
an audit without supplying an attestation string.
"""

from __future__ import annotations

import os

try:
    from mcp.server.fastmcp import FastMCP  # SDK 1.x
except ImportError:
    try:
        from fastmcp import FastMCP  # SDK 2.x / standalone package
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "No MCP SDK found. Install the optional extra:  pip install .[mcp]"
        ) from exc

from . import Auditor, build_json, write_reports

mcp = FastMCP("asset-audit")

_DEFAULT_OUT = os.environ.get("ASSET_AUDIT_OUT", "audit-report")


@mcp.tool()
def audit_domains(domains: list[str], authorization: str) -> dict:
    """Passive, GET-only external audit of domains you own.

    Args:
        domains: host list ("example.com" or "example.com:8443").
        authorization: REQUIRED attestation of scope, e.g.
            "I own these domains and authorize this audit."
            Embedded in every artifact produced.

    Returns:
        JSON-serializable dict: per-target fingerprint, cves_confirmed
        (version-proven only — safe to escalate), cves_suspected (needs
        confirmation), config_exposure, missing_security_headers.
        Unreachable targets return an `error` field, never raise.
    """
    if not authorization or not authorization.strip():
        raise ValueError("authorization statement is required — state your scope")
    if not domains:
        raise ValueError("domains list is empty")
    results = Auditor(authorization=authorization).audit(domains)
    write_reports(results, authorization, _DEFAULT_OUT)
    return build_json(results, {
        "targets": [r.host for r in results],
        "authorization": authorization,
    })


@mcp.tool()
def get_report() -> str:
    """Return the markdown report from the most recent audit run.

    Run audit_domains first; this reads <out>.md where <out> is
    ASSET_AUDIT_OUT (default 'audit-report').
    """
    path = _DEFAULT_OUT + ".md"
    if not os.path.exists(path):
        return f"no report found at {path} — run audit_domains first"
    with open(path) as f:
        return f.read()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
