# Changelog

All notable changes to asset-audit. Dates are YYYY-MM-DD.

## [1.0.0] — 2026-10-27

### Added
- Initial release as an installable Python package (`pip install .`), zero
  third-party dependencies, Python ≥ 3.9.
- `Auditor` class — passive, GET-only external auditing of domains you own:
  DNS/HTTP(S) inventory, tech fingerprinting, version-confirmed CVE mapping,
  config-exposure probes, security-header review.
- **0-false-positive gate (core design):** a CVE is reported CONFIRMED only when
  the detected version falls inside the affected range; software-without-version
  findings land in a clearly labeled SUSPECTED bucket. Enforced in
  `_map_cves`, not left to caller discipline.
- Authorization gate: `Auditor(authorization=...)` raises without an attestation
  statement, and the statement is embedded in every generated report.
- Fingerprinting across 9 stacks: WordPress, Drupal, Joomla, nginx, Apache, PHP,
  Tomcat, Express, Next.js — plus SPA markers (Angular/Next/Nuxt/React/Vue) and
  Express tells (X-Powered-By, X-Recruiting, ETag shape).
- WordPress version fallbacks (v3): `/feed/` generator, `/readme.html` title
  (browser-UA for CDN-fronted sites), `/wp-links-opml.php`, `/?feed=rss2`.
- NVD 2.0 enrichment (`NVDClient`) with local JSON cache — live CVSS/descriptions,
  offline-safe cache-first lookups.
- Report builders: markdown + JSON (+ optional zip bundling).
- CLI: `asset-audit targets.txt --authorize "..." [--nvd] [--zip] [--workers N]`,
  also runnable as `python -m asset_audit`.
- `examples/quickstart.py` — four usage patterns, runnable against a local target.
- Curated knowledge base (~25 version-ranged CVE entries) in `asset_audit/knowledge.py`.

### Fixed
- `.env` exposure validator hardened: Shopify/SPA catch-all routes return HTML
  that previously satisfied the loose `=`+`KEY` check. A real env file is now
  3+ KEY=VALUE lines with no markup; HTML bodies are rejected. Unit-tested both ways.
- `host:port` target probing tried `https://` twice and never `http://` —
  port-specified targets were unreachable.
- Report CVE tables now use the knowledge-base keys (`from`/`to`) consistently.

### Added (2026-10-28)
- Optional MCP server (`pip install .[mcp]`, requires `fastmcp>=2.0`):
  `audit_domains(domains, authorization)` and `get_report()` as standard MCP
  tools, stdio transport. The `authorization` parameter is required in the tool
  schema itself — the scope gate survives the wire. Works with any
  MCP-compatible harness; no client is assumed.
- Hard exit codes in CLI: `0` success, `1` bad invocation (missing/empty
  targets), `2` engine error (blank authorization, crashes). Documented in
  AGENTS.md as the harness decision surface.

### Security
- GET-only by design; no exploit logic exists in the codebase and none will be added.
- Scope safety is structural (engine verbs, constructor gate, enforced 0-FP split),
  not advisory.
