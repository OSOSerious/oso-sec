"""SDK quickstart — the 4 ways to use asset_audit.

Run: python3 examples/quickstart.py
"""

# 1 ── Simplest: one host, one call -----------------------------------------
from asset_audit import Auditor

auditor = Auditor(authorization="local lab self-test — 127.0.0.1 only")
result = auditor.audit_host("127.0.0.1:8083")     # WP lab target

print("== single host ==")
print(f"host:      {result.host}")
print(f"stack:     {result.fingerprint}")
print(f"confirmed: {len(result.cves_confirmed)} CVEs")
for c in result.cves_confirmed:
    print(f"  - {c['cve']} ({c['software']} {c['detected_version']}, {c['sev']})")
print(f"exposure:  {len(result.config_exposure)} findings")
print(f"headers:   missing {len(result.missing_security_headers)}")

# 2 ── Batch + reports -------------------------------------------------------
from asset_audit import write_reports

results = auditor.audit(["127.0.0.1:3000", "127.0.0.1:8081", "127.0.0.1:8083"])
md, js = write_reports(results, auditor.authorization, "/tmp/sdk-quickstart-report")
print(f"\n== batch ==\nreports written: {md}, {js}")

# 3 ── NVD enrichment (network) ----------------------------------------------
from asset_audit import NVDClient

nvd = NVDClient()
nvd.enrich(results)
first = next((c for r in results for c in r.cves_confirmed if c.get("nvd")), None)
if first:
    print(f"\n== nvd ==\n{first['cve']}: CVSS {first['nvd'].get('cvss')} "
          f"({first['nvd'].get('cvss_severity', '')})")

# 4 ── Version logic, reusable ------------------------------------------------
from asset_audit import in_range

assert in_range("4.2.1", "1.0", "4.7.0") is True
assert in_range("5.0.0", "1.0", "4.7.0") is False
assert in_range("garbage", "1.0", "4.7.0") is False
print("\n== in_range == 4.2.1 in [1.0, 4.7.0]:", in_range("4.2.1", "1.0", "4.7.0"))
print("\nquickstart complete ✓")
