"""asset-audit — passive, GET-only external audit SDK for domains you own.

3-line usage:

    from asset_audit import Auditor, write_reports
    results = Auditor(authorization="I own example.com").audit(["example.com"])
    write_reports(results, "I own example.com", "audit-report")

Safety model (structural, not advisory):
- GET-only. No exploit logic exists in this package.
- Authorization statement is REQUIRED at Auditor construction and is
  embedded in every generated report.
- CVEs are only CONFIRMED when a detected version falls inside the
  affected range; unverifiable findings land in a labeled SUSPECTED bucket.
"""

__version__ = "1.0.0"
__all__ = ["Auditor", "TargetResult", "CVEFinding", "ExposureFinding",
           "NVDClient", "write_reports", "build_markdown", "build_json",
           "in_range", "parse_version", "CVE_MAP", "CONFIG_PROBES",
           "SECURITY_HEADERS", "__version__"]

from .core import Auditor, TargetResult, CVEFinding, ExposureFinding, in_range, parse_version
from .knowledge import CVE_MAP, CONFIG_PROBES, SECURITY_HEADERS
from .nvd import NVDClient
from .report import build_markdown, build_json, write_reports
