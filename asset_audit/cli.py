"""CLI entry point: python -m asset_audit (or the `asset-audit` console script)."""

from __future__ import annotations

import argparse
import sys

from . import Auditor, NVDClient, __version__, write_reports


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="asset-audit",
        description="Passive external audit for owned domains (GET-only).")
    ap.add_argument("targets", help="text file with one domain per line")
    ap.add_argument("--authorize", required=True, metavar="STATEMENT",
                    help='required, embedded in report: --authorize "I own example.com"')
    ap.add_argument("--out", default="audit-report", help="output basename")
    ap.add_argument("--zip", action="store_true", help="also bundle md+json into a zip")
    ap.add_argument("--nvd", action="store_true", help="enrich confirmed CVEs with NVD data")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--version", action="version", version=f"asset-audit {__version__}")
    args = ap.parse_args(argv)

    try:
        with open(args.targets) as f:
            domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        sys.exit(1)  # bad invocation
    if not domains:
        sys.exit(1)  # bad invocation

    print(f'[*] Authorization on record: "{args.authorize}"', file=sys.stderr)
    print(f"[*] Auditing {len(domains)} target(s), GET-only passive checks\n", file=sys.stderr)

    try:
        auditor = Auditor(authorization=args.authorize)
        results = auditor.audit(domains, workers=args.workers)
    except Exception as e:
        print(f"[!] engine error: {e}", file=sys.stderr)
        sys.exit(2)  # unhandled engine error

    for r in results:
        if r.error:
            print(f"[-] {r.host}: {r.error}", file=sys.stderr)
        else:
            print(f"[+] {r.host}: {r.fingerprint or 'no stack identified'}", file=sys.stderr)

    try:
        if args.nvd:
            NVDClient().enrich(results)
        md, js = write_reports(results, args.authorize, args.out)
    except Exception as e:
        print(f"[!] report error: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"[+] done: {md}, {js}", file=sys.stderr)

    if args.zip:
        import zipfile
        with zipfile.ZipFile(f"{args.out}.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.write(md)
            z.write(js)
        print(f"[+] wrote {args.out}.zip", file=sys.stderr)


if __name__ == "__main__":
    main()
