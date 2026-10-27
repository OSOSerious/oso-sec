#!/usr/bin/env bash
# monitor.sh — run audit, diff vs previous run, alert on NEW findings.
# Exit codes: 0 = no new findings, 2 = NEW findings (cron/launchd friendly).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS="$DIR/domains.txt"
STATE="$DIR/last-run.json"
AUTH="${AUDIT_AUTHORIZATION:-scheduled audit of owned domains}"

[ -s "$TARGETS" ] || { echo "domains.txt empty — nothing to monitor"; exit 0; }

cd "$DIR"
python3 audit.py "$TARGETS" --authorize "$AUTH" --out current-run >/dev/null 2>&1

if [ -f "$STATE" ]; then
  python3 - "$STATE" current-run.json <<'EOF'
import json, sys
old = json.load(open(sys.argv[1]))
new = json.load(open(sys.argv[2]))
old_c = {(r['host'], c['cve']) for r in old['results'] for c in r.get('cves_confirmed', [])}
old_e = {(r['host'], e['path']) for r in old['results'] for e in r.get('config_exposure', [])}
new_c = {(r['host'], c['cve']) for r in new['results'] for c in r.get('cves_confirmed', [])}
new_e = {(r['host'], e['path']) for r in new['results'] for e in r.get('config_exposure', [])}
added_c = new_c - old_c
added_e = new_e - old_e
removed_c = old_c - new_c
if added_c or added_e:
    print('⚠️  NEW FINDINGS SINCE LAST RUN:')
    for h, c in sorted(added_c): print(f'  + {h}: {c}')
    for h, p in sorted(added_e): print(f'  + {h}: exposure {p}')
    sys.exit(2)
print('no new findings' + (f' ({len(removed_c)} resolved/patched)' if removed_c else ''))
EOF
else
  echo "first run — baseline saved"
fi
cp current-run.json "$STATE"
