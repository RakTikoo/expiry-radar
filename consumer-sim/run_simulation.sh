#!/usr/bin/env bash
# Consumer simulation for Expiry Radar v0.2 — LOCAL ONLY.
# Rebuilds consumer-sim/repo, then executes the core steps of
# examples/expiry-radar.yml locally (single --json scan -> render the
# text report from that JSON -> living-issue body), and demonstrates
# the exit-code contract (2 = findings, 3 = broken invocation).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
REPO="$HERE/repo"
EVID="$HERE/evidence"
rm -rf "$REPO" "$EVID"
mkdir -p "$REPO/.github/workflows" "$REPO/certs" "$REPO/tests" \
         "$REPO/src" "$EVID"

# --- build the consumer repo -------------------------------------------
cp "$ROOT/expiry_radar.py" "$REPO/expiry_radar.py"
cp "$ROOT/examples/expiry-radar.yml" "$REPO/.github/workflows/expiry-radar.yml"
printf '"""Consumer-sim application module."""\n' > "$REPO/src/app.py"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$EVID/discarded-key.pem" -out "$REPO/certs/api.pem" \
  -days 30 -subj "/CN=api.consumer-sim.test/O=Consumer Sim" \
  -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
rm -f "$EVID/discarded-key.pem"   # keys are never kept as fixtures
python3 - "$REPO/tests/auth_tokens.py" <<'PYEOF'
import base64, json, sys
def b64(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
token = (f"{b64({'alg': 'HS256', 'typ': 'JWT'})}."
         f"{b64({'sub': 'sim-user', 'exp': 1577836800})}."
         "fixture-signature-not-real")
with open(sys.argv[1], "w") as fh:
    fh.write(f'SESSION_TOKEN = "{token}"  # planted: expired 2020-01-01\n')
PYEOF

# --- workflow step 1: single scan, JSON --------------------------------
cd "$REPO"
set +e
python3 expiry_radar.py . --json > "$EVID/expiry-radar.json"
CODE=$?
set -e

# --- workflow step 2: render the report FROM that JSON ------------------
# (the same rendering code the example workflow embeds)
python3 - "$EVID" <<'PYEOF'
import json, sys
evid = sys.argv[1]
with open(f"{evid}/expiry-radar.json") as fh:
    report = json.load(fh)
lines = [
    f"Expiry Radar {report['version']} — as of {report['now']}, "
    f"warning window {report['days']}d, "
    f"files scanned: {report['files_scanned']}",
    "",
]
for f in report["findings"]:
    lines.append(
        f"[{f['status'].upper()}] {f['kind']} "
        f"{f['path']}:{f['line']}  expires {f['expires']} "
        f"({f['days_left']:+d}d)  {f['detail']}")
if not report["findings"]:
    lines.append("No expired or expiring artefacts found.")
s = report["summary"]
lines += [
    "",
    f"Summary: {s['expired']} expired, {s['expiring']} expiring, "
    f"{s['safe']} safe, {s['unscanned']} unscanned, "
    f"{s['warnings']} warnings",
]
for item in report["unscanned"]:
    lines.append(f"Unscanned: {item['path']}: {item['reason']}")
for warning in report["warnings"]:
    lines.append(f"Warning: {warning}")
with open(f"{evid}/expiry-radar-report.txt", "w") as fh:
    fh.write("\n".join(lines) + "\n")
PYEOF

# --- workflow step 3: the living-issue body ------------------------------
{
  echo "Expiry Radar found artefacts that are expired or expiring soon."
  echo
  echo '```'
  cat "$EVID/expiry-radar-report.txt"
  echo '```'
  echo
  echo "_Updated by the weekly Expiry Radar workflow — this is the single tracking issue; it is edited in place, not duplicated._"
} > "$EVID/issue-body.md"

# --- exit-code contract ---------------------------------------------------
set +e
python3 expiry_radar.py . --days banana --json >/dev/null 2>&1
BROKEN=$?
set -e
{
  echo "consumer-sim simulation log (LOCAL — nothing ran on GitHub)"
  echo "scan exit code: $CODE (2 = expired findings present -> the workflow updates the living issue; NOT a broken invocation)"
  if [ "$CODE" -gt 2 ]; then echo "WORKFLOW WOULD FAIL: scan exit > 2"; fi
  echo "deliberately broken invocation (--days banana) exit code: $BROKEN (3 = usage error -> the workflow fails as BROKEN INVOCATION, never as findings)"
  echo "findings in expiry-radar.json:"
  python3 -c "import json; r=json.load(open('$EVID/expiry-radar.json')); [print(' ', f['status'], f['kind'], f['path'], f['expires']) for f in r['findings']]; print('  exit_code field:', r['exit_code'])"
} > "$EVID/simulation-log.txt"
cat "$EVID/simulation-log.txt"
