#!/usr/bin/env bash
# Public-only scan + pin match via decernor records (no second extractor).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR=${1:-dist/release}
PIN_TXT="$ROOT/keys/expected-fingerprints.txt"

if [ ! -f "$PIN_TXT" ]; then
	echo "error: missing $PIN_TXT" >&2
	exit 2
fi

PUB="$DIR/decernor-minisign.pub"
ASC="$DIR/decernor-release-signing-key.asc"

if [ ! -f "$PUB" ] || [ ! -f "$ASC" ]; then
	echo "error: exported public keys missing in $DIR" >&2
	exit 2
fi

if grep -Eqi "PRIVATE|SECRET|BEGIN PGP PRIVATE KEY|minisign secret key" "$PUB" "$ASC"; then
	echo "error: exported key file appears to contain private material" >&2
	exit 1
fi

DECERNOR_BIN="${DECERNOR_BIN:-}"
if [ -z "$DECERNOR_BIN" ]; then
	if [ -x "$ROOT/bin/decernor" ]; then
		DECERNOR_BIN="$ROOT/bin/decernor"
	elif command -v decernor >/dev/null 2>&1; then
		DECERNOR_BIN="$(command -v decernor)"
	else
		echo "error: decernor binary not found" >&2
		exit 2
	fi
fi

GPG_JSON="$("$DECERNOR_BIN" fingerprint "$ASC" --class public --kind gpg --format json --path-mode none --gpg-role primary)"
MINI_JSON="$("$DECERNOR_BIN" fingerprint "$PUB" --class public --kind minisign --format json --path-mode none)"

python3 - "$PIN_TXT" "$GPG_JSON" "$MINI_JSON" <<'PY'
import json
import sys

pin_path, gpg_raw, mini_raw = sys.argv[1], sys.argv[2], sys.argv[3]
want = {}
for line in open(pin_path):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    algo, fp, *_ = line.split()
    want[algo] = fp

gpg = json.loads(gpg_raw)
if len(gpg) != 1 or gpg[0].get("key_role") != "primary":
    raise SystemExit("error: GPG pin check did not yield one primary record")
if gpg[0].get("fingerprint") != want.get("gpg"):
    raise SystemExit("error: GPG fingerprint does not match keys/expected-fingerprints.txt")

mini = [
    r
    for r in json.loads(mini_raw)
    if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"
]
if len(mini) != 1:
    raise SystemExit("error: minisign pin check did not yield one blob-SHA record")
if mini[0].get("fingerprint") != want.get("minisign"):
    raise SystemExit("error: minisign fingerprint does not match keys/expected-fingerprints.txt")

print("[ok] exported publics match committed fingerprint pins")
PY
