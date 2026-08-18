#!/usr/bin/env bash
# Verify staged pins in dist/release (the signed objects), not only keys/.
# Public-only scan + DDR-0001 validation + TXT/NDJSON/recomputed equality.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR=${1:-dist/release}
STAGED_TXT="$DIR/expected-fingerprints.txt"
STAGED_NDJSON="$DIR/expected-fingerprints.ndjson"
SCHEMA="$ROOT/schemas/fingerprint-record.v0.schema.json"

if [ ! -f "$STAGED_TXT" ] || [ ! -f "$STAGED_NDJSON" ]; then
	echo "error: missing staged pins in $DIR" >&2
	exit 2
fi

if [ -f "$ROOT/keys/expected-fingerprints.txt" ]; then
	if ! cmp -s "$STAGED_TXT" "$ROOT/keys/expected-fingerprints.txt"; then
		echo "error: staged TXT differs from keys/expected-fingerprints.txt" >&2
		exit 1
	fi
fi
if [ -f "$ROOT/keys/expected-fingerprints.ndjson" ]; then
	if ! cmp -s "$STAGED_NDJSON" "$ROOT/keys/expected-fingerprints.ndjson"; then
		echo "error: staged NDJSON differs from keys/expected-fingerprints.ndjson" >&2
		exit 1
	fi
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

"$ROOT/scripts/validate-pin-pair.sh" "$STAGED_TXT" "$STAGED_NDJSON" "$SCHEMA"

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

python3 - "$STAGED_TXT" "$GPG_JSON" "$MINI_JSON" <<'PY'
import json
import pathlib
import sys

txt_path, gpg_raw, mini_raw = sys.argv[1:4]
want = {}
for line in pathlib.Path(txt_path).read_text().splitlines():
    algo, fp = line.split()
    want[algo] = fp

gpg = json.loads(gpg_raw)
if len(gpg) != 1 or gpg[0].get("key_role") != "primary":
    raise SystemExit("error: GPG recompute did not yield one primary record")
if gpg[0].get("fingerprint") != want["gpg"]:
    raise SystemExit("error: recomputed GPG fingerprint does not match staged TXT")

mini = [
    r
    for r in json.loads(mini_raw)
    if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"
]
if len(mini) != 1:
    raise SystemExit("error: minisign recompute did not yield one blob-SHA record")
if mini[0].get("fingerprint") != want["minisign"]:
    raise SystemExit("error: recomputed minisign fingerprint does not match staged TXT")

print("[ok] staged pins, schema, TXT/NDJSON, and recomputed publics agree")
PY
