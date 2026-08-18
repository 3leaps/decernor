#!/usr/bin/env bash
# Validate pin-pair shape and DDR-0001 schema. No pub recompute, no keys/ cmp.
# Shape checks run first so they do not depend on a built decernor binary.
# Usage: validate-pin-pair.sh <txt> <ndjson> [schema]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TXT=${1:?}
NDJSON=${2:?}
SCHEMA=${3:-"$ROOT/schemas/fingerprint-record.v0.schema.json"}

if [ ! -f "$TXT" ] || [ ! -f "$NDJSON" ]; then
	echo "error: pin pair incomplete" >&2
	exit 2
fi
if [ ! -f "$SCHEMA" ]; then
	echo "error: schema not found: $SCHEMA" >&2
	exit 2
fi

python3 - "$TXT" "$NDJSON" <<'PY'
import json
import pathlib
import sys

txt_path, ndjson_path = sys.argv[1], sys.argv[2]
physical = pathlib.Path(txt_path).read_text().splitlines()
if len(physical) != 2:
    raise SystemExit("error: pin TXT must be exactly two physical lines")
want = {}
for line in physical:
    parts = line.split()
    if len(parts) != 2:
        raise SystemExit("error: pin TXT line must have exactly two fields")
    algo, fp = parts
    if algo in want:
        raise SystemExit(f"error: duplicate {algo} line in pin TXT")
    want[algo] = fp
if set(want) != {"gpg", "minisign"}:
    raise SystemExit("error: pin TXT must contain exactly one gpg and one minisign line")

records = []
for line in pathlib.Path(ndjson_path).read_text().splitlines():
    if line.strip():
        records.append(json.loads(line))
if len(records) != 2:
    raise SystemExit("error: pin NDJSON must contain exactly two records")
gpg_rec = [r for r in records if r.get("fingerprint_scheme") == "openpgp-fingerprint-v1"]
mini_rec = [r for r in records if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"]
if len(gpg_rec) != 1 or gpg_rec[0].get("key_role") != "primary":
    raise SystemExit("error: pin NDJSON must contain one GPG primary record")
if len(mini_rec) != 1:
    raise SystemExit("error: pin NDJSON must contain one minisign blob-SHA record")
if gpg_rec[0].get("fingerprint") != want["gpg"]:
    raise SystemExit("error: pin NDJSON GPG fingerprint != pin TXT")
if mini_rec[0].get("fingerprint") != want["minisign"]:
    raise SystemExit("error: pin NDJSON minisign fingerprint != pin TXT")
PY

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

ONE_JSON="$(mktemp)"
cleanup_one() { rm -f "$ONE_JSON"; }
trap cleanup_one EXIT
while IFS= read -r line || [ -n "$line" ]; do
	[ -n "$line" ] || continue
	printf '%s\n' "$line" >"$ONE_JSON"
	"$DECERNOR_BIN" validate --schema "$SCHEMA" --data "$ONE_JSON" >/dev/null
done <"$NDJSON"
