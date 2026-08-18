#!/usr/bin/env bash
# Write keys/expected-fingerprints.{ndjson,txt} from decernor records.
# Requires DECERNOR_MINISIGN_PUB, DECERNOR_GPG_HOMEDIR, DECERNOR_PGP_KEY_ID.
# Never accepts a filesystem path as a flag. Env vars only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() {
	if [ -z "${!1:-}" ]; then
		echo "error: $1 is not set" >&2
		exit 2
	fi
}

need DECERNOR_MINISIGN_PUB
need DECERNOR_GPG_HOMEDIR
need DECERNOR_PGP_KEY_ID

if [ ! -f "$DECERNOR_MINISIGN_PUB" ]; then
	echo "error: DECERNOR_MINISIGN_PUB is not a readable file" >&2
	exit 2
fi
if [ ! -d "$DECERNOR_GPG_HOMEDIR" ]; then
	echo "error: DECERNOR_GPG_HOMEDIR is not a directory" >&2
	exit 2
fi

DECERNOR_BIN="${DECERNOR_BIN:-}"
if [ -z "$DECERNOR_BIN" ]; then
	if [ -x "$ROOT/bin/decernor" ]; then
		DECERNOR_BIN="$ROOT/bin/decernor"
	elif command -v decernor >/dev/null 2>&1; then
		DECERNOR_BIN="$(command -v decernor)"
	else
		echo "error: decernor binary not found (build it or set DECERNOR_BIN)" >&2
		exit 2
	fi
fi

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

PUB="$WORKDIR/decernor.pub"
ASC="$WORKDIR/decernor.asc"
cp "$DECERNOR_MINISIGN_PUB" "$PUB"
gpg --batch --no-tty --homedir "$DECERNOR_GPG_HOMEDIR" --armor --export "$DECERNOR_PGP_KEY_ID" >"$ASC"

GPG_NDJSON="$WORKDIR/gpg.ndjson"
MINI_NDJSON="$WORKDIR/mini.ndjson"
STAGING="$WORKDIR/pair"
mkdir -p "$STAGING"

"$DECERNOR_BIN" fingerprint "$ASC" --class public --kind gpg \
	--format ndjson --path-mode none --gpg-role primary >"$GPG_NDJSON"
"$DECERNOR_BIN" fingerprint "$PUB" --class public --kind minisign \
	--format ndjson --path-mode none >"$MINI_NDJSON"

python3 - "$GPG_NDJSON" "$MINI_NDJSON" "$STAGING" <<'PY'
import json
import pathlib
import sys

gpg_path, mini_path, out_dir = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])


def load_ndjson(path):
    records = []
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


gpg = load_ndjson(gpg_path)
if len(gpg) != 1:
    raise SystemExit(f"error: expected exactly one GPG primary record, got {len(gpg)}")
g = gpg[0]
if g.get("fingerprint_scheme") != "openpgp-fingerprint-v1" or g.get("key_role") != "primary":
    raise SystemExit("error: GPG record is not openpgp-fingerprint-v1 primary")
gpg_fp = g.get("fingerprint") or ""
if len(gpg_fp) != 40 or any(c not in "0123456789ABCDEF" for c in gpg_fp):
    raise SystemExit("error: GPG fingerprint is not uppercase 40-hex")

mini = [
    r
    for r in load_ndjson(mini_path)
    if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"
]
if len(mini) != 1:
    raise SystemExit(f"error: expected exactly one minisign blob-SHA record, got {len(mini)}")
m = mini[0]
mini_fp = m.get("fingerprint") or ""
if len(mini_fp) != 64 or any(c not in "0123456789abcdef" for c in mini_fp):
    raise SystemExit("error: minisign fingerprint is not lowercase 64-hex")

out_dir.mkdir(parents=True, exist_ok=True)
# Selected-record receipt (primary + blob SHA only), not raw dual-record stdout.
(out_dir / "expected-fingerprints.ndjson").write_text(
    json.dumps(g, separators=(",", ":")) + "\n" + json.dumps(m, separators=(",", ":")) + "\n"
)
(out_dir / "expected-fingerprints.txt").write_text(f"gpg {gpg_fp}\nminisign {mini_fp}\n")
PY

SCHEMA="$ROOT/schemas/fingerprint-record.v0.schema.json"
while IFS= read -r line; do
	[ -n "$line" ] || continue
	printf '%s\n' "$line" >"$WORKDIR/one.json"
	"$DECERNOR_BIN" validate --schema "$SCHEMA" --data "$WORKDIR/one.json" >/dev/null
done <"$STAGING/expected-fingerprints.ndjson"

KEYS="$ROOT/keys"
mkdir -p "$KEYS"
NEW_NDJSON="$KEYS/expected-fingerprints.ndjson.new"
NEW_TXT="$KEYS/expected-fingerprints.txt.new"
DEST_NDJSON="$KEYS/expected-fingerprints.ndjson"
DEST_TXT="$KEYS/expected-fingerprints.txt"
BAK_NDJSON="$KEYS/expected-fingerprints.ndjson.bak"
BAK_TXT="$KEYS/expected-fingerprints.txt.bak"

cp "$STAGING/expected-fingerprints.ndjson" "$NEW_NDJSON"
cp "$STAGING/expected-fingerprints.txt" "$NEW_TXT"

rollback() {
	rm -f "$NEW_NDJSON" "$NEW_TXT"
	if [ -f "$BAK_NDJSON" ]; then
		mv -f "$BAK_NDJSON" "$DEST_NDJSON"
	fi
	if [ -f "$BAK_TXT" ]; then
		mv -f "$BAK_TXT" "$DEST_TXT"
	fi
}

if [ -f "$DEST_NDJSON" ]; then
	cp "$DEST_NDJSON" "$BAK_NDJSON"
fi
if [ -f "$DEST_TXT" ]; then
	cp "$DEST_TXT" "$BAK_TXT"
fi

if ! mv -f "$NEW_NDJSON" "$DEST_NDJSON"; then
	rollback
	echo "error: failed to install ndjson pin" >&2
	exit 1
fi
if ! mv -f "$NEW_TXT" "$DEST_TXT"; then
	rollback
	echo "error: failed to install txt pin; restored previous pair" >&2
	exit 1
fi
rm -f "$BAK_NDJSON" "$BAK_TXT"
echo "[ok] wrote $DEST_NDJSON"
echo "[ok] wrote $DEST_TXT"
