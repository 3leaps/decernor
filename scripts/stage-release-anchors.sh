#!/usr/bin/env bash
# Copy committed fingerprint pins into dist/release before checksums.
# Net-new step: existing checksum scripts do not invent this file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${1:-dist/release}"

NDJSON="$ROOT/keys/expected-fingerprints.ndjson"
TXT="$ROOT/keys/expected-fingerprints.txt"

if [ ! -f "$NDJSON" ] || [ ! -f "$TXT" ]; then
	echo "error: missing keys/expected-fingerprints.ndjson or .txt" >&2
	echo "run: make release-insert-anchors" >&2
	exit 2
fi

mkdir -p "$DIR"
cp "$NDJSON" "$DIR/expected-fingerprints.ndjson"
cp "$TXT" "$DIR/expected-fingerprints.txt"
echo "[ok] staged fingerprint pins into $DIR"
