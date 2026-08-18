#!/usr/bin/env bash
# Atomically replace dest/expected-fingerprints.{ndjson,txt} from a staging pair.
# First-use: if the second install fails, remove any newly installed dest.
# Usage: atomic-install-pair.sh <staging-dir> <dest-dir>
set -euo pipefail

STAGING=${1:?}
DEST=${2:?}
SRC_NDJSON="$STAGING/expected-fingerprints.ndjson"
SRC_TXT="$STAGING/expected-fingerprints.txt"
DEST_NDJSON="$DEST/expected-fingerprints.ndjson"
DEST_TXT="$DEST/expected-fingerprints.txt"
NEW_NDJSON="$DEST/expected-fingerprints.ndjson.new"
NEW_TXT="$DEST/expected-fingerprints.txt.new"
BAK_NDJSON="$DEST/expected-fingerprints.ndjson.bak"
BAK_TXT="$DEST/expected-fingerprints.txt.bak"

if [ ! -f "$SRC_NDJSON" ] || [ ! -f "$SRC_TXT" ]; then
	echo "error: staging pair incomplete" >&2
	exit 2
fi
mkdir -p "$DEST"

had_ndjson=0
had_txt=0
[ -f "$DEST_NDJSON" ] && had_ndjson=1 && cp "$DEST_NDJSON" "$BAK_NDJSON"
[ -f "$DEST_TXT" ] && had_txt=1 && cp "$DEST_TXT" "$BAK_TXT"

cp "$SRC_NDJSON" "$NEW_NDJSON"
cp "$SRC_TXT" "$NEW_TXT"

rollback() {
	rm -f "$NEW_NDJSON" "$NEW_TXT"
	if [ "$had_ndjson" -eq 1 ]; then
		mv -f "$BAK_NDJSON" "$DEST_NDJSON"
	else
		rm -f "$DEST_NDJSON"
	fi
	if [ "$had_txt" -eq 1 ]; then
		mv -f "$BAK_TXT" "$DEST_TXT"
	else
		rm -f "$DEST_TXT"
	fi
}

if ! mv -f "$NEW_NDJSON" "$DEST_NDJSON"; then
	rollback
	echo "error: failed to install ndjson pin" >&2
	exit 1
fi
if [ "${DECERNOR_TEST_FAIL_SECOND:-}" = 1 ]; then
	rollback
	echo "error: failed to install txt pin; restored previous pair" >&2
	exit 1
fi
if ! mv -f "$NEW_TXT" "$DEST_TXT"; then
	rollback
	echo "error: failed to install txt pin; restored previous pair" >&2
	exit 1
fi
rm -f "$BAK_NDJSON" "$BAK_TXT"
