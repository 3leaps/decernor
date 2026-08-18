#!/usr/bin/env bash
# Generate SHA256SUMS and SHA512SUMS for this tag's payload.
# Requires staged release notes and fingerprint pins (net-new).
set -euo pipefail

DIR=${1:-dist/release}
TAG=${2:-${DECERNOR_RELEASE_TAG:-}}

if [ ! -d "$DIR" ]; then
	echo "Error: Directory $DIR does not exist" >&2
	exit 1
fi

if [ -z "$TAG" ] || [ "$TAG" = "v" ]; then
	echo "Error: No release tag. Pass the tag or set DECERNOR_RELEASE_TAG=vX.Y.Z" >&2
	exit 1
fi

VERSION="${TAG#v}"
NOTES="release-notes-${TAG}.md"
PIN_TXT="expected-fingerprints.txt"
PIN_NDJSON="expected-fingerprints.ndjson"

cd "$DIR"

for required in "$NOTES" "$PIN_TXT" "$PIN_NDJSON"; do
	if [ ! -f "$required" ]; then
		echo "Error: $required not in $DIR" >&2
		echo "Copy notes and pins before checksums:" >&2
		echo "  make release-notes" >&2
		echo "  make release-stage-anchors" >&2
		exit 1
	fi
done

echo "Generating checksums in $DIR for $TAG..."

CHECKSUM_FILES=()
for f in "$NOTES" "$PIN_TXT" "$PIN_NDJSON" \
	"decernor_${VERSION}_"*.tar.gz \
	"decernor_${VERSION}_"*.zip; do
	if [ -f "$f" ]; then
		CHECKSUM_FILES+=("$f")
	fi
done

if [ ${#CHECKSUM_FILES[@]} -lt 3 ]; then
	echo "Error: no archive candidates for $TAG in $DIR" >&2
	exit 1
fi

printf '%s\n' "${CHECKSUM_FILES[@]}" | LC_ALL=C sort | xargs shasum -a 256 >SHA256SUMS
printf '%s\n' "${CHECKSUM_FILES[@]}" | LC_ALL=C sort | xargs shasum -a 512 >SHA512SUMS

echo "Generated SHA256SUMS:"
cat SHA256SUMS
echo ""
echo "[ok] Checksums generated"
