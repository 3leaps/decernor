#!/usr/bin/env bash
# Upload signed provenance. Leaves the GitHub release as a draft.
set -euo pipefail

TAG=${1:?"usage: upload-release-assets.sh <tag> [dir]"}
DIR=${2:-dist/release}

if [ ! -d "$DIR" ]; then
	echo "Error: Directory $DIR does not exist" >&2
	exit 1
fi

cd "$DIR"

REQUIRED_FILES=(
	"SHA256SUMS"
	"SHA256SUMS.minisig"
	"SHA512SUMS"
	"SHA512SUMS.minisig"
	"decernor-minisign.pub"
	"expected-fingerprints.txt"
	"expected-fingerprints.ndjson"
	"release-notes-${TAG}.md"
)

for file in "${REQUIRED_FILES[@]}"; do
	if [ ! -f "$file" ]; then
		echo "Error: Required file missing: $file" >&2
		exit 1
	fi
done

UPLOAD_FILES=(
	"SHA256SUMS"
	"SHA256SUMS.minisig"
	"SHA512SUMS"
	"SHA512SUMS.minisig"
	"decernor-minisign.pub"
	"expected-fingerprints.txt"
	"expected-fingerprints.ndjson"
	"release-notes-${TAG}.md"
)

for optional in "SHA256SUMS.asc" "SHA512SUMS.asc" "decernor-release-signing-key.asc"; do
	if [ -f "$optional" ]; then
		UPLOAD_FILES+=("$optional")
	fi
done

echo "Uploading files:"
printf '  %s\n' "${UPLOAD_FILES[@]}"
gh release upload "$TAG" "${UPLOAD_FILES[@]}" --clobber
gh release edit "$TAG" --notes-file "release-notes-${TAG}.md"

echo "[ok] Release $TAG assets uploaded (draft unchanged)"
echo "Publish when ready: gh release edit $TAG --draft=false"
