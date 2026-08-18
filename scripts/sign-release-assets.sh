#!/usr/bin/env bash
# Sign checksum manifests. Requires DECERNOR_MINISIGN_KEY. PGP optional.
set -euo pipefail

TAG=${1:?"usage: sign-release-assets.sh <tag> [dir]"}
DIR=${2:-dist/release}

if [ ! -d "$DIR" ]; then
	echo "Error: Directory $DIR does not exist" >&2
	exit 1
fi

if [ -z "${DECERNOR_MINISIGN_KEY:-}" ]; then
	echo "error: DECERNOR_MINISIGN_KEY is not set" >&2
	exit 2
fi
if [ ! -f "$DECERNOR_MINISIGN_KEY" ]; then
	echo "error: DECERNOR_MINISIGN_KEY is not a readable file" >&2
	exit 2
fi

cd "$DIR"

for manifest in SHA256SUMS SHA512SUMS; do
	if [ ! -f "$manifest" ]; then
		echo "Error: $manifest not found in $DIR" >&2
		echo "Run: make release-checksums" >&2
		exit 1
	fi
done

echo "Signing release $TAG..."
for manifest in SHA256SUMS SHA512SUMS; do
	minisign -S -s "$DECERNOR_MINISIGN_KEY" \
		-m "$manifest" \
		-t "decernor $TAG" \
		-x "${manifest}.minisig"
	echo "[ok] Created ${manifest}.minisig"
done

if [ -n "${DECERNOR_PGP_KEY_ID:-}" ]; then
	GPG_OPTS=(--armor --detach-sign --local-user "$DECERNOR_PGP_KEY_ID")
	if [ -n "${DECERNOR_GPG_HOMEDIR:-}" ]; then
		GPG_OPTS=(--homedir "$DECERNOR_GPG_HOMEDIR" "${GPG_OPTS[@]}")
	fi
	for manifest in SHA256SUMS SHA512SUMS; do
		gpg "${GPG_OPTS[@]}" --output "${manifest}.asc" "$manifest"
		echo "[ok] Created ${manifest}.asc"
	done
else
	echo "[--] PGP signing skipped (DECERNOR_PGP_KEY_ID not set)"
fi
