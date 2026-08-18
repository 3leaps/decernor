#!/usr/bin/env bash
# Export public signing keys into dist/release. Env vars only.
set -euo pipefail

DIR=${1:-dist/release}
mkdir -p "$DIR"

echo "Exporting public keys to $DIR..."

if [ -z "${DECERNOR_MINISIGN_PUB:-}" ]; then
	echo "error: DECERNOR_MINISIGN_PUB is not set" >&2
	exit 2
fi
if [ ! -f "$DECERNOR_MINISIGN_PUB" ]; then
	echo "error: DECERNOR_MINISIGN_PUB is not a readable file" >&2
	exit 2
fi
cp "$DECERNOR_MINISIGN_PUB" "$DIR/decernor-minisign.pub"
echo "[ok] Exported $DIR/decernor-minisign.pub"

if [ -z "${DECERNOR_PGP_KEY_ID:-}" ]; then
	echo "error: DECERNOR_PGP_KEY_ID is not set" >&2
	exit 2
fi
GPG_OPTS=(--batch --no-tty --armor --export "$DECERNOR_PGP_KEY_ID")
if [ -n "${DECERNOR_GPG_HOMEDIR:-}" ]; then
	GPG_OPTS=(--homedir "$DECERNOR_GPG_HOMEDIR" "${GPG_OPTS[@]}")
fi
gpg "${GPG_OPTS[@]}" >"$DIR/decernor-release-signing-key.asc"
echo "[ok] Exported $DIR/decernor-release-signing-key.asc"
