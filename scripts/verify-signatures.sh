#!/usr/bin/env bash
# Verify minisign (required) and PGP (if present) signatures on SUMS.
set -euo pipefail

DIR=${1:-dist/release}
cd "$DIR"

ERRORS=0

if [ ! -f "decernor-minisign.pub" ]; then
	echo "[!!] decernor-minisign.pub not found" >&2
	exit 1
fi

for manifest in SHA256SUMS SHA512SUMS; do
	if [ ! -f "$manifest" ] || [ ! -f "${manifest}.minisig" ]; then
		echo "[!!] missing $manifest or ${manifest}.minisig" >&2
		ERRORS=$((ERRORS + 1))
		continue
	fi
	if minisign -Vm "$manifest" -p decernor-minisign.pub; then
		echo "[ok] $manifest minisign valid"
	else
		echo "[!!] $manifest minisign INVALID" >&2
		ERRORS=$((ERRORS + 1))
	fi
done

if [ -f "decernor-release-signing-key.asc" ]; then
	GNUPGHOME=$(mktemp -d)
	export GNUPGHOME
	trap 'rm -rf "$GNUPGHOME"' EXIT
	gpg --import decernor-release-signing-key.asc >/dev/null 2>&1
	for manifest in SHA256SUMS SHA512SUMS; do
		if [ -f "${manifest}.asc" ]; then
			if gpg --verify "${manifest}.asc" "$manifest" >/dev/null 2>&1; then
				echo "[ok] $manifest PGP valid"
			else
				echo "[!!] $manifest PGP INVALID" >&2
				ERRORS=$((ERRORS + 1))
			fi
		fi
	done
fi

if [ "$ERRORS" -ne 0 ]; then
	exit 1
fi
echo "[ok] All signatures verified"
