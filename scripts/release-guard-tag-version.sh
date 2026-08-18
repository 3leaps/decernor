#!/usr/bin/env bash
# Verify DECERNOR_RELEASE_TAG matches VERSION.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ ! -f VERSION ]; then
	echo "error: VERSION file not found" >&2
	exit 1
fi
version="$(tr -d ' \t\r\n' <VERSION)"
expected="v${version}"
tag="${DECERNOR_RELEASE_TAG:-}"
if [ -z "$tag" ]; then
	tag="$(git describe --tags --exact-match 2>/dev/null || true)"
fi
if [ -z "$tag" ]; then
	tag="$expected"
fi
if [ "$tag" != "$expected" ]; then
	echo "error: release tag/version mismatch ($tag != $expected)" >&2
	exit 1
fi
echo "[ok] release guard: tag matches VERSION ($tag)"
