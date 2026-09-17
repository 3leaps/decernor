#!/usr/bin/env bash
# Negative controls for the draft-release workflow invariant.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY="$ROOT/scripts/verify-release-workflow-policy.sh"
SOURCE="$ROOT/.github/workflows/release.yml"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/decernor-release-policy.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

"$VERIFY" "$SOURCE"

expect_rejected() {
    local name=$1
    local file=$2
    if "$VERIFY" "$file" >/dev/null 2>&1; then
        echo "error: accepted release workflow mutation: $name" >&2
        exit 1
    fi
    echo "[ok] rejected release workflow mutation: $name"
}

sed 's/draft: true/draft: false/' "$SOURCE" >"$WORK/public.yml"
expect_rejected 'non-draft publication' "$WORK/public.yml"

sed 's/softprops\/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64/softprops\/action-gh-release@v3/' \
    "$SOURCE" >"$WORK/floating-action.yml"
expect_rejected 'floating release action' "$WORK/floating-action.yml"

cat "$SOURCE" "$SOURCE" >"$WORK/duplicate-upload.yml"
expect_rejected 'duplicate publication step' "$WORK/duplicate-upload.yml"
