#!/usr/bin/env bash
# Assert the release upload remains a single pinned draft publication step.

set -euo pipefail

workflow="${1:-.github/workflows/release.yml}"
release_sha='efb35369e0ad2afab669f228072c1b0d510eae64'

[ -f "$workflow" ] || {
    echo "error: workflow not found: $workflow" >&2
    exit 2
}

upload_count="$(grep -Ec "^[[:space:]]+uses: softprops/action-gh-release@${release_sha}([[:space:]]+#.*)?[[:space:]]*$" "$workflow" || true)"
[ "$upload_count" -eq 1 ] || {
    echo "error: expected exactly one pinned action-gh-release upload, found $upload_count" >&2
    exit 1
}

draft_count="$(grep -Ec '^[[:space:]]+draft:[[:space:]]+true[[:space:]]*$' "$workflow" || true)"
[ "$draft_count" -eq 1 ] || {
    echo "error: expected exactly one draft: true publication setting, found $draft_count" >&2
    exit 1
}

echo '[ok] release workflow has one pinned draft publication step'
