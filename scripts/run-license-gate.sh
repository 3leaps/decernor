#!/usr/bin/env bash
# Run Goneat policy and independently reconcile it against the full Go graph.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/decernor-license-gate.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM
REPORT="$WORK/goneat-license-report.json"

cd "$ROOT"
goneat_output="$(goneat version)"
printf '%s\n' "$goneat_output"
DECERNOR_GONEAT_VERSION="$(printf '%s\n' "$goneat_output" | awk '$1 == "Module:" { print $2; exit }')"
[ -n "$DECERNOR_GONEAT_VERSION" ] || {
    echo 'error: could not resolve Goneat module version' >&2
    exit 1
}
export DECERNOR_GONEAT_VERSION
goneat dependencies --licenses --fail-on high --format json --output "$REPORT"
python3 scripts/verify-license-report.py "$REPORT"
