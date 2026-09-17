#!/usr/bin/env bash
# Mutation controls for full-graph license reconciliation.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY="$ROOT/scripts/verify-license-report.py"
BASELINE="$ROOT/.goneat/license-baseline.json"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/decernor-license-report.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

cd "$ROOT"
python3 - "$BASELINE" "$WORK/report.json" <<'PY'
import json, subprocess, sys

baseline = json.load(open(sys.argv[1], encoding="utf-8"))
by_id = {
    (item["path"], item["version"]): item.get("goneat", {}).get("license", item["license"])
    for item in baseline["modules"]
}
proc = subprocess.run(["go", "list", "-deps", "-json", "./..."], check=True, capture_output=True, text=True)
decoder = json.JSONDecoder()
offset = 0
runtime = set()
while offset < len(proc.stdout):
    while offset < len(proc.stdout) and proc.stdout[offset].isspace():
        offset += 1
    if offset == len(proc.stdout):
        break
    value, offset = decoder.raw_decode(proc.stdout, offset)
    module = value.get("Module")
    if module:
        runtime.add((module["Path"], module.get("Version", "")))
dependencies = []
for identity in sorted(runtime):
    path, version = identity
    dependencies.append({"Name": path, "Version": version, "License": {"Type": by_id[identity]}})
report = {
    "Dependencies": dependencies,
    "Issues": [{
        "Type": "license",
        "Severity": "medium",
        "Message": "License detection degraded: some errors occurred when loading direct and transitive dependency packages",
        "Dependency": None,
    }],
    "Passed": True,
}
json.dump(report, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY

DECERNOR_GONEAT_VERSION=v0.6.0 "$VERIFY" "$WORK/report.json" "$BASELINE" >/dev/null
echo '[ok] complete graph and exact known degradation accepted'

expect_rejected() {
    local name=$1
    local report=$2
    local baseline=${3:-$BASELINE}
    local goneat_version=${DECERNOR_GONEAT_VERSION:-v0.6.0}
    if DECERNOR_GONEAT_VERSION="$goneat_version" "$VERIFY" "$report" "$baseline" >/dev/null 2>&1; then
        echo "error: accepted license mutation: $name" >&2
        exit 1
    fi
    echo "[ok] rejected license mutation: $name"
}

jq 'del(.Dependencies[0])' "$WORK/report.json" >"$WORK/missing-runtime.json"
expect_rejected 'degraded report with missing runtime module' "$WORK/missing-runtime.json"

jq '.Issues[0].Message = "different detector failure"' "$WORK/report.json" >"$WORK/unexpected-issue.json"
expect_rejected 'unexpected issue identity' "$WORK/unexpected-issue.json"

jq '(.Dependencies[] | select(.Name == "github.com/google/uuid")).License.Type = "BSD-3-Clause"' \
    "$WORK/report.json" >"$WORK/unlisted-classifier.json"
expect_rejected 'unlisted classifier value' "$WORK/unlisted-classifier.json"

jq 'del(.modules[] | select(.path == "github.com/clipperhouse/uax29/v2"))' \
    "$BASELINE" >"$WORK/missing-graph.json"
expect_rejected 'degraded report with missing non-runtime graph module' \
    "$WORK/report.json" "$WORK/missing-graph.json"

jq '.scope.goneat_runtime = "go list -deps -test -json ./..."' \
    "$BASELINE" >"$WORK/scope-drift.json"
expect_rejected 'unreviewed reconciliation scope' "$WORK/report.json" "$WORK/scope-drift.json"

jq '.modules[0].license = "GPL-3.0"' "$BASELINE" >"$WORK/disallowed.json"
expect_rejected 'disallowed license' "$WORK/report.json" "$WORK/disallowed.json"

jq '.modules[0].license = ""' "$BASELINE" >"$WORK/empty.json"
expect_rejected 'empty license' "$WORK/report.json" "$WORK/empty.json"

jq '(.modules[] | select(.path == "github.com/google/uuid")).goneat.license = "GPL-3.0"' \
    "$BASELINE" >"$WORK/disallowed-alias.json"
expect_rejected 'disallowed classifier alias' "$WORK/report.json" "$WORK/disallowed-alias.json"

DECERNOR_GONEAT_VERSION=v0.6.1 expect_rejected \
    'detector upgrade invalidates aliases' "$WORK/report.json"
