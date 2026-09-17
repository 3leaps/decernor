#!/usr/bin/env bash
# Demonstrate that every security gate and tool preparation failure propagates.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$ROOT/scripts/run-security-gates.sh"
REAL_GO="$(command -v go)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/decernor-security-gates.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

MOCK_BIN="$WORK/mock-bin"
TOOLS_BIN="$WORK/tools-bin"
LOG="$WORK/invocations.log"
LICENSE_REPORT="$WORK/license-report.json"
mkdir -p "$MOCK_BIN" "$TOOLS_BIN"

python3 - "$ROOT/.goneat/license-baseline.json" "$LICENSE_REPORT" <<'PY'
import json, subprocess, sys
baseline = json.load(open(sys.argv[1], encoding="utf-8"))
by_id = {
    (item["path"], item["version"]): item.get("goneat", {}).get("license", item["license"])
    for item in baseline["modules"]
}
proc = subprocess.run(["go", "list", "-deps", "-json", "./..."], check=True, capture_output=True, text=True)
decoder = json.JSONDecoder(); offset = 0; runtime = set()
while offset < len(proc.stdout):
    while offset < len(proc.stdout) and proc.stdout[offset].isspace(): offset += 1
    if offset == len(proc.stdout): break
    value, offset = decoder.raw_decode(proc.stdout, offset)
    module = value.get("Module")
    if module: runtime.add((module["Path"], module.get("Version", "")))
dependencies = [{"Name": p, "Version": v, "License": {"Type": by_id[(p, v)]}} for p, v in sorted(runtime)]
json.dump({"Dependencies": dependencies, "Issues": [], "Passed": True}, open(sys.argv[2], "w", encoding="utf-8"))
PY

cat >"$MOCK_BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'go %s\n' "$*" >>"$SECURITY_GATE_TEST_LOG"
case "${1:-}" in
version)
    echo 'go version go1.26.6 test/arch'
    ;;
install)
    if [ "${FAIL_GATE:-}" = 'prepare' ]; then
        echo 'synthetic download failure' >&2
        exit 73
    fi
    case "${2:-}" in
    *gosec*) name=gosec ;;
    *gitleaks*) name=gitleaks ;;
    *) exit 2 ;;
    esac
    if [ "${FAIL_GATE:-}" = "missing-$name" ]; then
        exit 0
    fi
    cat >"$GOBIN/$name" <<TOOL
#!/usr/bin/env bash
set -euo pipefail
printf '$name %s\\n' "\$*" >>"\$SECURITY_GATE_TEST_LOG"
if [ "\${FAIL_GATE:-}" = '$name' ] && [[ "\${1:-}" != *version* ]]; then
    exit 74
fi
if [ '$name' = 'gitleaks' ] && [ "\${FAIL_GATE:-}" = 'gitleaks-dir' ] && [ "\${1:-}" = 'dir' ]; then
    exit 77
fi
echo '$name synthetic-version'
TOOL
    chmod +x "$GOBIN/$name"
    ;;
run)
    if [ "${2:-}" != 'golang.org/x/vuln/cmd/govulncheck@v1.8.0' ]; then
        exit 2
    fi
    if [ "${3:-}" = '-version' ]; then
        echo 'govulncheck synthetic-version'
    elif [ "${FAIL_GATE:-}" = 'govulncheck' ]; then
        exit 75
    fi
    ;;
*) exit 2 ;;
esac
EOF
chmod +x "$MOCK_BIN/go"

cat >"$MOCK_BIN/goneat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'goneat %s\n' "$*" >>"$SECURITY_GATE_TEST_LOG"
if [ "${1:-}" = 'version' ]; then
    echo 'goneat v0.6.0'
    echo 'Module: v0.6.0'
elif [ "${FAIL_GATE:-}" = 'license' ]; then
    exit 76
elif [ "${1:-}" = 'dependencies' ]; then
    output=''
    while [ "$#" -gt 0 ]; do
        if [ "$1" = '--output' ]; then
            output=$2
            break
        fi
        shift
    done
    [ -n "$output" ] || exit 2
    cp "$SECURITY_GATE_LICENSE_REPORT" "$output"
fi
EOF
chmod +x "$MOCK_BIN/goneat"

run_case() {
    local fail_gate=$1
    local want_success=$2
    : >"$LOG"
    rm -rf "$TOOLS_BIN"
    mkdir -p "$TOOLS_BIN"
    set +e
    PATH="$MOCK_BIN:/usr/bin:/bin" \
        FAIL_GATE="$fail_gate" \
        SECURITY_GATE_TEST_LOG="$LOG" \
        SECURITY_GATE_LICENSE_REPORT="$LICENSE_REPORT" \
        DECERNOR_LICENSE_GO="$REAL_GO" \
        DECERNOR_SECURITY_TOOLS_BIN="$TOOLS_BIN" \
        "$RUNNER" >"$WORK/output.log" 2>&1
    status=$?
    set -e
    if [ "$want_success" = 'yes' ] && [ "$status" -ne 0 ]; then
        cat "$WORK/output.log" >&2
        echo "error: positive control failed with status $status" >&2
        exit 1
    fi
    if [ "$want_success" = 'no' ] && [ "$status" -eq 0 ]; then
        echo "error: $fail_gate failure was accepted" >&2
        exit 1
    fi
}

run_case '' yes
echo '[ok] security-gate positive control passes'

for gate in prepare missing-gosec govulncheck gosec gitleaks gitleaks-dir license; do
    run_case "$gate" no
    echo "[ok] $gate failure propagates"
done
