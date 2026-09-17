#!/usr/bin/env bash
# Prove required bootstrap scope failures cannot be masked by later successes.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/decernor-bootstrap.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

BIN="$WORK/bin"
LOG="$WORK/invocations.log"
mkdir -p "$BIN"

cat >"$BIN/sfetch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'sfetch %s\n' "$*" >>"$BOOTSTRAP_TEST_LOG"
if [ "${1:-}" = '--version' ]; then
    echo 'sfetch v0.4.12'
fi
EOF

cat >"$BIN/goneat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'goneat %s\n' "$*" >>"$BOOTSTRAP_TEST_LOG"
if [ "${1:-}" = '--version' ]; then
    echo 'goneat v0.6.0'
    exit 0
fi
if [ "${1:-}" = 'doctor' ]; then
    for ((i = 1; i <= $#; i++)); do
        if [ "${!i}" = '--scope' ]; then
            next=$((i + 1))
            scope="${!next}"
            if [ "$scope" = "${FAIL_SCOPE:-}" ]; then
                exit 73
            fi
            exit 0
        fi
    done
fi
exit 0
EOF

cat >"$BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'go %s\n' "$*" >>"$BOOTSTRAP_TEST_LOG"
EOF

chmod +x "$BIN/sfetch" "$BIN/goneat" "$BIN/go"

run_bootstrap() {
    PATH="$BIN:$PATH" \
        BOOTSTRAP_TEST_LOG="$LOG" \
        FAIL_SCOPE="$1" \
        make -C "$ROOT" bootstrap BINDIR="$BIN" >/dev/null 2>&1
}

for failed_scope in foundation security; do
    : >"$LOG"
    if run_bootstrap "$failed_scope"; then
        echo "error: required bootstrap scope passed after $failed_scope failure" >&2
        exit 1
    fi
    grep -q "goneat doctor tools --scope $failed_scope --install --yes" "$LOG"
    if grep -q '^go ' "$LOG"; then
        echo "error: Go dependency step ran after $failed_scope failure" >&2
        exit 1
    fi
    echo "[ok] required $failed_scope failure propagates"
done

: >"$LOG"
run_bootstrap bootstrap
grep -q 'goneat doctor tools --scope format --install --yes' "$LOG"
grep -q '^go mod tidy$' "$LOG"
echo '[ok] advisory bootstrap-scope failure still permits required scopes'
