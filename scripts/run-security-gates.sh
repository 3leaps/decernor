#!/usr/bin/env bash
# Reproducible security and license gates shared by local, CI, and release runs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_BIN="${DECERNOR_SECURITY_TOOLS_BIN:-${ROOT}/.cache/security-tools/bin}"
GOSEC_PACKAGE='github.com/securego/gosec/v2/cmd/gosec@v2.29.0'
GITLEAKS_PACKAGE='github.com/zricethezav/gitleaks/v8@v8.30.1'
GOVULNCHECK_PACKAGE='golang.org/x/vuln/cmd/govulncheck@v1.8.0'

mkdir -p "$TOOLS_BIN"
export GOBIN="$TOOLS_BIN"
export PATH="$TOOLS_BIN:$PATH"
cd "$ROOT"

echo '==> Preparing pinned security tools'
go install "$GOSEC_PACKAGE"
go install "$GITLEAKS_PACKAGE"

echo '==> Resolved security toolchain'
go version
go run "$GOVULNCHECK_PACKAGE" -version
gosec --version
go version -m "$TOOLS_BIN/gosec"
gitleaks version
go version -m "$TOOLS_BIN/gitleaks"
goneat version

echo '==> govulncheck: no reachable or package vulnerabilities'
go run "$GOVULNCHECK_PACKAGE" ./...

echo '==> gosec: no high-severity, high-confidence findings'
gosec -severity high -confidence high ./...

echo '==> gitleaks: no findings in full repository history'
gitleaks detect --no-banner --redact --exit-code 1
echo '==> gitleaks: no findings in the current working tree'
gitleaks dir --no-banner --redact --exit-code 1 .

echo '==> dependency licenses: existing high-severity policy'
./scripts/run-license-gate.sh

echo '[ok] security and license gates passed'
