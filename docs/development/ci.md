# CI

Decernor uses GitHub Actions with the Fulmen goneat toolbox runner image
(`ghcr.io/fulmenhq/goneat-tools-runner-glibc:v0.5.6`, pinned by digest;
Go `1.26.6`, Goneat module `v0.6.0`).

The CI workflow currently verifies:

- embedded identity mirror
- module download
- pinned govulncheck, gosec, and gitleaks scans
- dependency-license policy
- format check
- lint
- tests
- build
- standalone binary execution outside the repository

The runner image owns build, format, and lint tools. It does not bundle the
security scanners, so CI installs their exact reviewed versions through the
shared `make security-gates` target. Missing tools, downloads, scanner errors,
findings at the configured thresholds, and license-policy failures are fatal.

License verification has two explicit scopes. The committed
`.goneat/license-baseline.json` must exactly match `go list -m all`, including
test-only and graph modules, and every entry must name an allowed license.
Goneat's report is then reconciled exactly against the narrower runtime package
set from `go list -deps ./...`. Goneat v0.6.0's known Go 1.26 standard-library
metadata degradation is accepted only after both coverage checks pass. The
three reviewed classifier aliases in the baseline are pinned to exact module
and Goneat versions, so dependency or detector changes require review.
