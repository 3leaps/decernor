# Decernor Development

## Local Gates

```sh
make test
make build
make test-standalone-binary
make cdrl-verify
make validate-app-identity
```

Run `make check-all` when goneat is installed.

## Command Smoke Tests

```sh
./bin/decernor version
./bin/decernor envinfo
./bin/decernor doctor
./bin/decernor readiness validate-config examples/github-org-bootstrap.readiness.json
./bin/decernor scan examples --format json --fail-on none
```

## Implementation Notes

- Keep stdout clean for scan and readiness data output.
- Keep logs disabled by default; use `--log-level` only when the caller asks for diagnostics.
- Use synthetic scanner fixtures only.
- Keep scanner detector strings and filename patterns in `internal/scanner/corpus.go`.
- Review `docs/search-materials.md` before changing detector material.
- Update `.fulmen/app.yaml` first for identity changes, then run `make sync-embedded-identity`.
- Add tests for every new classifier, severity change, readiness rule, and report contract change.
