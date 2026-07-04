# Release Notes

This file will track Decernor release notes once the first release candidate is cut.

## Unreleased

### Current State

Decernor is in initial application bootstrap. The repository now builds as `decernor`, carries the product README and naming record, and includes the first scanner/readiness functionality from the successful proof of concept.

### Verification Baseline

- `make test`
- `make build`
- `make cdrl-verify`
- `make validate-app-identity`
- `make test-standalone-binary`
- Command smoke tests for `version`, `envinfo`, `doctor`, `scan`, and `readiness validate-config`

### Release Notes Policy

Keep release notes product-focused. Do not include private scan outputs, local file paths from real users, client identifiers, key fingerprints from real material, or passphrase/key handling details beyond generic behavior.
