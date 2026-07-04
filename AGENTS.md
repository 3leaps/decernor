# Decernor Agent Guide

This guide is for agents and contributors working in this repository.

## Project

**Name:** decernor
**Purpose:** local key-material hygiene and readiness checks for humans and agents

Decernor is a CLI-only Go application. It inspects local signing and authentication
material and emits structured findings without printing private key contents.

## Before Changing Behavior

Read these files first:

- `README.md`
- `NAMING.md`
- `.fulmen/app.yaml`
- `docs/backlog.md`
- `docs/decisions/`

## Development

Use Make targets unless there is a narrow reason not to:

```sh
make test
make build
make cdrl-verify
make validate-app-identity
make test-standalone-binary
```

`make check-all` is the intended full local gate when the goneat toolchain is
available.

## Safety Rules

- Do not commit real private keys, revocation certificates, passphrases, client
  material, or generated sensitive scan output.
- Tests must use synthetic data only. Keep fixture content intentionally
  non-secret and scanner-safe.
- Scanner output may include paths. Treat real user scan output as potentially
  sensitive operational data.
- Keep stdout clean for machine-readable reports. Logs and diagnostics belong on
  stderr or explicit human-facing commands.
- Preserve app identity embedding: edit `.fulmen/app.yaml`, then run
  `make sync-embedded-identity`.

## Product Shape

Current commands:

- `scan PATH`: classify local key-related artifacts.
- `guardread PATH`: read one regular file to stdout only after guarded key-material checks pass.
- `readiness validate-config PATH`: validate readiness config JSON.
- `fingerprint PATH`: emit safe fingerprint records.
- `validate`: schema/data validation utility with local contract resolution.
- `version`, `envinfo`, `doctor`: baseline operational commands.

If scope grows into a daemon, service, or control plane, pause and revisit the
architecture before adding server behavior.
