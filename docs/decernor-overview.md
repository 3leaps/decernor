---
title: "Decernor Overview"
description: "Local key-material hygiene and readiness checks"
status: "draft"
---

# Decernor Overview

Decernor is a CLI tool for inspecting local signing and authentication material without exposing private key contents. It classifies local artifacts and emits structured findings that humans, CI jobs, and AI agents can consume safely.

## Scope

Decernor answers a few questions:

- `scan`: what risky or sensitive key material is present in this path?
- `guardread`: can this one file be written to stdout without first exposing supported key-material bytes?
- `fingerprint`: what safe public identity fingerprints can be emitted for this key material?
- `readiness`: does an asset set appear to have enough protected material for a capability?

It is intentionally CLI-only. It should not become a daemon, web service, remote scanner, or key store without an explicit architecture review.

## Current Commands

| Command                          | Purpose                                                                   |
| -------------------------------- | ------------------------------------------------------------------------- |
| `scan PATH`                      | Inspect a directory and report local key-material findings.               |
| `guardread FILE`                 | Write one file to stdout only if it is not supported key material.        |
| `fingerprint PATH`               | Emit public identity fingerprints (alias: `fp`).                          |
| `readiness validate-config PATH` | Validate readiness configuration JSON.                                    |
| `version`                        | Print build version, with optional extended dependency details.           |
| `envinfo`                        | Print runtime, config, and app identity details.                          |
| `doctor`                         | Run local installation diagnostics.                                       |
| `validate`                       | Validate schema/data files; retained while readiness schema work matures. |

## Scanner Model

The scanner currently handles:

- OpenPGP public material, encrypted containers, protected secret keys, unprotected secret keys, and revocation certificates.
- OpenSSH encrypted and unprotected private keys.
- Minisign secret material markers and common secret-key filenames.
- Generic PEM private-key headers.
- Copied GPG keyring internals such as `.gnupg`, `private-keys-v1.d`, and trust/keybox files.

Findings include stable code, priority, severity, classification, retention, exposure, sensitivity, confidence, evidence, and recommendation fields.

The detector corpus is isolated in `internal/scanner/corpus.go`; see `docs/search-materials.md` for fixture and review rules.

## Output Contract

- Data reports go to stdout.
- Logs are disabled by default and must not contaminate JSON report output.
- The tool never prints private key material or passphrases.
- Real scan output may still include local file paths and should be treated as operationally sensitive.

## Readiness Model

Readiness configs describe capabilities using provider and verb pairs such as:

- `gpg/sign`
- `gpg/encrypt`
- `minisign/sign`
- `ssh/auth`

The current implementation validates config shape. Future work should add static readiness evaluation and local-only proof checks without transmitting key material.

## Build And Verification

```sh
make test
make build
make test-standalone-binary
make cdrl-verify
make validate-app-identity
```

Use `make check-all` when the full goneat toolchain is available.
