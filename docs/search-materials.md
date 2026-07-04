# Search Materials

Decernor detects key-material artifacts using a deliberately small local corpus of packet markers, armor headers, filename patterns, and keyring-internal names.

## Corpus Location

Scanner search material lives in:

- `internal/scanner/corpus.go`: detector markers, armor header constructors, filename maps, and extension maps.
- `internal/scanner/classifier.go`: policy decisions that convert corpus matches into findings.
- `internal/scanner/*_test.go`: runtime-generated synthetic inputs and mocked packet output.

Keep detector strings and filename lists in `corpus.go` unless a value is purely local to a parser.

## Fixture Rules

- Do not commit real private keys, public keys tied to real identities, revocation certificates, keyrings, passphrases, fingerprints from real material, or scan output from real machines.
- Prefer runtime-generated synthetic inputs in tests.
- Use mocked `gpg --list-packets` output for OpenPGP packet classification tests.
- If a static fixture becomes necessary, it must be synthetic, documented, and
  reviewed for secret-handling risk.

## Current Guardrails

- `TestCommittedFixturesContainNoPrivateKeyMaterial` scans committed docs/examples/schemas/tests for private-material markers.
- Scanner tests construct OpenPGP/OpenSSH/minisign-looking content at runtime rather than storing key fixture files.
- `find . -type f` should not show committed `.asc`, `.gpg`, `.kbx`, `.pem`, `.key`, `.minisig`, or `.sig` fixture files unless a reviewed exception is documented.

## Review Checklist

- Does the corpus include only generic format markers or common local filenames?
- Does any committed fixture represent a real key layout or real user's material?
- Does any finding print private material instead of a short evidence phrase?
- Are severity and retention changes covered by tests?
