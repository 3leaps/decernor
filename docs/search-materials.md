# Search Materials

Decernor detects key-material artifacts using a deliberately small local corpus of packet markers, armor headers, filename patterns, keyring-internal names, and GnuPG agent key S-expression tokens.

## Corpus Location

Scanner search material lives in:

- `internal/scanner/corpus.go`: detector markers, armor header constructors, filename maps, and extension maps.
- `internal/scanner/classifier.go`: policy decisions that convert corpus matches into findings.
- `internal/scanner/*_test.go`: mocked packet output and non-key inputs. Key-shaped inputs come from the external fixture corpus ([PDR-0002](decisions/PDR-0002-tests-consume-external-fixture-corpus.md)).

Keep detector strings and filename lists in `corpus.go` unless a value is purely local to a parser.

## Fixture Rules

- Do not commit real private keys, public keys tied to real identities, revocation certificates, keyrings, passphrases, fingerprints from real material, or scan output from real machines.
- Key-shaped test inputs come from the external fixture corpus, never from test helpers in this repository ([PDR-0002](decisions/PDR-0002-tests-consume-external-fixture-corpus.md)).
- Use mocked `gpg --list-packets` output for OpenPGP packet classification tests.
- If a static fixture becomes necessary, it must be synthetic, documented, and
  reviewed for secret-handling risk.

## Current Guardrails

- `TestCommittedFixturesContainNoPrivateKeyMaterial` scans committed docs/examples/schemas/tests for private-material markers.
- Some tests still construct key-shaped content at runtime. That is transitional under [PDR-0002](decisions/PDR-0002-tests-consume-external-fixture-corpus.md). The hygiene test rejects committed plaintext agent key tokens.
- `find . -type f` should not show committed `.asc`, `.gpg`, `.kbx`, `.pem`, `.key`, `.minisig`, or `.sig` fixture files unless a reviewed exception is documented.

## Review Checklist

- Does the corpus include only generic format markers or common local filenames?
- Does any committed fixture represent a real key layout or real user's material?
- Does any finding print private material instead of a short evidence phrase?
- Are severity and retention changes covered by tests?
