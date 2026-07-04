# Decernor Backlog

This backlog tracks product capabilities at a public, implementation-oriented
level. It intentionally avoids internal planning identifiers.

## Now

### Validate + Hygiene-Gate POC Port

Status: implemented

Acceptance:

- Repository builds as `decernor`.
- No inherited upstream release history remains in `CHANGELOG.md`,
  `RELEASE_NOTES.md`, or `docs/releases/`.
- Scanner detection material is compartmentalized for review.
- Committed fixtures remain synthetic-only.
- POC license/provenance is documented.
- `make test`, `make build`, `make cdrl-verify`, `make validate-app-identity`,
  and `make test-standalone-binary` pass.

### Scanner Command Integration

Status: implemented

Acceptance:

- `decernor scan PATH` supports text and JSON output.
- `--fail-on none|warn|unsafe` controls policy exit behavior.
- `--detectors all,gpg,ssh,minisign` allows detector selection.
- JSON output remains uncontaminated by default logs.

### Readiness Config Validation

Status: implemented

Acceptance:

- `decernor readiness validate-config PATH` validates readiness configs.
- Example configs pass validation.
- Invalid provider, verb, material, and check values fail with useful errors.

### Safe Fingerprint Command

Status: implemented

Acceptance:

- `decernor fingerprint [PATHS...]` and `decernor fp [PATHS...]` emit
  structured fingerprint records.
- Default output is NDJSON; `--format json` emits a JSON array of the same
  records.
- Records are schema-versioned and covered by
  `schemas/fingerprint-record.v0.schema.json`.
- Supports `--kind`, `--class`, `--include`, `--exclude`, `--fail-on-empty`,
  and JSON config files.
- Output records use schema-constrained paths; `relative` is the default, with
  `hash` and `none` modes available.
- Walk-discovered symlinks are diagnostics, not stdout fingerprint records;
  named symlink inputs are fatal.
- The command emits safe public identity fingerprints or null fingerprints with
  closed reason enums, without printing private bytes, UIDs, SSH comments, or
  raw helper output.
- Minisign public keys emit both the native key ID and a collision-resistant
  public-blob SHA-256 fingerprint suitable for trust-anchor projection.

### Contract Validation

Status: implemented

Acceptance:

- `decernor validate --contract` resolves schemas from an explicit local
  `--contract-base`.
- Contract resolution is confined to the base, rejects symlink components, and
  does not fetch remote references.
- Version-directory contract layouts resolve through strict `contract.json`
  entry manifests.

### Classification Gate

Status: implemented

Acceptance:

- `decernor validate --classification-gate` runs after structural contract
  validation.
- Gate refusals are deterministic, sanitized, and exit with the documented gate
  refusal code.
- Unknown or missing sensitivity and unsafe predicate-pushdown descriptors fail
  closed by default.

### Guarded File Read

Status: review-ready

Acceptance:

- `decernor guardread PATH` accepts one named regular file.
- Clean text passes byte-for-byte to stdout with no stderr diagnostics.
- Supported key material, including embedded key-looking markers, refuses before
  any file byte reaches stdout.
- Symlinks, directories, special files, oversized files, and binary/ambiguous
  files fail closed.
- Refusal diagnostics are written to stderr and do not include raw matched bytes.

## Next

### Readiness Static Evaluation

Add a readiness evaluator that maps scanner findings to requested capabilities
without prompting for passphrases.

Acceptance:

- Evaluates `material-present`, `not-plaintext`, `public-counterpart`, and
  `revocation-present`.
- Emits structured readiness results suitable for CI.
- Does not read or print private key contents.

### Finding Code Catalog

Document stable finding codes and expected remediation guidance.

Acceptance:

- Every scanner code has a short description.
- Severity, retention, exposure, and recommendation are documented.
- Tests guard accidental code renames.

### Scanner Fixture Expansion

Expand synthetic fixture coverage without committing real key material.

Acceptance:

- Fixtures remain synthetic and scanner-safe.
- Coverage includes protected/unprotected OpenPGP, OpenSSH, minisign,
  revocation, public material, and keyring internals.
- No static secret scanners should flag committed test files as real private
  keys.

### Report Contract Tests

Pin JSON and text output shapes with focused tests.

Acceptance:

- JSON fields are stable and sorted where necessary.
- Text output remains human-readable.
- Logs remain absent from stdout by default.

## Later

### Local Proof Checks

Add optional proof checks such as sign-and-verify, encrypt-and-decrypt,
derive-public-key, and remote-auth simulations where safe.

Acceptance:

- Proof checks are opt-in.
- The tool never captures or transmits passphrases.
- All proof operations are local except explicitly named remote-auth checks.

### Release Provenance

Dogfood Decernor release hygiene.

Acceptance:

- Release artifacts include checksums and signatures.
- Public signing keys are verified to contain no private material.
- Release instructions include local Decernor scan examples for release bundles.
