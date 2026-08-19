# decernor

> **Discern, then decide — before you sign.**
> Local key-material hygiene and readiness checks for humans and agents.

`decernor` inspects local signing and authentication material — GPG, minisign, and
SSH keys, revocation certificates, public counterparts, and checksum manifests — and
**decides** what is plaintext, what is protected, what is public, and what to remove,
retain, or inspect. It reads the _state_, never the _secret_.

> **Name note:** `decernor` (from Latin _decernere_, "to decide / determine / decree";
> root _cernere_, "to sift, distinguish, discern") is the locked name for the tool
> previously proven in an internal prototype. Pronounced **deh-SUR-nor**.
> See [`NAMING.md`](NAMING.md) for the decision record. The binary, module path, and
> config surfaces below use the final name; mechanical rename of the prototype is a
> graduation task.

## Product Thesis

This tool helps humans and AI agents inspect local key-material hygiene without directly reading, copying, or disclosing private key contents.

Modern release and automation workflows depend on local signing and authentication assets: GPG keys, minisign keys, SSH keys, revocation certificates, public counterparts, and checksum/signature manifests. Those assets are powerful and easy to mishandle. A human operator may need to know whether a machine is clean enough, whether a secure archive contains the right encrypted materials, or whether an automation session can proceed without exposing secrets to a remote agent.

The core idea is simple:

> Trusted local code inspects sensitive local state and emits structured findings. Humans and agents consume the findings, not the private key material.

The tool does not make a software-held key magically safe. It distinguishes between plaintext private material, encrypted/passphrase-protected material, public material, operationally sensitive artifacts such as revocation certificates, and copied keyring internals. It reports whether something should be removed, retained with controls, or inspected manually.

## Positioning

This is a general OSS trust utility, homed in the **`3leaps`** collection org.

It is adjacent to tools like:

- `sfetch`: verifies downloaded release artifacts before execution.
- `shellsentry`: inspects shell scripts before execution.
- `decernor` (this tool): inspects local key-material state before humans or agents act on it.

AI-assisted workflows are an important use case: agents can use this tool to avoid asking users to paste, upload, or describe private key files in a live session. Decernor uses Fulmen microtool foundations for config, schema validation, structured logging, identity, and release ceremony patterns.

## Audiences

- Release engineers preparing signed OSS releases.
- Operators creating or archiving GPG, minisign, and SSH assets.
- Less experienced users who need plain guidance on whether local key files are plaintext, encrypted, or public-only.
- AI agents that need to reason about key readiness without reading key contents.
- Enterprise teams that need policy-shaped output for local machine cleansing, secure handoff, and release signing readiness.

## Main Modes

### Scan

`scan` answers:

> What risky or sensitive key material is present here?

Examples:

```sh
go run ./cmd/decernor scan /path/to/artifacts
go run ./cmd/decernor scan /path/to/artifacts --format json
go run ./cmd/decernor scan /path/to/artifacts --profile workstation
go run ./cmd/decernor scan /path/to/artifacts --fail-on warn
go run ./cmd/decernor scan /path/to/artifacts --allow-protected-secret-keys
go run ./cmd/decernor --log-level info scan /path/to/artifacts --format json
```

Scan reports are written to stdout. Operational logs are written to stderr when enabled with `--log-level info`, so CI can safely pipe JSON reports without log contamination.

### Guardread

`guardread` answers:

> Can this one file be read to stdout without first exposing supported key-material bytes?

Example:

```sh
go run ./cmd/decernor guardread ./notes.txt
```

The command accepts one named regular file. It rejects symlinks, directories,
special files, oversized files, binary/ambiguous input, and supported key-material
detections before writing any file byte to stdout. On pass, stdout is the file
content only. On refusal, stdout is empty and sanitized diagnostics are written to
stderr with exit code 3. Input and usage errors exit 2.

`guardread` is not a prompt-injection filter or a general content-safety system.
It protects the supported detector classes Decernor can recognize; arbitrary
prose still needs whatever higher-level review applies to that workflow.

### Readiness

`readiness` answers:

> Do I have enough usable, protected material for a capability?

Capabilities use a provider plus verb model:

- `gpg/sign`
- `gpg/encrypt`
- `minisign/sign`
- `ssh/auth`

The current prototype includes schema-backed config validation:

```sh
go run ./cmd/decernor readiness validate-config examples/github-org-bootstrap.readiness.json
```

### Fingerprint

`fingerprint` answers:

> What safe public identity fingerprints can be emitted for this key material?

Examples:

```sh
go run ./cmd/decernor fingerprint /path/to/artifacts
go run ./cmd/decernor fp /path/to/artifacts --kind ssh,minisign
go run ./cmd/decernor fingerprint /path/to/artifacts --format json
go run ./cmd/decernor fingerprint /path/to/artifacts --fail-on-empty
go run ./cmd/decernor fingerprint ./release.gpg.asc --class public --kind gpg \
  --format json --path-mode none --gpg-role primary
```

The default format is newline-delimited JSON. `--format json` emits an array of
the same records. Fingerprint records are written to stdout; diagnostics remain on
stderr. Output paths default to `--path-mode relative`, which emits paths relative
to the input root. Use `--path-mode hash` for artifacts leaving a repository
boundary, or `--path-mode none` to omit path metadata. The command does not
traverse symlinks or consult ambient keyrings, agents, home directories, hardware
tokens, or the network.

Records use `schema_version:"v0"` and the schema in
`schemas/fingerprint-record.v0.schema.json`. Config files use
`schemas/fingerprint-config.v0.schema.json`.

For minisign public keys, `fingerprint` emits both the native
`minisign-key-id-v1` identifier and the collision-resistant
`minisign-public-blob-sha256-v1` fingerprint (lowercase 64-hex in the
record). Use the public-blob SHA-256 field for committed trust anchors; the
key ID remains useful for display and operator correlation. A GPG public
export uses `--gpg-role primary` when the caller needs exactly one primary
fingerprint.

Future readiness checks should support two levels:

- Static readiness: key material exists, is not plaintext, has expected public counterpart, revocation certificate is present where required.
- Proof readiness: local-only proof such as sign-and-verify, encrypt-and-decrypt, or derive public key. Proof mode may prompt for passphrases, but must not transmit key material.

## Finding Model

Findings are structured for both humans and automation.

Fields include:

- `code`: stable finding identifier, suitable for runbooks and allow/deny policy.
- `priority`: remediation priority from `P0` to `P5`.
- `rank`: numeric sort rank derived from priority.
- `classification`: artifact category, such as `protected-secret`, `ssh-private-key`, or `minisign-secret`.
- `severity`: current policy severity: `info`, `warn`, or `unsafe`.
- `retention`: `allowed`, `retain-with-controls`, `inspect-manually`, or `remove`.
- `exposure`: `public`, `sensitive`, `secret`, or `unknown`.
- `sensitivity`: 3 Leaps classifier value embedded in the scanner model.
- `confidence`: `high`, `medium`, or `low`.
- `evidence`: short explanation without printing private material.
- `recommendation`: next action.

Example:

```json
{
  "code": "MINISIGN-ENCRYPTED-SECRET",
  "priority": "P3",
  "rank": 300,
  "classification": "minisign-secret",
  "severity": "warn",
  "retention": "retain-with-controls",
  "exposure": "secret",
  "sensitivity": "5-privileged",
  "confidence": "high",
  "evidence": "encrypted minisign secret material detected",
  "recommendation": "Potentially retainable with strong passphrase and local controls; keep out of artifact bundles unless policy allows it."
}
```

## Policy Principles

- ASCII armor is encoding, not protection.
- Public keys and signatures are not private, but may still be operationally relevant.
- Passphrase-protected software keys are sensitive and potentially retainable with controls.
- Plaintext private keys are unsafe.
- Copied keyring internals are suspicious outside their expected home.
- Revocation certificates are operationally sensitive and should be archived intentionally.
- Hardware-backed keys should be preferred or required where policy calls for that.
- The tool should not decrypt user data, collect passphrases, or print private key material.

## Provenance Story

Decernor dogfoods the same trust practices it encourages. It fingerprints
its own release-signing publics and pins those values into the signed set.
The assets this tool scans are the same class of assets used to sign its
releases.

A cut is two phases:

1. Tag `vX.Y.Z`. CI packages unsigned archives and opens a GitHub release.
2. On an operator host, `make release` downloads those archives, stages
   committed fingerprint pins and notes, checksums, signs the SUMS
   (minisign required; PGP optional), exports publics, verifies, and
   uploads onto the same release.

The signed payload is archives + notes +
`expected-fingerprints.{txt,ndjson}`. Exported `.pub` / `.asc` files ride
beside it; they do not vouch for themselves. Pins are generated by
`decernor fingerprint` on those exported publics
(`make release-insert-anchors`), never hand-typed. Bindings are
environment-variable identifiers only.

Reviewers:

1. Inspect the source, including `keys/expected-fingerprints.txt`.
2. Download archives, signed SUMS, exported publics, and the staged pin pair.
3. Verify the signatures over the checksum manifests.
4. Verify archive checksums. The pin files must be members of SUMS.
5. Run `decernor fingerprint` on the exported publics and compare to the
   pin file (see below).
6. Run the tool locally and consume structured findings, not key files.

Layout and signed-set membership:
[`docs/decisions/PDR-0001-committed-signing-anchors.md`](docs/decisions/PDR-0001-committed-signing-anchors.md).
Inserter: [`keys/README.md`](keys/README.md).

## Verify a signed release

Consume fingerprints, not secrets. Per-cut commands live in
[`docs/releases/v0.1.3.md`](docs/releases/v0.1.3.md).

Download the release assets (archives, signed SUMS, exported publics,
staged pin pair). Verify SUMS signatures, then:

```sh
decernor fingerprint decernor-release-signing-key.asc \
  --class public --kind gpg --format json --path-mode none --gpg-role primary
decernor fingerprint decernor-minisign.pub \
  --class public --kind minisign --format json --path-mode none
```

The GPG primary fingerprint and the minisign public-blob SHA-256 must
match the `gpg` and `minisign` lines in `expected-fingerprints.txt`.
Never hand-type hex into notes or a README.

## Build

```sh
go build ./...
make build
./bin/decernor version
```

## Readiness Configs

Readiness configs describe what capabilities an asset set must support.

The schema is in `schemas/readiness-config.v0.schema.json`. Example configs live in `examples/`.

Example capability:

```json
{
  "id": "gpg-release-sign",
  "provider": "gpg",
  "verb": "sign",
  "accepted_material": ["protected-secret-key", "hardware-backed-key"],
  "require_public_counterpart": true,
  "require_revocation_certificate": true,
  "static_checks": [
    "material-present",
    "not-plaintext",
    "public-counterpart",
    "revocation-present"
  ],
  "proof_checks": ["sign-and-verify"]
}
```

## Name & Brand

`decernor` was selected to suggest local trust, key-material hygiene, and readiness
before signing/authentication — without sounding like malware, spyware, a password
manager, a generic cleaner, or a destructive wipe tool, and without implying the tool
stores secrets or guarantees safety.

- **Etymology:** Latin _decernere_ — "to decide, determine, decree, resolve" — on the
  root _cernere_ ("to sift, distinguish, discern"). The tool _discerns_ key-material
  state, then _decides_ the verdict: remove, retain-with-controls, inspect, or allowed.
- **Tagline shapes:**
  - _Discern, then decide — before you sign._ (CLI / repo subtitle)
  - _Know what's safe to keep — without reading the secret._ (landing)
  - _ASCII armor is encoding, not protection. Decernor tells the difference._ (technical overview)
- **Surfaces:** binary `decernor`, config path `~/.config/3leaps/decernor.yaml`, env prefix
  `DECERNOR_`, default config `decernor.yaml`. Finding codes and readiness-config
  shapes are name-agnostic and unchanged.

Full decision record, surfaces grid, and the considered-but-passed runner-up (`cernor`)
are in [`NAMING.md`](NAMING.md).

## Test Fixture Strategy

The repository avoids committed real keys and avoids full static secret-key fixtures. Tests generate small synthetic files at runtime and mock packet output so downstream secret scanners have less static material to flag.

## Provenance

Decernor was initially built from the public Fulmen microtool forge baseline [`forge-microtool-gimlet`](https://github.com/fulmenhq/forge-microtool-gimlet), then adapted as a 3 Leaps OSS tool.
