---
id: PDR-0001
title: Committed signing anchors and signed-payload inclusion
status: Accepted
date: 2026-08-18
deciders:
  - cxotech
  - "@3leapsdave"
relates-to:
  - ddr-0001-fingerprint-record-contract.md
  - crucible ADR-0003 (taxonomy: PDR = revisable ways-of-working)
---

# PDR-0001 — Committed signing anchors and signed-payload inclusion

**Status: Accepted.** Process for _where_ Decernor writes release-signing
identity and _how_ that file becomes part of a signed GitHub release.

This is a **PDR**, not an EPR or DDR:

- **Not EPR.** "Never hand-type hex" is the durable rule, but _where the
  file lives_ and _which sibling files we keep_ are revisable.
- **Not DDR.** Record shape is already [DDR-0001](ddr-0001-fingerprint-record-contract.md).
  This record is the ceremony and layout.
- **Not ADR.** No new runtime component.

## Producer / consumer contract

The emitter already defines one selectable GPG contract value (sole
`openpgp-fingerprint-v1` with `key_role=primary`, uppercase 40-hex) and
one minisign trust-anchor (`minisign-public-blob-sha256-v1`, lowercase
64-hex in the record). Downstream release repos consume a two-line pin
file plus a public-key verifier. This repository dogfoods that consumer
path first so other tools can copy it.

The inserter maps `decernor fingerprint` output onto the pin files. No
second OpenPGP or minisign extractor. No hand-typed hex.

## Where the material is written

**In the git tree (the pin, not the keys):**

```text
keys/
  README.md
  expected-fingerprints.ndjson   # decernor stdout (receipt)
  expected-fingerprints.txt      # verifier contract (derived)
```

| File                           | Role                                                                                                                                                                                                                                                                              |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `expected-fingerprints.ndjson` | Selected-record receipt: the GPG primary record and the minisign public-blob SHA-256 record from `decernor fingerprint` on the **exported public files** (`--format ndjson --path-mode none --class public`). Not raw dual-record minisign stdout. Schema-valid DDR-0001 records. |
| `expected-fingerprints.txt`    | Two lines, whitespace-separated: `gpg <40-hex>` and `minisign <64-hex>`. Values are **copied verbatim** from those records. This is what `verify-public-keys.sh` compares.                                                                                                        |
| `README.md`                    | Points at the inserter; does not restate hex.                                                                                                                                                                                                                                     |

**Never committed:** private keys, keystore trees, minisign secret
files, exported `.pub` / `.asc`, **or any filesystem path to those
things.** Public key **files** ride the GitHub release only (the in-repo
pin blesses the per-release pub, so the pub cannot vouch for itself).

### Env vars only (hard rule)

Scripts, Makefiles, workflows, and docs in this repo name **variable
identifiers**, never paths:

- `DECERNOR_MINISIGN_PUB` / `DECERNOR_MINISIGN_KEY`
- `DECERNOR_GPG_HOMEDIR` / `DECERNOR_PGP_KEY_ID`

The operator loads those from a **host-local** profile (outside this
tree). CI and `make` fail closed if a required variable is empty. No
`$HOME/…`, no `~/vault`, no checked-in `.env`.

### Net-new payload file (existing workflows will not see it)

gonimbus / sfetch / waitprims `release-checksums` today hash **binary
artifacts** (`${BINARY}-*`). They do **not** pick up a new pin file
unless we add a step. Release notes already have an explicit
`release-notes` copy; fingerprints need the same kind of **new**
target, for example `release-stage-anchors`, that:

1. Generates or copies `expected-fingerprints.txt` and
   `.ndjson` into `dist/release/`
2. Runs **before** `release-checksums`

Do not assume "put the file in `dist/release/` and the old script will
hash it." Extend the checksum input set, or the pin stays unsigned
commentary.

**Order** (matches `make release`):

1. Download unsigned archives
2. `release-notes` — copy per-cut notes into `dist/release/`
3. **`release-stage-anchors`** — copy committed pin files into `dist/release/`
4. `release-checksums` — must include notes + both pin files + **at least one archive**
5. `release-sign` — sign the SUMS (minisign required; PGP optional)
6. `release-export-keys` — export publics **after** signing (they are upload
   companions, not SUMS members; the pin in SUMS blesses them)
7. Verify (checksums, signatures, **staged** pins vs recomputed publics)
8. Upload provenance; draft stays draft

A pin that is only in git and never in `SHA256SUMS` is commentary. A pin
that is in `SHA256SUMS` and then signed is the load-bearing artifact.

## How insert actually works

Required env (set in the operator shell, not in git):
`DECERNOR_GPG_HOMEDIR`, `DECERNOR_PGP_KEY_ID`, `DECERNOR_MINISIGN_PUB`.
Same org keyset as other 3leaps tools; only the prefix changes.

```text
# 1. Export publics to a temp dir from those env vars
#    (copy $DECERNOR_MINISIGN_PUB; gpg --homedir $DECERNOR_GPG_HOMEDIR
#     --armor --export $DECERNOR_PGP_KEY_ID).
#    Never walk a keystore. Never fingerprint a secret file or a homedir tree.

# 2. Emit records (fail closed; both-or-none write).
decernor fingerprint "$ASC" --class public --kind gpg \
  --format ndjson --path-mode none --gpg-role primary
decernor fingerprint "$PUB" --class public --kind minisign \
  --format ndjson --path-mode none

# 3. Write keys/*.ndjson from those records.
#    Derive keys/*.txt from fingerprint fields (no second parser).
#    Refuse if GPG count != 1 primary or minisign blob-SHA count != 1.

# 4. verify-public-keys.sh: exported pubs match the txt lines.
#    validate: each ndjson line against fingerprint-record.v0.
```

Pin-pair install uses **process-lifetime rollback** on error or
INT/TERM/HUP (restore the prior pair, or remove a first-use dest). Two
dest files are not power-loss atomic.

Rekey = new export + same script. Do not immortalize today's hex in
docs or commit messages.

## Tag for the first signed cut

Do **not** move `v0.1.2`. That tag already triggered CI and a draft.
The signed kit is a new cut: **`v0.1.3`**.

## Consequences

- Other release repos can copy `keys/` + inserter +
  `release-stage-anchors` without inventing a layout.
- `make release-verify-keys` asserts the **staged** pin against
  recomputed publics, not "a pub file exists."
- The signed set is archives + notes + pin pair. Exported pubs ride
  beside it and are checked against that pin.

## Out of scope

Public visibility flip. Changing DDR-0001. Hand-maintained hex in
`RELEASE_NOTES.md`.
