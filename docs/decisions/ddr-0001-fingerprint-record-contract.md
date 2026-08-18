---
title: decernor DDR-0001 — Fingerprint Record Contract
description: The schema-backed output record emitted by `decernor fingerprint` — fields, closed enums, schemes, null behavior, determinism, and safe-output invariants.
status: Accepted
date: 2026-06-11
relates-to: adr-0001-symlink-policy.md
---

# decernor DDR-0001 — Fingerprint Record Contract

**Status: Accepted.** This record defines the durable fingerprint output contract
used by CI artifacts and downstream consumers.

## Context

`decernor fingerprint` emits one record per detected, in-scope key artifact. The
record is the product surface: it can be committed to repositories, diffed in CI,
and consumed by downstream tools. Its stability is the contract, so it is
schema-backed with **closed enums** and an explicit version field.

The record carries **fingerprints and metadata only — never secret or identifying
material**.

## Record shape

```json
{
  "schema_version": "v0",
  "path": "<relative-to-input-root | hashed | omitted>",
  "kind": "ssh | gpg | minisign",
  "class": "public | private | other",
  "algorithm": "openpgp-fingerprint | sha256 | minisign-key-id",
  "fingerprint": "<scheme-specific spelling | null>",
  "fingerprint_scheme": "openpgp-fingerprint-v1 | ssh-rfc4253-public-blob-sha256-v1 | minisign-key-id-v1 | minisign-public-blob-sha256-v1",
  "key_id": "...",
  "key_role": "primary | subkey",
  "confidence": "high | medium | low",
  "reason": "<reason-enum, present when fingerprint is null>"
}
```

## Field Semantics

- **`schema_version`** — **`v0`** while the contract evolves. Promote to a stable
  version only after downstream compatibility is proven.
- **`path`** — sensitive metadata. `path_mode` is **`relative`** (to input root;
  default), **`hash`** (hashed locator for artifacts leaving the repo boundary),
  or **`none`** (omit locator metadata). **Never absolute.** See
  [ADR-0001](adr-0001-symlink-policy.md).
- **`kind`** — closed enum; unsupported kinds are not emitted as matches.
- **`class`** — `public` | `private` | `other`. **`other` is narrow**:
  key-adjacent material with no safe fingerprint scheme, such as revocation
  certificates, keyring bundles, ambiguous packets, unsupported packets, or
  encrypted private material without an in-scope public counterpart. These emit
  metadata plus `null` and a reason only. Non-matches are skipped, not `other`.
- **`algorithm`** — best-effort algorithm label.
- **`fingerprint`** — the computed fingerprint, or **`null`** with a `reason`.
  Derived from the **public identity**; for plaintext private keys, derive the
  public key and fingerprint that. Never fingerprint private bytes. Successful
  spelling is scheme-specific (see encoding table).
- **`fingerprint_scheme`** — closed, versioned enum. `ssh-rfc4253-public-blob-sha256-v1`
  is SHA256 over the RFC4253/OpenSSH public-key blob, not file bytes. OpenPGP uses
  `openpgp-fingerprint-v1` (v4 40-hex); unsupported versions emit a null
  fingerprint with `unsupported-version`. Minisign public keys emit both a native
  key-id record for operator correlation and a `minisign-public-blob-sha256-v1`
  record over the canonical Ed25519 public blob. Only the public-blob SHA-256
  scheme is eligible for trust-anchor use. Non-conforming minisign blobs emit
  `parse-unsupported`.
- **`key_id`** — optional except on a successful GPG identity record, where it is
  the uppercase 16-hex long ID derived from the fingerprint suffix
  (`fingerprint[24:]`). If the helper `pub`/`sub` (or `sec`/`ssb`) row supplies a
  long ID, it is cross-checked against that suffix. Identity is never taken from
  UID text.
- **`key_role`** — closed enum `primary | subkey`. **Required** iff `kind=gpg`
  and `fingerprint` is a non-null string. **Prohibited** on every complementary
  branch (non-GPG records, and GPG records with a null fingerprint). Role is
  taken from the helper packet that owns the next `fpr` (`pub`/`sec` → primary,
  `sub`/`ssb` → subkey). Do not infer role from collection order, UID rows, or
  sort order.

## Encoding table

| Token                 | Record filter                                            | `fingerprint` spelling                            |
| --------------------- | -------------------------------------------------------- | ------------------------------------------------- |
| GPG identity          | `kind=gpg`, `scheme=openpgp-fingerprint-v1`              | uppercase 40-hex                                  |
| GPG contract          | same + `key_role=primary`                                | uppercase 40-hex                                  |
| Minisign trust-anchor | `kind=minisign`, `scheme=minisign-public-blob-sha256-v1` | lowercase 64-hex (no `SHA256:` prefix)            |
| Minisign key id       | `scheme=minisign-key-id-v1`                              | 16 hex                                            |
| SSH public blob       | `kind=ssh`, `scheme=ssh-rfc4253-public-blob-sha256-v1`   | `SHA256:` + exactly 43 unpadded base64 characters |

JSON Schema enforces those successful tuples. Encoding validation is keyed on
`fingerprint_scheme`, not `algorithm`.

## Contract-token selection

`--gpg-role primary` selects only successful GPG primary records. Cardinality is
enforced **per named GPG identity file** (public or private class): that file
must have exactly one primary. 0 or >1 primaries is a refusal. Two distinct
named files with one primary each are not ambiguous. Do not sort-and-take-first.

Refusal is atomic: the complete invocation is buffered and validated before any
stdout is written. 0 or >1 primary, and `--fail-on-empty` with no matching
records, exit **3** with **zero stdout bytes** (JSON mode must not emit `[]`).
Exit 2 remains usage, config, and input errors. Helper-output parse failures on
a single file remain `parse-unsupported` null records unless `--gpg-role
primary` then finds 0 primaries on that identity file.

- **`confidence`** — closed enum `high | medium | low`.
- **`reason`** — closed enum, present iff `fingerprint` is null:
  `encrypted-private-no-public-counterpart`, `parse-unsupported`,
  `unsupported-version`, `helper-unavailable`, `unreadable`, `too-large`,
  `unsupported-kind`. `filtered` is reserved for a future diagnostic mode and is
  never emitted in the default artifact.

## Determinism

Records are collected then **sorted before emit** by
`path, kind, class, fingerprint_scheme, key_role, key_id/fingerprint` so output
is stable regardless of walk order. Sorting only on `path/kind/class` is
insufficient when one file yields multiple records. Sort order is not a
substitute for `key_role`.

## Output Framing

- `--format ndjson` (default; one record per line) or `json` (schema-valid array
  of the same records).
- **stdout = records only; stderr = diagnostics only.**
- Walk-discovered symlinks are reported via stderr/scanner findings, not as
  fingerprint records; symlink target metadata obeys `path_mode`.

## Safe-Output Invariants

No secret bytes and no UIDs, emails/names, SSH comments, raw matched text,
armored blocks, or unsanitized helper output ever appear in a record or in
long-lived/loggable structures.

## Relationship to Other Surfaces

- The detector/classifier layer produces this fingerprint projection.
- `scan` maps the same artifacts to policy findings.
- Projection-only committed-artifact output forms over this record must not
  change detection, safety, or the canonical record's meaning.

## Out of Scope

- Output-shaping and committed-artifact projections.
- Guarded stream-read behavior.
