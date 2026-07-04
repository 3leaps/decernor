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
  "kind": "ssh | gpg | minisign | ...",
  "class": "public | private | other",
  "algorithm": "ed25519 | rsa-2048 | ...",
  "fingerprint": "SHA256:... | null",
  "fingerprint_scheme": "ssh-sha256 | openpgp-fpr-v4 | minisign-keyid | minisign-public-blob-sha256 | ...",
  "key_id": "...",
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
  public key and fingerprint that. Never fingerprint private bytes.
- **`fingerprint_scheme`** — closed, versioned enum. `ssh-sha256` is SHA256 over
  the RFC4253/OpenSSH public-key blob, not file bytes. OpenPGP uses the matching
  scheme for the packet version; unsupported versions emit a null fingerprint with
  `unsupported-version`. Minisign public keys emit both a native key-id record for
  operator correlation and a `minisign-public-blob-sha256-v1` record over the
  canonical Ed25519 public blob. Only the public-blob SHA-256 scheme is eligible
  for trust-anchor use. Non-conforming minisign blobs emit `parse-unsupported`.
- **`key_id`** — optional, for native IDs such as GPG long IDs or minisign key IDs.
- **`confidence`** — closed enum `high | medium | low`.
- **`reason`** — closed enum, present iff `fingerprint` is null:
  `encrypted-private-no-public-counterpart`, `parse-unsupported`,
  `unsupported-version`, `helper-unavailable`, `unreadable`, `too-large`,
  `unsupported-kind`. `filtered` is reserved for a future diagnostic mode and is
  never emitted in the default artifact.

## Determinism

Records are collected then **sorted before emit** by
`path, kind, class, fingerprint_scheme, key_id/fingerprint` so output is stable
regardless of walk order. Sorting only on `path/kind/class` is insufficient when
one file yields multiple records.

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
