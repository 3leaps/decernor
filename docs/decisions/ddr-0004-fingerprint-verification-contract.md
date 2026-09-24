---
title: decernor DDR-0004 — Fingerprint Verification Contract
description: Public-file anchor verification, result records, and exit behavior.
status: Accepted
date: 2026-09-24
relates-to: ddr-0001-fingerprint-record-contract.md
---

# decernor DDR-0004 — Fingerprint Verification Contract

`decernor fingerprint verify` compares a committed two-file anchor receipt with
the public GPG and minisign files supplied by the caller. It uses the existing
fingerprint derivation code. It is a reusable comparison, not an independent
fingerprint implementation or a signature verification command.

## Inputs

The command requires `--anchors`, `--anchors-ndjson`, `--gpg`, and `--minisign`.
Each value names one regular file. Symlinks, directories, special files, and
ambiguous key selections are refused. Files are captured under a size bound;
classification and GPG derivation inspect those captured bytes. No helper
reopens the caller's path. Private or other key material is refused, including
`sec` and `ssb` records returned by GPG. Caller key bytes, helper output,
fingerprint values, UIDs, and input paths are absent from diagnostics.

A revoked public export has one narrow verify-only exception to the refusal
of class `other`. If the shared classifier reports a revocation, the verifier
inspects the same captured bytes for a public primary packet, a primary
key-revocation signature (`sigclass 0x20`), and any secret-key packet. Secret
packets or `sec`/`ssb` helper lines are refused first. Admission then requires
exactly one primary `pub` with
fingerprint and GPG validity `r`. A revocation certificate alone, an unverified
revocation signature, or any other class `other` remains refused. This does
not change the shared classifier or the existing `fingerprint` command.
A public export with only a subkey-revocation signature (`sigclass 0x28`)
follows normal primary validation even if the classifier used a broad
revocation-reason phrase.
For a revocation candidate, a running GPG helper that rejects the material
or reports no verified primary is a refusal; helper unavailability or timeout
remains an input error.
The bounded refusal diagnostics are `gpg-secret-input-refused`,
`gpg-revocation-not-public`, and `gpg-revocation-unverified`; refusals emit no
result records.

`--as-of` accepts RFC3339 with a zone. Without it, UTC now is captured once
per invocation. `--allow-expired` has the narrow behavior below. The default
format is NDJSON; `--format json` emits an array.

The TXT receipt is exactly two LF-terminated lines in order: `gpg` followed by
one uppercase 40-character fingerprint, then `minisign` followed by one
lowercase 64-character public-blob SHA-256. Each line has one ASCII space and
no extra token. NDJSON is exactly two LF-terminated records in the same order.
Each validates against embedded `fingerprint-record.v0` and must be class
`public`, path-free, and non-null. The GPG receipt uses algorithm
`openpgp-fingerprint`, scheme `openpgp-fingerprint-v1`, and role `primary`.
The minisign receipt uses algorithm `sha256`, scheme
`minisign-public-blob-sha256-v1`, and no role. Values must agree across the
pair. The minisign key-id record is never an anchor.

The GPG public file may include subkeys. Exactly one primary is selected.
Minisign's public-blob digest is selected from its dual derivation. Expected
values in tests come from GPG directly and a separate standard-library digest
of the decoded minisign blob.

## Result

The schema is `schemas/fingerprint-verify-result.v0.schema.json`. It and the
fingerprint record schema are embedded in the standalone binary, checked for
source/mirror drift at build and release gates, and resolved offline without a
schemas directory or network fetch.

Every evaluable request emits two records, GPG first and minisign second. Each
record has `schema_version: v0`, `kind`, `scheme`, `status`, `validity`, and
`reason`. It carries no fingerprint, path, clock, or helper output.

| Field               | Closed values                                                                                                        |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `status`            | `match`, `mismatch`, `missing`, `extra`                                                                              |
| GPG `validity`      | `ok`, `expired`, `expired_allowed`, `revoked`, `not_yet_valid`                                                       |
| Minisign `validity` | `not_applicable`                                                                                                     |
| `reason`            | `none`, `fingerprint_mismatch`, `missing_key`, `extra_key`, `expired`, `expired_allowed`, `revoked`, `not_yet_valid` |

`missing` and `extra`, with `missing_key` and `extra_key`, are reserved in v0.
This release requires both named public files and refuses zero or multiple GPG
primaries before comparison, so those values are not emitted yet.

Comparison status takes precedence in `reason`; `validity` continues to carry
a simultaneous validity finding. A matching GPG record with a validity
finding never has `reason: none`. Human diagnostics give counts only.

## Time and validity

For the GPG primary, expiry occurs at `as_of.Unix() >= expiry`; a key is
`not_yet_valid` when `as_of.Unix() < creation`. The time comparison uses whole
Unix seconds. The GPG helper's clock-dependent expired marker is ignored.
An expired or revoked subkey does not change primary validity. A revocation
signature present in the supplied public file is fatal even when `--as-of`
precedes its creation. The strongest clean claim is that no revocation was
found **in the supplied file**; `--as-of` does not reconstruct historical key
state.

Expiry is fatal by default. `--allow-expired` produces exit 0 with
`validity: expired_allowed` only when expiry is the sole finding and both
anchors match. It never waives revocation, `not_yet_valid`, mismatch, unsafe
input, an invalid pair, or a helper failure.

## Exit and output composition

The earliest failing stage determines the exit code. Both kinds are evaluated
within a stage when evaluation reaches comparison and validity.

| Stage                                                                                                  | Exit |
| ------------------------------------------------------------------------------------------------------ | ---- |
| Arguments, unreadable or oversized input, GPG helper failure or timeout                                | 2    |
| Unsafe class, secret packet, unverified revocation, symlink, nonregular input, ambiguous key selection | 3    |
| Invalid receipt grammar, schema, eligibility, or pair agreement                                        | 4    |
| Fingerprint mismatch                                                                                   | 5    |
| Fatal primary validity finding                                                                         | 6    |
| Full match with acceptable validity                                                                    | 0    |

Records are buffered and written only after full evaluation for exits 0, 5,
and 6. Exits 2, 3, and 4 have empty stdout. A mismatch with expiry exits 5
and retains the expiry finding; a helper failure exits 2 before comparison.
With an explicit `--as-of`, identical inputs give byte-identical output.

Adding the `verify` child reserves the bare first operand `verify` under
`fingerprint`. A file with that name is passed as `./verify` or an explicit
path. Existing `fingerprint` record, flags, sort order, and private identity
derivation retain DDR-0001 behavior.
