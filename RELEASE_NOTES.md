# Release Notes

Landing page for the latest Decernor cut. Per-cut payload:
[`docs/releases/v0.1.3.md`](docs/releases/v0.1.3.md).

## v0.1.3 — 2026-08-18

First **signed** private release. Pins in `keys/expected-fingerprints.txt`
are produced by `decernor fingerprint` (not hand-typed) and copied into
`dist/release/` **before** checksums, then signed with the rest of the
payload.

Signing uses `DECERNOR_*` environment variables only. No key paths live
in this repository.

Still private. Draft GitHub release until a maintainer undrafts.

## v0.1.2 — 2026-08-18

First tagged snapshot (unsigned draft). See
[`docs/releases/v0.1.2.md`](docs/releases/v0.1.2.md).
