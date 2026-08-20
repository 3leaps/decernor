# Release Notes

Landing page for the latest Decernor cut. Per-cut payload:
[`docs/releases/v0.1.4.md`](docs/releases/v0.1.4.md).

## v0.1.4 — 2026-08-20

Signed cut. Same two-phase walk as v0.1.3: tag, then `make release` on an
operator host. Pins in `keys/expected-fingerprints.txt` are produced by
`decernor fingerprint` (not hand-typed) and copied into `dist/release/`
**before** checksums.

CI and Release run `goneat-tools-runner-glibc:v0.5.2` (goneat `v0.5.16`).
The README provenance story matches that walk.

Signing uses `DECERNOR_*` environment variables only. No key paths live
in this repository.

## v0.1.3 — 2026-08-18

First signed cut. The repository was private for that tag. See
[`docs/releases/v0.1.3.md`](docs/releases/v0.1.3.md).

## v0.1.2 — 2026-08-18

First tagged snapshot (unsigned draft). See
[`docs/releases/v0.1.2.md`](docs/releases/v0.1.2.md).
