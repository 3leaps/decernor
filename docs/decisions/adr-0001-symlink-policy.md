---
title: decernor ADR-0001 — Symlink Policy (named inputs + walk traversal)
description: decernor fails closed on symlinked named inputs and does not traverse symlinks while walking; symlinks are detected and reported, never followed.
status: Accepted
date: 2026-06-11
---

# decernor ADR-0001 — Symlink Policy

**Status: Accepted.**

## Context

decernor inspects local key-material state. Two distinct symlink exposures:

1. **Named inputs** (`--config`, future readiness/policy files) — a planted
   final-component symlink makes the file read not the file named.
2. **Tree walking** (`scan`, `fingerprint`, `migrate`, `guardread`) — decernor's
   bigger, decernor-specific exposure. While walking a directory of sensitive
   material, following a symlink:
   - **escapes the explicit input scope** — a link to `~/.ssh`, `/etc/ssl`, or
     another user's home would read/fingerprint key material _outside_ scope,
     breaking the no-ambient-access guarantee;
   - **forges migration assurance** — a symlink at the destination can
     fake "present", at the source fake "cleared";
   - **breaks determinism** — double-counts / misattributes keys.

Following a symlink here is asymmetric risk: refusing/skipping costs an operator a
correction; following can read out-of-scope secret material or forge a verdict.

## Decision

1. **Named inputs fail closed:** refuse final-component
   symlinks; refuse special files (dir/FIFO/socket/device); bounded read (default 4 MiB
   unless documented); stdin remains the streaming escape hatch. Error names the cause +
   remediation (pass the real path).
2. **Walks do not traverse symlinks:** the directory walk does **not follow** symlinked
   directories or symlinked files. This is an **engine invariant** in the shared
   walk/detect path, inherited by every walking command.
3. **Symlinks are detected and not traversed.** While walking, a symlink is identified by
   type and skipped without following; it is never emitted as a fingerprint record.
   `fingerprint` emits a `symlink-not-traversed` diagnostic (stderr, located per
   `path_mode`); `scan` today counts a skipped symlink toward `Skipped` without a finding.
   Richer symlink reporting — an explicit `scan` finding, the link target, and whether the
   target resolves **outside the input scope** (scope-escape / exfil signal) under
   verified-vs-advisory framing — is a **follow-on hardening item** (see Non-goals), not
   implemented in this merge.
4. **No ambient discovery.** Counterparts / related material are only considered within
   the explicit input roots after filtering.

## Non-goals / hardening path

- Final-component + per-entry no-follow walk is the **portable floor**.
  Intermediate-directory symlinks and TOCTOU races are documented residual risk.
- Hardening upgrade: handle-based no-follow (`O_NOFOLLOW` + `fstat`, `openat2`/
  `RESOLVE_NO_SYMLINKS` on Linux, lstat-before-open on the walk) where available —
  prioritized for any path that reads/derives from private material.
- **Symlink hygiene reporting (follow-on):** surface skipped symlinks as explicit `scan`
  findings (today they count toward `Skipped` with no finding) and classify each link's
  target as inside/outside the input scope under verified-vs-advisory framing. The accepted
  floor for this merge is no-traversal plus the `fingerprint` `symlink-not-traversed`
  diagnostic.

## Drift control / review process

- **CI conformance fixtures are mandatory**: symlinked dir, symlinked
  file, special files, oversize named input, and "symlink reported-not-traversed". Copying
  the pattern without these tests is not a security floor.
- Symlink handling is a **standing review gate** for any new walking command or input.
- Consider a shared Go helper (cf. gofulmen) so scan/fingerprint/migrate/guardread don't
  each re-implement the floor.

## Consequences

- Positive: keeps no-ambient-access honest; prevents scope-escape reads (links are not
  followed); makes migration assurance non-forgeable. Surfacing symlinks as a _reported
  hygiene signal_ is the intended direction, landed incrementally (see hardening path).
- Negative: operators relying on symlinked layouts must point decernor at real paths;
  symlink farms are skipped (not followed) and — until the follow-on lands — not surfaced
  as `scan` findings.
