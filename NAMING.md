# Naming Decision — `decernor` → **Decernor**

**Status:** LOCKED 2026-06-01
**Decided by:** 3 Leaps maintainers
**Working name retired:** `decernor` (generic, collision-prone — see README header)
**Final name:** **`decernor`**

> This resolves the open question in the README "Naming Prompt" section.

## Name

**Decernor** — from Latin _decernere_ ("to **decide, determine, decree, resolve**"),
built on the root _cernere_ ("to sift, separate, distinguish, discern") with the
completive prefix _de-_; agentive `-or` = "the one that sifts, then decides." It
names the tool's core act: discern plaintext from protected from public, then
**decide** remove / retain-with-controls / inspect — _reading the state, never the
secret_. Advisory by construction (it decrees a _state_, it doesn't guarantee one),
so it does not over-promise safety.

Pronounced **deh-SUR-nor**.

## Tagline

> Discern, then decide — before you sign. Local key-material hygiene and readiness for humans and agents.

## Why it fits the README's naming constraints

- Not `decernor / cleaner / wipe / vault / agent / secret-manager`.
- Doesn't imply the tool stores secrets (it inspects and decides; it doesn't hold).
- Doesn't imply guaranteed safety (a decree of state is advisory).
- Doesn't collide with a common CLI binary (coined; 11/11 checked surfaces free, incl. `.com`).
- Fits the trust-utility category without implying storage or guaranteed remediation.

## Considered and passed: `cernor`

`cernor` (from the bare root _cernere_) was considered and is a fine
name. We took the **safer route** to
`decernor` after a sibling-check pass: cernor was 10/11 with a parked `.com`, a MEDIUM
expert risk, and a phonetic adjacency to **Cerner** (Oracle Health); `decernor` came
back **11/11, `.com` available, deep risk LOW, no adjacency caveat**. Same root
etymology, strictly cleaner namespace.

## Surfaces

| Surface                                     | Value                          |
| ------------------------------------------- | ------------------------------ |
| CLI binary / repo                           | `decernor` / `3leaps/decernor` |
| Config dir                                  | `~/.config/decernor/`          |
| Env var prefix                              | `DECERNOR_`                    |
| Default config                              | `decernor.yaml`                |
| Finding codes (`GPG-UNPROTECTED-SECRET`, …) | unchanged — tool-agnostic      |
| Readiness configs (`*.readiness.json`)      | unchanged                      |
