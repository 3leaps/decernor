---
id: PDR-0002
title: Tests consume an external fixture corpus; Decernor generates no key material
status: Proposed
date: 2026-10-09
deciders:
  - cxotech
  - "@3leapsdave"
relates-to:
  - crucible EPR-0005 (proposed; test evidence is independent of the implementation it judges)
  - crucible EPR-0002 (gates are proven able to fail)
  - crucible ADR-0003 (taxonomy: PDR = revisable ways-of-working)
  - PDR-0001-committed-signing-anchors.md
---

# PDR-0002 — Tests consume an external fixture corpus; Decernor generates no key material

**Status: Proposed.** How Decernor's tests obtain the key-shaped inputs they
classify, and what Decernor may never produce.

This is a **PDR**, not an EPR or SecDR:

- **Not EPR.** "Evidence is independent of what it judges" is the durable
  principle, recorded upstream as crucible EPR-0005. Which corpus, how it is
  pinned, and how CI fetches it are revisable.
- **Not SecDR.** Whether a corpus specimen is safe to commit is the corpus
  repository's decision. This record governs consumption.
- **Not ADR.** No runtime component changes.

## Rule

Decernor **generates no key material**: not persisted, not in memory, not at
test time, real or synthetic. This covers test helpers that assemble key-shaped
bodies, as well as calls to key-generation tools or library key generators.

Not covered:

- **Detector search material**: an atomic needle the detector compares
  against, such as one marker, magic value, filename, or header string. A
  header constructor may return one needle. Policy tables, such as which
  parameter names are secret, are also search material. See
  `docs/search-materials.md`.

A body composed from needles is a specimen, not search material. A test that
concatenates markers or tokens into a key-shaped body is generation, wherever
the needles come from.

- Non-key test inputs: plain text, configuration, malformed non-key bytes.

## Corpus

Key-shaped test inputs come from
[`3leaps/synthcorpus`](https://github.com/3leaps/synthcorpus):

- **committed-synthetic** specimens, provably unusable as keys, for shape and
  classification tests;
- **generated-real** material, produced by the synthcorpus generator into an
  isolated root outside any git worktree, for tests that need real
  cryptographic validity.

synthcorpus owns what each specimen **is**: its class and its expected verdict,
recorded in a manifest. Decernor's tests prove that Decernor classifies each
specimen as the manifest states.

## Consumption

| Concern         | Rule                                                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Location        | `DECERNOR_SYNTHCORPUS_ROOT`, else a sibling `../synthcorpus` checkout                                                    |
| Pin             | `testdata/synthcorpus.pin`: full commit SHA and fixture-manifest digest                                                  |
| CI              | Check out synthcorpus at the pinned SHA with read-only contents and no persisted credentials; verify the manifest digest |
| Missing corpus  | **Fails** the run, in CI and in `make test`. Never a skip                                                                |
| Pin mismatch    | Fails, in CI and locally. `DECERNOR_SYNTHCORPUS_UNPINNED=1` permits an exploratory local run, reported as not evidence   |
| Dependency form | A pinned checkout, not a Go module dependency                                                                            |

## Tests

- **Class invariants.** For each specimen class, tests state what must never
  happen. Examples: a plaintext or protected specimen never classifies as a
  hardware stub or as no finding, and never passes `guardread`. A new specimen
  is covered by its class on arrival.
- **Findings become specimens.** A confirmed defect's demonstrating input is
  added to synthcorpus with its class. The new test is shown to fail against the
  pre-fix revision, built from its own checkout, before the defect is closed.
- **Lockstep.** A change that alters expected verdicts lands as a synthcorpus
  change first, then a Decernor change that bumps the pin. After a Decernor
  release, synthcorpus bumps its own pin of the Decernor binary.

## Transitional state

Some Decernor tests still assemble key-shaped bodies in memory, and four sites
invoke a key-generation tool: two in the OpenPGP verification tests and two in
the signed-tag release control tests. That is non-conforming with the rule above. **Owner:**
Decernor devlead. **Triggers:**

- **Agent-key specimens:** moved to the corpus in the same release that
  introduces agent-key content classification. That release does not ship
  with agent-key bodies assembled in tests.
- **Remaining bodies and generation calls:** moved in the first release after
  this record is accepted, including the release control tests. A repository
  policy test then rejects key-generation invocations anywhere in the tree,
  with no exemption for release tests.

## Consequences

- A behaviour change needs two coordinated changes and a pin bump.
- `make test` needs a synthcorpus checkout. Contributors clone it alongside.
- Classification expectations are reviewable in one place, against the
  manifest, rather than spread across test helpers.
- Confirmed findings accumulate as specimens that guard every later release
  and every other consumer of the corpus.

## Out of scope

Specimen safety and generator behaviour (synthcorpus records). Fuzzing strategy.
Changing DDR-0001 or DDR-0004.
