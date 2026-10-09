# Contributing

Contribution guidelines for 3 Leaps open source projects live in
[3leaps/oss-policies](https://github.com/3leaps/oss-policies).

This repository conforms to the Sensitive Local Data policy published there.

## Fixture corpus

Key-shaped test inputs come from the external fixture corpus
[`3leaps/synthcorpus`](https://github.com/3leaps/synthcorpus), pinned in
`testdata/synthcorpus.pin`. Clone it next to this repository, at the pinned
commit, or set `DECERNOR_SYNTHCORPUS_ROOT`. A missing or mismatched corpus
fails `make test`. See
[PDR-0002](docs/decisions/PDR-0002-tests-consume-external-fixture-corpus.md).
