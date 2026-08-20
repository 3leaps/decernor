# CI

Decernor uses GitHub Actions with the Fulmen goneat toolbox runner image
(`ghcr.io/fulmenhq/goneat-tools-runner-glibc:v0.5.2`, goneat `v0.5.16`).

The CI workflow currently verifies:

- embedded identity mirror
- module download
- format check
- lint
- tests
- build
- standalone binary execution outside the repository

The runner image is treated as the toolchain. Avoid adding ad hoc tool installs in CI unless the image no longer provides a required tool.
