# Decernor Maintainers

**Project**: decernor  
**Purpose**: local key-material hygiene and readiness checks

## Human Maintainer

### @3leapsdave (Dave Thompson)

- **Role**: Project lead and primary maintainer
- **Responsibilities**: product direction, release approval, and architecture supervision
- **Contact**: dave.thompson@3leaps.net | GitHub [@3leapsdave](https://github.com/3leapsdave)

## Review Areas

- Implementation, tests, and release preparation.
- Code review, regressions, and missing tests.
- Secret-handling, crypto-adjacent behavior, and local-data risk.
- Public docs, schemas, and finding taxonomy.
- Cross-tool architecture alignment.
- CI, release workflow, and packaging.

## Contribution Rules

- Preserve the CLI-only shape unless maintainers explicitly approve a new architecture.
- Keep private material out of repository content, examples, tests, issue text, and release notes.
- Run focused tests for changed packages and the full local gate before handoff when practical.
- Changes to scanner classification, finding severity, retention guidance, or readiness semantics require tests.
- Changes touching secret-handling behavior should receive security review before release.

## Release Readiness

Before a release candidate:

- `make test`
- `make build`
- `make test-standalone-binary`
- `make cdrl-verify`
- `make validate-app-identity`

Use `make check-all` when goneat is installed and available.
