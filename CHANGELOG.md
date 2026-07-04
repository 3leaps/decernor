# Changelog

All notable changes to Decernor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial Decernor CLI application bootstrapped from the Fulmen microtool baseline.
- `scan PATH` command for local GPG, minisign, SSH, private-key, revocation, and keyring-internal artifact classification.
- `readiness validate-config PATH` command for schema-shaped readiness configuration validation.
- Structured finding model with severity, retention, exposure, sensitivity, priority, confidence, evidence, and recommendation fields.
- Embedded Fulmen app identity for standalone binary operation outside the repository.
- Initial readiness examples and JSON schema.

### Changed

- Renamed the prototype to `decernor` across module, binary, app identity, environment prefix, and documentation surfaces.

### Removed

- Historical release notes and changelog entries inherited from the upstream baseline.
