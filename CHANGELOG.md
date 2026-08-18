# Changelog

All notable changes to Decernor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Fingerprint records now emit `key_role` and a derived GPG long `key_id` on
  successful OpenPGP identities, and spell minisign public-blob SHA-256 as
  lowercase hex. `decernor fingerprint --gpg-role primary` selects the unique
  primary on each named GPG identity file and refuses 0 or >1 primaries with no
  stdout artifact.

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
