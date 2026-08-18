# Release Checklist

Maintainer walk for each `vX.Y.Z` tag. Decernor is a Go CLI. There is no
crate publish, no bindings tag, and no FFI tarball.

This repository is **private**. A successful first cut is a private annotated
tag plus a **draft** GitHub release. Signing is optional until org public keys
are on disk and fingerprints are inserted from `decernor fingerprint` (not
hand-typed).

## Prerequisites

- `gh` authenticated with push access to `3leaps/decernor`
- Local `main` matches `origin/main`
- `gpg` / `minisign` only if this cut will sign

## 1. Write / prep

- [ ] `VERSION` is the tag without the `v` prefix
- [ ] `.fulmen/app.yaml` `app.version` matches `VERSION`
- [ ] Embedded identity is in sync: `make sync-embedded-identity` then
      `make verify-embedded-identity`
- [ ] `CHANGELOG.md` has a `## [X.Y.Z]` section and an empty `[Unreleased]`
- [ ] `RELEASE_NOTES.md` is the landing page for this cut
- [ ] `docs/releases/vX.Y.Z.md` is **that cut only**
- [ ] `make release-preflight` passes

Commit the prep on a `chore/release-vX.Y.Z` branch. Conventional subject only
(no private planning ids). Open a PR; merge after CI is green.

## 2. Tag (after the notes PR is on `main`)

```bash
git switch main
git pull --ff-only origin main
test "$(cat VERSION)" = "X.Y.Z"
make release-preflight
git tag -a "vX.Y.Z" -m "vX.Y.Z"
git push origin "vX.Y.Z"
```

Do not tag until CI on that `main` commit is green.

## 3. Draft GitHub release

`release.yml` builds on `v*` and opens a **draft** with `dist/release/*`.

- [ ] Confirm the workflow finished
- [ ] Confirm `VERSION` matched the tag (workflow fails closed if not)
- [ ] Leave the release **draft** unless this cut is explicitly a publish

## 4. Signing (optional, later)

Only when both org public files exist:

```text
decernor fingerprint <gpg.asc> --class public --kind gpg --format json \
  --path-mode none --gpg-role primary
decernor fingerprint <minisign.pub> --class public --kind minisign \
  --format json --path-mode none
```

Write `keys/expected-fingerprints.txt` from those records (verbatim hex).
Do not wrap `gpg --show-keys` or `xxd | head`. Then `make package-sign` and
`make verify-release-key`. Undraft only after verify is green.

If publics are missing, **stop after step 3**. Unsigned private draft is
success for that cut.

## 5. Out of scope for a private 0.1.x tag

- Flipping the GitHub repository public
- crates.io / Homebrew / Scoop
- Hand-typed fingerprints
