# Release Checklist

Maintainer walk for each `vX.Y.Z` tag. Decernor is a Go CLI.

Bindings are **environment variables only** (`DECERNOR_MINISIGN_KEY`,
`DECERNOR_MINISIGN_PUB`, `DECERNOR_GPG_HOMEDIR`, `DECERNOR_PGP_KEY_ID`).
No key paths in this tree. Load them from a host-local profile.

See [PDR-0001](docs/decisions/PDR-0001-committed-signing-anchors.md).

## 1. Write / prep

- [ ] `VERSION` is the tag without the `v` prefix
- [ ] `.fulmen/app.yaml` `app.version` matches `VERSION`
- [ ] `make sync-embedded-identity && make verify-embedded-identity`
- [ ] Pins exist (`make release-insert-anchors` after env is loaded)
- [ ] `CHANGELOG.md` has `## [X.Y.Z]`; `RELEASE_NOTES.md` has `## vX.Y.Z`
- [ ] `docs/releases/vX.Y.Z.md` is that cut only
- [ ] `make release-preflight` passes
- [ ] PR merge; CI green on `main`

## 2. Tag

```bash
git switch main && git pull --ff-only origin main
test "$(cat VERSION)" = "X.Y.Z"
make release-preflight
git tag -a "vX.Y.Z" -m "vX.Y.Z"
git push origin "vX.Y.Z"
```

Wait for the Release workflow to draft unsigned archives.

## 3. Sign / upload (MFA host)

```bash
# env already loaded: DECERNOR_*
export DECERNOR_RELEASE_TAG=vX.Y.Z
make release
```

That walk is: clean → download → **notes** → **stage-anchors** →
checksums → sign → export-keys → verify → upload.

`release-stage-anchors` is **net-new**. Checksum scripts will not pick
up the pin files unless this runs first.

The GitHub release stays **draft**. Undraft is a separate maintainer step.

## 4. Package managers

After the signed release is verified and undrafted:

- [ ] Confirm the GitHub release is published and anonymously downloadable.
- [ ] Run `make verify-package-manager-handoff DECERNOR_RELEASE_TAG=vX.Y.Z`.
- [ ] Run `make update-package-managers DECERNOR_RELEASE_TAG=vX.Y.Z`.
- [ ] Review and validate the Homebrew tap and Scoop bucket diffs.
- [ ] Open and merge their normal PRs; do not commit or push them from this repository.
- [ ] Smoke `brew install 3leaps/tap/decernor` on supported macOS/Linux hosts.
- [ ] Smoke `scoop install decernor` on Windows.
- [ ] Confirm each installed `decernor version` reports `X.Y.Z`.

## 5. Rekey

New export + `make release-insert-anchors` + new cut. Do not edit hex
by hand.
