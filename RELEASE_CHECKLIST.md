# Release Checklist

Maintainer walk for each `vX.Y.Z` tag. Decernor is a Go CLI.

Bindings are environment variables only. Load them from the host-local release
profile. No signing material or key paths belong in this tree or in CI.

- `DECERNOR_GPG_HOMEDIR` names the dedicated release keyring.
- `DECERNOR_GPG_SIGNING_FINGERPRINT` is the full uppercase primary fingerprint.
  It must equal the committed GPG anchor.
- `DECERNOR_PGP_KEY_ID` selects the exact signing subkey with a trailing `!`.
  Register that subkey on GitHub for the publishing account.
- `DECERNOR_TAGGER_NAME` and `DECERNOR_TAGGER_EMAIL` identify the release
  tagger. The email must be on the signing key and verified on GitHub.
- `DECERNOR_MINISIGN_KEY` and `DECERNOR_MINISIGN_PUB` serve asset signing.
- `DECERNOR_RELEASE_TAG` and `DECERNOR_RELEASE_COMMIT` are set for this cut;
  the commit is the literal full SHA from the ready record.

See [PDR-0001](docs/decisions/PDR-0001-committed-signing-anchors.md).

## 1. Write and review

- [ ] `VERSION` is the tag without the `v` prefix.
- [ ] `.fulmen/app.yaml` `app.version` matches `VERSION`.
- [ ] `make sync-embedded-identity && make verify-embedded-identity` passes.
- [ ] The committed signing anchors remain unchanged unless this is a rekey.
- [ ] `CHANGELOG.md` has the version heading and footer link; `RELEASE_NOTES.md`
      has the version heading; `docs/releases/vX.Y.Z.md` covers this cut.
- [ ] `make release-preflight` passes.
- [ ] The notes and changelog dates match the calendar date of tag creation.
- [ ] The PR is merged and CI is green on `main` at the merge commit.

## 2. Ready record

Agents and reviewers hand the maintainer one record containing:

- [ ] the literal full SHA of the merged, CI-green `main` commit;
- [ ] the green CI run and release-preflight result at that SHA;
- [ ] each required reviewer's assent for that SHA;
- [ ] release notes reconciled against `git log vPREV..<SHA`.

Reviewer readiness alone authorizes no signing. The maintainer records a
separate GO or NO-GO. Tag creation is maintainer-only after GO. Tag push needs
local verification and a separate explicit push authorization. Agents never
create, sign, push, or publish a tag or release, and never touch signing keys.

## 3. Signed tag (maintainer only, MFA host)

On a clean `main` checkout, set the tag and the literal SHA from the ready
record, then load the host-local release profile. The host needs `gpg`, `jq`,
authenticated `gh`, and an interactive terminal:

```sh
export DECERNOR_RELEASE_TAG="v$(tr -d '\n' < VERSION)"
export DECERNOR_RELEASE_COMMIT='<literal full SHA from the ready record>'
# Load the host-local release profile here.
make release-guard-tag-version
make release-guard-signing-env
```

The guard requires `HEAD`, `origin/main`, and `DECERNOR_RELEASE_COMMIT` to
agree and checks the exact valid signing subkey under the authorized primary.
Never replace the literal SHA with a newly resolved `HEAD` or `origin/main`.

After the maintainer's tag-creation GO, create and check the tag in an
interactive terminal. The YubiKey PIN and touch happen here:

```sh
make release-tag
git verify-tag "$DECERNOR_RELEASE_TAG"
```

`make release-tag` creates and locally verifies the signed tag; it never
pushes. After a separate push authorization:

```sh
make release-push-tag
make release-verify-remote-tag
```

The push helper re-verifies locally and pushes only the named tag ref. The
remote check requires GitHub to report Verified, reason `valid`, the literal
release commit, and the same tag object verified locally. `unknown_key` means
the signing subkey is not registered on GitHub; `bad_email` means the tagger
email is not verified on the account. Stop and fix the profile if either
appears. Do not sign or upload assets until the remote check passes.

Wait for the Release workflow to draft unsigned archives.

## 4. Sign and upload (maintainer only, MFA host)

```sh
make release
```

The walk is clean → download → notes → stage anchors → checksums → sign →
export public keys → verify → upload. Public-key verification includes
`fingerprint verify` beside the existing checks. Stage notes and anchors
before checksums. The GitHub release stays **draft**; undraft is a separate
maintainer step.

## 5. Package managers

After the signed release is verified and undrafted:

- [ ] Confirm the GitHub release is published and anonymously downloadable.
- [ ] Run `make verify-package-manager-handoff DECERNOR_RELEASE_TAG=vX.Y.Z`.
- [ ] Run `make update-package-managers DECERNOR_RELEASE_TAG=vX.Y.Z`.
- [ ] Review and validate the Homebrew tap and Scoop bucket diffs.
- [ ] Open and merge their normal PRs; do not commit or push them from this repository.
- [ ] Smoke `brew install 3leaps/tap/decernor` on supported macOS/Linux hosts.
- [ ] Smoke `scoop install decernor` on Windows.
- [ ] Confirm each installed `decernor version` reports `X.Y.Z`.

## 6. Rekey

Register the new signing subkey on GitHub before signing with it. Update the
exact subkey selector and authorized primary fingerprint together. Export the
new publics, run `make release-insert-anchors`, and cut a new release. Do not
edit hex by hand.

## 7. If something goes wrong

- A local tag that has not been pushed can be deleted and recreated from the
  ready record.
- Never move or delete a pushed tag. Leave the release draft and cut the next
  patch if published tag metadata is wrong.
- If remote verification fails, do not sign or upload assets. Resolve the
  profile problem and agree with reviewers whether the tag can stand.
