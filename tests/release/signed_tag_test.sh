#!/usr/bin/env bash
# Exercise the signed-tag boundary using disposable keys and a local bare remote.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/release-tag-common.sh
source "$ROOT/scripts/release-tag-common.sh"

if ! command -v gpg >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
	echo 'SKIP: signed-tag controls require gpg and jq; run on the maintainer host'
	exit 0
fi

TEST_ROOT="$(mktemp -d /tmp/dtr-XXXXXX)"
trap 'rm -rf "$TEST_ROOT"' EXIT
TEST_REPO="$TEST_ROOT/repo"
TEST_REMOTE="$TEST_ROOT/remote.git"
TEST_GPG="$TEST_ROOT/gpg"
mkdir -m 700 "$TEST_GPG"

git init -q --bare "$TEST_REMOTE"
git init -q -b main "$TEST_REPO"
git -C "$TEST_REPO" config user.name 'Synthetic Release Test'
git -C "$TEST_REPO" config user.email 'synthetic@example.invalid'
mkdir -p "$TEST_REPO/keys"
printf '0.1.8\n' >"$TEST_REPO/VERSION"

export DECERNOR_GPG_HOMEDIR="$TEST_GPG"
export DECERNOR_RELEASE_TAG=v0.1.8
export DECERNOR_TAGGER_NAME='3 Leaps Infosec Team'
export DECERNOR_TAGGER_EMAIL='infosec@3leaps.net'

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
	--quick-gen-key '3 Leaps Infosec Team <infosec@3leaps.net>' ed25519 sign never >/dev/null 2>&1
primary="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
	'infosec@3leaps.net' | awk -F: '$1 == "fpr" { print $10; exit }')"
gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$primary" ed25519 sign never >/dev/null 2>&1
subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
	'infosec@3leaps.net' | awk -F: '$1 == "fpr" { n++; if (n == 2) { print $10; exit } }')"
if [ "${#primary}" -ne 40 ] || [ "${#subkey}" -ne 40 ]; then
	echo 'error: synthetic GPG identities are incomplete' >&2
	exit 1
fi
export DECERNOR_PGP_KEY_ID="${subkey}!"
export DECERNOR_GPG_SIGNING_FINGERPRINT="$primary"
printf 'gpg %s\nminisign %064d\n' "$primary" 0 >"$TEST_REPO/keys/expected-fingerprints.txt"

git -C "$TEST_REPO" add VERSION keys/expected-fingerprints.txt
git -C "$TEST_REPO" commit -q -m 'Synthetic release fixture'
git -C "$TEST_REPO" remote add origin "$TEST_REMOTE"
git -C "$TEST_REPO" push -q -u origin main
cd "$TEST_REPO"
DECERNOR_RELEASE_COMMIT="$(git rev-parse HEAD)"
export DECERNOR_RELEASE_COMMIT

expect_fail() {
	local label="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		echo "error: $label unexpectedly passed" >&2
		exit 1
	fi
}

release_validate_signing_env
release_assert_checkout
release_assert_tag_absent

DECERNOR_RELEASE_COMMIT='' expect_fail 'missing literal release commit' release_assert_checkout
DECERNOR_RELEASE_COMMIT="$(printf '%040d' 0)" expect_fail 'wrong literal release commit' release_assert_checkout
DECERNOR_RELEASE_COMMIT=short expect_fail 'short release commit' release_assert_checkout

DECERNOR_RELEASE_TAG=v0.1.9 expect_fail 'tag/version mismatch' release_assert_tag_version
DECERNOR_PGP_KEY_ID="$primary!" expect_fail 'primary used as subkey selector' release_validate_verification_env
DECERNOR_PGP_KEY_ID="$subkey" expect_fail 'selector without exact bang' release_validate_verification_env
DECERNOR_GPG_SIGNING_FINGERPRINT="$(printf '%040d' 0)" expect_fail 'wrong authorized primary' release_validate_verification_env
DECERNOR_TAGGER_NAME='Wrong Tagger' expect_fail 'wrong tagger' release_validate_verification_env
DECERNOR_TAGGER_EMAIL='wrong@example.invalid' expect_fail 'wrong tagger email' release_validate_verification_env
DECERNOR_GPG_HOMEDIR='' expect_fail 'missing GPG home' release_validate_verification_env
DECERNOR_PGP_KEY_ID='' expect_fail 'missing key selector' release_validate_verification_env

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
	--quick-gen-key 'Old <old@example.invalid>' ed25519 sign never >/dev/null 2>&1
revoked_primary="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
	'old@example.invalid' | awk -F: '$1 == "fpr" { print $10; exit }')"
gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$revoked_primary" ed25519 sign never >/dev/null 2>&1
revoked_subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
	'old@example.invalid' | awk -F: '$1 == "fpr" { n++; if (n == 2) { print $10; exit } }')"
cp keys/expected-fingerprints.txt "$TEST_ROOT/anchor.good"
printf 'gpg %s\nminisign %064d\n' "$revoked_primary" 0 >keys/expected-fingerprints.txt
DECERNOR_GPG_SIGNING_FINGERPRINT="$revoked_primary" DECERNOR_PGP_KEY_ID="${revoked_subkey}!" \
	expect_fail 'matching UID is absent' release_validate_verification_env
gpg --homedir "$TEST_GPG" --batch --quick-add-uid "$revoked_primary" \
	'Team <infosec@3leaps.net>' >/dev/null 2>&1
gpg --homedir "$TEST_GPG" --batch --quick-revoke-uid "$revoked_primary" \
	'Team <infosec@3leaps.net>' >/dev/null 2>&1
DECERNOR_GPG_SIGNING_FINGERPRINT="$revoked_primary" DECERNOR_PGP_KEY_ID="${revoked_subkey}!" \
	expect_fail 'only matching UID is revoked' release_validate_verification_env
cp "$TEST_ROOT/anchor.good" keys/expected-fingerprints.txt

expect_fail 'disabled primary state' release_validate_key_state primary s d 0
expect_fail 'expired subkey state' release_validate_key_state subkey s e 0
expect_fail 'past subkey expiry' release_validate_key_state subkey s u 1
expect_fail 'non-signing subkey' release_resolve_signing_subkey "$(printf 'pub:u:256:22:ABC:0:0:::::c:\nfpr:::::::::%s:\nsub:u:256:22:DEF:0:0:::::e:\nfpr:::::::::%s:\n' "$primary" "$subkey")"

printf 'gpg %040d\nminisign %064d\n' 0 0 >keys/expected-fingerprints.txt
expect_fail 'committed anchor mismatch' release_validate_verification_env
cp "$TEST_ROOT/anchor.good" keys/expected-fingerprints.txt

expect_fail 'no interactive terminal' "$ROOT/scripts/release-tag.sh"
if git show-ref --verify --quiet refs/tags/v0.1.8; then
	echo 'error: noninteractive tag attempt created a tag' >&2
	exit 1
fi

# pty supplies a real terminal; the synthetic key is unprotected and cannot
# request a PIN. The release helper itself still refuses a missing terminal.
python3 - "$ROOT/scripts/release-tag.sh" <<'PY'
import os, pty, sys
status = pty.spawn([sys.argv[1]])
if os.waitstatus_to_exitcode(status) != 0:
    raise SystemExit('synthetic signed-tag creation failed')
PY

release_verify_local_tag
"$ROOT/scripts/release-verify-tag.sh" >/dev/null
"$ROOT/scripts/release-guard-signing-env.sh" >/dev/null
if git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.1.8; then
	echo 'error: release-tag pushed the synthetic tag' >&2
	exit 1
fi
expect_fail 'existing local tag' release_assert_tag_absent

# A new signed object with an unexpected public message cannot be accepted.
git tag -d v0.1.8 >/dev/null
GIT_COMMITTER_NAME="$DECERNOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "$DECERNOR_PGP_KEY_ID" \
	-m 'unexpected release message' v0.1.8 "$DECERNOR_RELEASE_COMMIT"
expect_fail 'unexpected signed tag message' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

git tag v0.1.8 "$DECERNOR_RELEASE_COMMIT"
expect_fail 'lightweight tag object' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

GIT_COMMITTER_NAME='Wrong Tagger' GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "$DECERNOR_PGP_KEY_ID" \
	-m 'decernor v0.1.8' v0.1.8 "$DECERNOR_RELEASE_COMMIT"
expect_fail 'wrong tag object tagger' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

alternate_commit="$(git commit-tree 'HEAD^{tree}' -p HEAD -m 'Alternate synthetic target')"
GIT_COMMITTER_NAME="$DECERNOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "$DECERNOR_PGP_KEY_ID" \
	-m 'decernor v0.1.8' v0.1.8 "$alternate_commit"
expect_fail 'tag targets another commit' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

GIT_COMMITTER_NAME="$DECERNOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "${primary}!" \
	-m 'decernor v0.1.8' v0.1.8 "$DECERNOR_RELEASE_COMMIT"
expect_fail 'tag signed by primary instead of selected subkey' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$primary" ed25519 sign never >/dev/null 2>&1
other_subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
	'infosec@3leaps.net' | awk -F: '$1 == "fpr" { n++; if (n == 3) { print $10; exit } }')"
if [ "${#other_subkey}" -ne 40 ] || [ "$other_subkey" = "$subkey" ]; then
	echo 'error: second synthetic signing subkey is incomplete' >&2
	exit 1
fi
GIT_COMMITTER_NAME="$DECERNOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "${other_subkey}!" \
	-m 'decernor v0.1.8' v0.1.8 "$DECERNOR_RELEASE_COMMIT"
expect_fail 'wrong signing subkey' release_verify_local_tag
git tag -d v0.1.8 >/dev/null

GIT_COMMITTER_NAME="$DECERNOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$DECERNOR_TAGGER_EMAIL" \
	GNUPGHOME="$TEST_GPG" git tag -s -a -u "$DECERNOR_PGP_KEY_ID" \
	-m 'decernor v0.1.8' v0.1.8 "$DECERNOR_RELEASE_COMMIT"

"$ROOT/scripts/release-push-tag.sh" >/dev/null
git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.1.8
if [ "$(git --git-dir="$TEST_REMOTE" rev-parse refs/heads/main)" != "$DECERNOR_RELEASE_COMMIT" ]; then
	echo 'error: tag push changed remote main' >&2
	exit 1
fi
expect_fail 'existing pushed tag' "$ROOT/scripts/release-push-tag.sh"

# The remote verifier is tested against synthetic GitHub responses. The local
# tag object remains a real signed Git object in the disposable repository.
mkdir -p "$TEST_ROOT/bin"
cat >"$TEST_ROOT/bin/gh" <<'SH'
#!/usr/bin/env bash
case "$*" in
  *git/ref/tags/*) cat "$GH_TAG_REF_FILE" ;;
  *git/tags/*) cat "$GH_TAG_OBJECT_FILE" ;;
  *) exit 1 ;;
esac
SH
chmod +x "$TEST_ROOT/bin/gh"
export GH_TAG_REF_FILE="$TEST_ROOT/tag-ref.json"
export GH_TAG_OBJECT_FILE="$TEST_ROOT/tag-object.json"
tag_object_sha="$(git rev-parse refs/tags/v0.1.8)"
jq -n --arg sha "$tag_object_sha" '{object:{type:"tag",sha:$sha}}' >"$GH_TAG_REF_FILE"
jq -n --arg tag "$DECERNOR_RELEASE_TAG" --arg sha "$DECERNOR_RELEASE_COMMIT" \
	--arg name "$DECERNOR_TAGGER_NAME" --arg email "$DECERNOR_TAGGER_EMAIL" \
	'{tag:$tag,object:{type:"commit",sha:$sha},tagger:{name:$name,email:$email},verification:{verified:true,reason:"valid"}}' >"$GH_TAG_OBJECT_FILE"
PATH="$TEST_ROOT/bin:$PATH" "$ROOT/scripts/release-verify-remote-tag.sh" >/dev/null
jq '.verification.reason="unknown_key" | .verification.verified=false' "$GH_TAG_OBJECT_FILE" >"$TEST_ROOT/bad-object.json"
cp "$TEST_ROOT/bad-object.json" "$GH_TAG_OBJECT_FILE"
PATH="$TEST_ROOT/bin:$PATH" expect_fail 'remote unknown key' "$ROOT/scripts/release-verify-remote-tag.sh"
jq -n '{object:{type:"tag",sha:"0000000000000000000000000000000000000000"}}' >"$GH_TAG_REF_FILE"
PATH="$TEST_ROOT/bin:$PATH" expect_fail 'remote tag-object mismatch' "$ROOT/scripts/release-verify-remote-tag.sh"

printf 'dirty\n' >dirty.txt
expect_fail 'dirty checkout' release_assert_checkout
rm dirty.txt
git switch -q -c another
expect_fail 'non-main checkout' release_assert_checkout
git switch -q main
printf 'drift\n' >drift.txt
git add drift.txt
git commit -q -m 'Synthetic remote drift'
expect_fail 'HEAD not equal origin/main' release_assert_checkout
git push -q origin main
git tag -d v0.1.8 >/dev/null
expect_fail 'existing remote tag' release_assert_tag_absent

echo 'signed-tag controls passed'
