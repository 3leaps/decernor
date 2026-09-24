#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"

root="$(release_repo_root)"
cd "${root}"

release_validate_signing_env
release_setup_gpg_tty
release_assert_checkout
release_assert_tag_absent

export GIT_COMMITTER_NAME="${DECERNOR_TAGGER_NAME}"
export GIT_COMMITTER_EMAIL="${DECERNOR_TAGGER_EMAIL}"

echo "Creating GPG-signed tag ${DECERNOR_RELEASE_TAG} at ${DECERNOR_RELEASE_COMMIT}"
GNUPGHOME="${GNUPGHOME}" git -c gpg.format=openpgp -c gpg.program=gpg tag -s -a \
	-u "${DECERNOR_PGP_KEY_ID}" \
	-m "decernor ${DECERNOR_RELEASE_TAG}" \
	"${DECERNOR_RELEASE_TAG}" \
	"${DECERNOR_RELEASE_COMMIT}"

release_verify_local_tag

echo "[ok] created and verified signed tag ${DECERNOR_RELEASE_TAG}"
echo "[--] the tag is local only; push requires separate maintainer authorization"
