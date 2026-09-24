#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"

root="$(release_repo_root)"
cd "${root}"

release_assert_tag_version
release_validate_verification_env
release_assert_checkout
release_verify_local_tag
release_require_command gh
release_require_command jq

release_commit="${DECERNOR_RELEASE_COMMIT}"
local_tag_object_sha="$(git rev-parse "refs/tags/${DECERNOR_RELEASE_TAG}")"
tag_ref="$(gh api \
	"repos/3leaps/decernor/git/ref/tags/${DECERNOR_RELEASE_TAG}")"
if ! jq -e '.object.type == "tag"' >/dev/null <<<"${tag_ref}"; then
	echo "error: remote version-tag ref does not target an annotated tag object" >&2
	exit 1
fi

tag_object_sha="$(jq -r '.object.sha' <<<"${tag_ref}")"
if [ "${tag_object_sha}" != "${local_tag_object_sha}" ]; then
	echo "error: remote tag object differs from the locally verified tag object" >&2
	exit 1
fi
tag_object="$(gh api "repos/3leaps/decernor/git/tags/${tag_object_sha}")"
if ! jq -e \
	--arg tag "${DECERNOR_RELEASE_TAG}" \
	--arg commit "${release_commit}" \
	--arg name "${DECERNOR_TAGGER_NAME}" \
	--arg email "${DECERNOR_TAGGER_EMAIL}" '
        .tag == $tag and
        .object.type == "commit" and
        .object.sha == $commit and
        .tagger.name == $name and
        .tagger.email == $email and
        .verification.verified == true and
        .verification.reason == "valid"
    ' >/dev/null <<<"${tag_object}"; then
	echo "error: GitHub does not report the expected verified signed tag and target" >&2
	exit 1
fi

echo "[ok] GitHub reports a verified signed tag at ${release_commit}"
