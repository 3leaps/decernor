#!/usr/bin/env bash
set -euo pipefail
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"
release_validate_verification_env
release_assert_checkout
release_verify_local_tag
release_assert_tag_absent_remote() {
	local remote_status
	set +e
	git ls-remote --exit-code --tags origin "refs/tags/${DECERNOR_RELEASE_TAG}" >/dev/null 2>&1
	remote_status=$?
	set -e
	case "${remote_status}" in
	2) ;;
	0)
		echo "error: remote tag already exists" >&2
		return 1
		;;
	*)
		echo "error: unable to determine remote tag state" >&2
		return 1
		;;
	esac
}
release_assert_tag_absent_remote
git push origin "refs/tags/${DECERNOR_RELEASE_TAG}:refs/tags/${DECERNOR_RELEASE_TAG}"
echo "[ok] pushed signed tag ${DECERNOR_RELEASE_TAG} only"
