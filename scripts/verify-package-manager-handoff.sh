#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <release-tag> <homebrew-tap-dir> <scoop-bucket-dir>" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

release_tag="$1"
homebrew_tap_dir="$2"
scoop_bucket_dir="$3"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '[:space:]' < "${root_dir}/VERSION")"

if [[ "${release_tag}" != "v${version}" ]]; then
  echo "error: release tag ${release_tag} does not match VERSION ${version}" >&2
  exit 1
fi

for sibling in "${homebrew_tap_dir}" "${scoop_bucket_dir}"; do
  if ! git -C "${sibling}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: sibling worktree is missing or not a git repository: ${sibling}" >&2
    exit 1
  fi
  if [[ -n "$(git -C "${sibling}" status --porcelain)" ]]; then
    echo "error: sibling worktree is dirty: ${sibling}" >&2
    exit 1
  fi
done

if [[ ! -f "${homebrew_tap_dir}/Formula/decernor.rb" ]]; then
  echo "error: missing Homebrew seed formula: ${homebrew_tap_dir}/Formula/decernor.rb" >&2
  exit 1
fi
if [[ ! -f "${scoop_bucket_dir}/bucket/decernor.json" ]]; then
  echo "error: missing Scoop seed manifest: ${scoop_bucket_dir}/bucket/decernor.json" >&2
  exit 1
fi

metadata_path="${DECERNOR_RELEASE_METADATA:-}"
checksums_path="${DECERNOR_SHA256SUMS:-}"
cleanup=()
cleanup_files() {
  rm -f "${cleanup[@]}"
}
trap cleanup_files EXIT

if [[ -z "${metadata_path}" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "error: gh CLI is required" >&2; exit 1; }
  metadata_path="$(mktemp)"
  cleanup+=("${metadata_path}")
  gh release view "${release_tag}" --repo 3leaps/decernor \
    --json tagName,isDraft,isPrerelease,assets > "${metadata_path}"
fi

if [[ -z "${checksums_path}" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "error: gh CLI is required" >&2; exit 1; }
  checksums_path="$(mktemp)"
  cleanup+=("${checksums_path}")
  gh release download "${release_tag}" --repo 3leaps/decernor --pattern SHA256SUMS \
    --output "${checksums_path}" --clobber
fi

if [[ ! -f "${metadata_path}" || ! -f "${checksums_path}" ]]; then
  echo "error: release metadata and SHA256SUMS must be readable files" >&2
  exit 1
fi

python3 - "${release_tag}" "${metadata_path}" "${checksums_path}" <<'PY'
import json
import re
import sys
from pathlib import Path

tag, metadata_path, checksums_path = sys.argv[1:]
version = tag.removeprefix("v")
release = json.loads(Path(metadata_path).read_text())

if release.get("tagName") != tag:
    raise SystemExit(f"error: release metadata tag does not match {tag}")
if release.get("isDraft") or release.get("isPrerelease"):
    raise SystemExit(f"error: release {tag} is not a published stable release")

required = [
    f"decernor_{version}_darwin_amd64.tar.gz",
    f"decernor_{version}_darwin_arm64.tar.gz",
    f"decernor_{version}_linux_amd64.tar.gz",
    f"decernor_{version}_linux_arm64.tar.gz",
    f"decernor_{version}_windows_amd64.zip",
]
assets = release.get("assets", [])
asset_digests = {}
for name in required:
    matching = [asset for asset in assets if asset.get("name") == name]
    if len(matching) != 1:
        raise SystemExit(f"error: expected one release asset named {name}, found {len(matching)}")
    digest = matching[0].get("digest", "").removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit(f"error: missing SHA-256 digest for {name}")
    asset_digests[name] = digest

checksums = {}
for line in Path(checksums_path).read_text().splitlines():
    parts = line.split()
    if len(parts) != 2:
        continue
    digest, name = parts
    name = name.removeprefix("*")
    if name in checksums:
        raise SystemExit(f"error: duplicate checksum entry for {name}")
    checksums[name] = digest

for name, digest in asset_digests.items():
    checksum = checksums.get(name)
    if checksum is None:
        raise SystemExit(f"error: SHA256SUMS is missing {name}")
    if checksum != digest:
        raise SystemExit(f"error: SHA256SUMS digest mismatch for {name}")

print(f"verified published package-manager assets for {tag}")
PY

command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
release_url="https://github.com/3leaps/decernor/releases/download/${release_tag}"
for asset in \
  "SHA256SUMS" \
  "decernor_${version}_darwin_amd64.tar.gz" \
  "decernor_${version}_darwin_arm64.tar.gz" \
  "decernor_${version}_linux_amd64.tar.gz" \
  "decernor_${version}_linux_arm64.tar.gz" \
  "decernor_${version}_windows_amd64.zip"; do
  if ! curl --fail --location --range 0-0 --output /dev/null --silent --show-error \
    "${release_url}/${asset}"; then
    echo "error: published release asset is not anonymously downloadable: ${asset}" >&2
    exit 1
  fi
done

echo "verified anonymous package-manager downloads for ${release_tag}"
