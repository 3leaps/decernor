#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/var/tmp}/decernor-package-manager.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

homebrew_dir="${tmp_dir}/homebrew-tap"
scoop_dir="${tmp_dir}/scoop-bucket"
mock_bin="${tmp_dir}/bin"
mkdir -p "${homebrew_dir}/Formula" "${scoop_dir}/bucket" "${mock_bin}"
printf 'class Decernor < Formula\nend\n' > "${homebrew_dir}/Formula/decernor.rb"
printf '{}\n' > "${scoop_dir}/bucket/decernor.json"
printf '%s\n' 'update-decernor:' $'\t@test "$(VERSION)" = "0.1.6"' > "${scoop_dir}/Makefile"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "${mock_bin}/curl"
chmod +x "${mock_bin}/curl"

for sibling in "${homebrew_dir}" "${scoop_dir}"; do
  git -C "${sibling}" init -q
  git -C "${sibling}" config user.name test
  git -C "${sibling}" config user.email test@example.invalid
  git -C "${sibling}" add .
  git -C "${sibling}" commit -qm fixture
done

write_fixture() {
  local mode="$1"
  python3 - "${tmp_dir}/metadata.json" "${tmp_dir}/SHA256SUMS" "${mode}" <<'PY'
import json
import sys
from pathlib import Path

metadata_path, sums_path, mode = sys.argv[1:]
version = "0.1.6"
names = [
    f"decernor_{version}_darwin_amd64.tar.gz",
    f"decernor_{version}_darwin_arm64.tar.gz",
    f"decernor_{version}_linux_amd64.tar.gz",
    f"decernor_{version}_linux_arm64.tar.gz",
    f"decernor_{version}_windows_amd64.zip",
]
assets = []
lines = []
for index, name in enumerate(names, start=1):
    digest = f"{index:064x}"
    assets.append({"name": name, "digest": f"sha256:{digest}"})
    lines.append(f"{digest}  {name}")
if mode == "duplicate":
    assets.append(assets[0].copy())
if mode == "mismatch":
    lines[0] = f"{'0' * 64}  {names[0]}"
if mode == "missing-asset":
    assets = assets[1:]
if mode == "missing-checksum":
    lines = lines[1:]
Path(metadata_path).write_text(json.dumps({
    "tagName": "v0.1.6",
    "isDraft": False,
    "isPrerelease": False,
    "assets": assets,
}))
Path(sums_path).write_text("\n".join(lines) + "\n")
PY
}

run_handoff() {
  PATH="${mock_bin}:${PATH}" \
    DECERNOR_RELEASE_METADATA="${tmp_dir}/metadata.json" \
    DECERNOR_SHA256SUMS="${tmp_dir}/SHA256SUMS" \
    bash "${root_dir}/scripts/verify-package-manager-handoff.sh" \
    v0.1.6 "${homebrew_dir}" "${scoop_dir}"
}

write_fixture valid
run_handoff
PATH="${mock_bin}:${PATH}" \
  DECERNOR_RELEASE_METADATA="${tmp_dir}/metadata.json" \
  DECERNOR_SHA256SUMS="${tmp_dir}/SHA256SUMS" \
  make -C "${root_dir}" update-scoop-manifest \
  HOMEBREW_TAP_DIR="${homebrew_dir}" SCOOP_BUCKET_DIR="${scoop_dir}"

write_fixture duplicate
if run_handoff; then
  echo "expected duplicate asset fixture to fail" >&2
  exit 1
fi

write_fixture mismatch
if run_handoff; then
  echo "expected checksum mismatch fixture to fail" >&2
  exit 1
fi

write_fixture missing-asset
if run_handoff; then
  echo "expected missing asset fixture to fail" >&2
  exit 1
fi

write_fixture missing-checksum
if run_handoff; then
  echo "expected missing checksum fixture to fail" >&2
  exit 1
fi

echo "package-manager handoff tests passed"
