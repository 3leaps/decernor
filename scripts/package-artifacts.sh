#!/usr/bin/env bash
set -euo pipefail

# Package release artifacts for the microtool.
# Builds archives for each OS/arch with checksums; optional GPG signing via SIGN=1.
#
# Usage:
#   SIGN=1 ./scripts/package-artifacts.sh   # adds SHA256SUMS.asc if gpg is available
#
# Notes:
# - Expects binaries already built in ./bin (use `make build-all` first).
# - BINARY_NAME can be overridden via env; defaults to "decernor".
# - Archives land in dist/release alongside SHA256SUMS (and optional .asc).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PROJECT="${BINARY_NAME:-decernor}"
VERSION="$(cat VERSION)"
BIN_DIR="bin"
OUT_DIR="dist/release"
OUT_DIR_ABS="$(mkdir -p "${OUT_DIR}" && cd "${OUT_DIR}" && pwd)"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}/SHA256SUMS" "${OUT_DIR}/SHA256SUMS.asc"

package() {
    local os="$1" arch="$2"
    local ext="" archive_ext="tar.gz"
    local bin="${BIN_DIR}/${PROJECT}-${os}-${arch}"
    local archive_name="${PROJECT}_${VERSION}_${os}_${arch}.${archive_ext}"

    if [[ "${os}" == "windows" ]]; then
        ext=".exe"
        bin="${bin}${ext}"
        archive_ext="zip"
        archive_name="${PROJECT}_${VERSION}_${os}_${arch}.${archive_ext}"
    fi

    if [[ ! -f "${bin}" ]]; then
        echo "Skipping ${os}/${arch}: binary not found: ${bin}" >&2
        return
    fi

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' RETURN

    local bin_name="${PROJECT}${ext}"
    cp "${bin}" "${tmpdir}/${bin_name}"
    chmod +x "${tmpdir}/${bin_name}"

    case "${archive_ext}" in
        tar.gz)
            (cd "${tmpdir}" && tar -czf "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            ;;
        zip)
            # Prefer the `zip` CLI; fall back to python3 (the goneat-tools
            # runner image ships python3 but not zip).
            if command -v zip > /dev/null 2>&1; then
                (cd "${tmpdir}" && zip -q "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            elif command -v python3 > /dev/null 2>&1; then
                (cd "${tmpdir}" && python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w",zipfile.ZIP_DEFLATED); z.write(sys.argv[2]); z.close()' "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            else
                echo "Neither zip nor python3 available to create ${archive_name}" >&2
                exit 1
            fi
            ;;
    esac

    if command -v shasum > /dev/null 2>&1; then
        (cd "${OUT_DIR_ABS}" && shasum -a 256 "${archive_name}") >> "${OUT_DIR_ABS}/SHA256SUMS"
    elif command -v sha256sum > /dev/null 2>&1; then
        (cd "${OUT_DIR_ABS}" && sha256sum "${archive_name}") >> "${OUT_DIR_ABS}/SHA256SUMS"
    else
        echo "No sha256 tool available" >&2
        exit 1
    fi

    echo "Packaged ${archive_name}"
}

# Build matrix (aligns with make build-all)
package linux amd64
package linux arm64
package darwin amd64
package darwin arm64
package windows amd64

# Optional GPG signing of checksums
if [[ "${SIGN:-}" == "1" ]]; then
    if command -v gpg > /dev/null 2>&1; then
        gpg --batch --yes --armor --detach-sign -o "${OUT_DIR_ABS}/SHA256SUMS.asc" "${OUT_DIR_ABS}/SHA256SUMS"
        echo "Signed SHA256SUMS -> SHA256SUMS.asc"

        # Optional: export public key alongside signatures.
        # This supports `make verify-release-key` and ensures maintainers can publish
        # a public-only key file with the release.
        if [[ -n "${SIGNING_KEY_ID:-}" ]]; then
            gpg --armor --export "${SIGNING_KEY_ID}" > "${OUT_DIR_ABS}/${PROJECT}-release-signing-key.asc"
            echo "Exported public key -> ${PROJECT}-release-signing-key.asc"
        else
            echo "SIGN=1 but SIGNING_KEY_ID not set; skipping public key export" >&2
        fi
    else
        echo "SIGN=1 but gpg not found; skipping signature" >&2
    fi
fi

echo "Artifacts in ${OUT_DIR_ABS}:"
ls -lh "${OUT_DIR_ABS}"
