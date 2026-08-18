#!/usr/bin/env bash
# Download unsigned archive assets from the GitHub draft release.
set -euo pipefail

TAG=${1:?"usage: download-release-assets.sh <tag> [dest_dir]"}
DEST=${2:-dist/release}

echo "Downloading release assets for $TAG to $DEST..."
mkdir -p "$DEST"

gh release download "$TAG" --dir "$DEST" --clobber \
	--pattern 'decernor_*.tar.gz' \
	--pattern 'decernor_*.zip'

echo "Downloaded to $DEST:"
ls -la "$DEST"
