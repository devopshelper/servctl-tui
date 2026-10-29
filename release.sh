#!/usr/bin/env bash
# Builds dist/servctl-<version>.zip from the committed tree.
set -euo pipefail
cd "$(dirname "$0")"
ver=$(python3 -c "import servctl; print(servctl.__version__)")
mkdir -p dist
git archive --format=zip --prefix="servctl-$ver/" -o "dist/servctl-$ver.zip" HEAD
echo "dist/servctl-$ver.zip"
