#!/usr/bin/env bash
# download-pyspec-fixtures.sh — fetch the execution-spec-tests fixtures
# corpus used by test-evm-executor's Pyspec walkers.
#
# Usage:   ./scripts/download-pyspec-fixtures.sh [release-tag]
# Default: v5.4.0 (first release covering the full Fusaka / Osaka EIP set).
#
# The corpus is ~400 MB compressed / 8 GB extracted. Downloads are stored
# at test/conformance/execution-spec-tests/fixtures/ (gitignored).

set -euo pipefail

TAG="${1:-v5.4.0}"
BUILD="${BUILD:-develop}"   # 'develop' covers all Osaka EIPs; 'stable' only 7825+7883
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$REPO_ROOT/test/conformance/execution-spec-tests"
TAR="$DEST/fixtures_${BUILD}.tar.gz"
URL="https://github.com/ethereum/execution-spec-tests/releases/download/${TAG}/fixtures_${BUILD}.tar.gz"

mkdir -p "$DEST"

if [ -d "$DEST/fixtures" ]; then
    echo "Existing fixtures at $DEST/fixtures — remove first to refresh."
    exit 0
fi

echo "Downloading execution-spec-tests ${TAG} (${BUILD} build) from:"
echo "  $URL"
curl -fsSL -o "$TAR" "$URL"
echo "Extracting (this takes ~30 s)..."
tar -C "$DEST" -xzf "$TAR"
rm "$TAR"

echo "Done. Verify:"
echo "  ls $DEST/fixtures/state_tests/osaka/"
ls "$DEST/fixtures/state_tests/osaka/" 2>/dev/null || true
