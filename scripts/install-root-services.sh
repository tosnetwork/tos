#!/usr/bin/env bash
# Install a root-owned snapshot of everything the root-run development services
# (tos-pq-privacy, tos-pq-transfers, tos-pq-elections) execute.
#
#   install-root-services.sh BASE REPO BUILD GENERATOR
#
# Writes BASE/<stamp>/ with
#   src/scripts, src/test/tostester/src     the Python sources, copied
#   src/build/toslib/libtoslibjson.so       the native client library
#   src/crypto/smartcont/.../*.hex          contract code the drivers read
#   src/tools/.../local_pool_traffic        the private-traffic generator
#   python/, venv/                          a managed interpreter and the locked
#                                           third-party dependencies
# keeping the checkout's relative layout so the drivers' REPO-relative defaults
# resolve inside the snapshot, then points BASE/current at it and removes older
# snapshots. The units run only BASE/current and hide /home, so the checkout --
# and whoever can write it -- is never on a root service's execution path.
# Changing the drivers takes effect after the next install, not on restart.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 BASE REPO BUILD GENERATOR" >&2; exit 2; }
BASE="$1" REPO="$2" BUILD="$3" GENERATOR="$4"
UV="${UV:-$(command -v uv || true)}"
[[ -n "$UV" ]] || { echo 'uv is required' >&2; exit 1; }
for required in "$REPO/scripts" "$REPO/test/tostester/src" "$BUILD/toslib/libtoslibjson.so" "$GENERATOR" \
    "$REPO/crypto/smartcont/single-nominator-pool/single-nominator-code.hex"; do
    [[ -e "$required" ]] || { echo "missing $required" >&2; exit 1; }
done
umask 022
mkdir -p "$BASE"
[[ ! -L "$BASE" ]] || { echo "$BASE must not be a symlink" >&2; exit 1; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEST="$BASE/$STAMP"
mkdir "$DEST"
SRC="$DEST/src"
mkdir -p "$SRC/test/tostester" "$SRC/build/toslib" "$SRC/crypto/smartcont/single-nominator-pool" \
    "$SRC/tools/shielded-pool-circuit/crosscheck/target/release"
cp -R "$REPO/scripts" "$SRC/scripts"
cp -R "$REPO/test/tostester/src" "$SRC/test/tostester/src"
cp -L "$BUILD/toslib/libtoslibjson.so" "$SRC/build/toslib/libtoslibjson.so"
cp "$REPO/crypto/smartcont/single-nominator-pool/single-nominator-code.hex" \
    "$SRC/crypto/smartcont/single-nominator-pool/"
cp -L "$GENERATOR" "$SRC/tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"
find "$SRC" -name __pycache__ -type d -prune -exec rm -rf {} +
# The interpreter and dependencies come from the checkout's lock, installed into the
# snapshot itself; the workspace package is not installed, its sources are on
# PYTHONPATH from src/.
UV_PYTHON_INSTALL_DIR="$DEST/python" UV_PROJECT_ENVIRONMENT="$DEST/venv" \
    UV_PYTHON_PREFERENCE=only-managed UV_NO_CONFIG=1 \
    "$UV" sync --project "$REPO" --frozen --no-dev --no-install-workspace --quiet
chmod -R u+rwX,go+rX,go-w "$DEST"
if [[ $EUID -eq 0 ]]; then
    chown -R root:root "$DEST"
fi
ln -sfn "$STAMP" "$BASE/current.new"
mv -T "$BASE/current.new" "$BASE/current"
for old in "$BASE"/*; do
    [[ "$old" == "$DEST" || "$old" == "$BASE/current" ]] || rm -rf -- "$old"
done
echo "$DEST"
