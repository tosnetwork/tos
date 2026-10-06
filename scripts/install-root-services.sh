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
#                                           third-party dependencies, copied in
# keeping the checkout's relative layout so the drivers' REPO-relative defaults
# resolve inside the snapshot, then points BASE/current at it and removes older
# snapshots. The units run only BASE/current and hide /home, so the checkout --
# and whoever can write it -- is never on a root service's execution path.
#
# The checkout is trusted while this runs (the administrator runs it); nothing it
# leaves behind may still point back there. Before publishing, the snapshot is
# checked to reach nothing outside itself except system libraries. BASE and its
# ancestors must be writable by root alone. The services must be stopped: older
# snapshots are deleted. Changing the drivers takes effect after the next install.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 BASE REPO BUILD GENERATOR" >&2; exit 2; }
BASE="$1" REPO="$2" BUILD="$3" GENERATOR="$4"
UV="${UV:-$(command -v uv || true)}"
[[ -n "$UV" ]] || { echo 'uv is required' >&2; exit 1; }
CHECK=(/usr/bin/python3 -I -S "$REPO/scripts/install-root-services-check.py")
MARKER=.tos-dev-services-snapshot
for required in "$REPO/scripts" "$REPO/test/tostester/src" "$BUILD/toslib/libtoslibjson.so" "$GENERATOR" \
    "$REPO/crypto/smartcont/single-nominator-pool/single-nominator-code.hex"; do
    [[ -e "$required" ]] || { echo "missing $required" >&2; exit 1; }
done
if [[ $EUID -eq 0 ]] && command -v systemctl >/dev/null; then
    for unit in tos-pq-privacy tos-pq-transfers tos-pq-elections; do
        ! systemctl is-active --quiet "$unit" || { echo "stop $unit before installing" >&2; exit 1; }
    done
fi
"${CHECK[@]}" sources "$REPO/scripts" "$REPO/test/tostester/src"
"${CHECK[@]}" base "$BASE"
umask 022
mkdir -p "$BASE"
"${CHECK[@]}" base "$BASE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEST="$BASE/$STAMP"
mkdir "$DEST"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
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
# snapshot as copies (never links into a cache) from a clean environment; the
# workspace package is not installed, its sources are on PYTHONPATH from src/.
PASS=()
for name in HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR; do
    [[ -z "${!name:-}" ]] || PASS+=("$name=${!name}")
done
mkdir "$WORK/home" "$WORK/cache"
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME="$WORK/home" \
    "${PASS[@]}" UV_CACHE_DIR="$WORK/cache" UV_LINK_MODE=copy UV_NO_CONFIG=1 \
    UV_PYTHON_INSTALL_DIR="$DEST/python" UV_PROJECT_ENVIRONMENT="$DEST/venv" \
    UV_PYTHON_PREFERENCE=only-managed \
    "$UV" sync --project "$REPO" --frozen --no-dev --no-install-workspace --quiet
# The managed interpreter's Tk bindings carry their build machine's library search
# path (/tools/deps/lib), which a root process must not consult; the services never
# use Tk, so the bindings are not part of the snapshot.
find "$DEST/python" \( -name '_tkinter*.so' -o -name 'libtcl*.so*' -o -name 'libtk*.so*' \) -delete
touch "$DEST/$MARKER"
chmod -R u+rwX,go+rX,go-w "$DEST"
if [[ $EUID -eq 0 ]]; then
    chown -R root:root "$DEST"
fi
"${CHECK[@]}" snapshot "$DEST"
# Execute the staged generator, not current, with both original roots hidden.
# Failure leaves the old current link and its snapshot untouched.
/usr/bin/python3 -I -S "$REPO/scripts/check-local-pq-resources.py" "$DEST" "$REPO" "$BUILD"
ln -sfn "$STAMP" "$BASE/current.new"
mv -T "$BASE/current.new" "$BASE/current"
for old in "$BASE"/*; do
    [[ "$old" != "$DEST" && ! -L "$old" && -d "$old" && -e "$old/$MARKER" ]] || continue
    [[ "$(basename "$old")" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || continue
    rm -rf -- "$old"
done
echo "$DEST"
