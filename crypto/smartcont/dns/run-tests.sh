#!/bin/sh
# Run the vendored upstream test suite against the .tos contracts using the
# TOS toolchain. Adjust TOS_BUILD/TOS_SRC if your tree lives elsewhere.
set -e
TOS_SRC="${TOS_SRC:-$(cd "$(dirname "$0")/../../.." && pwd)}"
TOS_BUILD="${TOS_BUILD:-$TOS_SRC/build}"
export PATH="$TOS_BUILD/crypto:$PATH"
export FIFTPATH="$(cd "$(dirname "$0")" && pwd)/test/shim:$TOS_SRC/crypto/fift/lib"
cd "$(dirname "$0")"
sh test.sh
