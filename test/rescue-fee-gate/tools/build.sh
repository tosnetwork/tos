#!/bin/sh
# Build the test-only signers used by test_rescue_e2e.py from the vendored backends.
# Usage: build.sh <output-directory>; then export SLH_TOOL and MLDSA_TOOL to the binaries.
# They sign PUBLIC TEST DATA only (deterministic, no secret hygiene).
set -eu
out=${1:?output directory}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
slh=$root/third-party/slhdsa-c
mld=$root/third-party/mldsa-native/mldsa
mkdir -p "$out"
cc -O2 -w -I"$slh" -o "$out/slh_tool" "$here/slh_tool.c" \
  "$slh/slh_dsa.c" "$slh/slh_sha2.c" "$slh/sha2_256.c" "$slh/sha2_512.c"
cat > "$out/mldtest-config.h" <<'EOF'
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX mldtest
#define MLD_CONFIG_NO_RANDOMIZED_API
EOF
cc -O2 -w -I"$out" -I"$mld" -DMLD_CONFIG_FILE='"mldtest-config.h"' -o "$out/mldsa_tool" \
  "$here/mldsa_tool.c" "$mld/mldsa_native.c"
echo "built $out/slh_tool $out/mldsa_tool"
