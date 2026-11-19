#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# These defaults are only a convenience for a developer invoking this script
# directly. CI passes the compilers it has just built.
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
# SERVICE_ACTOR_PROFILE selects the build: "release" (the default) compiles
# the checked-in source; "test" compiles the TEST-NETWORK-ONLY build whose
# minimum response SLA and refund claim window are lowered (see
# scripts/tos_service_actor_profile.py). Each profile has its own manifest.
PROFILE=${SERVICE_ACTOR_PROFILE:-release}
PROFILE_TOOL="$REPO_ROOT/scripts/tos_service_actor_profile.py"
DEFAULT_OUTPUT=$(python3 "$PROFILE_TOOL" default-output "$PROFILE")
OUTPUT=${1:-"$DEFAULT_OUTPUT"}
# The profile's manifest is the one place its pins live.
MANIFEST=$(python3 "$PROFILE_TOOL" manifest "$PROFILE")
PINS=$(python3 - "$MANIFEST" <<'PY'
import json
import re
import sys

manifest = json.load(open(sys.argv[1]))
code_hash = manifest["code_hash"].removeprefix("tvm-cell-sha256:")
boc_sha256 = manifest["boc_sha256"].removeprefix("sha256:")
boc_bytes = manifest["boc_bytes"]
if not re.fullmatch(r"[0-9a-f]{64}", code_hash) or not re.fullmatch(r"[0-9a-f]{64}", boc_sha256):
    sys.exit("release manifest pins are not 64 lower-case hex digits")
if type(boc_bytes) is not int or boc_bytes <= 0:
    sys.exit("release manifest boc_bytes is not a positive integer")
print(code_hash, boc_sha256, boc_bytes)
PY
)
read -r EXPECTED_CODE_HASH EXPECTED_BOC_SHA256 EXPECTED_BOC_BYTES <<< "$PINS"

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "required compiler is unavailable: $binary" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT")"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
SOURCE=$(python3 "$PROFILE_TOOL" source "$PROFILE" "$BUILD_DIR/source")

# The release manifest records this argument vector; the placeholders are
# substituted here and nowhere else.
FUNC_ARGUMENTS=(-W "<output.boc>" -A -P -o "<temporary.fif>")
FUNC_COMMAND=()
for argument in "${FUNC_ARGUMENTS[@]}"; do
  case "$argument" in
    "<output.boc>") FUNC_COMMAND+=("$OUTPUT") ;;
    "<temporary.fif>") FUNC_COMMAND+=("$BUILD_DIR/service-actor-v1.fif") ;;
    *) FUNC_COMMAND+=("$argument") ;;
  esac
done
"$FUNC_BIN" "${FUNC_COMMAND[@]}" \
  "$REPO_ROOT/crypto/smartcont/stdlib.fc" \
  "$SOURCE"
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" \
  "$BUILD_DIR/service-actor-v1.fif"

HASH_OUTPUT=$(FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/hash-code-boc.fif" "$OUTPUT")
ACTUAL_CODE_HASH=$(printf '%s\n' "$HASH_OUTPUT" | sed -n 's/^tvm-cell-sha256:\([0-9a-f]*\).*/\1/p')
ACTUAL_CODE_HASH=$(printf '%064s' "$ACTUAL_CODE_HASH" | tr ' ' 0)
BOC_METADATA=$(python3 - "$OUTPUT" <<'PY'
import hashlib
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
print(hashlib.sha256(raw).hexdigest(), len(raw))
PY
)
read -r ACTUAL_BOC_SHA256 ACTUAL_BOC_BYTES <<< "$BOC_METADATA"

if [[ "$ACTUAL_CODE_HASH" != "$EXPECTED_CODE_HASH" ]]; then
  echo "code hash mismatch: $ACTUAL_CODE_HASH" >&2
  exit 1
fi
if [[ "$ACTUAL_BOC_SHA256" != "$EXPECTED_BOC_SHA256" ]]; then
  echo "BOC SHA-256 mismatch: $ACTUAL_BOC_SHA256" >&2
  exit 1
fi
if [[ "$ACTUAL_BOC_BYTES" != "$EXPECTED_BOC_BYTES" ]]; then
  echo "BOC size mismatch: $ACTUAL_BOC_BYTES" >&2
  exit 1
fi

printf 'profile=%s\n' "$PROFILE"
printf 'code_hash=tvm-cell-sha256:%s\n' "$ACTUAL_CODE_HASH"
printf 'boc_sha256=sha256:%s\n' "$ACTUAL_BOC_SHA256"
printf 'boc_bytes=%s\n' "$ACTUAL_BOC_BYTES"
printf 'compiler_arguments=%s\n' "${FUNC_ARGUMENTS[*]}"
printf 'output=%s\n' "$OUTPUT"
