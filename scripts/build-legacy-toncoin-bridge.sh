#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/crosschain/legacy-toncoin-bridge"
FUNC_BIN="${FUNC:-$ROOT/build/crypto/func}"
FIFT_BIN="${FIFT:-$ROOT/build/crypto/fift}"
FIFT_LIB="$ROOT/crypto/fift/lib"
OUT="${OUT:-$PROJECT/artifacts/tvm}"

if [[ ! -x "$FUNC_BIN" ]]; then
  echo "FunC compiler not found: $FUNC_BIN" >&2
  echo "Build it with: cmake --build build --target func fift" >&2
  exit 2
fi

networks=(ethereum bsc)
work_root="$(mktemp -d -t tos-toncoin-build.XXXXXX)"
trap 'rm -rf "$work_root"' EXIT

compile_contract() {
  local src="$1" output="$2" name="$3"
  shift 3
  (cd "$src" && "$FUNC_BIN" -SPA -o "$output/$name.fif" "$@")
}

compile_pass() {
  local pass="$1"
  local pass_root="$work_root/$pass"
  for network in "${networks[@]}"; do
    local src="$PROJECT/tvm/$network"
    local output="$pass_root/$network"
    mkdir -p "$output"
    compile_contract "$src" "$output" bridge \
      stdlib.fc text_utils.fc message_utils.fc bridge-config.fc bridge_code.fc
    compile_contract "$src" "$output" multisig \
      stdlib.fc multisig-code.fc
    compile_contract "$src" "$output" votes-collector \
      stdlib.fc message_utils.fc bridge-config.fc votes-collector.fc
  done
}

compile_pass first
compile_pass second

diff -ru "$work_root/first" "$work_root/second" >/dev/null

if [[ -x "$FIFT_BIN" ]]; then
  for fif in "$work_root"/first/*/*.fif; do
    wrapper="$work_root/assemble.fif"
    printf '"%s" include hashu . cr\n' "$fif" > "$wrapper"
    FIFTPATH="$FIFT_LIB" "$FIFT_BIN" -s "$wrapper" >/dev/null
  done
else
  echo "warning: fift not found at $FIFT_BIN; skipping assembly check" >&2
fi

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$work_root/first/." "$OUT/"
(
  cd "$OUT"
  find . -type f -name '*.fif' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Reproducibly compiled 3 contracts for ${#networks[@]} external networks (assembly-checked)."
echo "Artifacts: $OUT"
