#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/crosschain/token-bridge"
SRC="$PROJECT/tvm/contracts"
PARAMS="$PROJECT/tvm/params"
FUNC_BIN="${FUNC:-$ROOT/build/crypto/func}"
FIFT_BIN="${FIFT:-$ROOT/build/crypto/fift}"
FIFT_LIB="$ROOT/crypto/fift/lib"
OUT="${OUT:-$PROJECT/artifacts/tvm}"

# OUT is caller-supplied; refuse to recursively delete anything that is not a
# path inside this bridge's own artifacts directory.
canonical_out="$(readlink -m -- "$OUT")"
artifacts_root="$(readlink -m -- "$PROJECT/artifacts")"
if [[ "$canonical_out" != "$artifacts_root" && "$canonical_out" != "$artifacts_root"/* ]]; then
  echo "OUT must stay inside $artifacts_root (got: $canonical_out)" >&2
  exit 2
fi
OUT="$canonical_out"

if [[ ! -x "$FUNC_BIN" ]]; then
  echo "FunC compiler not found: $FUNC_BIN" >&2
  echo "Build it with: cmake --build build --target func fift" >&2
  exit 2
fi

contracts=(jetton-bridge jetton-minter jetton-wallet multisig votes-collector)
networks=(ethereum bsc polygon)
work_root="$(mktemp -d -t tos-token-bridge-build.XXXXXX)"
trap 'rm -rf "$work_root"' EXIT

compile_pass() {
  local pass="$1"
  local pass_root="$work_root/$pass"
  for network in "${networks[@]}"; do
    local work="$pass_root/$network/src"
    local output="$pass_root/$network/out"
    mkdir -p "$work" "$output"
    cp "$SRC"/*.fc "$work/"
    cp "$PARAMS/$network.fc" "$work/params.fc"
    for contract in "${contracts[@]}"; do
      (
        cd "$work"
        "$FUNC_BIN" -PS -o "$output/$contract.fif" "$contract.fc"
      )
    done
  done
}

compile_pass first
compile_pass second

diff -ru "$work_root/first" "$work_root/second" >/dev/null

if [[ ! -x "$FIFT_BIN" ]]; then
  echo "Fift assembler not found: $FIFT_BIN" >&2
  echo "Build it with: cmake --build build --target func fift" >&2
  echo "Assembly is part of this check; it is not optional." >&2
  exit 2
fi

for fif in "$work_root"/first/*/out/*.fif; do
  wrapper="$work_root/assemble.fif"
  printf '"Asm.fif" include "%s" include hashu . cr\n' "$fif" > "$wrapper"
  FIFTPATH="$FIFT_LIB" "$FIFT_BIN" -s "$wrapper" >/dev/null
done

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$work_root/first/." "$OUT/"
find "$OUT" -type d -name src -prune -exec rm -rf {} +
(
  cd "$OUT"
  find . -type f -name '*.fif' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Reproducibly compiled ${#contracts[@]} contracts for ${#networks[@]} external networks (assembly-checked)."
echo "Artifacts: $OUT"
