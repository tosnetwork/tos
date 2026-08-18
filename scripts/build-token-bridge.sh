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

# OUT is caller-supplied and drives a recursive delete, so it must be proven to
# sit inside this bridge's own artifacts directory. Traversal segments are
# refused outright: a legitimate value never needs them, and re-appending an
# unresolved tail to a resolved prefix would otherwise let ".." escape the
# prefix check. Resolution avoids `readlink -m`, which is GNU-only.
case "/$OUT/" in
  */../*)
    echo "OUT must not contain '..' segments (got: $OUT)" >&2
    exit 2
    ;;
esac

resolve_existing_prefix() {
  local target="$1" tail="" dir parent resolved
  case "$target" in
    /*) ;;
    *) target="$PWD/$target" ;;
  esac
  dir="$target"
  while [[ ! -d "$dir" ]]; do
    tail="$(basename -- "$dir")${tail:+/$tail}"
    parent="$(dirname -- "$dir")"
    [[ "$parent" == "$dir" ]] && break
    dir="$parent"
  done
  resolved="$(cd "$dir" 2>/dev/null && pwd -P)" || {
    echo "cannot resolve path: $1" >&2
    exit 2
  }
  if [[ -n "$tail" ]]; then
    printf '%s/%s\n' "${resolved%/}" "$tail"
  else
    printf '%s\n' "$resolved"
  fi
}

inside_artifacts() {
  [[ "$1" == "$artifacts_root" || "$1" == "$artifacts_root"/* ]]
}

mkdir -p "$PROJECT/artifacts"
artifacts_root="$(cd "$PROJECT/artifacts" && pwd -P)"
OUT="$(resolve_existing_prefix "$OUT")"
if ! inside_artifacts "$OUT"; then
  echo "OUT must stay inside $artifacts_root (got: $OUT)" >&2
  exit 2
fi

if [[ ! -x "$FUNC_BIN" ]]; then
  echo "FunC compiler not found: $FUNC_BIN" >&2
  echo "Build it with: cmake --build build --target func fift" >&2
  exit 2
fi

contracts=(jetton-bridge jetton-minter jetton-wallet multisig votes-collector)
networks=(ethereum bsc polygon tron)
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

mkdir -p "$OUT"
# Re-check once the path fully exists: only now can symlinks along it be
# resolved, and nothing destructive has run yet.
OUT="$(cd "$OUT" && pwd -P)"
if ! inside_artifacts "$OUT"; then
  echo "OUT resolves outside $artifacts_root (got: $OUT)" >&2
  exit 2
fi
rm -rf "${OUT:?}"
mkdir -p "$OUT"
cp -R "$work_root/first/." "$OUT/"
find "$OUT" -type d -name src -prune -exec rm -rf {} +
(
  cd "$OUT"
  find . -type f -name '*.fif' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Reproducibly compiled ${#contracts[@]} contracts for ${#networks[@]} external networks (assembly-checked)."
echo "Artifacts: $OUT"
