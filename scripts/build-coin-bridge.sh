#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/crosschain/coin-bridge"
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

networks=(ethereum bsc)
work_root="$(mktemp -d -t tos-coin-bridge-build.XXXXXX)"
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

if [[ ! -x "$FIFT_BIN" ]]; then
  echo "Fift assembler not found: $FIFT_BIN" >&2
  echo "Build it with: cmake --build build --target func fift" >&2
  echo "Assembly is part of this check; it is not optional." >&2
  exit 2
fi

for fif in "$work_root"/first/*/*.fif; do
  wrapper="$work_root/assemble.fif"
  printf '"%s" include hashu . cr\n' "$fif" > "$wrapper"
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
(
  cd "$OUT"
  find . -type f -name '*.fif' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Reproducibly compiled 3 contracts for ${#networks[@]} external networks (assembly-checked)."
echo "Artifacts: $OUT"
