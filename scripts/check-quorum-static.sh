#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

if ! command -v rg >/dev/null 2>&1; then
  echo "quorum static check failed: ripgrep is required but not installed" >&2
  exit 1
fi

paths=(
  "$root/validator/consensus"
  "$root/validator/impl"
  "$root/crypto/block"
)

# A missing scan root is lost security coverage, not an empty directory.  In
# particular, ripgrep exits non-zero for both "no matches" and "path missing";
# checking the roots separately prevents a refactor from silently shrinking
# the quorum-arithmetic audit.
for path in "${paths[@]}"; do
  if [[ ! -d "$path" ]]; then
    echo "quorum static check failed: scan path $path does not exist" >&2
    exit 1
  fi
done

patterns=(
  '\b(total_weight|voted_weight|signed_weight|approved_weight|signatures_weight|approve_signatures_weight)\s*\+='
  '\b(total_weight|voted_weight|signed_weight|approved_weight|signatures_weight|approve_signatures_weight|weight)\s*\*\s*[23]\b'
  '\b[23]\s*\*\s*(total_weight|voted_weight|signed_weight|approved_weight|signatures_weight|approve_signatures_weight|weight)\b'
)

for pattern in "${patterns[@]}"; do
  if rg -n --glob '*.cpp' --glob '*.h' "$pattern" "${paths[@]}"; then
    echo "quorum static check failed: use tos::checked_add_validator_weight() and tos::has_quorum()" >&2
    exit 1
  fi
done

echo "quorum static check passed"
