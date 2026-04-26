#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

paths=(
  "$root/validator-session"
  "$root/validator/consensus"
  "$root/validator/impl"
  "$root/crypto/block"
)

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
