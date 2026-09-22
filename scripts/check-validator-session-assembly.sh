#!/usr/bin/env bash
# Pin the live manager's three group-creation paths to the named, tested
# validator-session assembly. The behavioral vector proves the assembly; this
# bidirectional source check prevents a current, future, or observer path from
# silently returning to a private positional assembly.
set -euo pipefail

root="${1:-.}"
manager="$root/validator/manager.cpp"
failed=0
assembly_blocks=$(mktemp)
trap 'rm -f "$assembly_blocks"' EXIT
awk '
  /block::derive_validator_session_identity\(block::ValidatorSessionIdentityInput\{/ { capture=1; lines=0 }
  capture { print; lines++ }
  capture && lines == 12 { capture=0 }
' "$manager" > "$assembly_blocks"

require_count() {
  local marker="$1"
  local expected="$2"
  local description="$3"
  local actual
  actual=$(grep -cF "$marker" "$assembly_blocks" || true)
  if [ "$actual" -ne "$expected" ]; then
    echo "VALIDATOR_SESSION_ASSEMBLY_SOURCE_FAILURE: $description count=$actual expected=$expected" >&2
    failed=1
  fi
}

require_count 'block::derive_validator_session_identity(block::ValidatorSessionIdentityInput{' 3 \
  'current, future and observer manager paths must use the named production assembly'
require_count '.global_id = global_id' 3 'manager global_id wiring changed'
require_count '.validator_options_hash = opts_hash' 3 'manager Param29-hash wiring changed'
require_count '.simplex_config_cell_hash = selected_config.value().cell_hash' 3 \
  'manager selected Param30-cell-hash wiring changed'
require_count '.shard = shard' 3 'manager shard wiring changed'
require_count '.catchain_seqno = val_set->get_catchain_seqno()' 3 'manager catchain-seqno wiring changed'
require_count '.validators = val_set->export_vector()' 3 'manager validator-vector wiring changed'
require_count '.vertical_seqno = opts_->get_maximal_vertical_seqno()' 3 'manager vertical-seqno wiring changed'
require_count '.last_key_block_seqno = key_seqno' 3 'manager previous-key-block wiring changed'
require_count '.new_catchain_ids = opts.new_catchain_ids' 3 'manager constructor-selection wiring changed'

all_calls=$(grep -cF 'block::derive_validator_session_identity(' "$manager" || true)
if [ "$all_calls" -ne 3 ]; then
  echo "VALIDATOR_SESSION_ASSEMBLY_SOURCE_FAILURE: manager has $all_calls derivation calls, expected exactly 3 classified paths" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo 'VALIDATOR_SESSION_ASSEMBLY_SOURCE_OK: all three manager group paths use the named tested assembly'
