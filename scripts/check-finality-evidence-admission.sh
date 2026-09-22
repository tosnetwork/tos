#!/usr/bin/env bash
# Pin the production wiring that keeps unverified finality evidence from owning
# a block-wide transport/cache slot. Behavioural limits live in
# test-pending-finality-cache; this check makes removal at either ingress route
# or at the authenticated-sender handoff fail as well.
set -euo pipefail

root="${1:-.}"
failed=0

require_marker() {
  local file="$1"
  local marker="$2"
  local description="$3"
  if ! grep -qF "$marker" "$root/$file"; then
    echo "FINALITY_ADMISSION_SOURCE_FAILURE: $description ($file)" >&2
    failed=1
  fi
}

# Match a complete call/expression after collapsing whitespace.  This pins an
# argument to the call that consumes it without making clang-format line wraps
# part of the security contract.
require_statement_marker() {
  local file="$1"
  local anchor="$2"
  local terminator="$3"
  local marker="$4"
  local description="$5"
  if ! awk -v anchor="$anchor" -v terminator="$terminator" -v marker="$marker" '
      index($0, anchor) { collecting = 1; statement = "" }
      collecting {
        statement = statement " " $0
        if (index($0, terminator)) {
          gsub(/[[:space:]]+/, " ", statement)
          if (index(statement, marker)) found = 1
          collecting = 0
        }
      }
      END { exit(found ? 0 : 1) }
    ' "$root/$file"; then
    echo "FINALITY_ADMISSION_SOURCE_FAILURE: $description ($file)" >&2
    failed=1
  fi
}

require_marker validator/full-node-shard.cpp \
  'block_finality_broadcast_transport_id(finality)' \
  'public Plumtree finality route lost its evidence-aware transport id'
require_marker validator/full-node-fast-sync-overlays.cpp \
  'block_finality_broadcast_transport_id(finality)' \
  'fast-sync Plumtree finality route lost its evidence-aware transport id'
require_statement_marker validator/full-node-shard.cpp \
  '&FullNode::process_block_finality_broadcast' ');' \
  'std::move(parsed_finality), src, BroadcastSource::public_overlay, false' \
  'public finality ingress no longer carries its authenticated sender'
require_statement_marker validator/full-node-fast-sync-overlays.cpp \
  '&FullNode::process_block_finality_broadcast' ');' \
  'std::move(parsed_finality), src, BroadcastSource::fast_sync_overlay, true' \
  'fast-sync finality ingress no longer carries its authenticated sender'
require_statement_marker validator/full-node-custom-overlays.cpp \
  '&FullNode::process_block_finality_broadcast' ');' \
  'std::move(parsed_finality), src, BroadcastSource::custom_overlay, !block_senders_.contains(local_id_)' \
  'custom-overlay finality ingress no longer carries its authenticated sender'
require_statement_marker validator/full-node.cpp \
  '&ValidatorManagerInterface::new_block_finality_broadcast' '.detach("full-node finality broadcast");' \
  'std::move(finality), source, td::optional<PublicKeyHash>(source_peer)' \
  'full-node finality ingress no longer hands the authenticated sender to the manager'
require_statement_marker validator/manager.cpp \
  'prepare_pending_finality_ingress(' ');' \
  'source_peer ? &*source_peer : nullptr, finality.received_bytes, local_signature_bytes' \
  'manager admission no longer applies its checked accounting and sender decision'
require_marker validator/manager.cpp \
  'if (!ingress.admitted()) {' \
  'manager no longer fails closed when ingress accounting rejects evidence'
require_marker validator/manager.cpp \
  'pending_finality_ingress_rejection_name(ingress.rejection)' \
  'manager ingress rejection log no longer names its reason'
require_marker validator/manager.cpp \
  'if (!admission.admitted()) {' \
  'manager no longer stops after the pending store rejects evidence'
require_marker validator/manager.cpp \
  'pending_finality_rejection_name(admission.rejection)' \
  'manager pending-store rejection log no longer names its reason'
require_marker validator/manager.cpp \
  'pending_finality_authority_memo_.get({shard, claimed_catchain_seqno}' \
  'manager no longer shares memoized validator sets between authority classification and classical verification'
require_statement_marker validator/manager.cpp \
  'pending_finality_coordinate_is_admissible(' ')) {' \
  'state->get_shard_from_config(shard, true).not_null(), current_catchain_seqno, claimed_catchain_seqno' \
  'manager authority classification no longer requires an exact configured shard before set computation'
require_marker validator/pending-finality-ingress.h \
  'pending_finality_catchain_is_current_or_next(current, claimed)' \
  'manager authority classification no longer rejects implausible catchain claims before set computation'
require_marker validator/pending-finality-ingress.h \
  'set.validator_set_hash == claimed_validator_set_hash' \
  'authority memo no longer compares the claimed set hash with the locally computed hash'
require_marker validator/manager.cpp \
  'pending_finality_authority_memo_.clear()' \
  'manager no longer invalidates authority classifications when trusted state changes'
require_marker validator/manager.cpp \
  '*pending_finality_authority_memo_state_ != last_masterchain_block_id_' \
  'manager no longer keys authority-memo lifetime to the trusted masterchain state'
require_statement_marker validator/manager.cpp \
  'check_finality_signatures(' ';' \
  'finality.block_id, finality.sig_set, std::move(validator_sets)' \
  'classical finality verification no longer consumes validator sets from the shared authority memo'
if sed -n '/static td::actor::Task<> check_finality_signatures/,/^}/p' "$root/validator/manager.cpp" | \
    grep -qF 'get_validator_set('; then
  echo "FINALITY_ADMISSION_SOURCE_FAILURE: classical finality verification recomputes a validator set outside the shared memo" >&2
  failed=1
fi
require_statement_marker validator/manager.cpp \
  'pending_block_finality_.admit(' ');' \
  'ingress.accounted_bytes, capacity, signatures_verified' \
  'manager no longer passes the authority capacity class into the pending store'
require_marker validator/manager.cpp \
  'new_block_finality_broadcast(finality.clone(), BroadcastSource::consensus_overlay)' \
  'locally originated finality no longer uses the explicit local-source path'

# Five occurrences are the interface declaration, implementation declaration,
# implementation definition, authenticated full-node call, and explicit local
# consensus call. A sixth occurrence is an unclassified ingress route.
caller_sites=$(grep -R --include='*.cpp' --include='*.h' --include='*.hpp' \
  -F 'new_block_finality_broadcast' "$root/validator" | wc -l)
if [ "$caller_sites" -ne 5 ]; then
  echo "FINALITY_ADMISSION_SOURCE_FAILURE: new_block_finality_broadcast has $caller_sites declaration/call sites, expected 5 classified sites" >&2
  failed=1
fi
require_marker validator/full-node-shard.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'public finality ingress no longer records the received payload size'
require_marker validator/full-node-fast-sync-overlays.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'fast-sync finality ingress no longer records the received payload size'
require_marker validator/full-node-custom-overlays.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'custom-overlay finality ingress no longer records the received payload size'
require_marker validator/manager.cpp \
  'finality.received_bytes' \
  'manager admission no longer charges the received payload bytes'

if grep -qF 'serialize_tl_object(finality.sig_set->tl(), true)' "$root/validator/manager.cpp"; then
  echo "FINALITY_ADMISSION_SOURCE_FAILURE: manager reserializes remote finality before admission" >&2
  failed=1
fi
if grep -qE 'rejection=.*static_cast<int>\(' "$root/validator/manager.cpp"; then
  echo "FINALITY_ADMISSION_SOURCE_FAILURE: manager logs a finality rejection as a bare integer" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "FINALITY_ADMISSION_SOURCE_OK: both Plumtree routes use evidence-aware ids and all ingress routes carry authenticated senders"
