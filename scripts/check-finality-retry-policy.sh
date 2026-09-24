#!/usr/bin/env bash
# Pin the production composition around the behaviour exercised by
# test-pending-finality-cache. Error classifications stay at their creation
# sites; the manager must retain transient failures, schedule a bounded retry,
# and discard permanent or exhausted candidates.
set -euo pipefail

root="${1:-.}"
failed=0

require_marker() {
  local file="$1"
  local marker="$2"
  local description="$3"
  if ! grep -qF "$marker" "$root/$file"; then
    echo "PENDING_FINALITY_RETRY_SOURCE_FAILURE: $description ($file)" >&2
    failed=1
  fi
}

require_regex() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if ! grep -qPzo "$pattern" "$root/$file"; then
    echo "PENDING_FINALITY_RETRY_SOURCE_FAILURE: $description ($file)" >&2
    failed=1
  fi
}

if grep -qF 'pending->complete_front(false);' "$root/validator/manager.cpp"; then
  echo "PENDING_FINALITY_RETRY_SOURCE_FAILURE: transient verification failure still discards the front candidate (validator/manager.cpp)" >&2
  failed=1
fi

require_marker validator/manager.cpp \
  'pending->resolve_front_failure(attempt_token, error.code(), td::Time::now())' \
  'manager no longer applies the bounded transient/permanent failure decision'
require_marker validator/manager.cpp \
  'schedule_pending_block_finality_retry(block_id, failure.retry_at);' \
  'manager no longer schedules another attempt after retaining transient evidence'
require_marker validator/manager.cpp \
  'expire_pending_block_finality, block_id' \
  'manager no longer schedules independent expiry of an admitted candidate'
require_marker validator/manager.cpp \
  'pending->erase_expired(td::Time::now())' \
  'manager expiry callback no longer frees expired sender slots'
require_marker validator/manager.cpp \
  'failed_pending_block_proof(block_id, attempt_token, proof_failure_source, proof.move_as_error())' \
  'proof-construction failure no longer reaches the manager proof-failure handler'
require_marker validator/manager.cpp \
  'pending_block_proof_failure_action(source, error.code())' \
  'manager no longer classifies proof failure by its input source'
require_marker validator/manager.cpp \
  'action != PendingBlockProofFailureAction::DiscardBlockBytes' \
  'manager can again erase block bytes for finality-evidence proof failure'
require_marker validator/manager.cpp \
  'failed_pending_block_finality(block_id, attempt_token, std::move(error),' \
  'evidence/context proof failure no longer uses the bounded retry decision'
require_marker validator/downloaders/wait-block-data.cpp \
  'failure_source = PendingBlockProofFailureSource::FinalityEvidence;' \
  'signature-set proof failures no longer identify the evidence input'
require_marker validator/downloaders/wait-block-data.cpp \
  'failure_source = PendingBlockProofFailureSource::TrustedContext;' \
  'context proof failures no longer identify the trusted-state input'
require_marker validator/downloaders/wait-block-data.cpp \
  'pending_block_proof_identity_verdict(' \
  'proof construction no longer compares block-header, trusted-set and evidence identities'
require_marker validator/manager.cpp \
  'failed_pending_block_finality(block_id, attempt_token, result.move_as_error(), "verify signatures")' \
  'signature-check failure no longer uses the bounded retry decision'
require_marker validator/manager.cpp \
  'failed_pending_block_finality(block_id, attempt_token, result.move_as_error(), "apply verified evidence")' \
  'apply failure no longer uses the bounded retry decision'
require_marker validator/manager.cpp \
  'finality->verified || !broadcast.sig_set->is_pq()' \
  'verified evidence is reverified instead of resuming its interrupted apply'
require_marker validator/manager.cpp \
  'const auto attempt_token = finality.token;' \
  'manager no longer captures the immutable processing-attempt token'
token_checks=$(grep -cF 'pending->is_processing(attempt_token)' "$root/validator/manager.cpp")
if [ "$token_checks" -ne 4 ]; then
  echo "PENDING_FINALITY_RETRY_SOURCE_FAILURE: expected 4 proof/callback attempt-token guards, found $token_checks (validator/manager.cpp)" >&2
  failed=1
fi
require_marker validator/manager.cpp \
  'pending->mark_front_verified(attempt_token)' \
  'signature success can mark a front candidate without matching its attempt token'
require_marker validator/manager.cpp \
  'pending->complete_front(attempt_token, true)' \
  'apply success can complete a front candidate without matching its attempt token'
require_marker validator/manager.cpp \
  'pending->cancel_processing(attempt_token)' \
  'proof-construction failure can cancel a different processing attempt'
require_regex validator/validate-broadcast.cpp \
  'ErrorCode::protoviolation,\s*"catchain seqno in block header and signature set does not match"' \
  'catchain-seqno mismatch is no longer a permanent protocol violation'
require_regex validator/validate-broadcast.cpp \
  'ErrorCode::protoviolation,\s*"validator set hash in block header and signature set does not match"' \
  'header/signature validator-set mismatch is no longer a permanent protocol violation'
require_regex validator/validate-broadcast.cpp \
  'ErrorCode::protoviolation,\s*"bad validator set hash"' \
  'validator-set mismatch with an exact key block is no longer a permanent protocol violation'

monitoring_permanent_sites=$(grep -cF 'td::Status::Error("not monitoring shard")' "$root/validator/manager.cpp")
if [ "$monitoring_permanent_sites" -ne 2 ]; then
  echo "PENDING_FINALITY_RETRY_SOURCE_FAILURE: expected 2 permanent not-monitoring-shard creation sites, found $monitoring_permanent_sites (validator/manager.cpp)" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PENDING_FINALITY_RETRY_SOURCE_OK: proof failure reaches the manager handler, which classifies source and guards the attempt token; bounded retry markers remain"
