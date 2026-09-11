#pragma once
#include "block/workchain-account-closure.h"

namespace block {
// The live caller supplies the root extracted from permanent entry.input and
// the registration body from that same authenticated inbox. No external proof
// argument exists. These pure consumers do not fetch state, publish or claim
// live reachability. Acquisition exceptions propagate with caller provenance.
inline td::Result<WorkchainRegistrationTransition> replay_workchain_registration(
    const WorkchainRegistrationPolicy& policy, const WorkchainRegistrationSnapshot& old,
    const td::Bits256& destination, const td::Ref<vm::Cell>& registration_body,
    const td::Ref<vm::Cell>& replay_root, WorkchainProofVerifier& verifier) {
  TRY_RESULT(wire, decode_workchain_replay_input(replay_root));
  const auto* input = std::get_if<WorkchainRegistrationReplayInput>(&wire);
  if (!input) return td::Status::Error(-7200, "registration replay operation mismatch");
  // The caller acquired this body from the candidate's authenticated inbox.
  // Unlike an AcquiredView historical-state read, a malformed body is a
  // candidate verdict. The Native payment wrapper checks it too, but direct
  // replay must not leak the codec's deliberately neutral error category.
  auto decoded = decode_workchain_confidential_account(registration_body);
  if (decoded.is_error())
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                             "malformed candidate registration body");
  auto account = decoded.move_as_ok();
  TRY_RESULT(id, derive_workchain_registration_operation_id(policy, account));
  TRY_STATUS(check_workchain_claimed_operation_id(wire, id));
  TRY_STATUS(check_workchain_possession_replay_context(input->context, policy.possession, account,
                                                       WorkchainReplayOperation::Registration));
  return execute_workchain_registration(policy, old, destination, registration_body, input->proof, verifier);
}

inline td::Result<WorkchainAccountClosureTransition> replay_workchain_account_closure(
    const WorkchainConfidentialAccount& old_account, const WorkchainCoordinatorState& old_coordinator,
    const WorkchainPossessionPolicy& policy,
    const std::array<unsigned char, 80>& authenticated_domain, const td::Ref<vm::Cell>& replay_root,
    WorkchainProofVerifier& verifier) {
  TRY_RESULT(wire, decode_workchain_replay_input(replay_root));
  const auto* input = std::get_if<WorkchainClosureReplayInput>(&wire);
  if (!input) return td::Status::Error(-7200, "closure replay operation mismatch");
  const auto& p = policy.protocol;
  TRY_RESULT(id, derive_workchain_closure_operation_id(
      {p.global_id, p.genesis_hash, p.workchain_instance}, old_account.address, old_account.auth_nonce));
  TRY_STATUS(check_workchain_claimed_operation_id(wire, id));
  TRY_STATUS(check_workchain_possession_replay_context(input->context, policy, old_account,
                                                       WorkchainReplayOperation::Closure));
  return execute_workchain_account_closure(old_account, old_coordinator,
                                           policy, authenticated_domain, input->proof, verifier);
}
}
