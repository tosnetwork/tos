#pragma once
#include "block/workchain-confidential-state.h"
#include "block/workchain-confidential-input.h"
#include "block/workchain-execution-errors.h"
#include "uno/crypto/include/uno_crypto.h"
#include <array>

namespace block {
// Mandatory authenticated configuration, independently acquired by each host.
// No candidate context, nonce, revision or account address is accepted here.
struct WorkchainPossessionPolicy {
  gen::UnoV2ReplayProtocolV1::Record protocol;
  gen::UnoV2TransferRulesV1::Record rules;
  gen::UnoV2TransferProfilesV1::Record profiles;
  td::Bits256 fee_profile;
  std::uint32_t fee_effective_height;
  WorkchainPossessionPolicy() = delete;
  WorkchainPossessionPolicy(gen::UnoV2ReplayProtocolV1::Record p, gen::UnoV2TransferRulesV1::Record r,
                           gen::UnoV2TransferProfilesV1::Record profiles_, td::Bits256 fee, std::uint32_t height)
      : protocol(std::move(p)), rules(std::move(r)), profiles(std::move(profiles_)),
        fee_profile(fee), fee_effective_height(height) {}
};
inline WorkchainReplayContext rebuild_workchain_possession_context(
    const WorkchainPossessionPolicy& policy, const WorkchainConfidentialAccount& account) {
  return {policy.protocol, policy.rules, policy.profiles, policy.fee_profile, policy.fee_effective_height,
          account.address, account.auth_nonce, account.available_revision, account.key_epoch};
}
// Comparison does NOT bind a prover. After this succeeds, verification must
// absorb bytes rebuilt again from policy/account, never reuse the claimed bytes.
inline td::Status check_workchain_possession_replay_context(
    const WorkchainReplayContext& claimed, const WorkchainPossessionPolicy& policy,
    const WorkchainConfidentialAccount& account, WorkchainReplayOperation operation) {
  auto rebuilt = encode_workchain_replay_context(rebuild_workchain_possession_context(policy, account), operation);
  if (rebuilt.is_error()) return td::Status::Error(-7201, "authenticated possession context unavailable");
  TRY_RESULT(encoded, encode_workchain_replay_context(claimed, operation));
  if (encoded != rebuilt.ok()) return td::Status::Error(-7200, "possession replay context mismatch");
  return td::Status::OK();
}
// Populate from host-resolved registration fields, not an opaque caller-supplied
// challenge. Address/configuration matching is registration admission's job;
// success here proves possession only, never the origin/independence of a secret.
td::Status verify_workchain_registration_possession(
    const WorkchainConfidentialAccount& registration,
    const WorkchainPossessionPolicy& policy,
    const std::array<unsigned char, 64>& proof);

// Reconstruct the zero-balance statement from the current authenticated account.
// Domain comes from authenticated protocol configuration. Pending and in-flight
// obligations are separate host predicates; this proof says nothing about them.
td::Status verify_workchain_closure_possession(
    const WorkchainConfidentialAccount& account,
    const WorkchainPossessionPolicy& policy,
    const std::array<unsigned char, 80>& domain,
    const std::array<unsigned char, 96>& proof);
}
