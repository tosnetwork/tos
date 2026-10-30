/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "proof-verify.h"
#include "simulation-account.h"

namespace tos::proofverify {

inline constexpr std::size_t kMaxSelfPaySimulationResultBytes = 2u << 20;
inline constexpr std::size_t kMaxSelfPaySimulationStateBytes = 1u << 20;
// Separate from the account/configuration component error domains.
enum class SelfPaySimulationError { Input = -1, Proof = -2, Internal = -4, Resource = -5, Context = -6 };
inline td::Status self_pay_simulation_error(SelfPaySimulationError error) {
  return td::Status::Error(static_cast<int>(error), "self-pay simulation refused");
}

enum class SimulationOutcome { Unsupported, ImportRejected, NotAccepted, Executed };

struct SimulatedTransaction {
  std::string codec_json;
  std::string expected_balance;
  td::Bits256 expected_state_hash;
};

struct SelfPaySimulation {
  SimulationOutcome outcome{SimulationOutcome::Unsupported};
  std::optional<int> vm_exit_code;
  td::Bits256 message_bytes_hash = td::Bits256::zero();
  td::Bits256 message_root_hash = td::Bits256::zero();
  td::Bits256 config_root_hash = td::Bits256::zero();
  td::Bits256 simulation_seed = td::Bits256::zero();
  std::optional<detail::SelfPaySimulationContext> context;
  std::string authenticated_balance;
  std::optional<SimulatedTransaction> transaction;
};

struct ProofBoundSelfPaySimulation {
  Verified authenticated_read;
  SelfPaySimulation estimate;
};

// One-shot live authentication and simulation. The caller must durably commit
// authenticated_read.next_state before using the estimate, and must persist the
// exact signed BOC before broadcast. A result never authorizes another signature
// or releases an existing outbox slot. This function performs no persistence.
td::Result<ProofBoundSelfPaySimulation> simulate_self_pay(const Anchor& anchor, const Request& request,
                                                          td::Slice request_bytes, const Material& material,
                                                          const std::optional<LiveState>& state, const Policy& policy,
                                                          td::Slice message_boc);

td::Result<std::string> render_self_pay_simulation(const ProofBoundSelfPaySimulation& result);

namespace detail {
struct BoundSimulationMessage {
  td::Ref<vm::Cell> root;
  td::Bits256 bytes_hash;
  td::Bits256 root_hash;
};
// Exact, bounded external-in message structure and destination binding; no signing grant.
td::Result<BoundSimulationMessage> bind_simulation_message(const block::StdAddress& destination, td::Slice bytes);
// Internal execution of already authenticated/prepared input. No transport,
// persistence or signature-bypass option. Tests may use explicit synthetic
// observations; only the final one-shot proof entry point can authenticate them.
td::Result<SelfPaySimulation> execute_prepared_self_pay(const tos::BlockIdExt& target,
                                                        std::shared_ptr<block::Config> config,
                                                        td::Ref<vm::Tuple> previous_blocks,
                                                        PreparedSimulationAccount prepared, td::Slice message_boc);
}  // namespace detail

}  // namespace tos::proofverify
