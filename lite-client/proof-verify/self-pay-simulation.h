/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "proof-verify.h"
#include "simulation-account.h"

namespace tos::proofverify {

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
  detail::SelfPaySimulationContext context;
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

namespace detail {
// Internal execution of already authenticated/prepared input. No transport,
// persistence or signature-bypass option. Tests may use explicit synthetic
// observations; only the final one-shot proof entry point can authenticate them.
td::Result<SelfPaySimulation> execute_prepared_self_pay(const tos::BlockIdExt& target,
                                                        std::shared_ptr<block::Config> config,
                                                        td::Ref<vm::Tuple> previous_blocks,
                                                        PreparedSimulationAccount prepared, td::Slice message_boc);
}  // namespace detail

}  // namespace tos::proofverify
