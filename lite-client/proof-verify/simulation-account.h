/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "block/check-proof.h"
#include "block/transaction.h"

#include "self-pay-simulation-context.h"

namespace tos::proofverify::detail {

inline constexpr std::size_t kMaxSimulationAccountBytes = 1u << 20;
inline constexpr std::size_t kMaxSimulationAccountCells = 16384;

enum class SimulationAccountError { Input = 1, Proof = 2, Resource = 3, State = 4, Context = 5 };

struct PreparedSimulationAccount {
  block::Account account;
  SelfPaySimulationContext context;
  td::Bits256 authenticated_state_hash;
  bool existed;
};

// Restore only authenticated observations. This does not validate a proof or
// authorize simulation/signing. A null true_root means proven dictionary absence.
// Frozen/uninitialized states retain their exact native representation; the
// eventual signed-message adapter must enforce code/StateInit support separately.
td::Result<PreparedSimulationAccount> restore_simulation_account(const block::StdAddress& address,
                                                                 const block::AccountState::Info& proven,
                                                                 const block::ConfigInfo& config,
                                                                 std::int64_t local_now);

// The caller authenticates target from its anchor/live chain and obtains config
// through extract_simulation_config at that same target. This verifies the
// account answer and then restores native input without transport or persistence.
td::Result<PreparedSimulationAccount> prepare_simulation_account(const tos::BlockIdExt& target,
                                                                 const block::StdAddress& address, td::Slice raw_reply,
                                                                 const block::ConfigInfo& config,
                                                                 std::int64_t local_now);

}  // namespace tos::proofverify::detail
