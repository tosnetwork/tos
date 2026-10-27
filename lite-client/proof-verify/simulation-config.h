/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>
#include <memory>

#include "block/mc-config.h"
#include "td/utils/Slice.h"

namespace tos::proofverify::detail {

// Internal WIP budgets, pending mobile resource acceptance and ABI freeze.
inline constexpr std::size_t kMaxSimulationConfigCells = 65536;
inline constexpr std::size_t kMaxSimulationConfigProofCells = 131072;
inline constexpr std::size_t kMaxSimulationConfigReplyBytes = 16u << 20;
inline constexpr unsigned kMaxSimulationConfigDepth = 1023;

enum class SimulationConfigError { Input = 1, Proof = 2, Incomplete = 3, Resource = 4, Unsupported = 5 };

// Inspect every distinct loaded DataCell representation, retaining its identity
// until the scan ends. Equal commitments do not imply equal representations.
// The cell budget counts these identities, including separately allocated equal
// values. Only the config subtree is checked: unrelated state may remain pruned.
td::Result<std::size_t> check_complete_simulation_config(const td::Ref<vm::Cell>& root);

// The caller must first authenticate target from its anchor/live proof chain.
// This binds the configuration answer to that exact target, not to the mode
// bits or method name claimed by the server. No proof/state capability is minted.
td::Result<std::unique_ptr<block::ConfigInfo>> extract_simulation_config(const tos::BlockIdExt& target,
                                                                         td::Slice raw_reply);

}  // namespace tos::proofverify::detail
