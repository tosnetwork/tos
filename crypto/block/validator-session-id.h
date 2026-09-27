/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <vector>

#include "tos/tos-types.h"

namespace block {

// The canonical hash of ConfigParam 29's validator session options.  This is
// kept with the complete session derivation so non-consensus proof consumers
// do not acquire a dependency on the live consensus implementation.
td::Bits256 validator_session_options_hash(const tos::ValidatorSessionConfig& config);

// Commits a consensus session to the governing state's intrinsic network id,
// its Param29 options, and the exact selected ConfigParam 30 cell.
td::Bits256 validator_session_config_hash(td::int32 global_id, const td::Bits256& validator_options_hash,
                                          const td::Bits256& simplex_config_cell_hash);

struct ValidatorSessionIdentity {
  td::Bits256 session_config_hash;
  tos::ValidatorSessionId session_id;
};

// Named form of every coordinate assembled by ValidatorManagerImpl when it
// creates a live validator or observer group. Keeping these inputs together
// makes that production assembly directly testable without starting the actor
// scheduler, while the derivation below remains the single formula.
struct ValidatorSessionIdentityInput {
  td::int32 global_id;
  td::Bits256 validator_options_hash;
  td::Bits256 simplex_config_cell_hash;
  tos::ShardIdFull shard;
  tos::CatchainSeqno catchain_seqno;
  std::vector<tos::ValidatorDescr> validators;
  td::uint32 vertical_seqno;
  tos::BlockSeqno last_key_block_seqno;
  bool new_catchain_ids;
};

// The one complete derivation and constructor-selection rule for validator
// session identity. Live group creation and proof verification must call this
// helper; neither is allowed to restate either hash or the
// group/groupEx/groupNew choice.
ValidatorSessionIdentity derive_validator_session_identity(
    td::int32 global_id, const td::Bits256& validator_options_hash, const td::Bits256& simplex_config_cell_hash,
    tos::ShardIdFull shard, tos::CatchainSeqno catchain_seqno, const std::vector<tos::ValidatorDescr>& validators,
    td::uint32 vertical_seqno, tos::BlockSeqno last_key_block_seqno, bool new_catchain_ids);

ValidatorSessionIdentity derive_validator_session_identity(const ValidatorSessionIdentityInput& input);

}  // namespace block
