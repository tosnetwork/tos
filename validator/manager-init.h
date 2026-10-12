/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include "interfaces/db.h"
#include "interfaces/validator-manager.h"

#include "shard-client.hpp"

namespace tos {

namespace validator {

struct ValidatorManagerInitResult {
  BlockHandle handle;
  td::Ref<MasterchainState> state;
  td::actor::ActorOwn<ShardClient> clients;

  BlockHandle gc_handle;
  td::Ref<MasterchainState> gc_state;

  BlockHandle last_key_block_handle_;

  // The consensus cleanup checkpoint, loaded and verified before any validator
  // group can be built. Both are null when the checkpoint key is absent.
  BlockHandle consensus_cleanup_checkpoint_handle;
  td::Ref<MasterchainState> consensus_cleanup_checkpoint_state;
};

// A loaded consensus cleanup checkpoint: its applied handle and its own state.
// A null handle means the key is absent.
struct LoadedConsensusCleanupCheckpoint {
  BlockHandle handle;
  td::Ref<MasterchainState> state;
};

// Reads the checkpoint key and loads its handle and state. Only a genuinely
// absent key yields an empty result. A read error, a damaged record, a missing or
// unapplied handle, a pruned state, or a state that does not describe the
// checkpoint fails with a refusal (consensus::is_consensus_checkpoint_refusal).
td::actor::Task<LoadedConsensusCleanupCheckpoint> load_consensus_cleanup_checkpoint_for_startup(
    td::actor::ActorId<Db> db, td::actor::ActorId<ValidatorManager> manager);

// Startup boundary checks against a loaded checkpoint. `head` is a block the
// node is about to start from (the init block, a reinitialization block, or a
// rollback target) and `head_state` its state. `allow_behind` admits a block
// below the checkpoint (normal startup replays from an older init block; the
// validator groups wait for the replay). A block at or above the checkpoint's
// height must be the checkpoint or a verified descendant of it.
td::Status check_consensus_cleanup_checkpoint_boundary(const LoadedConsensusCleanupCheckpoint &checkpoint,
                                                       const BlockIdExt &head,
                                                       const td::Ref<MasterchainState> &head_state, bool allow_behind,
                                                       td::Slice what);

// The GC block a reinitialization at `block` persists and starts with: the
// consensus cleanup checkpoint when one exists (the reinitialization block is
// then the checkpoint or a verified descendant of it, already checked), else
// `block` itself. Persists it through the manager before returning.
struct ReinitGcBlock {
  BlockHandle handle;
  td::Ref<MasterchainState> state;
};
td::actor::Task<ReinitGcBlock> persist_reinit_gc_block(td::actor::ActorId<ValidatorManager> manager,
                                                       const LoadedConsensusCleanupCheckpoint &checkpoint,
                                                       BlockHandle block, td::Ref<MasterchainState> state);

// Logs the refusal and stops the process with exit status 2. Used for every
// startup refusal tied to the consensus cleanup checkpoint.
[[noreturn]] void refuse_startup_for_consensus_cleanup_checkpoint(const td::Status &status);

void validator_manager_init(td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager,
                            td::actor::ActorId<Db> db, td::Promise<ValidatorManagerInitResult> promise);

}  // namespace validator

}  // namespace tos
