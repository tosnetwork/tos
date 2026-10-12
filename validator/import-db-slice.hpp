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

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <optional>

#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "validator/db/package.hpp"
#include "validator/import-settlement.h"
#include "validator/interfaces/validator-manager.h"
#include "validator/startup-catchup.h"

namespace tos {

namespace validator {

// Imports one archive slice (a masterchain package plus the shard packages it
// needs) and applies its blocks.
//
// Two modes share the code:
// - unbounded (the legacy archive loop and operator import files): the original
//   behaviour, with 3600-second downloads, retries without end and a fail-fast
//   join; it reports (masterchain top, shard-client seqno) or an error;
// - bounded (the startup catch-up mode): every network and compute child is
//   bounded by the attempt deadline, the first error or the deadline makes the
//   importer drain (no new work, no retries, late downloads unlinked), and the
//   structured outcome is reported only once every child it started has settled.
//   Local database reads are awaited without a deadline.
//
// Every external operation goes through a protected virtual request_* or parse_*
// method, so the settlement logic can be exercised with substituted children.
class ArchiveImporter : public td::actor::Actor {
 public:
  ArchiveImporter(std::string db_root, td::Ref<MasterchainState> state, BlockSeqno shard_client_seqno,
                  td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager,
                  std::vector<std::string> to_import_files, td::Promise<std::pair<BlockSeqno, BlockSeqno>> promise);
  // Bounded network import for one startup catch-up attempt.
  ArchiveImporter(std::string db_root, td::Ref<MasterchainState> state, BlockSeqno shard_client_seqno,
                  td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager,
                  td::Timestamp attempt_deadline, td::Promise<startup_catchup::ImportOutcome> promise);
  void start_up() override;
  void alarm() override;

  void abort_query(td::Status error);
  void finish_query();

  void got_mc_archive(td::Result<std::string> R);
  void downloaded_mc_archive(std::string path);
  td::Status process_package(std::string path, bool with_masterchain);

  void processed_mc_archive();
  void check_masterchain_block(BlockSeqno seqno);
  void checked_masterchain_proof_result(BlockIdExt prev, td::Ref<BlockData> data, td::Result<BlockHandle> R);
  void checked_masterchain_proof(BlockHandle handle, td::Ref<BlockData> data);
  void applied_masterchain_block_result(BlockHandle handle, td::Result<td::Unit> R);
  void applied_masterchain_block(BlockHandle handle);
  void got_new_masterchain_state_result(td::Result<td::Ref<ShardState>> R);
  void got_new_masterchain_state(td::Ref<MasterchainState> state);

  void checked_all_masterchain_blocks();
  void got_start_state_result(td::Result<td::Ref<ShardState>> R);
  void download_shard_archives(td::Ref<MasterchainState> start_state);
  void download_shard_archive(ShardIdFull shard_prefix);
  void got_shard_archive(ShardIdFull shard_prefix, td::Result<std::string> R);
  void retry_shard_archive(ShardIdFull shard_prefix);
  void downloaded_shard_archive(std::string path);

  void check_next_shard_client_seqno(BlockSeqno seqno);
  void got_masterchain_state_result(td::Result<td::Ref<ShardState>> R);
  void got_masterchain_state(td::Ref<MasterchainState> state);
  void shard_join_result(BlockSeqno seqno, td::Result<td::Unit> R);
  void checked_shard_client_seqno(BlockSeqno seqno);
  void apply_shard_block(BlockIdExt block_id, BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise);
  void shard_chain_done(td::Promise<td::Unit> promise, td::Result<td::Unit> R);
  void shard_block_handle_result(BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise,
                                 td::Result<BlockHandle> R);
  void apply_shard_block_cont1(BlockHandle handle, BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise);
  void shard_state_downloaded(td::Promise<td::Unit> promise, td::Result<td::Ref<ShardState>> R);
  void shard_proof_link_checked(BlockHandle handle, BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise,
                                td::Result<BlockHandle> R);
  void apply_shard_block_cont2(BlockHandle handle, BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise);
  void apply_shard_block_cont3(BlockHandle handle, BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise);
  void shard_block_applied(td::Promise<td::Unit> promise, td::Result<td::Unit> R);
  void check_shard_block_applied(BlockIdExt block_id, td::Promise<td::Unit> promise);
  void shard_block_applied_check_result(td::Promise<td::Unit> promise, td::Result<BlockHandle> R);

 protected:
  // External operations. The defaults are the production paths.
  virtual void request_archive(BlockSeqno masterchain_seqno, ShardIdFull shard_prefix, td::Timestamp timeout,
                               td::Promise<std::string> promise);
  virtual td::Result<td::Ref<Proof>> parse_proof(BlockIdExt block_id, td::BufferSlice data);
  virtual td::Result<td::Ref<ProofLink>> parse_proof_link(BlockIdExt block_id, td::BufferSlice data);
  virtual td::Result<td::Ref<BlockData>> parse_block(BlockIdExt block_id, td::BufferSlice data);
  virtual void request_masterchain_proof_check(BlockIdExt block_id, td::Ref<Proof> proof,
                                               td::Ref<MasterchainState> state, bool is_hardfork, td::Timestamp timeout,
                                               td::Promise<BlockHandle> promise);
  virtual void request_proof_link_check(BlockIdExt block_id, td::Ref<ProofLink> proof, td::Timestamp timeout,
                                        td::Promise<BlockHandle> promise);
  virtual void request_apply(BlockIdExt block_id, td::Ref<BlockData> data, BlockIdExt masterchain_block_id,
                             td::Timestamp timeout, td::Promise<td::Unit> promise);
  virtual void request_state_download(BlockIdExt block_id, BlockIdExt masterchain_block_id, td::uint32 split_depth,
                                      td::Timestamp timeout, td::Promise<td::Ref<ShardState>> promise);
  virtual void request_masterchain_state(BlockHandle handle, td::Promise<td::Ref<ShardState>> promise);
  virtual void request_masterchain_state_short(BlockIdExt block_id, td::Promise<td::Ref<ShardState>> promise);
  virtual void request_block_handle(BlockIdExt block_id, bool force, td::Promise<BlockHandle> promise);

  // The clock the attempt deadline is compared with.
  virtual double clock_now() const;

  const ImportSettlement& settlement() const {
    return settlement_;
  }

 private:
  using Child = ImportSettlement::Child;

  // The timeout of a child with its own fixed cap: the cap, further bounded by the
  // attempt deadline in bounded mode.
  td::Timestamp child_timeout(double cap_seconds) const;
  // A short check (proof, proof link) starts only with time left before the
  // attempt deadline, and never runs past it.
  std::optional<td::Timestamp> check_timeout(double cap_seconds) const;
  bool deadline_passed() const;
  void settled(Child child);
  void fail(td::Status error);
  void maybe_publish();

  std::string db_root_;
  td::Ref<MasterchainState> last_masterchain_state_;
  BlockSeqno shard_client_seqno_;
  BlockSeqno start_import_seqno_;

  td::Ref<ValidatorManagerOptions> opts_;

  td::actor::ActorId<ValidatorManager> manager_;

  std::vector<std::string> to_import_files_;
  bool use_imported_files_;
  td::Promise<std::pair<BlockSeqno, BlockSeqno>> promise_;

  bool bounded_ = false;
  td::Timestamp attempt_deadline_;
  bool deadline_fired_ = false;
  td::Promise<startup_catchup::ImportOutcome> outcome_promise_;
  ImportSettlement settlement_;
  // The per-masterchain-block join of the required shard applications.
  struct ShardJoin {
    BlockSeqno seqno = 0;
    size_t pending = 0;
    td::Status first_error;
  };
  ShardJoin shard_join_;

  std::map<BlockSeqno, BlockIdExt> masterchain_blocks_;
  BlockSeqno last_masterchain_seqno_ = 0;

  struct BlockInfo {
    std::shared_ptr<Package> data_pkg;
    td::uint64 data_offset = 0;
    std::shared_ptr<Package> proof_pkg;
    td::uint64 proof_offset = 0;
  };
  std::map<BlockIdExt, BlockInfo> blocks_;

  td::Ref<MasterchainState> start_state_;
  size_t pending_shard_archives_ = 0;

  bool imported_any_ = false;
  bool have_shard_blocks_ = false;
  std::vector<std::string> files_to_cleanup_;

  td::PerfWarningTimer perf_timer_;
};

}  // namespace validator

}  // namespace tos
