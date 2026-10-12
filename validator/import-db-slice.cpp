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
#include <delay.h>

#include "common/checksum.h"
#include "downloaders/download-state.hpp"
#include "td/actor/MultiPromise.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/path.h"
#include "tos/tos-io.hpp"
#include "validator/db/fileref.hpp"
#include "validator/fabric.h"

#include "import-db-slice.hpp"

namespace tos {

namespace validator {

namespace {

td::PerfWarningTimer make_import_perf_timer(td::actor::ActorId<ValidatorManager> manager) {
  return td::PerfWarningTimer("import-slice", 10.0, [manager](double duration) {
    if (!manager.empty()) {
      send_closure(manager, &ValidatorManager::add_perf_timer_stat, "import-slice", duration);
    }
  });
}

}  // namespace

ArchiveImporter::ArchiveImporter(std::string db_root, td::Ref<MasterchainState> state, BlockSeqno shard_client_seqno,
                                 td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager,
                                 std::vector<std::string> to_import_files,
                                 td::Promise<std::pair<BlockSeqno, BlockSeqno>> promise)
    : db_root_(std::move(db_root))
    , last_masterchain_state_(std::move(state))
    , shard_client_seqno_(shard_client_seqno)
    , start_import_seqno_(shard_client_seqno + 1)
    , opts_(std::move(opts))
    , manager_(manager)
    , to_import_files_(std::move(to_import_files))
    , use_imported_files_(!to_import_files_.empty())
    , promise_(std::move(promise))
    , perf_timer_(make_import_perf_timer(manager)) {
}

ArchiveImporter::ArchiveImporter(std::string db_root, td::Ref<MasterchainState> state, BlockSeqno shard_client_seqno,
                                 td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager,
                                 td::Timestamp attempt_deadline, td::Promise<startup_catchup::ImportOutcome> promise)
    : db_root_(std::move(db_root))
    , last_masterchain_state_(std::move(state))
    , shard_client_seqno_(shard_client_seqno)
    , start_import_seqno_(startup_catchup::saturating_add(shard_client_seqno, 1))
    , opts_(std::move(opts))
    , manager_(manager)
    , use_imported_files_(false)
    , bounded_(true)
    , attempt_deadline_(attempt_deadline)
    , outcome_promise_(std::move(promise))
    , perf_timer_(make_import_perf_timer(manager)) {
}

double ArchiveImporter::clock_now() const {
  return td::Time::now();
}

td::Timestamp ArchiveImporter::child_timeout(double cap_seconds) const {
  if (!bounded_) {
    return td::Timestamp::in(cap_seconds);
  }
  double left = attempt_deadline_.at() - clock_now();
  return td::Timestamp::in(left < cap_seconds ? left : cap_seconds);
}

std::optional<td::Timestamp> ArchiveImporter::check_timeout(double cap_seconds) const {
  if (!bounded_) {
    return td::Timestamp::in(cap_seconds);
  }
  double left = attempt_deadline_.at() - clock_now();
  if (left <= 0) {
    return std::nullopt;
  }
  return td::Timestamp::in(left < cap_seconds ? left : cap_seconds);
}

bool ArchiveImporter::deadline_passed() const {
  return bounded_ && attempt_deadline_.at() <= clock_now();
}

void ArchiveImporter::settled(Child child) {
  if (!bounded_) {
    return;
  }
  if (!settlement_.end(child)) {
    LOG(ERROR) << "archive import: a " << ImportSettlement::child_name(child)
               << " reported with none outstanding; settlement accounting is broken";
  }
}

void ArchiveImporter::fail(td::Status error) {
  if (!settlement_.draining()) {
    LOG(INFO) << "Archive import attempt draining after: " << error;
  }
  settlement_.drain(std::move(error));
  maybe_publish();
}

void ArchiveImporter::maybe_publish() {
  if (!bounded_ || !settlement_.ready_to_publish()) {
    return;
  }
  for (const std::string &f : files_to_cleanup_) {
    td::unlink(f).ignore();
  }
  files_to_cleanup_.clear();
  startup_catchup::ImportOutcome outcome;
  outcome.masterchain_top = last_masterchain_state_->get_seqno();
  outcome.coherent_shard_client_seqno = std::min<BlockSeqno>(outcome.masterchain_top, shard_client_seqno_);
  outcome.first_error = settlement_.publish();
  LOG(INFO) << "Archive import attempt settled in " << perf_timer_.elapsed() << "s: mc_top=" << outcome.masterchain_top
            << " coherent_shard_client=" << outcome.coherent_shard_client_seqno
            << " error=" << (outcome.first_error.is_error() ? outcome.first_error.to_string() : std::string("none"));
  outcome_promise_.set_value(std::move(outcome));
  stop();
}

void ArchiveImporter::alarm() {
  if (!bounded_ || settlement_.published()) {
    return;
  }
  if (!deadline_fired_) {
    deadline_fired_ = true;
    fail(td::Status::Error(ErrorCode::timeout, "archive import attempt deadline passed"));
    if (settlement_.published()) {
      return;
    }
    alarm_timestamp() = td::Timestamp::at(attempt_deadline_.at() + startup_catchup::kSettlementWatchdogSeconds);
    return;
  }
  LOG(ERROR) << "archive import attempt has not settled " << startup_catchup::kSettlementWatchdogSeconds
             << "s after its deadline; still waiting for: " << settlement_.outstanding_summary();
  alarm_timestamp() = td::Timestamp::in(startup_catchup::kSettlementWatchdogSeconds);
}

void ArchiveImporter::request_archive(BlockSeqno masterchain_seqno, ShardIdFull shard_prefix, td::Timestamp timeout,
                                      td::Promise<std::string> promise) {
  td::actor::send_closure(manager_, &ValidatorManager::send_download_archive_request, masterchain_seqno, shard_prefix,
                          db_root_ + "/tmp/", timeout, std::move(promise));
}

td::Result<td::Ref<Proof>> ArchiveImporter::parse_proof(BlockIdExt block_id, td::BufferSlice data) {
  return create_proof(block_id, std::move(data));
}

td::Result<td::Ref<ProofLink>> ArchiveImporter::parse_proof_link(BlockIdExt block_id, td::BufferSlice data) {
  return create_proof_link(block_id, std::move(data));
}

td::Result<td::Ref<BlockData>> ArchiveImporter::parse_block(BlockIdExt block_id, td::BufferSlice data) {
  return create_block(block_id, std::move(data));
}

void ArchiveImporter::request_masterchain_proof_check(BlockIdExt block_id, td::Ref<Proof> proof,
                                                      td::Ref<MasterchainState> state, bool is_hardfork,
                                                      td::Timestamp timeout, td::Promise<BlockHandle> promise) {
  run_check_proof_query(block_id, std::move(proof), manager_, timeout, std::move(promise), std::move(state),
                        is_hardfork);
}

void ArchiveImporter::request_proof_link_check(BlockIdExt block_id, td::Ref<ProofLink> proof, td::Timestamp timeout,
                                               td::Promise<BlockHandle> promise) {
  run_check_proof_link_query(block_id, std::move(proof), manager_, timeout, std::move(promise));
}

void ArchiveImporter::request_apply(BlockIdExt block_id, td::Ref<BlockData> data, BlockIdExt masterchain_block_id,
                                    td::Timestamp timeout, td::Promise<td::Unit> promise) {
  run_apply_block_query(block_id, std::move(data), masterchain_block_id, manager_, timeout, std::move(promise));
}

void ArchiveImporter::request_state_download(BlockIdExt block_id, BlockIdExt masterchain_block_id,
                                             td::uint32 split_depth, td::Timestamp timeout,
                                             td::Promise<td::Ref<ShardState>> promise) {
  td::actor::create_actor<DownloadShardState>("downloadstate", block_id, masterchain_block_id, split_depth, 2, manager_,
                                              timeout, std::move(promise))
      .release();
}

void ArchiveImporter::request_masterchain_state(BlockHandle handle, td::Promise<td::Ref<ShardState>> promise) {
  td::actor::send_closure(manager_, &ValidatorManager::get_shard_state_from_db, std::move(handle), std::move(promise));
}

void ArchiveImporter::request_masterchain_state_short(BlockIdExt block_id, td::Promise<td::Ref<ShardState>> promise) {
  td::actor::send_closure(manager_, &ValidatorManager::get_shard_state_from_db_short, block_id, std::move(promise));
}

void ArchiveImporter::request_block_handle(BlockIdExt block_id, bool force, td::Promise<BlockHandle> promise) {
  td::actor::send_closure(manager_, &ValidatorManager::get_block_handle, block_id, force, std::move(promise));
}

void ArchiveImporter::start_up() {
  if (use_imported_files_) {
    LOG(INFO) << "Importing archive for masterchain seqno #" << start_import_seqno_ << " from disk";
    for (const std::string &path : to_import_files_) {
      LOG(INFO) << "Importing file from disk " << path;
      td::Status S = process_package(path, true);
      if (S.is_error()) {
        LOG(INFO) << "Error processing package " << path << ": " << S;
      }
    }
    files_to_cleanup_.clear();
    processed_mc_archive();
    return;
  }
  LOG(INFO) << "Importing archive for masterchain seqno #" << start_import_seqno_ << " from net"
            << (bounded_ ? " (bounded startup catch-up attempt)" : "");
  if (bounded_) {
    alarm_timestamp() = attempt_deadline_;
    settlement_.begin(Child::MasterchainArchive);
  }
  request_archive(start_import_seqno_, ShardIdFull{masterchainId}, child_timeout(3600.0),
                  [SelfId = actor_id(this)](td::Result<std::string> R) {
                    td::actor::send_closure(SelfId, &ArchiveImporter::got_mc_archive, std::move(R));
                  });
}

void ArchiveImporter::got_mc_archive(td::Result<std::string> R) {
  settled(Child::MasterchainArchive);
  if (bounded_ && settlement_.draining()) {
    if (R.is_ok()) {
      td::unlink(R.ok()).ignore();
    }
    maybe_publish();
    return;
  }
  if (R.is_error()) {
    abort_query(R.move_as_error());
    return;
  }
  downloaded_mc_archive(R.move_as_ok());
}

void ArchiveImporter::downloaded_mc_archive(std::string path) {
  td::Status S = process_package(path, true);
  if (S.is_error()) {
    abort_query(std::move(S));
    return;
  }
  processed_mc_archive();
}

void ArchiveImporter::processed_mc_archive() {
  if (masterchain_blocks_.empty()) {
    LOG(DEBUG) << "No masterchain blocks in archive";
    last_masterchain_seqno_ = last_masterchain_state_->get_seqno();
    checked_all_masterchain_blocks();
    return;
  }

  auto seqno = masterchain_blocks_.begin()->first;
  LOG(DEBUG) << "First mc seqno in archive = " << seqno;
  if (seqno > last_masterchain_state_->get_seqno() + 1) {
    abort_query(td::Status::Error(ErrorCode::notready, "too big first masterchain seqno"));
    return;
  }

  check_masterchain_block(seqno);
}

td::Status ArchiveImporter::process_package(std::string path, bool with_masterchain) {
  LOG(DEBUG) << "Processing package " << path << " (with_masterchain=" << with_masterchain << ")";
  files_to_cleanup_.push_back(path);
  TRY_RESULT(p, Package::open(path, false, false));
  auto package = std::make_shared<Package>(std::move(p));

  td::Status S = td::Status::OK();
  package
      ->iterate([&](std::string filename, td::BufferSlice, td::uint64 offset) -> bool {
        auto F = FileReference::create(filename);
        if (F.is_error()) {
          S = F.move_as_error();
          return false;
        }
        auto f = F.move_as_ok();

        BlockIdExt b;
        bool is_proof = false;
        bool ignore = true;

        f.ref().visit(td::overloaded(
            [&](const fileref::Proof &p) {
              b = p.block_id;
              ignore = !b.is_masterchain();
              is_proof = true;
            },
            [&](const fileref::ProofLink &p) {
              b = p.block_id;
              ignore = b.is_masterchain();
              is_proof = true;
            },
            [&](const fileref::Block &p) {
              b = p.block_id;
              ignore = false;
              is_proof = false;
            },
            [&](const auto &) { ignore = true; }));

        if (!ignore && (with_masterchain || !b.is_masterchain())) {
          if (is_proof) {
            blocks_[b].proof_pkg = package;
            blocks_[b].proof_offset = offset;
          } else {
            blocks_[b].data_pkg = package;
            blocks_[b].data_offset = offset;
          }
          if (b.is_masterchain()) {
            masterchain_blocks_[b.seqno()] = b;
            last_masterchain_seqno_ = std::max(last_masterchain_seqno_, b.seqno());
          } else {
            have_shard_blocks_ = true;
          }
        }
        return true;
      })
      .ignore();
  return S;
}

void ArchiveImporter::check_masterchain_block(BlockSeqno seqno) {
  if (bounded_ && settlement_.draining()) {
    maybe_publish();
    return;
  }
  auto it = masterchain_blocks_.find(seqno);
  if (it == masterchain_blocks_.end()) {
    if (seqno == 0) {
      abort_query(td::Status::Error(ErrorCode::notready, "no new blocks"));
      return;
    }
    checked_all_masterchain_blocks();
    return;
  }
  while (seqno <= last_masterchain_state_->get_block_id().seqno()) {
    if (seqno < last_masterchain_state_->get_block_id().seqno()) {
      if (!last_masterchain_state_->check_old_mc_block_id(it->second)) {
        abort_query(td::Status::Error(ErrorCode::protoviolation, "bad old masterchain block id"));
        return;
      }
    } else {
      if (last_masterchain_state_->get_block_id() != it->second) {
        abort_query(td::Status::Error(ErrorCode::protoviolation, "bad old masterchain block id"));
        return;
      }
    }
    seqno++;
    it = masterchain_blocks_.find(seqno);
    if (it == masterchain_blocks_.end()) {
      checked_all_masterchain_blocks();
      return;
    }
  }
  LOG(DEBUG) << "Checking masterchain block #" << seqno;
  if (seqno != last_masterchain_state_->get_block_id().seqno() + 1) {
    abort_query(td::Status::Error(ErrorCode::protoviolation, "hole in masterchain seqno"));
    return;
  }
  auto it2 = blocks_.find(it->second);
  CHECK(it2 != blocks_.end());
  if (!it2->second.proof_pkg) {
    abort_query(td::Status::Error(ErrorCode::protoviolation, "no masterchain block proof"));
    return;
  }
  if (!it2->second.data_pkg) {
    abort_query(td::Status::Error(ErrorCode::protoviolation, "no masterchain block data"));
    return;
  }

  auto R1 = it2->second.proof_pkg->read(it2->second.proof_offset);
  if (R1.is_error()) {
    abort_query(R1.move_as_error());
    return;
  }

  auto proofR = parse_proof(it->second, std::move(R1.move_as_ok().second));
  if (proofR.is_error()) {
    abort_query(proofR.move_as_error());
    return;
  }

  auto R2 = it2->second.data_pkg->read(it2->second.data_offset);
  if (R2.is_error()) {
    abort_query(R2.move_as_error());
    return;
  }

  if (sha256_bits256(R2.ok().second.as_slice()) != it->second.file_hash) {
    abort_query(td::Status::Error(ErrorCode::protoviolation, "bad block file hash"));
    return;
  }
  auto dataR = parse_block(it->second, std::move(R2.move_as_ok().second));
  if (dataR.is_error()) {
    abort_query(dataR.move_as_error());
    return;
  }

  auto proof = proofR.move_as_ok();
  auto data = dataR.move_as_ok();

  auto timeout = check_timeout(2.0);
  if (!timeout) {
    abort_query(td::Status::Error(ErrorCode::timeout, "no time left before the attempt deadline for a proof check"));
    return;
  }
  if (bounded_) {
    settlement_.begin(Child::ProofCheck);
  }
  auto P = [SelfId = actor_id(this), id = last_masterchain_state_->get_block_id(),
            data](td::Result<BlockHandle> R) mutable {
    td::actor::send_closure(SelfId, &ArchiveImporter::checked_masterchain_proof_result, id, std::move(data),
                            std::move(R));
  };
  request_masterchain_proof_check(it->second, std::move(proof), last_masterchain_state_, opts_->is_hardfork(it->second),
                                  *timeout, std::move(P));
}

void ArchiveImporter::checked_masterchain_proof_result(BlockIdExt prev, td::Ref<BlockData> data,
                                                       td::Result<BlockHandle> R) {
  settled(Child::ProofCheck);
  if (bounded_ && settlement_.draining()) {
    maybe_publish();
    return;
  }
  if (R.is_error()) {
    abort_query(R.move_as_error());
    return;
  }
  auto handle = R.move_as_ok();
  if (bounded_) {
    if (handle->merge_before()) {
      abort_query(td::Status::Error(ErrorCode::protoviolation, "masterchain block proof claims a merge"));
      return;
    }
  } else {
    CHECK(!handle->merge_before());
  }
  if (handle->one_prev(true) != prev) {
    abort_query(td::Status::Error(ErrorCode::protoviolation, "prev block mismatch"));
    return;
  }
  checked_masterchain_proof(std::move(handle), std::move(data));
}

void ArchiveImporter::checked_masterchain_proof(BlockHandle handle, td::Ref<BlockData> data) {
  LOG(DEBUG) << "Checked proof for masterchain block #" << handle->id().seqno();
  if (bounded_) {
    if (data.is_null()) {
      abort_query(td::Status::Error(ErrorCode::error, "masterchain block data missing after its proof check"));
      return;
    }
    if (deadline_passed()) {
      abort_query(td::Status::Error(ErrorCode::timeout, "no time left before the attempt deadline for an apply"));
      return;
    }
    settlement_.begin(Child::Apply);
  } else {
    CHECK(data.not_null());
  }
  auto P = [SelfId = actor_id(this), handle](td::Result<td::Unit> R) {
    td::actor::send_closure(SelfId, &ArchiveImporter::applied_masterchain_block_result, handle, std::move(R));
  };
  request_apply(handle->id(), std::move(data), handle->id(), child_timeout(600.0), std::move(P));
}

void ArchiveImporter::applied_masterchain_block_result(BlockHandle handle, td::Result<td::Unit> R) {
  if (!bounded_) {
    R.ensure();
    applied_masterchain_block(std::move(handle));
    return;
  }
  settled(Child::Apply);
  if (R.is_error()) {
    abort_query(R.move_as_error_prefix("masterchain block apply: "));
    return;
  }
  if (settlement_.draining()) {
    maybe_publish();
    return;
  }
  applied_masterchain_block(std::move(handle));
}

void ArchiveImporter::applied_masterchain_block(BlockHandle handle) {
  LOG(DEBUG) << "Applied masterchain block #" << handle->id().seqno();
  if (bounded_) {
    settlement_.begin(Child::StateRead);
  }
  request_masterchain_state(std::move(handle), [SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    td::actor::send_closure(SelfId, &ArchiveImporter::got_new_masterchain_state_result, std::move(R));
  });
}

void ArchiveImporter::got_new_masterchain_state_result(td::Result<td::Ref<ShardState>> R) {
  if (!bounded_) {
    R.ensure();
    got_new_masterchain_state(td::Ref<MasterchainState>(R.move_as_ok()));
    return;
  }
  settled(Child::StateRead);
  if (R.is_error()) {
    abort_query(R.move_as_error_prefix("applied masterchain state: "));
    return;
  }
  td::Ref<MasterchainState> state{R.move_as_ok()};
  if (state.is_null()) {
    abort_query(td::Status::Error(ErrorCode::error, "applied masterchain state is not a masterchain state"));
    return;
  }
  // The block is applied whether or not the attempt is draining: the masterchain
  // top reported in the outcome follows it.
  last_masterchain_state_ = std::move(state);
  imported_any_ = true;
  if (settlement_.draining()) {
    maybe_publish();
    return;
  }
  check_masterchain_block(last_masterchain_state_->get_block_id().seqno() + 1);
}

void ArchiveImporter::got_new_masterchain_state(td::Ref<MasterchainState> state) {
  last_masterchain_state_ = std::move(state);
  imported_any_ = true;
  check_masterchain_block(last_masterchain_state_->get_block_id().seqno() + 1);
}

void ArchiveImporter::checked_all_masterchain_blocks() {
  LOG(DEBUG) << "Done importing masterchain blocks. Last block seqno = " << last_masterchain_seqno_;
  if (start_import_seqno_ > last_masterchain_state_->get_seqno()) {
    abort_query(td::Status::Error("no new masterchain blocks were imported"));
    return;
  }
  BlockIdExt block_id;
  CHECK(last_masterchain_state_->get_old_mc_block_id(start_import_seqno_ - 1, block_id));
  if (bounded_) {
    settlement_.begin(Child::StateRead);
  }
  request_masterchain_state_short(block_id, [SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    td::actor::send_closure(SelfId, &ArchiveImporter::got_start_state_result, std::move(R));
  });
}

void ArchiveImporter::got_start_state_result(td::Result<td::Ref<ShardState>> R) {
  if (!bounded_) {
    R.ensure();
    download_shard_archives(td::Ref<MasterchainState>{R.move_as_ok()});
    return;
  }
  settled(Child::StateRead);
  // Phase boundary between the masterchain and the shard-download phases: nothing
  // may be outstanding here, and that alone must not end the attempt. Completion
  // is decided by the draining or completion state, never by a zero count.
  maybe_publish();
  if (settlement_.published()) {
    return;
  }
  if (R.is_error()) {
    abort_query(R.move_as_error_prefix("start masterchain state: "));
    return;
  }
  td::Ref<MasterchainState> state{R.move_as_ok()};
  if (state.is_null()) {
    abort_query(td::Status::Error(ErrorCode::error, "start state is not a masterchain state"));
    return;
  }
  if (settlement_.draining()) {
    maybe_publish();
    return;
  }
  download_shard_archives(std::move(state));
}

static bool have_new_shards(td::Ref<MasterchainState> new_state, td::Ref<MasterchainState> old_state,
                            ShardIdFull shard_prefix) {
  for (auto &shard : new_state->get_shards()) {
    if (!shard_intersects(shard_prefix, shard->shard())) {
      continue;
    }
    auto old_shard = old_state->get_shard_from_config(shard->shard());
    if (old_shard.is_null() || old_shard->top_block_id() != shard->top_block_id()) {
      return true;
    }
  }
  return false;
}

void ArchiveImporter::download_shard_archives(td::Ref<MasterchainState> start_state) {
  start_state_ = start_state;
  td::uint32 monitor_min_split = start_state->monitor_min_split_depth(basechainId);
  LOG(DEBUG) << "Monitor min split = " << monitor_min_split
             << (have_shard_blocks_ ? ", shard blocks in the main package" : ", no shard blocks in the main package");
  // If masterchain package has shard blocks then it's old archive format, don't need to download shards
  if (!have_shard_blocks_ && !use_imported_files_) {
    for (td::uint64 i = 0; i < (1ULL << monitor_min_split); ++i) {
      ShardIdFull shard_prefix{basechainId, (i * 2 + 1) << (64 - monitor_min_split - 1)};
      if (opts_->need_monitor(shard_prefix, start_state)) {
        if (have_new_shards(last_masterchain_state_, start_state_, shard_prefix)) {
          ++pending_shard_archives_;
          LOG(INFO) << "Downloading shard archive #" << start_import_seqno_ << " " << shard_prefix.to_str();
          download_shard_archive(shard_prefix);
        } else {
          LOG(INFO) << "Not downloading shard archive #" << start_import_seqno_ << " " << shard_prefix.to_str()
                    << " : no new shard blocks";
        }
      }
    }
  } else {
    LOG(INFO) << "Skip downloading shard archives";
  }
  if (pending_shard_archives_ == 0) {
    check_next_shard_client_seqno(shard_client_seqno_ + 1);
  }
}

void ArchiveImporter::download_shard_archive(ShardIdFull shard_prefix) {
  if (bounded_) {
    // No new download and no retry once the attempt drains or its deadline passed.
    if (settlement_.draining() || deadline_passed()) {
      abort_query(td::Status::Error(ErrorCode::timeout,
                                    PSTRING() << "shard archive " << shard_prefix.to_str() << " not downloaded"));
      return;
    }
    settlement_.begin(Child::ShardArchive);
  }
  request_archive(start_import_seqno_, shard_prefix, child_timeout(3600.0),
                  [SelfId = actor_id(this), shard_prefix](td::Result<std::string> R) {
                    td::actor::send_closure(SelfId, &ArchiveImporter::got_shard_archive, shard_prefix, std::move(R));
                  });
}

void ArchiveImporter::got_shard_archive(ShardIdFull shard_prefix, td::Result<std::string> R) {
  settled(Child::ShardArchive);
  if (R.is_error()) {
    LOG(WARNING) << "Failed to download archive slice #" << start_import_seqno_ << " for shard "
                 << shard_prefix.to_str();
    if (bounded_) {
      if (settlement_.draining() || deadline_passed()) {
        abort_query(R.move_as_error_prefix(PSTRING() << "shard archive " << shard_prefix.to_str() << ": "));
        return;
      }
      settlement_.begin(Child::RetryWait);
      delay_action(
          [SelfId = actor_id(this), shard_prefix]() {
            td::actor::send_closure(SelfId, &ArchiveImporter::retry_shard_archive, shard_prefix);
          },
          td::Timestamp::in(2.0));
      return;
    }
    delay_action(
        [SelfId = actor_id(this), shard_prefix]() {
          td::actor::send_closure(SelfId, &ArchiveImporter::download_shard_archive, shard_prefix);
        },
        td::Timestamp::in(2.0));
    return;
  }
  LOG(DEBUG) << "Downloaded shard archive #" << start_import_seqno_ << " " << shard_prefix.to_str();
  if (bounded_ && settlement_.draining()) {
    // The attempt is ending: this file is not imported, and nobody else owns it.
    td::unlink(R.ok()).ignore();
    maybe_publish();
    return;
  }
  downloaded_shard_archive(R.move_as_ok());
}

void ArchiveImporter::retry_shard_archive(ShardIdFull shard_prefix) {
  settled(Child::RetryWait);
  download_shard_archive(shard_prefix);
}

void ArchiveImporter::downloaded_shard_archive(std::string path) {
  td::Status S = process_package(path, false);
  if (S.is_error()) {
    LOG(INFO) << "Error processing package: " << S;
    if (bounded_) {
      // The attempt cannot apply this prefix: record the error and drain. Sibling
      // downloads still outstanding settle and their files are unlinked.
      --pending_shard_archives_;
      abort_query(S.move_as_error_prefix("shard archive package: "));
      return;
    }
  }
  --pending_shard_archives_;
  if (pending_shard_archives_ == 0) {
    check_next_shard_client_seqno(shard_client_seqno_ + 1);
  }
}

void ArchiveImporter::check_next_shard_client_seqno(BlockSeqno seqno) {
  if (bounded_ && settlement_.draining()) {
    maybe_publish();
    return;
  }
  if (seqno > last_masterchain_state_->get_seqno() || seqno > last_masterchain_seqno_) {
    finish_query();
  } else if (seqno == last_masterchain_state_->get_seqno()) {
    got_masterchain_state(last_masterchain_state_);
  } else {
    BlockIdExt b;
    bool f = last_masterchain_state_->get_old_mc_block_id(seqno, b);
    CHECK(f);
    if (bounded_) {
      settlement_.begin(Child::StateRead);
    }
    request_masterchain_state_short(b, [SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      td::actor::send_closure(SelfId, &ArchiveImporter::got_masterchain_state_result, std::move(R));
    });
  }
}

void ArchiveImporter::got_masterchain_state_result(td::Result<td::Ref<ShardState>> R) {
  if (!bounded_) {
    R.ensure();
    got_masterchain_state(td::Ref<MasterchainState>{R.move_as_ok()});
    return;
  }
  settled(Child::StateRead);
  if (R.is_error()) {
    abort_query(R.move_as_error_prefix("shard-client masterchain state: "));
    return;
  }
  td::Ref<MasterchainState> state{R.move_as_ok()};
  if (state.is_null()) {
    abort_query(td::Status::Error(ErrorCode::error, "shard-client state is not a masterchain state"));
    return;
  }
  if (settlement_.draining()) {
    maybe_publish();
    return;
  }
  got_masterchain_state(std::move(state));
}

void ArchiveImporter::got_masterchain_state(td::Ref<MasterchainState> state) {
  if (state->get_seqno() != start_import_seqno_ && state->is_key_state()) {
    finish_query();
    return;
  }
  LOG(DEBUG) << "Applying shard client seqno " << state->get_seqno();
  auto s = state->get_shards();
  if (!bounded_) {
    td::MultiPromise mp;
    auto ig = mp.init_guard();
    for (auto &shard : s) {
      if (opts_->need_monitor(shard->shard(), state)) {
        apply_shard_block(shard->top_block_id(), state->get_block_id(), ig.get_promise());
      }
    }
    ig.add_promise([SelfId = actor_id(this), seqno = state->get_seqno()](td::Result<td::Unit> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ArchiveImporter::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &ArchiveImporter::checked_shard_client_seqno, seqno);
      }
    });
    return;
  }
  // Bounded: collect the result of every required shard application of this
  // masterchain block before deciding. The coherent frontier reaches this block
  // only if all of them succeeded, whatever order they report in.
  std::vector<BlockIdExt> required;
  for (auto &shard : s) {
    if (opts_->need_monitor(shard->shard(), state)) {
      required.push_back(shard->top_block_id());
    }
  }
  auto seqno = state->get_seqno();
  if (required.empty()) {
    checked_shard_client_seqno(seqno);
    return;
  }
  shard_join_ = ShardJoin{seqno, required.size(), td::Status::OK()};
  settlement_.begin(Child::ShardJoin);
  for (auto &block_id : required) {
    apply_shard_block(block_id, state->get_block_id(), [SelfId = actor_id(this), seqno](td::Result<td::Unit> R) {
      td::actor::send_closure(SelfId, &ArchiveImporter::shard_join_result, seqno, std::move(R));
    });
  }
}

void ArchiveImporter::shard_join_result(BlockSeqno seqno, td::Result<td::Unit> R) {
  if (shard_join_.seqno != seqno || shard_join_.pending == 0) {
    LOG(ERROR) << "archive import: unexpected shard application result for masterchain block " << seqno;
    return;
  }
  if (R.is_error() && shard_join_.first_error.is_ok()) {
    shard_join_.first_error = R.move_as_error_prefix(PSTRING() << "shard application for #" << seqno << ": ");
    // Drain at once: the siblings still outstanding stay counted until they settle,
    // but none of them may start further predecessor work or an apply.
    settlement_.drain(shard_join_.first_error.clone());
  }
  shard_join_.pending--;
  if (shard_join_.pending > 0) {
    return;
  }
  settled(Child::ShardJoin);
  if (shard_join_.first_error.is_error()) {
    abort_query(std::move(shard_join_.first_error));
    return;
  }
  checked_shard_client_seqno(seqno);
}

void ArchiveImporter::checked_shard_client_seqno(BlockSeqno seqno) {
  if (bounded_) {
    if (startup_catchup::saturating_add(shard_client_seqno_, 1) != seqno) {
      abort_query(td::Status::Error(
          ErrorCode::error, PSTRING() << "shard-client step " << seqno << " does not follow " << shard_client_seqno_));
      return;
    }
  } else {
    CHECK(shard_client_seqno_ + 1 == seqno);
  }
  shard_client_seqno_++;
  imported_any_ = true;
  check_next_shard_client_seqno(seqno + 1);
}

void ArchiveImporter::apply_shard_block(BlockIdExt block_id, BlockIdExt masterchain_block_id,
                                        td::Promise<td::Unit> promise) {
  LOG(DEBUG) << "Applying shard block " << block_id.id.to_str();
  if (bounded_) {
    if (settlement_.draining()) {
      promise.set_error(td::Status::Error(ErrorCode::cancelled, "archive import attempt is draining"));
      return;
    }
    // The chain apply_shard_block -> cont1..cont3 is one counted parent: it settles
    // when its promise is completed, however the chain ends.
    settlement_.begin(Child::ShardChain);
    promise = [SelfId = actor_id(this), inner = std::move(promise)](td::Result<td::Unit> R) mutable {
      td::actor::send_closure(SelfId, &ArchiveImporter::shard_chain_done, std::move(inner), std::move(R));
    };
    settlement_.begin(Child::HandleRead);
  }
  request_block_handle(
      block_id, true,
      [SelfId = actor_id(this), masterchain_block_id, promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
        td::actor::send_closure(SelfId, &ArchiveImporter::shard_block_handle_result, masterchain_block_id,
                                std::move(promise), std::move(R));
      });
}

void ArchiveImporter::shard_chain_done(td::Promise<td::Unit> promise, td::Result<td::Unit> R) {
  settled(Child::ShardChain);
  promise.set_result(std::move(R));
  maybe_publish();
}

void ArchiveImporter::shard_block_handle_result(BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise,
                                                td::Result<BlockHandle> R) {
  if (!bounded_) {
    R.ensure();
    apply_shard_block_cont1(R.move_as_ok(), masterchain_block_id, std::move(promise));
    return;
  }
  settled(Child::HandleRead);
  if (R.is_error()) {
    promise.set_error(R.move_as_error_prefix("shard block handle: "));
    return;
  }
  if (settlement_.draining()) {
    promise.set_error(td::Status::Error(ErrorCode::cancelled, "archive import attempt is draining"));
    return;
  }
  apply_shard_block_cont1(R.move_as_ok(), masterchain_block_id, std::move(promise));
}

void ArchiveImporter::apply_shard_block_cont1(BlockHandle handle, BlockIdExt masterchain_block_id,
                                              td::Promise<td::Unit> promise) {
  if (handle->is_applied()) {
    promise.set_value(td::Unit());
    return;
  }

  if (handle->id().seqno() == 0) {
    auto split_depth = start_state_->persistent_state_split_depth(handle->id().shard_full().workchain);
    if (!bounded_) {
      auto P = td::PromiseCreator::lambda(
          [promise = std::move(promise)](td::Result<td::Ref<ShardState>>) mutable { promise.set_value(td::Unit()); });
      request_state_download(handle->id(), masterchain_block_id, split_depth, td::Timestamp::in(3600), std::move(P));
      return;
    }
    if (deadline_passed()) {
      promise.set_error(td::Status::Error(ErrorCode::timeout, "no time left for a shard state download"));
      return;
    }
    settlement_.begin(Child::StateDownload);
    request_state_download(
        handle->id(), masterchain_block_id, split_depth, child_timeout(3600.0),
        [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::Ref<ShardState>> R) mutable {
          td::actor::send_closure(SelfId, &ArchiveImporter::shard_state_downloaded, std::move(promise), std::move(R));
        });
    return;
  }

  auto it = blocks_.find(handle->id());
  if (it == blocks_.end() || !it->second.proof_pkg || !it->second.data_pkg) {
    promise.set_error(
        td::Status::Error(ErrorCode::notready, PSTRING() << "no data/proof for shard block " << handle->id()));
    return;
  }
  TRY_RESULT_PROMISE(promise, proof_data, it->second.proof_pkg->read(it->second.proof_offset));
  TRY_RESULT_PROMISE(promise, proof, parse_proof_link(handle->id(), std::move(proof_data.second)));
  auto timeout = check_timeout(10.0);
  if (!timeout) {
    promise.set_error(td::Status::Error(ErrorCode::timeout, "no time left for a proof link check"));
    return;
  }
  if (bounded_) {
    settlement_.begin(Child::ProofLinkCheck);
  }
  auto P = [SelfId = actor_id(this), handle, masterchain_block_id,
            promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
    td::actor::send_closure(SelfId, &ArchiveImporter::shard_proof_link_checked, std::move(handle), masterchain_block_id,
                            std::move(promise), std::move(R));
  };
  request_proof_link_check(handle->id(), std::move(proof), *timeout, std::move(P));
}

void ArchiveImporter::shard_state_downloaded(td::Promise<td::Unit> promise, td::Result<td::Ref<ShardState>> R) {
  settled(Child::StateDownload);
  if (R.is_error()) {
    promise.set_error(R.move_as_error_prefix("shard zero state download: "));
    return;
  }
  promise.set_value(td::Unit());
}

void ArchiveImporter::shard_proof_link_checked(BlockHandle handle, BlockIdExt masterchain_block_id,
                                               td::Promise<td::Unit> promise, td::Result<BlockHandle> R) {
  settled(Child::ProofLinkCheck);
  if (R.is_error()) {
    promise.set_error(R.move_as_error());
    return;
  }
  apply_shard_block_cont2(std::move(handle), masterchain_block_id, std::move(promise));
}

void ArchiveImporter::apply_shard_block_cont2(BlockHandle handle, BlockIdExt masterchain_block_id,
                                              td::Promise<td::Unit> promise) {
  if (bounded_ && settlement_.draining()) {
    promise.set_error(td::Status::Error(ErrorCode::cancelled, "archive import attempt is draining"));
    return;
  }
  if (handle->is_applied()) {
    promise.set_value(td::Unit());
    return;
  }
  CHECK(handle->id().seqno() > 0);

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), handle, masterchain_block_id,
                                       promise = std::move(promise)](td::Result<td::Unit> R) mutable {
    if (R.is_error()) {
      promise.set_error(R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &ArchiveImporter::apply_shard_block_cont3, std::move(handle),
                              masterchain_block_id, std::move(promise));
    }
  });
  if (!handle->merge_before() && handle->one_prev(true).shard_full() == handle->id().shard_full()) {
    apply_shard_block(handle->one_prev(true), masterchain_block_id, std::move(P));
  } else {
    td::MultiPromise mp;
    auto ig = mp.init_guard();
    ig.add_promise(std::move(P));
    check_shard_block_applied(handle->one_prev(true), ig.get_promise());
    if (handle->merge_before()) {
      check_shard_block_applied(handle->one_prev(false), ig.get_promise());
    }
  }
}

void ArchiveImporter::apply_shard_block_cont3(BlockHandle handle, BlockIdExt masterchain_block_id,
                                              td::Promise<td::Unit> promise) {
  if (bounded_ && settlement_.draining()) {
    promise.set_error(td::Status::Error(ErrorCode::cancelled, "archive import attempt is draining"));
    return;
  }
  auto it = blocks_.find(handle->id());
  if (bounded_) {
    if (it == blocks_.end() || !it->second.data_pkg) {
      promise.set_error(
          td::Status::Error(ErrorCode::notready, PSTRING() << "no data for shard block " << handle->id()));
      return;
    }
  } else {
    CHECK(it != blocks_.end() && it->second.data_pkg);
  }
  TRY_RESULT_PROMISE(promise, data, it->second.data_pkg->read(it->second.data_offset));
  if (sha256_bits256(data.second.as_slice()) != handle->id().file_hash) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "bad block file hash"));
    return;
  }
  TRY_RESULT_PROMISE(promise, block, parse_block(handle->id(), std::move(data.second)));

  if (!bounded_) {
    request_apply(handle->id(), std::move(block), masterchain_block_id, td::Timestamp::in(600.0), std::move(promise));
    return;
  }
  if (deadline_passed()) {
    promise.set_error(td::Status::Error(ErrorCode::timeout, "no time left before the attempt deadline for an apply"));
    return;
  }
  settlement_.begin(Child::Apply);
  request_apply(handle->id(), std::move(block), masterchain_block_id, child_timeout(600.0),
                [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
                  td::actor::send_closure(SelfId, &ArchiveImporter::shard_block_applied, std::move(promise),
                                          std::move(R));
                });
}

void ArchiveImporter::shard_block_applied(td::Promise<td::Unit> promise, td::Result<td::Unit> R) {
  settled(Child::Apply);
  promise.set_result(std::move(R));
}

void ArchiveImporter::check_shard_block_applied(BlockIdExt block_id, td::Promise<td::Unit> promise) {
  if (bounded_) {
    settlement_.begin(Child::HandleRead);
    request_block_handle(block_id, false,
                         [SelfId = actor_id(this), promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
                           td::actor::send_closure(SelfId, &ArchiveImporter::shard_block_applied_check_result,
                                                   std::move(promise), std::move(R));
                         });
    return;
  }
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
        } else {
          auto handle = R.move_as_ok();
          if (!handle->is_applied()) {
            promise.set_error(td::Status::Error(ErrorCode::notready, "not applied"));
          } else {
            LOG(DEBUG) << "Applied shard block " << handle->id().id.to_str();
            promise.set_value(td::Unit());
          }
        }
      });
  request_block_handle(block_id, false, std::move(P));
}

void ArchiveImporter::shard_block_applied_check_result(td::Promise<td::Unit> promise, td::Result<BlockHandle> R) {
  settled(Child::HandleRead);
  if (R.is_error()) {
    promise.set_error(R.move_as_error());
    return;
  }
  auto handle = R.move_as_ok();
  if (!handle->is_applied()) {
    promise.set_error(td::Status::Error(ErrorCode::notready, "not applied"));
    return;
  }
  LOG(DEBUG) << "Applied shard block " << handle->id().id.to_str();
  promise.set_value(td::Unit());
}

void ArchiveImporter::abort_query(td::Status error) {
  if (bounded_) {
    fail(std::move(error));
    return;
  }
  if (!imported_any_) {
    for (const std::string &f : files_to_cleanup_) {
      td::unlink(f).ignore();
    }
    promise_.set_error(std::move(error));
    stop();
    return;
  }
  LOG(INFO) << "Archive import: " << error;
  finish_query();
}

void ArchiveImporter::finish_query() {
  if (bounded_) {
    settlement_.request_completion();
    maybe_publish();
    return;
  }
  for (const std::string &f : files_to_cleanup_) {
    td::unlink(f).ignore();
  }
  if (promise_) {
    LOG(INFO) << "Imported archive in " << perf_timer_.elapsed();
    promise_.set_value({last_masterchain_state_->get_seqno(),
                        std::min<BlockSeqno>(last_masterchain_state_->get_seqno(), shard_client_seqno_)});
  }
  stop();
}

}  // namespace validator

}  // namespace tos
