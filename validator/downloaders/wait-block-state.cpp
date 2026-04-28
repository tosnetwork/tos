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
#include "common/checksum.h"
#include "common/delay.h"
#include "td/utils/port/FileFd.h"
#include "tos/tos-io.hpp"
#include "validator/downloaders/download-state.hpp"
#include "validator/fabric.h"
#include "vm/boc.h"

#include "wait-block-state.hpp"

namespace tos {

namespace validator {

void WaitBlockState::alarm() {
  abort_query(td::Status::Error(ErrorCode::timeout, "timeout"));
}

void WaitBlockState::abort_query(td::Status reason) {
  if (promise_no_store_) {
    promise_no_store_.set_error(
        reason.clone().move_as_error_prefix(PSTRING() << "failed to download state " << handle_->id() << ": "));
  }
  if (promise_final_) {
    if (priority_ > 0 || (reason.code() != ErrorCode::timeout && reason.code() != ErrorCode::notready)) {
      LOG(WARNING) << "aborting wait block state query for " << handle_->id() << " priority=" << priority_ << ": "
                   << reason;
    } else {
      LOG(DEBUG) << "aborting wait block state query for " << handle_->id() << " priority=" << priority_ << ": "
                 << reason;
    }
    promise_final_.set_error(
        reason.move_as_error_prefix(PSTRING() << "failed to download state " << handle_->id() << ": "));
  }
  stop();
}

void WaitBlockState::finish_query() {
  // Internal invariant: finish_query is invoked only after the actor's
  // state machine has confirmed the state is durably received (either
  // by reading from local DB or by completing a download + persist
  // cycle). The handle flag is set by local code paths only and is not
  // sourced from peer input.
  CHECK(handle_->received_state());
  if (promise_no_store_) {
    promise_no_store_.set_result(prev_state_);
  }
  if (promise_final_) {
    promise_final_.set_result(prev_state_);
  }
  stop();
}

void WaitBlockState::start_up() {
  alarm_timestamp() = timeout_;

  // Internal invariant: handle_ is constructor-injected by the caller
  // (ValidatorManager) from local block-handle state and is never null
  // for a properly-spawned actor. Not sourced from peer input.
  CHECK(handle_);
  start();
}

void WaitBlockState::start() {
  if (reading_from_db_ || force_reading_from_db_) {
    return;
  }
  bool inited_proof = handle_->id().is_masterchain() ? handle_->inited_proof() : handle_->inited_proof_link();
  bool allow_download =
      last_masterchain_state_.is_null() || opts_->need_monitor(handle_->id().shard_full(), last_masterchain_state_);
  if (handle_->received_state() && inited_proof) {
    reading_from_db_ = true;

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db error: "));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_db, R.move_as_ok(), false);
      }
    });
    td::actor::send_closure(manager_, &ValidatorManager::get_shard_state_from_db, handle_, std::move(P));
  } else if (handle_->id().id.seqno == 0 && next_static_file_attempt_.is_in_past()) {
    next_static_file_attempt_ = td::Timestamp::in(60.0);
    // id.file_hash contains correct file hash of zero state
    // => if file with this sha256 is found it is guaranteed to be correct
    // => if it is not, this error is permanent
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), id = handle_->id()](td::Result<td::BufferSlice> R) {
      if (R.is_error()) {
        if (R.error().code() == ErrorCode::notready) {
          td::actor::send_closure(SelfId, &WaitBlockState::start);
        } else {
          td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("static db error: "));
        }
      } else {
        auto data = R.move_as_ok();
        td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_net, std::move(data));
      }
    });
    td::actor::send_closure(manager_, &ValidatorManager::try_get_static_file, handle_->id().file_hash, std::move(P));
  } else if (handle_->id().id.seqno == 0) {
    auto P = td::PromiseCreator::lambda(
        [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
          if (R.is_error()) {
            td::actor::send_closure(SelfId, &WaitBlockState::failed_to_get_state_from_net,
                                    R.move_as_error_prefix("net error: "));
          } else {
            td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_net_budgeted, R.move_as_ok());
          }
        });
    td::actor::send_closure(manager_, &ValidatorManager::send_get_zero_state_request, handle_->id(), priority_,
                            std::move(P));
  } else if (check_persistent_state_desc() && !handle_->received_state() && allow_download) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      if (R.is_error()) {
        LOG(WARNING) << "failed to get persistent state: " << R.move_as_error();
        td::actor::send_closure(SelfId, &WaitBlockState::start);
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::written_state, R.move_as_ok());
      }
    });

    BlockIdExt masterchain_id = persistent_state_desc_->masterchain_id;
    td::uint32 split_depth = 0;
    bool block_found = false;
    for (const auto& [block, block_split_depth] : persistent_state_desc_->shard_blocks) {
      if (block == handle_->id()) {
        split_depth = block_split_depth;
        block_found = true;
        break;
      }
    }
    if (!block_found) {
      LOG(ERROR) << "invalid persistent state description passed to WaitBlockState for block "
                 << handle_->id().to_str();
      P.set_error(td::Status::Error("invalid persistent state description"));
    } else {
      td::actor::create_actor<DownloadShardState>("downloadstate", handle_->id(), masterchain_id, split_depth,
                                                  priority_, manager_, timeout_, std::move(P))
          .release();
    }
  } else if (!handle_->inited_prev() || (!handle_->inited_proof() && !handle_->inited_proof_link())) {
    if (!allow_download) {
      abort_query(td::Status::Error(PSTRING() << "not monitoring shard " << handle_->id().shard_full()));
      return;
    }
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
      if (R.is_error()) {
        delay_action([SelfId]() { td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof_link); },
                     td::Timestamp::in(0.1));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::got_proof_link, R.move_as_ok());
      }
    });

    waiting_proof_link_ = true;
    td::actor::send_closure(manager_, &ValidatorManager::send_get_block_proof_link_request, handle_->id(), priority_,
                            std::move(P));
  } else if (prev_state_.is_null()) {
    // Internal invariant: this branch is reached only after the
    // surrounding `else if` chain has confirmed proof/proof-link is
    // initialized; the flags are mutated locally on the actor strand
    // and are not sourced from peer input.
    CHECK(handle_->inited_proof() || handle_->inited_proof_link());
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &WaitBlockState::failed_to_get_prev_state,
                                R.move_as_error_prefix("prev state wait error: "));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::got_prev_state, R.move_as_ok());
      }
    });

    td::actor::send_closure(manager_, &ValidatorManager::wait_prev_block_state, handle_, priority_, timeout_,
                            std::move(P));
  } else if (handle_->id().is_masterchain() && !handle_->inited_proof()) {
    if (!allow_download) {
      abort_query(td::Status::Error(PSTRING() << "not monitoring shard " << handle_->id().shard_full()));
      return;
    }
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), handle = handle_](td::Result<td::BufferSlice> R) {
      if (R.is_error()) {
        delay_action([SelfId]() { td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof); },
                     td::Timestamp::in(0.1));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::got_proof, R.move_as_ok());
      }
    });

    waiting_proof_ = true;
    td::actor::send_closure(manager_, &ValidatorManager::send_get_block_proof_request, handle_->id(), priority_,
                            std::move(P));
  } else if (block_.is_null()) {
    if (!allow_download && !handle_->received()) {
      abort_query(td::Status::Error(PSTRING() << "not monitoring shard " << handle_->id().shard_full()));
      return;
    }
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<BlockData>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &WaitBlockState::failed_to_get_block_data,
                                R.move_as_error_prefix("block wait error: "));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::got_block_data, R.move_as_ok());
      }
    });

    td::actor::send_closure(manager_, &ValidatorManager::wait_block_data, handle_, priority_, timeout_, std::move(P));
  } else {
    apply();
  }
}

void WaitBlockState::failed_to_get_prev_state(td::Status reason) {
  if (reason.code() == ErrorCode::notready) {
    start();
  } else {
    abort_query(std::move(reason));
  }
}

void WaitBlockState::got_prev_state(td::Ref<ShardState> state) {
  prev_state_ = std::move(state);

  start();
}

void WaitBlockState::got_proof_link(td::BufferSlice data) {
  if (!waiting_proof_link_ || force_reading_from_db_) {
    return;
  }
  auto R = create_proof_link(handle_->id(), std::move(data));
  if (R.is_error()) {
    LOG(INFO) << "received bad proof link: " << R.move_as_error();
    start();
    return;
  }
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    if (R.is_ok()) {
      auto h = R.move_as_ok();
      // Internal invariant: run_check_proof_link_query is the local
      // proof-link verifier; on success it always sets inited_prev on
      // the returned handle as part of its post-validation contract.
      // The flag is mutated by local validator code, not by peer input.
      CHECK(h->inited_prev());
      td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof_link);
    } else {
      LOG(INFO) << "received bad proof link: " << R.move_as_error();
      delay_action([SelfId]() { td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof_link); },
                   td::Timestamp::in(0.1));
    }
  });
  run_check_proof_link_query(handle_->id(), R.move_as_ok(), manager_, timeout_, std::move(P));
}

void WaitBlockState::got_proof(td::BufferSlice data) {
  if (!waiting_proof_ || force_reading_from_db_) {
    return;
  }
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_ok()) {
      td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof);
    } else {
      LOG(INFO) << "received bad proof link: " << R.move_as_error();
      td::actor::send_closure(SelfId, &WaitBlockState::after_get_proof);
    }
  });
  td::actor::send_closure(manager_, &ValidatorManager::validate_block_proof, handle_->id(), std::move(data),
                          std::move(P));
}

void WaitBlockState::failed_to_get_block_data(td::Status reason) {
  if (reason.code() == ErrorCode::notready) {
    start();
  } else {
    abort_query(std::move(reason));
  }
}

void WaitBlockState::got_block_data(td::Ref<BlockData> data) {
  block_ = std::move(data);

  start();
}

void WaitBlockState::apply() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db set error: "));
    } else {
      td::actor::send_closure(SelfId, &WaitBlockState::written_state, R.move_as_ok());
    }
  });

  if (opts_->get_permanent_celldb()) {
    td::actor::send_closure(manager_, &ValidatorManager::set_block_state_from_data, handle_, block_, std::move(P));
    return;
  }
  TD_PERF_COUNTER(apply_block_to_state);
  td::PerfWarningTimer t{"applyblocktostate", 0.1};
  vm::StoreCellHint hint;
  auto S = prev_state_.write().apply_block(handle_->id(), block_, &hint);
  if (S.is_error()) {
    abort_query(S.move_as_error_prefix("apply error: "));
    return;
  }

  td::actor::send_closure(manager_, &ValidatorManager::set_block_state, handle_, prev_state_, std::move(hint),
                          std::move(P));
  if (promise_no_store_) {
    promise_no_store_.set_result(prev_state_);
    promise_no_store_ = {};
  }
}

void WaitBlockState::written_state(td::Ref<ShardState> upd_state) {
  prev_state_ = std::move(upd_state);
  finish_query();
}

void WaitBlockState::got_state_from_db(td::Ref<ShardState> state, bool force_reading) {
  if (force_reading_from_db_ && !force_reading) {
    return;
  }
  prev_state_ = state;
  if (!handle_->received_state()) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db set error: "));
      } else {
        td::actor::send_closure(SelfId, &WaitBlockState::written_state, R.move_as_ok());
      }
    });

    td::actor::send_closure(manager_, &ValidatorManager::set_block_state, handle_, prev_state_, vm::StoreCellHint{},
                            std::move(P));
    if (promise_no_store_) {
      promise_no_store_.set_result(prev_state_);
      promise_no_store_ = {};
    }
  } else {
    finish_query();
  }
}

void WaitBlockState::got_state_from_static_file(td::Ref<ShardState> state, td::BufferSlice data) {
  auto P =
      td::PromiseCreator::lambda([SelfId = actor_id(this), state = std::move(state)](td::Result<td::Unit> R) mutable {
        // tos27 P1-4: store_zero_state_file persists peer/static-file
        // bytes to the local archive. Surface a storage failure as a
        // structured error via abort_query instead of aborting the
        // validator process.
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &WaitBlockState::abort_query,
                                  R.move_as_error_prefix("store_zero_state_file: "));
          return;
        }
        td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_db, std::move(state), false);
      });
  td::actor::send_closure(manager_, &ValidatorManager::store_zero_state_file, handle_->id(), std::move(data),
                          std::move(P));
}

void WaitBlockState::force_read_from_db() {
  if (!handle_ || reading_from_db_ || force_reading_from_db_) {
    return;
  }
  force_reading_from_db_ = true;

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db get error: "));
    } else {
      td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_db, R.move_as_ok(), true);
    }
  });
  td::actor::send_closure(manager_, &ValidatorManager::get_shard_state_from_db, handle_, std::move(P));
}

void WaitBlockState::got_state_from_net(td::BufferSlice data) {
  if (force_reading_from_db_) {
    return;
  }
  auto r_root = vm::std_boc_deserialize(data);
  if (r_root.is_error()) {
    LOG(WARNING) << "received bad state from net: " << r_root.move_as_error();
    start();
    return;
  }
  auto r_state = create_shard_state(handle_->id(), r_root.move_as_ok());
  if (r_state.is_error()) {
    LOG(WARNING) << "received bad state from net: " << r_state.move_as_error();
    start();
    return;
  }
  auto state = r_state.move_as_ok();

  if (handle_->id().id.seqno == 0) {
    handle_->set_state_root_hash(handle_->id().root_hash);
  }
  if (state->root_hash() != handle_->state()) {
    LOG(WARNING) << "received state have bad root hash";
    start();
    return;
  }

  if (handle_->id().id.seqno != 0) {
    auto S = state->validate_deep();
    if (S.is_error()) {
      LOG(WARNING) << "received bad state from net: " << S;
      start();
      return;
    }
  } else {
    if (sha256_bits256(data.as_slice()) != handle_->id().file_hash) {
      LOG(WARNING) << "received bad state from net: file hash mismatch";
      start();
      return;
    }
  }
  handle_->set_logical_time(state->get_logical_time());
  handle_->set_unix_time(state->get_unix_time());
  handle_->set_is_key_block(handle_->id().is_masterchain() && handle_->id().id.seqno == 0);
  handle_->set_split(state->before_split());

  prev_state_ = std::move(state);
  // If a download-budget reservation was attached to this buffer (via
  // got_state_from_net_budgeted), capture it into the disk-write
  // completion lambda so the budget stays charged until the file is on
  // disk. Then it is released.
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), reservation = std::move(data_reservation_)](td::Result<td::Unit> R) mutable {
        reservation.reset();
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db set error: "));
        } else {
          td::actor::send_closure(SelfId, &WaitBlockState::written_state_file);
        }
      });

  td::actor::send_closure(manager_, &ValidatorManager::store_zero_state_file, handle_->id(), std::move(data),
                          std::move(P));
}

void WaitBlockState::got_state_from_net_budgeted(fullnode::DownloadedPersistentState downloaded) {
  // Pin the reservation to the actor so the global download budget stays
  // charged across deserialize/validate/persist; it is released once
  // the disk write completes (see got_state_from_net above for the
  // InMemory path).
  if (downloaded.is_memory()) {
    data_reservation_ = std::move(downloaded.memory().reservation);
    got_state_from_net(std::move(downloaded.memory().data));
    return;
  }
  // OnDisk path for zero state. Three stages, all streaming:
  //   1. mmap the tempfile and validate the file_hash against the
  //      mmap'd Slice — no heap BufferSlice of file size is allocated.
  //      The mmap is mandatory here: zero state is content-addressed by
  //      the SHA256 of the BoC envelope (handle_->id().file_hash), and
  //      that hash MUST be computed over the full byte stream before
  //      any deserializer logic runs. A streamed-in-chunks SHA256 over
  //      the same file would also be acceptable, but mmap reuses the
  //      already-allocated BudgetedStateFile mapping at zero extra
  //      cost.
  //   2. deserialize + validate the shard state via the streaming
  //      bounded BoC importer. Peak resident memory is bounded by
  //      `opts.max_resident_bytes`, NOT by the file size — the legacy
  //      one-shot vm::std_boc_deserialize call peaked at file size,
  //      which is the regression this stage closes.
  //   3. persist via store_zero_state_file_gen with a 1 MiB-chunk
  //      writer (copy_tempfile_to_writer). No BufferSlice of state
  //      size is ever allocated, regardless of state size.
  auto file = std::move(downloaded.file());
  {
    auto r_slice = fullnode::mmap_persistent_state_file(file);
    if (r_slice.is_error()) {
      abort_query(r_slice.move_as_error());
      return;
    }
    td::Slice mapped = r_slice.move_as_ok();
    if (sha256_bits256(mapped) != handle_->id().file_hash) {
      abort_query(td::Status::Error("bad zero state from net: file hash mismatch"));
      return;
    }
    // Drop `mapped` here. The streaming importer reads the same file
    // fresh through its own FileFd; keeping the mmap around would
    // double-account the resident bytes of the BoC envelope and is no
    // longer needed once the file_hash check has passed.
  }

  td::Ref<vm::Cell> root;
  {
    auto r_fd = td::FileFd::open(file.path, td::FileFd::Flags::Read);
    if (r_fd.is_error()) {
      abort_query(r_fd.move_as_error_prefix("received bad zero state from net: "));
      return;
    }
    auto fd = r_fd.move_as_ok();
    auto budget_cfg = fullnode::persistent_state_budget_config();
    // H-02 fail-closed cap, mirrored on the zero-state OnDisk path.
    // With true CellDb streaming enabled, the importer returns a
    // hash-only ExtCell root instead of the full resident DAG.
    if (file.size > budget_cfg.max_returned_dag_bytes_per_parse &&
        !budget_cfg.enable_true_cell_db_streaming_import) {
      abort_query(td::Status::Error(
          ErrorCode::notready,
          PSTRING() << "zero state too large for in-memory returned DAG (file_size=" << file.size
                    << " > max_returned_dag_bytes_per_parse="
                    << budget_cfg.max_returned_dag_bytes_per_parse
                    << "); enable CellDb streaming importer"));
      return;
    }
    vm::StreamingBocImportOptions opts;
    opts.max_resident_bytes = budget_cfg.max_resident_bytes_per_parse;
    opts.max_cells = budget_cfg.max_cells_per_parse;
    opts.max_scaffolding_bytes = budget_cfg.max_scaffolding_bytes_per_parse;
    opts.max_total_cell_bytes = std::min(file.size, budget_cfg.max_total_cell_bytes_per_parse);
    auto r_root = vm::std_boc_deserialize_from_file_bounded(
        fd, file.size, opts, vm::StreamingPersistCellFn{});
    fd.close();
    if (r_root.is_error()) {
      abort_query(r_root.move_as_error_prefix("received bad zero state from net: "));
      return;
    }
    root = r_root.move_as_ok();
  }
  auto r_state = create_shard_state(handle_->id(), std::move(root));
  if (r_state.is_error()) {
    abort_query(r_state.move_as_error_prefix("received bad zero state from net: "));
    return;
  }
  auto state = r_state.move_as_ok();
  if (state->root_hash() != handle_->state()) {
    abort_query(td::Status::Error("received zero state has bad root hash"));
    return;
  }

  // Zero state is the seqno=0 case: stamp metadata that the seqno!=0
  // path normally derives from validate_deep().
  handle_->set_state_root_hash(handle_->id().root_hash);
  handle_->set_logical_time(state->get_logical_time());
  handle_->set_unix_time(state->get_unix_time());
  handle_->set_is_key_block(handle_->id().is_masterchain() && handle_->id().id.seqno == 0);
  handle_->set_split(state->before_split());

  prev_state_ = std::move(state);

  // Pin the download reservation across the persist step so the global
  // download budget stays charged until the archive write fsync's.
  auto reservation = std::move(file.reservation);
  auto src_path = file.path;
  auto src_size = file.size;
  auto write_data = [src_path, src_size](td::FileFd &dst) -> td::Status {
    return copy_tempfile_to_writer(src_path, src_size, dst);
  };
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), reservation = std::move(reservation),
       file = std::move(file)](td::Result<td::Unit> R) mutable {
        // Drop the BudgetedStateFile (unmaps + unlinks the tempfile)
        // and release the download reservation exactly once on this
        // completion.
        (void)file;
        reservation.reset();
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &WaitBlockState::abort_query,
                                  R.move_as_error_prefix("db set error: "));
        } else {
          td::actor::send_closure(SelfId, &WaitBlockState::written_state_file);
        }
      });
  td::actor::send_closure(manager_, &ValidatorManager::store_zero_state_file_gen, handle_->id(),
                          std::move(write_data), std::move(P));
}

void WaitBlockState::written_state_file() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &WaitBlockState::abort_query, R.move_as_error_prefix("db set error: "));
    } else {
      td::actor::send_closure(SelfId, &WaitBlockState::written_state, R.move_as_ok());
    }
  });

  td::actor::send_closure(manager_, &ValidatorManager::set_block_state, handle_, prev_state_, vm::StoreCellHint{},
                          std::move(P));
}

void WaitBlockState::failed_to_get_zero_state() {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &WaitBlockState::failed_to_get_state_from_net,
                                  R.move_as_error_prefix("net error: "));
        } else {
          td::actor::send_closure(SelfId, &WaitBlockState::got_state_from_net_budgeted, R.move_as_ok());
        }
      });
  td::actor::send_closure(manager_, &ValidatorManager::send_get_zero_state_request, handle_->id(), priority_,
                          std::move(P));
}

void WaitBlockState::failed_to_get_state_from_net(td::Status reason) {
  if (reason.code() == ErrorCode::notready) {
    LOG(DEBUG) << "failed to download state for " << handle_->id() << " from net: " << reason;
  } else {
    LOG(WARNING) << "failed to download state for " << handle_->id() << " from net: " << reason;
  }

  start();
}

}  // namespace validator

}  // namespace tos
