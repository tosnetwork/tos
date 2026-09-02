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
#include "adnl/utils.hpp"
#include "td/actor/MultiPromise.h"
#include "tos/tos-io.hpp"
#include "validator/fabric.h"
#include "validator/invariants.hpp"

#include "apply-block.hpp"
#include "wc0-block-hook.h"

namespace tos {

namespace validator {

void ApplyBlock::abort_query(td::Status reason) {
  if (promise_) {
    VLOG(VALIDATOR_WARNING) << "aborting apply block query for " << id_.to_str() << ": " << reason;
    promise_.set_error(std::move(reason));
  }
  stop();
}

void ApplyBlock::finish_query() {
  VLOG(VALIDATOR_DEBUG) << "successfully finishing apply block query in " << perf_timer_.elapsed() << " s";
  handle_->set_processed();
  handle_->set_applied_stored();
  ValidatorInvariants::check_post_apply(handle_);

  if (promise_) {
    promise_.set_value(td::Unit());
  }
  stop();
}

void ApplyBlock::alarm() {
  abort_query(td::Status::Error(ErrorCode::timeout, "timeout"));
}

void ApplyBlock::start_up() {
  VLOG(VALIDATOR_DEBUG) << "running apply_block for " << id_.to_str() << ", mc_seqno=" << masterchain_block_id_.seqno();

  if (id_.is_masterchain()) {
    masterchain_block_id_ = id_;
  }

  alarm_timestamp() = timeout_;

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &ApplyBlock::got_block_handle, R.move_as_ok());
    }
  });

  td::actor::send_closure(manager_, &ValidatorManager::get_block_handle, id_, true, std::move(P));
}

void ApplyBlock::got_block_handle(BlockHandle handle) {
  VLOG(VALIDATOR_DEBUG) << "got_block_handle";
  handle_ = std::move(handle);

  if (handle_->is_applied() && handle_->applied_stored() &&
      (!handle_->id().is_masterchain() || handle_->processed())) {
    finish_query();
    return;
  }

  if (handle_->is_applied() && handle_->applied_stored()) {
    VLOG(VALIDATOR_DEBUG) << "already applied";
    auto P =
        td::PromiseCreator::lambda([SelfId = actor_id(this), seqno = handle_->id().id.seqno](td::Result<BlockIdExt> R) {
          R.ensure();
          auto h = R.move_as_ok();
          if (h.id.seqno < seqno) {
            td::actor::send_closure(SelfId, &ApplyBlock::written_block_data);
          } else {
            td::actor::send_closure(SelfId, &ApplyBlock::finish_query);
          }
        });
    td::actor::send_closure(manager_, &ValidatorManager::get_top_masterchain_block, std::move(P));
    return;
  }

  if (handle_->id().id.seqno == 0) {
    VLOG(VALIDATOR_DEBUG) << "seqno == 0";
    written_block_data();
    return;
  }

  if (handle_->received()) {
    VLOG(VALIDATOR_DEBUG) << "already received";
    written_block_data();
    return;
  }

  if (block_.not_null()) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &ApplyBlock::written_block_data);
      }
    });

    VLOG(VALIDATOR_DEBUG) << "storing block data";
    td::actor::send_closure(manager_, &ValidatorManager::set_block_data, handle_, block_, std::move(P));
  } else {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), handle = handle_](td::Result<td::Ref<BlockData>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
      } else {
        CHECK(handle->received());
        td::actor::send_closure(SelfId, &ApplyBlock::got_block_data, R.move_as_ok());
      }
    });

    VLOG(VALIDATOR_DEBUG) << "wait for block data";
    td::actor::send_closure(manager_, &ValidatorManager::wait_block_data, handle_, apply_block_priority(), timeout_,
                            std::move(P));
  }
}

void ApplyBlock::got_block_data(td::Ref<BlockData> block) {
  block_ = std::move(block);
  written_block_data();
}

void ApplyBlock::written_block_data() {
  VLOG(VALIDATOR_DEBUG) << "written_block_data";
  if (!handle_->id().seqno()) {
    CHECK(handle_->inited_split_after());
    CHECK(handle_->inited_state_root_hash());
    CHECK(handle_->inited_logical_time());
  } else {
    if (handle_->id().is_masterchain() && !handle_->inited_proof()) {
      abort_query(td::Status::Error(ErrorCode::notready, "proof is absent"));
      return;
    }
    if (!handle_->id().is_masterchain() && !handle_->inited_proof_link()) {
      abort_query(td::Status::Error(ErrorCode::notready, "proof link is absent"));
      return;
    }
    CHECK(handle_->inited_merge_before());
    CHECK(handle_->inited_split_after());
    CHECK(handle_->inited_prev());
    CHECK(handle_->inited_state_root_hash());
    CHECK(handle_->inited_logical_time());
  }
  if (handle_->is_applied() && handle_->applied_stored() && handle_->processed()) {
    finish_query();
  } else {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &ApplyBlock::got_cur_state, R.move_as_ok());
      }
    });

    VLOG(VALIDATOR_DEBUG) << "wait_block_state";
    td::actor::send_closure(manager_, &ValidatorManager::wait_block_state, handle_, apply_block_priority(), timeout_,
                            true, std::move(P));
  }
}

void ApplyBlock::got_cur_state(td::Ref<ShardState> state) {
  VLOG(VALIDATOR_DEBUG) << "got_cur_state";
  state_ = std::move(state);
  CHECK(handle_->received_state());
  written_state();
}

void ApplyBlock::written_state() {
  VLOG(VALIDATOR_DEBUG) << "written_state";
  if (handle_->is_applied() && handle_->applied_stored() && handle_->processed()) {
    finish_query();
    return;
  }
  VLOG(VALIDATOR_DEBUG) << "setting next for parents";

  if (handle_->id().id.seqno != 0 && !handle_->is_applied()) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &ApplyBlock::written_next);
      }
    });

    td::MultiPromise mp;
    auto g = mp.init_guard();
    g.add_promise(std::move(P));

    td::actor::send_closure(manager_, &ValidatorManager::set_next_block, handle_->one_prev(true), id_, g.get_promise());
    if (handle_->merge_before()) {
      td::actor::send_closure(manager_, &ValidatorManager::set_next_block, handle_->one_prev(false), id_,
                              g.get_promise());
    }
  } else {
    written_next();
  }
}

void ApplyBlock::written_next() {
  VLOG(VALIDATOR_DEBUG) << "written_next";
  if (handle_->is_applied() && handle_->applied_stored() && handle_->processed()) {
    finish_query();
    return;
  }

  VLOG(VALIDATOR_DEBUG) << "applying parents";

  if (handle_->id().id.seqno != 0 && !handle_->is_applied()) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error_prefix("prev: "));
      } else {
        td::actor::send_closure(SelfId, &ApplyBlock::applied_prev);
      }
    });

    td::MultiPromise mp;
    auto g = mp.init_guard();
    g.add_promise(std::move(P));
    BlockIdExt m = masterchain_block_id_;
    if (id_.is_masterchain()) {
      m = id_;
    }
    run_apply_block_query(handle_->one_prev(true), td::Ref<BlockData>{}, m, manager_, timeout_, g.get_promise());
    if (handle_->merge_before()) {
      run_apply_block_query(handle_->one_prev(false), td::Ref<BlockData>{}, m, manager_, timeout_, g.get_promise());
    }
  } else {
    applied_prev();
  }
}

void ApplyBlock::applied_prev() {
  VLOG(VALIDATOR_DEBUG) << "applying parents";
  VLOG(VALIDATOR_DEBUG) << "applied_prev, waiting manager's confirm";
  if (!id_.is_masterchain()) {
    handle_->set_masterchain_ref_block(masterchain_block_id_.seqno());
  }
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &ApplyBlock::applied_set);
    }
  });
  td::actor::send_closure(manager_, &ValidatorManager::new_block, handle_, state_, std::move(P));
}

void ApplyBlock::applied_set() {
  VLOG(VALIDATOR_DEBUG) << "applied_set";
  handle_->set_applied();
  // wc=0 wallet index hook (best-effort, installed by validator-engine). Runs
  // here — after the block is applied — so only canonical-chain blocks are ever
  // indexed; data stored for unfinalized candidates (e.g. nonfinal candidate
  // broadcasts) must not reach the index. When the block data was already in the
  // database before this apply (block_ is null), fetch it asynchronously; a
  // fetch failure only degrades RPC for this block.
  if (g_wc0_block_index_hook && handle_->id().id.workchain == 0 && handle_->id().seqno() > 0) {
    auto state_root = state_.not_null() ? state_->root_cell() : td::Ref<vm::Cell>{};
    if (block_.not_null()) {
      try {
        g_wc0_block_index_hook(block_->root_cell(), state_root, handle_->id());
      } catch (...) {
        // Indexing must never affect block application.
      }
    } else {
      td::actor::send_closure(
          manager_, &ValidatorManager::get_block_data_from_db, handle_,
          [id = handle_->id(), state_root](td::Result<td::Ref<BlockData>> R) {
            if (R.is_error() || R.ok().is_null() || !g_wc0_block_index_hook) {
              return;
            }
            try {
              g_wc0_block_index_hook(R.ok()->root_cell(), state_root, id);
            } catch (...) {
              // Indexing must never affect block application.
            }
          });
    }
  }
  if (handle_->id().seqno() > 0) {
    CHECK(handle_->handle_moved_to_archive());
    CHECK(handle_->moved_to_archive());
  }
  if (handle_->need_flush()) {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Unit> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &ApplyBlock::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &ApplyBlock::cleanup_and_finish);
      }
    });
    VLOG(VALIDATOR_DEBUG) << "flush handle";
    handle_->flush(manager_, handle_, std::move(P));
  } else {
    cleanup_and_finish();
  }
}

void ApplyBlock::schedule_external_messages_cleanup() {
  td::actor::send_closure(manager_, &ValidatorManager::cleanup_applied_external_messages, handle_, block_);
}

void ApplyBlock::cleanup_and_finish() {
  schedule_external_messages_cleanup();
  finish_query();
}

}  // namespace validator

}  // namespace tos
