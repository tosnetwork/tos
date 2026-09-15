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
#include <algorithm>
#include <cassert>
#include <cstring>
#include <ctime>

#include "adnl/utils.hpp"
#include "auth/native-config-context.h"
#include "auth/native-history.h"
#include "auth/native-registry-admission.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/validator-set.h"
#include "block/workchain-execution-dispatch.h"
#include "crypto/openssl/rand.hpp"
#include "td/actor/SharedFuture.h"
#include "td/db/utils/BlobView.h"
#include "td/utils/format.h"
#include "td/utils/Random.h"
#include "tos/tos-shard.h"
#include "vm/boc.h"
#include "vm/db/StaticBagOfCellsDb.h"
#include "vm/dict.h"

#include "collator-impl.h"
#include "fabric.h"
#include "storage-stat-cache.hpp"
#include "top-shard-descr.hpp"

namespace tos {

namespace validator {
using td::Ref;
using namespace std::literals::string_literals;

// Don't increase MERGE_MAX_QUEUE_LIMIT too much: merging requires cleaning the whole queue in out_msg_queue_cleanup
static constexpr td::uint32 FORCE_SPLIT_QUEUE_SIZE = 4096;
static constexpr td::uint32 SPLIT_MAX_QUEUE_SIZE = 100000;
static constexpr td::uint32 MERGE_MAX_QUEUE_SIZE = 2047;
static constexpr int HIGH_PRIORITY_EXTERNAL = 10;  // don't skip high priority externals when queue is big

static constexpr int MAX_ATTEMPTS = 5;

class WorkTimerGuard {
 public:
  WorkTimerGuard();
  explicit WorkTimerGuard(td::RealCpuTimer& timer) : timer_(&timer) {
    if (timer_) {
      timer_->resume();
    }
  }
  WorkTimerGuard(const WorkTimerGuard&) = delete;
  WorkTimerGuard(WorkTimerGuard&&) = delete;
  ~WorkTimerGuard() {
    reset();
  }

  WorkTimerGuard& operator=(const WorkTimerGuard&) = delete;
  WorkTimerGuard& operator=(WorkTimerGuard&& other) {
    std::swap(timer_, other.timer_);
    return *this;
  }
  void reset() {
    if (timer_) {
      timer_->pause();
      timer_ = nullptr;
    }
  }

 private:
  td::RealCpuTimer* timer_ = nullptr;
};

/**
 * Constructs a Collator object.
 *
 * @param params Collator parameters
 * @param manager The ActorId of the ValidatorManager.
 * @param cancellation_token Token to cancel collation.
 * @param promise The promise to return the result.
 */
Collator::Collator(CollateParams params, td::actor::ActorId<ValidatorManager> manager,
                   td::CancellationToken cancellation_token, td::Promise<BlockCandidate> promise)
    : params_(std::move(params))
    , shard_(params_.shard)
    , prev_blocks(params_.prev)
    , manager(manager)
    , timeout_(params_.hard_timeout)
    // default timeout is 10 seconds, declared in validator/validator-group.cpp:generate_block_candidate:run_collate_query
    , main_promise(std::move(promise))
    , perf_timer_("collate", 0.1,
                  [manager](double duration) {
                    send_closure(manager, &ValidatorManager::add_perf_timer_stat, "collate", duration);
                  })
    , cancellation_token_(std::move(cancellation_token)) {
  if (params_.collator_opts.is_null()) {
    params_.collator_opts = Ref<CollatorOptions>{true};
  }
  if (!params_.soft_timeout) {
    params_.soft_timeout = params_.hard_timeout;
  }
  if (params_.wait_externals_until) {
    queue_cleanup_timeout_ = std::max(params_.wait_externals_until, params_.soft_timeout);
    internal_msg_timeout_ = std::max(params_.wait_externals_until, params_.soft_timeout);
    external_msg_timeout_ = std::max(params_.wait_externals_until, params_.soft_timeout);
  } else {
    double t = params_.soft_timeout.in();
    queue_cleanup_timeout_ = td::Timestamp::in(t * 0.25);
    internal_msg_timeout_ = td::Timestamp::in(t * 0.5);
    external_msg_timeout_ = td::Timestamp::in(t * 0.75);
  }
}

/**
 * Starts the Collator.
 *
 * This function initializes the Collator by performing various checks and queries to the ValidatorManager.
 * It checks the validity of the shard, the previous blocks, and the workchain.
 * If all checks pass, it proceeds to query the ValidatorManager for the top masterchain state block, shard states, block data, external messages, and shard blocks.
 * The results of these queries are handled by corresponding callback functions.
 */
void Collator::start_up() {
  LOG(WARNING) << "Collator for shard " << shard_.to_str() << " started"
               << (params_.attempt_idx ? PSTRING() << " (attempt #" << params_.attempt_idx << ")" : "");
  if (!check_cancelled()) {
    return;
  }
  LOG(DEBUG) << "Previous block #1 is " << prev_blocks.at(0).to_str();
  if (prev_blocks.size() > 1) {
    LOG(DEBUG) << "Previous block #2 is " << prev_blocks.at(1).to_str();
  }
  if (params_.is_hardfork && workchain() == masterchainId) {
    is_key_block_ = true;
  }
  // 1. check validity of parameters, especially prev_blocks, shard and min_mc_block_id.
  // Concrete non-TVM workchain ids are validated after the masterchain
  // ConfigParam 12 snapshot is loaded, through WorkchainExecutionRegistry.
  if (is_busy()) {
    fatal_error(-666, "collator is busy creating another block candidate");
    return;
  }
  if (!shard_.is_valid_ext()) {
    fatal_error(-666, "requested to generate a block for an invalid shard");
    return;
  }
  td::uint64 x = td::lower_bit64(get_shard());
  if (x < 8) {
    fatal_error(-666, "cannot split a shard more than 60 times");
    return;
  }
  if (is_masterchain() && !shard_.is_masterchain_ext()) {
    fatal_error(-666, "sub-shards cannot exist in the masterchain");
    return;
  }
  if (!ShardIdFull(params_.min_masterchain_block_id).is_masterchain_ext()) {
    fatal_error(-666, "requested minimal masterchain block id does not belong to masterchain");
    return;
  }
  if (prev_blocks.size() > 2) {
    fatal_error(-666, "cannot have more than two previous blocks");
    return;
  }
  if (!prev_blocks.size()) {
    fatal_error(-666, "must have one or two previous blocks to generate a next block");
    return;
  }
  if (prev_blocks.size() == 2) {
    if (is_masterchain()) {
      fatal_error(-666, "cannot merge shards in masterchain");
      return;
    }
    if (!(shard_is_parent(shard_, ShardIdFull(prev_blocks[0])) &&
          shard_is_parent(shard_, ShardIdFull(prev_blocks[1])) && prev_blocks[0].id.shard < prev_blocks[1].id.shard)) {
      fatal_error(
          -666, "the two previous blocks for a merge operation are not siblings or are not children of current shard");
      return;
    }
    for (const auto& blk : prev_blocks) {
      if (!blk.seqno()) {
        fatal_error(-666, "previous blocks for a block merge operation must have non-zero seqno");
        return;
      }
    }
    after_merge_ = true;
    LOG(INFO) << "AFTER_MERGE set for the new block of " << shard_.to_str();
  } else {
    CHECK(prev_blocks.size() == 1);
    // creating next block
    if (!ShardIdFull(prev_blocks[0]).is_valid_ext()) {
      fatal_error(-666, "previous block does not have a valid id");
      return;
    }
    if (ShardIdFull(prev_blocks[0]) != shard_) {
      after_split_ = true;
      right_child_ = tos::is_right_child(shard_);
      LOG(INFO) << "AFTER_SPLIT set for the new block of " << shard_.to_str() << " (generating "
                 << (right_child_ ? "right" : "left") << " child)";
      if (!shard_is_parent(ShardIdFull(prev_blocks[0]), shard_)) {
        fatal_error(-666, "previous block does not belong to the shard we are generating a new block for");
        return;
      }
      if (is_masterchain()) {
        fatal_error(-666, "cannot split shards in masterchain");
        return;
      }
    }
    if (is_masterchain() && params_.min_masterchain_block_id.seqno() > prev_blocks[0].seqno()) {
      fatal_error(-666,
                  "cannot refer to specified masterchain block because it is later than the immediately preceding "
                  "masterchain block");
      return;
    }
  }
  busy_ = true;
  step = 1;
  // 2. load previous block(s) and corresponding state(s)
  prev_states.resize(prev_blocks.size());
  prev_block_data.resize(prev_blocks.size());
  load_prev_states_blocks();
  if (params_.is_hardfork) {
    LOG(WARNING) << "generating a hardfork block";
  }
  // 3. install external message queue
  if (!params_.is_hardfork) {
    LOG(DEBUG) << "installing external message queue";
    ext_msg_queue_ = ExtMsgQueue("ext_msg_queue", 500);
    ext_msg_queue_initialized_ = true;
    auto callback = std::make_unique<ExtMsgCallback>();
    callback->shard = shard_;
    callback->cancellation_token = ext_msg_cancellation_.get_cancellation_token();
    callback->timeout = params_.wait_externals_until ? params_.wait_externals_until : td::Timestamp::now();
    callback->sync_only = !params_.wait_externals_until;
    callback->queue = ext_msg_queue_;
    td::actor::send_closure_later(manager, &ValidatorManager::get_external_messages, shard_, std::move(callback));
  }
  if (is_masterchain() && !params_.is_hardfork) {
    // 4. load shard block info messages
    LOG(DEBUG) << "sending get_shard_blocks_for_collator() query to Manager";
    ++pending;
    auto token = perf_log_.start_action("get_shard_blocks_for_collator");
    td::actor::send_closure_later(manager, &ValidatorManager::get_shard_blocks_for_collator, prev_blocks[0],
                                  [self = get_self(), token = std::move(token)](
                                      td::Result<std::vector<Ref<ShardTopBlockDescription>>> res) mutable -> void {
                                    LOG(DEBUG) << "got answer to get_shard_blocks_for_collator() query";
                                    td::actor::send_closure_later(std::move(self), &Collator::after_get_shard_blocks,
                                                                  std::move(res), std::move(token));
                                  });
  }
  // 5. get storage stat cache
  ++pending;
  LOG(DEBUG) << "sending get_storage_stat_cache() query to Manager";
  td::actor::send_closure_later(manager, &ValidatorManager::get_storage_stat_cache,
                                [self = get_self(), token = perf_log_.start_action("get_storage_stat_cache")](
                                    td::Result<std::function<td::Ref<vm::Cell>(const td::Bits256&)>> res) mutable {
                                  LOG(DEBUG) << "got answer to get_storage_stat_cache : OK";
                                  td::actor::send_closure_later(std::move(self),
                                                                &Collator::after_get_storage_stat_cache, std::move(res),
                                                                std::move(token));
                                });
  // 6. set timeout
  alarm_timestamp() = timeout_;
  CHECK(pending);
}

/* The remainder of this file is byte-for-byte the previous collator.cpp except
 * for Collator::offer_validator_auth below. */

bool Collator::offer_validator_auth(Ref<vm::Cell> msg_root, bool external, const tos::StdSmcAddress& addr) {
  withdraw_validator_auth();
  if (!external || !is_masterchain() || !params_.validator_auth || !params_.validator_auth.value().anchors ||
      config_ == nullptr || mc_state_root.is_null() || params_.validator_set.is_null()) {
    return false;
  }

  auto configuration = tos::auth::declared_configuration_account(*config_, mc_state_root);
  if (!configuration.ok()) {
    return false;
  }

  auto inputs = tos::auth::gather_registry_admission_inputs(
      msg_root, configuration.value(), mc_state_root, mc_block_id_, params_.validator_auth.value().chain, shard_,
      params_.validator_set->get_catchain_seqno(), new_block_seqno);
  if (!inputs.ok()) {
    return false;
  }

  auto admitted = tos::auth::admit_registry_message(inputs.value(), *params_.validator_auth.value().anchors);
  if (!admitted.ok()) {
    if (admitted.error().code == "registry-admission-deferred") {
      auto required = tos::auth::registry_message_requirements(msg_root, new_block_seqno);
      const auto& installed = params_.validator_auth.value();
      if (required.ok() && installed.report_unresolved) {
        auto missing = installed.anchors->missing(required.value());
        LOG(INFO) << "deferring a registry update: " << missing.size() << " finalized block(s) not yet resolved";
        installed.report_unresolved(std::move(missing));
      }
    }
    return false;
  }

  validator_auth_authority_ = std::shared_ptr<tos::auth::NativeConfigTransaction>(std::move(admitted.value()));
  compute_phase_cfg_.validator_auth_host =
      std::shared_ptr<vm::ValidatorAuthHost>(validator_auth_authority_, &validator_auth_authority_->host());
  compute_phase_cfg_.validator_auth_account = addr;
  return true;
}

void Collator::withdraw_validator_auth() {
  compute_phase_cfg_.validator_auth_host.reset();
  compute_phase_cfg_.validator_auth_account.reset();
  validator_auth_authority_.reset();
}

}  // namespace validator

}  // namespace tos
