// Offline C04 candidate: real PQ Config34 genesis -> seqno-1 Merkle/proof.
#include <filesystem>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <vector>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "common/delay.h"
#include "quic/quic-sender.h"
#include "validator/downloaders/wait-block-data.hpp"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/check-proof.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/consensus/simplex/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "validator/consensus/chain-state.h"
#include "validator/consensus/manager-facade.h"
#include "validator/consensus/db-path.h"
#include "validator/pq-finality-verification.h"
#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"
#include "pq-block-signature-test-common.h"

using namespace tos;
using namespace tos::validator;
using pq_block_signature_test::require_ok;

extern char **environ;

namespace tos::validator {

class C04StaleConfig final : public ConfigHolder {
 public:
  explicit C04StaleConfig(td::Ref<block::ValidatorSet> set) : set_(std::move(set)) {
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int) const override { return set_; }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull, UnixTime, CatchainSeqno) const override { return set_; }
  std::pair<UnixTime, UnixTime> get_validator_set_start_stop(int) const override { return {0, 0x7fffffff}; }
  td::int32 get_global_id() const override { return 0; }
  td::Result<td::int32> get_config_global_id() const override { return 0; }
  ValidatorSessionConfig get_consensus_config() const override { return {}; }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId) const override { return {}; }

 private:
  td::Ref<block::ValidatorSet> set_;
};

class C04StaleState final : public MasterchainStateQ {
 public:
  C04StaleState(BlockIdExt id, td::Ref<block::ValidatorSet> set)
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm()), set_(std::move(set)) {
  }
  td::Result<td::Ref<ConfigHolder>> get_config_holder() const override {
    return td::Ref<ConfigHolder>{td::make_ref<C04StaleConfig>(set_)};
  }

 private:
  td::Ref<block::ValidatorSet> set_;
};

// Suppress only network-heavy Manager startup. The real DB actor and the
// production broadcast/proof/apply methods remain in the path.
class PendingFinalityManagerActorProbe final : public ValidatorManagerImpl {
 public:
  PendingFinalityManagerActorProbe(BlockIdExt zero_id, std::string root,
                                   std::shared_ptr<std::atomic<bool>> cut2_gate = {},
                                   std::optional<BlockIdExt> cut2_target = std::nullopt)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(zero_id, zero_id), std::move(root), {}, {}, {}, {}, {})
      , cut2_gate_(std::move(cut2_gate))
      , cut2_target_(std::move(cut2_target)) {
  }

  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("c04-ext-messages", opts_, actor_id(this));
  }

  // N03's controlled write-after gate is after production RootDb has returned
  // from set_block_signatures, but before this separate proof write begins.
  // Hold the AcceptBlock promise until this writer process exits; the resumed
  // process must re-enter the real AcceptBlock path from the journalled cert.
  void set_block_proof(BlockHandle handle, td::Ref<Proof> proof, td::Promise<td::Unit> promise) override {
    if (cut2_gate_ && cut2_target_ && handle->id() == *cut2_target_) {
      if (handle->inited_proof()) {
        return promise.set_error(td::Status::Error("N5 cut2 proof gate came after proof write"));
      }
      cut2_proof_promise_.emplace(std::move(promise));
      cut2_gate_->store(true, std::memory_order_release);
      std::cout << "N5_CUT2_BLOCKED_PROOF block=" << handle->id().to_str()
                << " signatures_flag=" << handle->inited_signatures() << '\n';
      return;
    }
    ValidatorManagerImpl::set_block_proof(std::move(handle), std::move(proof), std::move(promise));
  }

  void seed_zerostate(BlockIdExt zero_id, td::Ref<MasterchainStateQ> state, td::BufferSlice boc,
                      td::Promise<td::Unit> promise) {
    auto after_file = [self = actor_id(this), zero_id, state, promise = std::move(promise)](
                          td::Result<td::Unit> result) mutable {
      if (result.is_error()) {
        promise.set_error(result.move_as_error());
        return;
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::seed_zero_state_root, zero_id, state,
                              std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_zero_state_file, zero_id, std::move(boc),
                            td::PromiseCreator::lambda(std::move(after_file)));
  }

  void seed_zero_state_root(BlockIdExt zero_id, td::Ref<MasterchainStateQ> state, td::Promise<td::Unit> promise) {
    auto handle = create_empty_block_handle(zero_id);
    handle->set_logical_time(state->get_logical_time());
    handle->set_unix_time(state->get_unix_time());
    handle->set_split(false);
    handle->set_merge(false);
    handle->set_is_key_block(true);
    handle->set_applied();
    handle->set_applied_stored();
    handle->set_processed();
    last_masterchain_state_ = state;
    last_masterchain_block_id_ = zero_id;
    last_masterchain_block_handle_ = handle;
    last_key_block_handle_ = handle;
    last_known_key_block_handle_ = handle;
    auto on_state = [self = actor_id(this), handle, promise = std::move(promise)](
                        td::Result<td::Ref<ShardState>> result) mutable {
      if (result.is_error()) {
        promise.set_error(result.move_as_error());
        return;
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::store_zero_handle, handle, std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_block_state, handle, td::Ref<ShardState>{state}, vm::StoreCellHint{},
                            td::PromiseCreator::lambda(std::move(on_state)));
  }

  void store_zero_handle(BlockHandle handle, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::store_block_handle, std::move(handle), std::move(promise));
  }

  // Restart cut: re-establish the Manager's in-memory genesis pointers only
  // from RootDb. Unlike seed_zerostate this performs no DB write.
  void restore_zero_context(BlockIdExt zero_id, RootHash expected_root, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::get_block_handle, zero_id,
                            td::PromiseCreator::lambda(
        [self = actor_id(this), zero_id, expected_root, promise = std::move(promise)]
        (td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 restart genesis handle: "));
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::restore_zero_state,
                              zero_id, expected_root, result.move_as_ok(), std::move(promise));
    }));
  }

  void restore_zero_state(BlockIdExt zero_id, RootHash expected_root, BlockHandle handle,
                          td::Promise<td::Unit> promise) {
    if (handle->id() != zero_id || !handle->received_state() || !handle->is_applied() ||
        handle->state() != expected_root) {
      return promise.set_error(td::Status::Error("N5 restart genesis handle lacks cold state"));
    }
    td::actor::send_closure(db_, &Db::get_block_state, ConstBlockHandle{handle},
                            td::PromiseCreator::lambda(
        [self = actor_id(this), zero_id, expected_root, handle, promise = std::move(promise)]
        (td::Result<td::Ref<ShardState>> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 restart genesis state: "));
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::installed_zero_context,
                              zero_id, expected_root, handle, result.move_as_ok(), std::move(promise));
    }));
  }

  void installed_zero_context(BlockIdExt zero_id, RootHash expected_root, BlockHandle handle,
                              td::Ref<ShardState> state, td::Promise<td::Unit> promise) {
    if (state->root_hash() != expected_root) {
      return promise.set_error(td::Status::Error("N5 restart genesis state root differs from DB handle"));
    }
    last_masterchain_state_ = td::Ref<MasterchainState>{state};
    last_masterchain_block_id_ = zero_id;
    last_masterchain_block_handle_ = handle;
    last_key_block_handle_ = handle;
    last_known_key_block_handle_ = handle;
    std::cout << "N5_CUT1_MANAGER_RESTORED_FROM_ROOTDB root=" << expected_root.to_hex() << '\n';
    promise.set_value(td::Unit());
  }

  void broadcast_bad_then_good(BlockIdExt id, td::BufferSlice data, td::Ref<block::BlockSignatureSet> bad,
                               td::Ref<block::BlockSignatureSet> good, td::Promise<td::Unit> promise) {
    cached_masterchain_block_candidates_.put(id, std::move(data));
    const auto expiry = td::Time::now() + 10.0;
    auto first = pending_block_finality_.admit(
        id, PendingBlockFinalitySender::remote(PublicKeyHash{pq_block_signature_test::hash_of("C04-bad")}),
        PendingBlockFinalityCandidate{std::move(bad), BroadcastSource::consensus_overlay}, 4096,
        PendingFinalityCapacity::Shared, false, true, expiry);
    auto second = pending_block_finality_.admit(
        id, PendingBlockFinalitySender::remote(PublicKeyHash{pq_block_signature_test::hash_of("C04-good")}),
        PendingBlockFinalityCandidate{std::move(good), BroadcastSource::consensus_overlay}, 4096,
        PendingFinalityCapacity::Shared, false, true, expiry);
    if (!first.admitted() || !second.admitted() || !pending_block_finality_.get_if_exists(id) ||
        pending_block_finality_.get_if_exists(id)->size() != 2) {
      return promise.set_error(td::Status::Error("C04 bad-front/good-back queue was not admitted"));
    }
    std::cout << "C04_MANAGER_QUEUE_ADMITTED entries=2\n";
    try_process_pending_block_finality(id);
    await_queue_drained(id, td::Timestamp::in(5.0), std::move(promise));
  }

  void await_queue_drained(BlockIdExt id, td::Timestamp deadline, td::Promise<td::Unit> promise) {
    if (!pending_block_finality_.get_if_exists(id) && !cached_masterchain_block_candidates_.contains(id) &&
        last_masterchain_block_handle_ && last_masterchain_block_handle_->id() == id &&
        last_masterchain_block_handle_->processed()) {
      return promise.set_value(td::Unit());
    }
    if (deadline.is_in_past()) {
      auto *pending = pending_block_finality_.get_if_exists(id);
      std::cerr << "C04_MANAGER_QUEUE_TIMEOUT candidate_present="
                << cached_masterchain_block_candidates_.contains(id) << " pending_entries="
                << (pending ? pending->size() : 0) << " target_processed="
                << (last_masterchain_block_handle_ && last_masterchain_block_handle_->id() == id &&
                    last_masterchain_block_handle_->processed()) << '\n';
      return promise.set_error(td::Status::Error("C04 bad-front/good-back queue did not drain through apply"));
    }
    delay_action([self = actor_id(this), id, deadline, promise = std::move(promise)]() mutable {
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::await_queue_drained, id, deadline,
                              std::move(promise));
    }, td::Timestamp::in(0.01));
  }

  void start_stale_context_case(BlockIdExt id, td::BufferSlice data, td::Ref<block::BlockSignatureSet> good,
                                td::Ref<block::ValidatorSet> stale_set, td::Ref<MasterchainStateQ> real_state,
                                bool expire, td::Promise<td::Unit> promise) {
    if (expire) {
      // Admit through the real Manager coroutine while genesis context is
      // still available and before candidate bytes arrive. That coroutine
      // owns the production 60-second retention timer.
      new_block_finality_broadcast({id, good, 0}, BroadcastSource::consensus_overlay).start().detach();
      await_ingress_expiry_admission(id, std::move(data), std::move(good), std::move(stale_set),
                                    td::Timestamp::in(2.0), std::move(promise));
      return;
    }
    auto expected_data = data.clone();
    cached_masterchain_block_candidates_.put(id, std::move(data));
    last_masterchain_state_ = td::make_ref<C04StaleState>(id, std::move(stale_set));
    // The exact candidate/certificate/context triple must fail at the
    // trusted-context boundary, before any evidence-validity verdict.
    auto block = create_block(id, expected_data.clone());
    if (block.is_error()) {
      return promise.set_error(block.move_as_error());
    }
    PendingBlockProofFailureSource failure_source = PendingBlockProofFailureSource::BlockBytes;
    auto stale_proof = WaitBlockData::generate_proof(id, block.ok()->root_cell(), good,
                                                    last_masterchain_state_, failure_source);
    if (stale_proof.is_ok() || failure_source != PendingBlockProofFailureSource::TrustedContext) {
      return promise.set_error(td::Status::Error("C04 stale proof did not identify TrustedContext"));
    }
    std::cout << "C04_MANAGER_TRUSTED_CONTEXT_SOURCE_OK\n";
    const double expires_at = td::Time::now() + 10.0;
    auto admitted = pending_block_finality_.admit(
        id, PendingBlockFinalitySender::local_source(),
        PendingBlockFinalityCandidate{std::move(good), BroadcastSource::consensus_overlay}, 4096,
        PendingFinalityCapacity::Shared, false, true, expires_at);
    if (!admitted.admitted()) {
      return promise.set_error(td::Status::Error("C04 trusted-context evidence was not admitted"));
    }
    try_process_pending_block_finality(id);
    auto *pending = pending_block_finality_.get_if_exists(id);
    auto *cached = cached_masterchain_block_candidates_.get_if_exists(id);
    if (!pending || pending->size() != 1 || pending->processing() ||
        !cached || cached->as_slice() != expected_data.as_slice()) {
      return promise.set_error(td::Status::Error("C04 stale context did not retain evidence and block bytes"));
    }
    std::cout << "C04_MANAGER_STALE_RETAINED evidence=1 candidate=1\n";
    last_masterchain_state_ = std::move(real_state);
    delay_action([self = actor_id(this), id, promise = std::move(promise)]() mutable {
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::resume_stale_case, id, std::move(promise));
    }, td::Timestamp::in(0.1));
  }

  void await_ingress_expiry_admission(BlockIdExt id, td::BufferSlice data,
                                     td::Ref<block::BlockSignatureSet> good,
                                     td::Ref<block::ValidatorSet> stale_set,
                                     td::Timestamp deadline, td::Promise<td::Unit> promise) {
    auto *pending = pending_block_finality_.get_if_exists(id);
    if (!pending) {
      if (deadline.is_in_past()) {
        return promise.set_error(td::Status::Error("C04 Manager ingress did not admit finality"));
      }
      delay_action([self = actor_id(this), id, data = std::move(data), good = std::move(good),
                    stale_set = std::move(stale_set), deadline, promise = std::move(promise)]() mutable {
        td::actor::send_closure(self, &PendingFinalityManagerActorProbe::await_ingress_expiry_admission, id,
                                std::move(data), std::move(good), std::move(stale_set), deadline,
                                std::move(promise));
      }, td::Timestamp::in(0.01));
      return;
    }
    if (pending->size() != 1 || pending->processing()) {
      return promise.set_error(td::Status::Error("C04 Manager ingress admitted wrong evidence count"));
    }
    std::cout << "C04_MANAGER_INGRESS_ADMITTED evidence=1 retention_seconds="
              << pending_finality_retention_seconds << '\n';
    auto expected_data = data.clone();
    last_masterchain_state_ = td::make_ref<C04StaleState>(id, std::move(stale_set));
    cached_masterchain_block_candidates_.put(id, std::move(data));
    auto block = create_block(id, expected_data.clone());
    if (block.is_error()) {
      return promise.set_error(block.move_as_error());
    }
    PendingBlockProofFailureSource failure_source = PendingBlockProofFailureSource::BlockBytes;
    auto stale_proof = WaitBlockData::generate_proof(id, block.ok()->root_cell(), good,
                                                    last_masterchain_state_, failure_source);
    if (stale_proof.is_ok() || failure_source != PendingBlockProofFailureSource::TrustedContext) {
      return promise.set_error(td::Status::Error("C04 ingress expiry did not identify TrustedContext"));
    }
    // Keep the candidate bytes available without triggering proof processing:
    // otherwise the scheduled retry can lazily erase expired evidence before
    // the ingress timer, and the control measures only empty-map cleanup.
    auto *cached = cached_masterchain_block_candidates_.get_if_exists(id);
    if (!pending_block_finality_.get_if_exists(id) ||
        pending_block_finality_.get_if_exists(id)->size() != 1 || !cached ||
        cached->as_slice() != expected_data.as_slice()) {
      return promise.set_error(td::Status::Error("C04 ingress expiry lost evidence or candidate bytes"));
    }
    std::cout << "C04_MANAGER_INGRESS_TIMER_ONLY evidence=1 candidate_equal=1\n";
    delay_action([self = actor_id(this), id, expected_data = std::move(expected_data),
                  promise = std::move(promise)]() mutable {
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::finish_stale_expiry, id,
                              std::move(expected_data), std::move(promise));
    }, td::Timestamp::in(pending_finality_retention_seconds + 0.5));
  }

  void resume_stale_case(BlockIdExt id, td::Promise<td::Unit> promise) {
    // Do not retry manually: only the production scheduled retry can drain it.
    await_queue_drained(id, td::Timestamp::in(5.0), std::move(promise));
  }

  void finish_stale_expiry(BlockIdExt id, td::BufferSlice expected_data, td::Promise<td::Unit> promise) {
    auto *cached = cached_masterchain_block_candidates_.get_if_exists(id);
    auto *pending = pending_block_finality_.get_if_exists(id);
    const bool candidate_equal = cached && cached->as_slice() == expected_data.as_slice();
    const bool target_live = last_masterchain_block_handle_ && last_masterchain_block_handle_->id() == id;
    if (pending || !candidate_equal || target_live) {
      std::cerr << "C04_MANAGER_EXPIRY_FLAGS pending_present=" << (pending != nullptr)
                << " pending_entries=" << (pending ? pending->size() : 0)
                << " candidate_equal=" << candidate_equal << " target_live=" << target_live << '\n';
      return promise.set_error(td::Status::Error("C04 expiry changed block bytes or accepted target"));
    }
    std::cout << "C04_MANAGER_INGRESS_TIMER_EXPIRED\n";
    td::actor::send_closure(db_, &Db::get_block_handle, id,
                            td::PromiseCreator::lambda([promise = std::move(promise)](
                                                          td::Result<BlockHandle> result) mutable {
      if (result.is_ok() || result.error().code() != ErrorCode::notready) {
        return promise.set_error(td::Status::Error("C04 expired context produced a target DB handle"));
      }
      promise.set_value(td::Unit());
    }));
  }

  void verify_target_absent(BlockIdExt id, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::get_block_handle, id,
                            td::PromiseCreator::lambda([promise = std::move(promise)](
                                                          td::Result<BlockHandle> result) mutable {
      if (result.is_ok() || result.error().code() != ErrorCode::notready) {
        return promise.set_error(td::Status::Error("C04 cold DB unexpectedly contains expired target"));
      }
      promise.set_value(td::Unit());
    }));
  }

  void verify_persisted(BlockIdExt zero_id, BlockIdExt target_id, RootHash expected_root,
                        std::string expected_proof_hash, bool require_live, td::Promise<td::Unit> promise) {
    if (require_live && (!last_masterchain_block_handle_ || last_masterchain_block_handle_->id() != target_id ||
                         !last_masterchain_block_handle_->processed())) {
      return promise.set_error(td::Status::Error("Manager did not process target masterchain block"));
    }
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, target_id,
                            td::PromiseCreator::lambda(
                                [db, zero_id, target_id, expected_root, expected_proof_hash = std::move(expected_proof_hash),
                                 promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("DB target handle: "));
      }
      auto handle = result.move_as_ok();
      if (handle->id() != target_id || !handle->received() || !handle->inited_proof() ||
          !handle->received_state() || !handle->is_applied() || !handle->applied_stored() ||
          handle->state() != expected_root) {
        std::cerr << "C04_MANAGER_DB_FLAGS id=" << (handle->id() == target_id) << " received=" << handle->received()
                  << " proof=" << handle->inited_proof() << " state=" << handle->received_state()
                  << " applied=" << handle->is_applied() << " applied_stored=" << handle->applied_stored()
                  << " processed=" << handle->processed() << " root=" << handle->state().to_hex() << '\n';
        return promise.set_error(td::Status::Error("DB target handle lacks received/proof/state/applied flags or root"));
      }
      td::actor::send_closure(db, &Db::get_block_data, ConstBlockHandle{handle},
                              td::PromiseCreator::lambda(
                                  [db, zero_id, target_id, expected_root,
                                   expected_proof_hash = std::move(expected_proof_hash), handle = std::move(handle),
                                   promise = std::move(promise)](td::Result<td::Ref<BlockData>> result) mutable {
        if (result.is_error()) {
          return promise.set_error(result.move_as_error_prefix("DB target data: "));
        }
        if (result.ok()->block_id() != target_id || result.ok()->file_hash() != target_id.file_hash) {
          return promise.set_error(td::Status::Error("DB target data changed"));
        }
        td::actor::send_closure(db, &Db::get_block_proof, ConstBlockHandle{handle},
                                td::PromiseCreator::lambda(
                                    [db, zero_id, expected_root, expected_proof_hash = std::move(expected_proof_hash),
                                     handle = std::move(handle), promise = std::move(promise)](
                                        td::Result<td::Ref<Proof>> result) mutable {
          if (result.is_error()) {
            return promise.set_error(result.move_as_error_prefix("DB target proof: "));
          }
          if (block::compute_file_hash(result.ok()->data().as_slice()).to_hex() != expected_proof_hash) {
            return promise.set_error(td::Status::Error("DB target proof bytes changed"));
          }
          td::actor::send_closure(db, &Db::get_block_state, ConstBlockHandle{handle},
                                  td::PromiseCreator::lambda(
                                      [db, zero_id, target_id = handle->id(), expected_root, promise = std::move(promise)](
                                          td::Result<td::Ref<ShardState>> result) mutable {
            if (result.is_error()) {
              return promise.set_error(result.move_as_error_prefix("DB target state: "));
            }
            if (result.ok()->root_hash() != expected_root) {
              return promise.set_error(td::Status::Error("DB target state root changed"));
            }
            td::actor::send_closure(db, &Db::get_block_handle, zero_id,
                                    td::PromiseCreator::lambda(
                                        [target_id, promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
              if (result.is_error()) {
                return promise.set_error(result.move_as_error_prefix("DB predecessor handle: "));
              }
              if (!result.ok()->inited_next() || result.ok()->one_next(true) != target_id) {
                return promise.set_error(td::Status::Error("DB predecessor next does not identify target"));
              }
              promise.set_value(td::Unit());
            }));
          }));
        }));
      }));
    }));
  }

  void verify_n5_accept_cold(BlockIdExt zero_id, BlockIdExt target_id, RootHash expected_root,
                             td::Ref<block::ValidatorSet> vset, ValidatorSessionId session,
                             std::string expected_proof_hash,
                             std::vector<block::PQBlockSignature> expected_cert_signatures,
                             td::Promise<td::Unit> promise) {
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, target_id,
                            td::PromiseCreator::lambda(
        [db, zero_id, target_id, expected_root, vset, session,
         expected_proof_hash = std::move(expected_proof_hash),
         expected_cert_signatures = std::move(expected_cert_signatures), promise = std::move(promise)]
        (td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 cold handle: "));
      }
      auto handle = result.move_as_ok();
      if (handle->id() != target_id || !handle->received() || !handle->inited_signatures() ||
          !handle->inited_proof() || !handle->received_state() || !handle->is_applied() ||
          handle->state() != expected_root) {
        return promise.set_error(td::Status::Error("N5 cold handle lacks accepted signature/proof/state flags"));
      }
      // A completed AcceptBlock may move the short-lived signature file into
      // an archive, where RootDb::get_block_signatures deliberately refuses it.
      // The durable BlockProof carries the same PQ finality set; verify that
      // envelope from the cold process instead of treating its transient copy
      // as the persistence contract.
      td::actor::send_closure(db, &Db::get_block_proof, ConstBlockHandle{handle},
                                td::PromiseCreator::lambda(
            [db, handle, zero_id, target_id, expected_root, vset, session,
             expected_proof_hash = std::move(expected_proof_hash),
             expected_cert_signatures = std::move(expected_cert_signatures), promise = std::move(promise)]
            (td::Result<td::Ref<Proof>> result) mutable {
          if (result.is_error()) {
            return promise.set_error(result.move_as_error_prefix("N5 cold BlockProof: "));
          }
          if (block::compute_file_hash(result.ok()->data().as_slice()).to_hex() != expected_proof_hash) {
            return promise.set_error(td::Status::Error("N5 cold BlockProof bytes differ from writer"));
          }
          auto root = result.ok()->get_root_cell();
          if (root.is_error()) {
            return promise.set_error(root.move_as_error_prefix("N5 cold BlockProof root: "));
          }
          auto envelope = parse_block_proof_signature_envelope(root.move_as_ok());
          if (envelope.is_error() || envelope.ok().block_id != target_id ||
              envelope.ok().signatures.is_null() || !envelope.ok().signatures->is_pq()) {
            return promise.set_error(td::Status::Error("N5 cold BlockProof PQ envelope differs"));
          }
          auto proof_session = envelope.ok().signatures->pq_session_id();
          if (proof_session.is_error() || proof_session.ok() != session) {
            return promise.set_error(td::Status::Error("N5 cold BlockProof session differs"));
          }
          block::PQFinalityVerificationContext context{vset, target_id, session};
          auto verified = verify_pq_proof_signatures(context, *envelope.ok().signatures,
                                                     envelope.ok().claimed_weight);
          if (verified.is_error()) {
            return promise.set_error(verified.move_as_error_prefix("N5 cold BlockProof signatures: "));
          }
          if (!expected_cert_signatures.empty()) {
            auto carried = envelope.ok().signatures->export_pq_signatures();
            if (carried.is_error() || carried.ok().size() != expected_cert_signatures.size()) {
              return promise.set_error(td::Status::Error("N5 cold proof signer count differs from exact FinalCert"));
            }
            for (const auto &expected : expected_cert_signatures) {
              const auto match = std::find_if(carried.ok().begin(), carried.ok().end(),
                                              [&](const auto &actual) {
                return actual.validator_id == expected.validator_id &&
                       actual.algorithm_id == expected.algorithm_id &&
                       actual.signature.as_slice() == expected.signature.as_slice();
              });
              if (match == carried.ok().end()) {
                return promise.set_error(td::Status::Error("N5 cold proof signature bytes differ from exact FinalCert"));
              }
            }
            std::cout << "N5_JOINED_COLD_PROOF_SIGNATURES_MATCH count=" << carried.ok().size() << '\n';
          }
          td::actor::send_closure(db, &Db::get_block_state, ConstBlockHandle{handle},
                                  td::PromiseCreator::lambda(
              [db, handle, zero_id, target_id, expected_root, promise = std::move(promise)]
              (td::Result<td::Ref<ShardState>> result) mutable {
            if (result.is_error()) {
              return promise.set_error(result.move_as_error_prefix("N5 cold state: "));
            }
            if (result.ok()->root_hash() != expected_root) {
              return promise.set_error(td::Status::Error("N5 cold state root differs"));
            }
            td::actor::send_closure(db, &Db::get_block_data, ConstBlockHandle{handle},
                                    td::PromiseCreator::lambda(
                [db, zero_id, target_id, promise = std::move(promise)]
                (td::Result<td::Ref<BlockData>> result) mutable {
              if (result.is_error()) {
                return promise.set_error(result.move_as_error_prefix("N5 cold block data: "));
              }
              if (result.ok()->block_id() != target_id || result.ok()->file_hash() != target_id.file_hash) {
                return promise.set_error(td::Status::Error("N5 cold block bytes differ"));
              }
              td::actor::send_closure(db, &Db::get_block_handle, zero_id,
                                      td::PromiseCreator::lambda(
                  [target_id, promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
                if (result.is_error()) {
                  return promise.set_error(result.move_as_error_prefix("N5 cold predecessor: "));
                }
                if (!result.ok()->inited_next() || result.ok()->one_next(true) != target_id) {
                  return promise.set_error(td::Status::Error("N5 cold predecessor next differs"));
                }
                promise.set_value(td::Unit());
              }));
            }));
          }));
        }));
    }));
  }

  void n5_written_proof_hash(BlockIdExt id, td::Promise<std::string> promise) {
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, id,
                            td::PromiseCreator::lambda(
        [db, promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 writer handle: "));
      }
      auto handle = result.move_as_ok();
      if (!handle->inited_proof() || !handle->inited_signatures()) {
        return promise.set_error(td::Status::Error("N5 writer proof/signatures not initialized"));
      }
      td::actor::send_closure(db, &Db::get_block_proof, ConstBlockHandle{handle},
                              td::PromiseCreator::lambda(
          [promise = std::move(promise)](td::Result<td::Ref<Proof>> result) mutable {
        if (result.is_error()) {
          return promise.set_error(result.move_as_error_prefix("N5 writer BlockProof: "));
        }
        promise.set_value(block::compute_file_hash(result.ok()->data().as_slice()).to_hex());
      }));
    }));
  }

  void verify_n5_cut2_signatures(BlockIdExt target_id,
                                 std::vector<block::PQBlockSignature> expected,
                                 td::Promise<td::Unit> promise) {
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, target_id,
                            td::PromiseCreator::lambda(
        [db, target_id, expected = std::move(expected), promise = std::move(promise)]
        (td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 cut2 cold handle: "));
      }
      auto handle = result.move_as_ok();
      if (handle->id() != target_id || !handle->received() || !handle->inited_signatures() ||
          handle->inited_proof() || handle->is_applied() || handle->moved_to_archive()) {
        return promise.set_error(td::Status::Error("N5 cut2 cold handle did not stop between #13 and proof"));
      }
      td::actor::send_closure(db, &Db::get_block_signatures, ConstBlockHandle{handle},
                              td::PromiseCreator::lambda(
          [db, handle, expected = std::move(expected), promise = std::move(promise)]
          (td::Result<td::Ref<block::BlockSignatureSet>> result) mutable {
        if (result.is_error()) {
          return promise.set_error(result.move_as_error_prefix("N5 cut2 cold #13: "));
        }
        if (!result.ok()->is_pq()) {
          return promise.set_error(td::Status::Error("N5 cut2 cold #13 is not PQ"));
        }
        auto carried = result.ok()->export_pq_signatures();
        if (carried.is_error() || carried.ok().size() != expected.size()) {
          return promise.set_error(td::Status::Error("N5 cut2 cold #13 signer count differs from FinalCert"));
        }
        for (const auto &signature : expected) {
          const auto match = std::find_if(carried.ok().begin(), carried.ok().end(),
                                          [&](const auto &actual) {
            return actual.validator_id == signature.validator_id &&
                   actual.algorithm_id == signature.algorithm_id &&
                   actual.signature.as_slice() == signature.signature.as_slice();
          });
          if (match == carried.ok().end()) {
            return promise.set_error(td::Status::Error("N5 cut2 cold #13 bytes differ from FinalCert"));
          }
        }
        const auto count = carried.ok().size();
        td::actor::send_closure(db, &Db::get_block_proof, ConstBlockHandle{handle},
                                td::PromiseCreator::lambda(
            [count, promise = std::move(promise)](td::Result<td::Ref<Proof>> result) mutable {
          if (result.is_ok() || result.error().code() != ErrorCode::notready) {
            return promise.set_error(td::Status::Error("N5 cut2 cold BlockProof was not specifically absent"));
          }
          std::cout << "N5_CUT2_COLD_SIGNATURES_MATCH count=" << count
                    << " proof=notready" << '\n';
          promise.set_value(td::Unit());
        }));
      }));
    }));
  }

 private:
  std::shared_ptr<std::atomic<bool>> cut2_gate_;
  std::optional<BlockIdExt> cut2_target_;
  std::optional<td::Promise<td::Unit>> cut2_proof_promise_;
};

// The production Bridge owns an anonymous ManagerFacadeImpl. Keep this test
// adapter narrow: BlockAccepter still calls its real accept_block request and
// the adapter forwards it to the same production AcceptBlock query and real
// Manager/RootDb. It does not simulate a successful acceptance.
class N5AcceptFacade final : public consensus::ManagerFacade {
 public:
  N5AcceptFacade(td::actor::ActorId<ValidatorManager> manager, td::Ref<block::ValidatorSet> set,
                 std::shared_ptr<std::atomic<bool>> cut3_gate = {},
                 std::optional<BlockIdExt> cut3_target = std::nullopt,
                 std::shared_ptr<std::atomic<unsigned>> accept_calls = {})
      : manager_(manager), set_(std::move(set)), cut3_gate_(std::move(cut3_gate)),
        cut3_target_(std::move(cut3_target)), accept_calls_(std::move(accept_calls)) {
  }

  td::actor::Task<GeneratedCandidate> collate_block(
      CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("N5 fixture does not collate");
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(
      BlockCandidate, ValidateParams, td::Timestamp) override {
    co_return td::Status::Error("N5 fixture does not validate candidates");
  }

  td::actor::Task<> accept_block(BlockIdExt id, td::Ref<BlockData> data, size_t,
                                  td::Ref<block::BlockSignatureSet> signatures,
                                  ValidatorSessionId session, int block_mode, int finality_mode,
                                  bool send_desc, bool apply) override {
    if (accept_calls_) {
      accept_calls_->fetch_add(1, std::memory_order_relaxed);
    }
    auto [task, promise] = td::actor::StartedTask<>::make_bridge();
    run_accept_block_query(id, data, {}, set_, signatures, session, block_mode,
                           finality_mode, send_desc, apply, manager_, std::move(promise));
    co_await std::move(task);
    if (cut3_gate_ && cut3_target_ && id == *cut3_target_) {
      if (cut3_cancelled_) {
        co_return td::Status::Error(ErrorCode::cancelled, "N5 cut3 controlled stop");
      }
      // StateResolver cannot write its marker until FinalizeBlock returns.
      // Hold only this test facade's response after production AcceptBlock.
      auto [held, held_promise] = td::actor::StartedTask<>::make_bridge();
      cut3_promise_.emplace(std::move(held_promise));
      cut3_gate_->store(true, std::memory_order_release);
      std::cout << "N5_CUT3_ACCEPT_BLOCK_RETURN_HELD block=" << id.to_str() << '\n';
      co_await std::move(held);
    }
    co_return td::Unit{};
  }

  void cancel_cut3(td::Promise<td::Unit> acknowledged) {
    cut3_cancelled_ = true;
    if (cut3_promise_) {
      cut3_promise_->set_error(td::Status::Error(ErrorCode::cancelled, "N5 cut3 controlled stop"));
      cut3_promise_.reset();
    }
    acknowledged.set_value(td::Unit());
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(
      BlockIdExt id, td::Timestamp timeout, std::optional<consensus::CandidateId>) override {
    auto state = co_await td::actor::ask(manager_, &ValidatorManager::wait_block_state_short,
                                         id, 0, timeout, false);
    co_return state->root_cell();
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt id, td::Timestamp timeout) override {
    co_return co_await td::actor::ask(manager_, &ValidatorManager::wait_block_data_short,
                                      id, 0, timeout);
  }

 private:
  td::actor::ActorId<ValidatorManager> manager_;
  td::Ref<block::ValidatorSet> set_;
  std::shared_ptr<std::atomic<bool>> cut3_gate_;
  std::optional<BlockIdExt> cut3_target_;
  std::optional<td::Promise<td::Unit>> cut3_promise_;
  bool cut3_cancelled_ = false;
  std::shared_ptr<std::atomic<unsigned>> accept_calls_;
};

}  // namespace tos::validator

namespace {

namespace sx = tos::validator::consensus::simplex;

struct N5ReplayState {
  consensus::CandidateId expected_id;
  td::Bits256 expected_cert_hash;
  std::atomic<unsigned> observed{0};
  std::atomic<bool> mismatch{false};
};

// Runtime creates event subscribers with a default constructor. This pointer
// is confined to one short-lived cold child process and one scheduler.
std::shared_ptr<N5ReplayState> n5_replay_state;

class N5ReplayObserver final : public td::actor::SpawnsWith<sx::Bus>, public td::actor::ConnectsTo<sx::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(sx::BusHandle, std::shared_ptr<const consensus::StopRequested>) {
    stop();
  }

  template <>
  void handle(sx::BusHandle, std::shared_ptr<const sx::FinalizationObserved> event) {
    if (!n5_replay_state) {
      return;
    }
    auto cert_tl = serialize_tl_object(event->certificate->to_tl(), true);
    if (event->id != n5_replay_state->expected_id ||
        event->certificate->vote.id != n5_replay_state->expected_id ||
        sha256_bits256(cert_tl.as_slice()) != n5_replay_state->expected_cert_hash) {
      n5_replay_state->mismatch.store(true, std::memory_order_release);
    }
    n5_replay_state->observed.fetch_add(1, std::memory_order_release);
  }
};

std::shared_ptr<sx::Bus> n5_joined_bus(td::Ref<block::ValidatorSet> set,
                                        ValidatorSessionId session,
                                        td::actor::ActorId<consensus::ManagerFacade> facade,
                                        const std::string &journal_path) {
  auto bus = std::make_shared<sx::Bus>();
  bus->session_id = session;
  bus->shard = ShardIdFull{masterchainId};
  bus->manager = facade;
  bus->cc_seqno = set->get_catchain_seqno();
  bus->validator_set_hash = set->get_validator_set_hash();
  bus->config.protocol_version = 2;
  bus->config.slots_per_leader_window = 4;
  bus->validator_opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  for (const auto &descriptor : set->export_vector()) {
    pq::ConsensusPQKey key;
    key.algorithm_id = static_cast<pq::PQAlgorithmId>(descriptor.algorithm_id);
    std::memcpy(key.key_id.data(), descriptor.key_id.value.data(), 32);
    key.public_key = descriptor.pq_public_key;
    const auto adnl_id = adnl::AdnlNodeIdShort{block::validator_adnl_identity(descriptor)};
    bus->validator_set.push_back(consensus::PeerValidator{
        .validator_id = descriptor.validator_id,
        .idx = consensus::PeerValidatorId{bus->validator_set.size()},
        .consensus_key = std::move(key),
        .transport_key_id = adnl_id.pubkey_hash(),
        .adnl_id = adnl_id,
        .weight = descriptor.weight,
    });
    bus->all_validators.push_back(adnl_id);
    CHECK(tos::checked_add_validator_weight(bus->total_weight, descriptor.weight));
  }
  bus->local_id = bus->validator_set.front();
  bus->local_adnl_id = bus->local_id->adnl_id;
  bus->db = consensus::open_rocksdb_consensus_db(journal_path);
  return bus;
}

template <typename V>
td::Result<td::Ref<sx::Certificate<V>>> n5_joined_cert(V vote, const sx::Bus &bus,
                                                        const pq_block_signature_test::Fixture &keys) {
  auto unsigned_vote = serialize_tl_object(vote.to_tl(), true);
  auto envelope = create_serialize_tl_object<tos_api::consensus_dataToSign>(bus.session_id,
                                                                              unsigned_vote.clone());
  std::vector<sx::tl::VoteSignatureRef> signatures;
  for (size_t index = 0; index < 3; ++index) {
    const auto &validator = bus.validator_set[index];
    auto key_index = std::find(keys.validator_ids.begin(), keys.validator_ids.end(), validator.validator_id);
    if (key_index == keys.validator_ids.end()) {
      return td::Status::Error("N5 joined cert signer is not in Config34 fixture");
    }
    auto signed_vote = keys.stores[static_cast<size_t>(key_index - keys.validator_ids.begin())].sign_consensus(
        std::string_view(envelope.data(), envelope.size()));
    if (!signed_vote) {
      return td::Status::Error("N5 joined cert signing failed");
    }
    signatures.push_back(create_tl_object<sx::tl::voteSignature>(static_cast<int>(index),
                                                                  td::BufferSlice(signed_vote->signature)));
  }
  auto set = create_tl_object<sx::tl::voteSignatureSet>(std::move(signatures));
  return sx::Certificate<V>::from_tl(std::move(*set), vote, bus);
}

class N5JoinedPublisher final : public td::actor::Actor {
 public:
  void publish(sx::BusHandle bus, consensus::CandidateRef candidate, sx::NotarCertRef notar,
               sx::FinalCertRef final, bool cut_after_journal,
               std::shared_ptr<std::atomic<bool>> cut_after_signatures,
               std::shared_ptr<std::atomic<bool>> cut_after_proof,
               td::Promise<td::Unit> promise) {
    publish_inner(std::move(bus), std::move(candidate), std::move(notar), std::move(final),
                  cut_after_journal, std::move(cut_after_signatures), std::move(cut_after_proof),
                  std::move(promise)).start().detach();
  }

 private:
  td::actor::Task<> publish_inner(sx::BusHandle bus, consensus::CandidateRef candidate,
                                   sx::NotarCertRef notar, sx::FinalCertRef final,
                                   bool cut_after_journal,
                                   std::shared_ptr<std::atomic<bool>> cut_after_signatures,
                                   std::shared_ptr<std::atomic<bool>> cut_after_proof,
                                   td::Promise<td::Unit> promise) {
    const auto id = candidate->id;
    auto stored = co_await bus.publish<sx::StoreCandidate>(candidate).wrap();
    if (stored.is_error()) {
      promise.set_error(stored.move_as_error_prefix("N5 StoreCandidate: "));
      co_return td::Unit{};
    }
    const auto source = bus->validator_set.front().adnl_id;
    bus.publish<consensus::IncomingProtocolMessage>(std::nullopt, source, notar->serialize());
    auto resolved = co_await bus.publish<sx::ResolveCandidate>(id).wrap();
    if (resolved.is_error() || resolved.ok().candidate->id != id || resolved.ok().notar->vote.id != id) {
      promise.set_error(td::Status::Error("N5 Pool notar certificate did not make exact candidate resolvable"));
      co_return td::Unit{};
    }
    const auto final_hash = sha256_bits256(serialize_tl_object(final->to_tl(), true));
    bus.publish<consensus::IncomingProtocolMessage>(std::nullopt, source, final->serialize());
    auto marker = create_serialize_tl_object<tos_api::consensus_simplex_db_key_finalizedBlock>(id.to_tl());
    auto cert_key = create_serialize_tl_object<tos_api::consensus_simplex_db_key_vote>(final_hash);
    const auto deadline = td::Timestamp::in(30.0);
    while (!deadline.is_in_past()) {
      if (cut_after_proof && cut_after_proof->load(std::memory_order_acquire)) {
        auto saved = co_await bus->db->get_latest(cert_key.clone()).wrap();
        auto finalized = co_await bus->db->get_latest(marker.clone()).wrap();
        if (saved.is_error() || !saved.ok().has_value() || finalized.is_error() ||
            finalized.ok().has_value()) {
          promise.set_error(td::Status::Error("N5 cut3 proof gate lacks cert journal or already has marker"));
          co_return td::Unit{};
        }
        auto closed = co_await bus->db->close().wrap();
        if (closed.is_error()) {
          promise.set_error(closed.move_as_error_prefix("N5 cut3 journal close: "));
          co_return td::Unit{};
        }
        std::cout << "N5_CUT3_PROOF_WRITTEN_BEFORE_MARKER cert=" << final_hash.to_hex() << '\n';
        promise.set_value(td::Unit());
        co_return td::Unit{};
      }
      if (cut_after_signatures && cut_after_signatures->load(std::memory_order_acquire)) {
        auto saved = co_await bus->db->get_latest(cert_key.clone()).wrap();
        auto finalized = co_await bus->db->get_latest(marker.clone()).wrap();
        if (saved.is_error() || !saved.ok().has_value() || finalized.is_error() ||
            finalized.ok().has_value()) {
          promise.set_error(td::Status::Error("N5 cut2 gate lacks cert journal or already has marker"));
          co_return td::Unit{};
        }
        auto closed = co_await bus->db->close().wrap();
        if (closed.is_error()) {
          promise.set_error(closed.move_as_error_prefix("N5 cut2 journal close: "));
          co_return td::Unit{};
        }
        std::cout << "N5_CUT2_SIGNATURES_WRITTEN_BEFORE_PROOF cert=" << final_hash.to_hex() << '\n';
        promise.set_value(td::Unit());
        co_return td::Unit{};
      }
      if (cut_after_journal) {
        auto saved = co_await bus->db->get_latest(cert_key.clone()).wrap();
        if (saved.is_error()) {
          promise.set_error(saved.move_as_error_prefix("N5 cut1 FinalCert journal: "));
          co_return td::Unit{};
        }
        if (saved.ok().has_value()) {
          auto too_late = co_await bus->db->get_latest(marker.clone());
          if (too_late.has_value()) {
            promise.set_error(td::Status::Error("N5 cut1 unexpectedly passed finalized marker"));
            co_return td::Unit{};
          }
          auto closed = co_await bus->db->close().wrap();
          if (closed.is_error()) {
            promise.set_error(closed.move_as_error_prefix("N5 cut1 journal close: "));
            co_return td::Unit{};
          }
          std::cout << "N5_CUT1_FINALCERT_SAVED_BEFORE_MARKER hash=" << final_hash.to_hex() << '\n';
          promise.set_value(td::Unit());
          co_return td::Unit{};
        }
      }
      auto present = co_await bus->db->get_latest(marker.clone()).wrap();
      if (present.is_error()) {
        promise.set_error(present.move_as_error_prefix("N5 finalized marker: "));
        co_return td::Unit{};
      }
      if (present.ok().has_value()) {
        if (cut_after_proof) {
          promise.set_error(td::Status::Error("N5 cut3 marker preceded the post-AcceptBlock proof gate"));
          co_return td::Unit{};
        }
        auto closed = co_await bus->db->close().wrap();
        if (closed.is_error()) {
          promise.set_error(closed.move_as_error_prefix("N5 consensus journal close: "));
          co_return td::Unit{};
        }
        promise.set_value(td::Unit());
        co_return td::Unit{};
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
    }
    promise.set_error(td::Status::Error(std::string(cut_after_journal
                                            ? "N5 cut1 FinalCert journal was not written"
                                            : "N5 same FinalCert did not reach finalized marker")));
    co_return td::Unit{};
  }
};

class N5RestartMarkerWaiter final : public td::actor::Actor {
 public:
  void await_replay(sx::BusHandle bus, consensus::CandidateId id, td::Promise<td::Unit> promise) {
    await_inner(std::move(bus), id, std::move(promise)).start().detach();
  }

 private:
  td::actor::Task<> await_inner(sx::BusHandle bus, consensus::CandidateId id,
                                 td::Promise<td::Unit> promise) {
    auto marker = create_serialize_tl_object<tos_api::consensus_simplex_db_key_finalizedBlock>(id.to_tl());
    const auto deadline = td::Timestamp::in(30.0);
    while (!deadline.is_in_past()) {
      auto found = co_await bus->db->get_latest(marker.clone()).wrap();
      if (found.is_error()) {
        promise.set_error(found.move_as_error_prefix("N5 cut1 replay marker: "));
        co_return td::Unit{};
      }
      if (found.ok().has_value()) {
        auto closed = co_await bus->db->close().wrap();
        if (closed.is_error()) {
          promise.set_error(closed.move_as_error_prefix("N5 cut1 replay journal close: "));
          co_return td::Unit{};
        }
        std::cout << "N5_CUT1_BOOTSTRAP_FINALCERT_REACHED_MARKER slot=" << id.slot
                  << " candidate_hash=" << id.hash.to_hex() << '\n';
        promise.set_value(td::Unit());
        co_return td::Unit{};
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
    }
    promise.set_error(td::Status::Error("N5 cut1 bootstrap FinalCert did not reach marker"));
    co_return td::Unit{};
  }
};

bool n5_cold_joined_journal(const std::string &path, ValidatorSessionId session,
                             td::Ref<block::ValidatorSet> set, consensus::CandidateId id,
                             td::Slice expected_cert, bool expect_marker,
                             std::vector<block::PQBlockSignature> &expected_signatures) {
  td::actor::Scheduler scheduler({1});
  bool matched = false;
  scheduler.run_in_context([&] {
    auto bus = n5_joined_bus(set, session, {}, path);
    const auto hash = sha256_bits256(expected_cert);
    auto cert_key = create_serialize_tl_object<tos_api::consensus_simplex_db_key_vote>(hash);
    auto saved = bus->db->get(cert_key.as_slice());
    if (!saved) {
      std::cerr << "N5_JOINED_COLD_FAILED: exact FinalCert journal key absent\n";
      return;
    }
    auto wrapper = fetch_tl_object<tos_api::consensus_simplex_db_cert>(*saved, true);
    if (wrapper.is_error() || !wrapper.ok()->cert_) {
      std::cerr << "N5_JOINED_COLD_FAILED: FinalCert journal value is not db_cert\n";
      return;
    }
    auto original = serialize_tl_object(wrapper.ok()->cert_, true);
    if (original.as_slice() != expected_cert) {
      std::cerr << "N5_JOINED_COLD_FAILED: FinalCert TL changed across restart\n";
      return;
    }
    auto verified = sx::Certificate<sx::Vote>::from_tl(std::move(*wrapper.ok()->cert_), *bus);
    if (verified.is_error() || !std::holds_alternative<sx::FinalizeVote>(verified.ok()->vote.vote) ||
        std::get<sx::FinalizeVote>(verified.ok()->vote.vote).id != id) {
      std::cerr << "N5_JOINED_COLD_FAILED: exact FinalCert fails production verification\n";
      return;
    }
    for (const auto &item : verified.ok()->signatures) {
      if (item.validator.value() >= bus->validator_set.size()) {
        std::cerr << "N5_JOINED_COLD_FAILED: FinalCert signer index outside Config34\n";
        return;
      }
      const auto &descriptor = bus->validator_set[item.validator.value()];
      expected_signatures.push_back(block::PQBlockSignature{
          descriptor.validator_id, descriptor.consensus_key.algorithm_id, item.signature.clone()});
    }
    auto marker_key = create_serialize_tl_object<tos_api::consensus_simplex_db_key_finalizedBlock>(id.to_tl());
    if (bus->db->get(marker_key.as_slice()).has_value() != expect_marker) {
      std::cerr << "N5_JOINED_COLD_FAILED: exact finalized marker has wrong presence\n";
      return;
    }
    matched = true;
    std::cout << (expect_marker ? "N5_JOINED_COLD_JOURNAL_MARKER_OK" : "N5_CUT1_COLD_JOURNAL_NO_MARKER_OK")
              << " slot=" << id.slot
              << " candidate_hash=" << id.hash.to_hex() << " finalcert_hash=" << hash.to_hex() << '\n';
  });
  scheduler.run(0.01);
  scheduler.stop();
  return matched;
}

}  // namespace

int main(int argc, char **argv) {
  const bool n5_accept = argc == 3 && std::string_view(argv[1]) == "--n5-accept";
  const bool n5_joined = argc == 3 && std::string_view(argv[1]) == "--n5-joined";
  const bool n5_cut1 = argc == 3 && std::string_view(argv[1]) == "--n5-cut1";
  const bool n5_cut2 = argc == 3 && std::string_view(argv[1]) == "--n5-cut2";
  const bool n5_cut3 = argc == 3 && std::string_view(argv[1]) == "--n5-cut3";
  const bool n5_cut4 = argc == 3 && std::string_view(argv[1]) == "--n5-cut4";
  const bool n5_joined_reopen = argc == 6 &&
      (std::string_view(argv[1]) == "--n5-joined-reopen" ||
       std::string_view(argv[1]) == "--n5-joined-reopen-bad-signature");
  const bool n5_cut1_reopen = argc == 5 && std::string_view(argv[1]) == "--n5-cut1-reopen";
  const bool n5_cut2_reopen = argc == 5 && std::string_view(argv[1]) == "--n5-cut2-reopen";
  const bool n5_cut3_reopen = argc == 6 && std::string_view(argv[1]) == "--n5-cut3-reopen";
  const bool n5_cut1_resume = argc == 5 && std::string_view(argv[1]) == "--n5-cut1-resume";
  const bool n5_cut2_resume = argc == 5 && std::string_view(argv[1]) == "--n5-cut2-resume";
  const bool n5_cut3_resume = argc == 5 && std::string_view(argv[1]) == "--n5-cut3-resume";
  const bool n5_cut4_resume = argc == 6 && std::string_view(argv[1]) == "--n5-cut4-resume";
  const bool n5_reopen = argc == 5 && (std::string_view(argv[1]) == "--n5-reopen" ||
                                           std::string_view(argv[1]) == "--n5-reopen-bad-hash" ||
                                           std::string_view(argv[1]) == "--n5-reopen-absent");
  const bool reopen = argc == 5 && (std::string_view(argv[1]) == "--reopen" ||
                                      std::string_view(argv[1]) == "--reopen-absent");
  if (!(argc == 2 || reopen || n5_accept || n5_joined || n5_cut1 || n5_cut2 || n5_cut3 || n5_cut4 ||
        n5_cut1_reopen || n5_cut2_reopen || n5_cut3_reopen ||
        n5_cut1_resume || n5_cut2_resume || n5_cut3_resume || n5_cut4_resume ||
        n5_reopen || n5_joined_reopen)) {
    std::cerr << "usage: c04-real-state-proof-test GENESIS_BOC | --n5-accept|--n5-joined|--n5-cut1|--n5-cut2|--n5-cut3|--n5-cut4 GENESIS_BOC | --n5-reopen GENESIS_BOC DB_ROOT PROOF_HASH | --reopen[|-absent] GENESIS_BOC DB_ROOT PROOF_HASH\n";
    return 2;
  }
  std::ifstream input((reopen || n5_accept || n5_joined || n5_cut1 || n5_cut2 || n5_cut3 || n5_cut4 ||
                       n5_cut1_reopen || n5_cut2_reopen || n5_cut3_reopen ||
                       n5_cut1_resume || n5_cut2_resume || n5_cut3_resume || n5_cut4_resume ||
                       n5_reopen || n5_joined_reopen) ? argv[2] : argv[1], std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis read\n";
    return 1;
  }
  td::BufferSlice boc{bytes.str()};
  auto root0 = require_ok(vm::std_boc_deserialize(boc.as_slice()), "genesis BOC");
  auto id0 = BlockIdExt{masterchainId, shardIdAll, 0, td::Bits256(root0->get_hash().bits()),
                        block::compute_file_hash(boc)};
  auto state0 = require_ok(MasterchainStateQ::fetch(id0, boc.clone(), root0), "genesis state fetch");
  block::gen::ShardStateUnsplit::Record record;
  if (!block::gen::t_ShardStateUnsplit.cell_unpack(root0, record) || record.seq_no != 0) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis header\n";
    return 1;
  }
  pq_block_signature_test::Fixture keys;
  auto target_time = record.gen_utime + 1;
  constexpr CatchainSeqno cc = 0;
  auto vset = state0->get_validator_set(ShardIdFull{masterchainId}, target_time, cc);
  if (vset.is_null() || vset->export_vector().size() != 4) {
    std::cerr << "C04_REAL_STATE_FAILED: Config34 validator set\n";
    return 1;
  }
  auto nodes = vset->export_vector();
  for (size_t i = 0; i < keys.validator_ids.size(); ++i) {
    auto node = vset->get_validator(keys.validator_ids[i]);
    if (!node || !node->is_pq() || node->pq_public_key != keys.stores[i].consensus_key().public_key ||
        node->weight != 17) {
      std::cerr << "C04_REAL_STATE_FAILED: Config34 signer mismatch index=" << i << "\n";
      return 1;
    }
  }
  // A post-genesis masterchain state must record the zerostate in OldMcBlocks.
  auto custom_root = record.custom->prefetch_ref();
  block::gen::McStateExtra::Record mc_state_extra;
  if (custom_root.is_null() || !block::gen::t_McStateExtra.cell_unpack(custom_root, mc_state_extra)) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis McStateExtra unpack\n";
    return 1;
  }
  vm::AugmentedDictionary old_blocks(mc_state_extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo);
  vm::CellBuilder zero_ref;
  zero_ref.store_bool_bool(true);
  zero_ref.store_long(0, 64).store_long(0, 32).store_bits(id0.root_hash.cbits(), 256)
      .store_bits(id0.file_hash.cbits(), 256);
  if (!old_blocks.set_builder(td::BitArray<32>::zero(), zero_ref)) {
    std::cerr << "C04_REAL_STATE_FAILED: OldMcBlocks insert\n";
    return 1;
  }
  mc_state_extra.r1.prev_blocks = old_blocks.get_root();
  td::Ref<vm::Cell> new_custom_root;
  if (!block::gen::t_McStateExtra.cell_pack(new_custom_root, mc_state_extra)) {
    std::cerr << "C04_REAL_STATE_FAILED: McStateExtra repack\n";
    return 1;
  }
  vm::CellBuilder custom_ref;
  custom_ref.store_bool_bool(true);
  custom_ref.store_ref_bool(new_custom_root);
  record.custom = custom_ref.as_cellslice_ref();
  record.seq_no = 1;
  record.gen_utime = target_time;
  record.gen_lt += 1000;
  td::Ref<vm::Cell> root1;
  if (!block::gen::t_ShardStateUnsplit.cell_pack(root1, record)) {
    std::cerr << "C04_REAL_STATE_FAILED: state1 pack\n";
    return 1;
  }
  auto update = vm::CellBuilder::create_merkle_update(root0, root1);
  auto applied = require_ok(vm::MerkleUpdate::apply(root0, update, nullptr), "seq0-to-seq1 Merkle apply");
  if (applied->get_hash() != root1->get_hash()) {
    std::cerr << "C04_REAL_STATE_FAILED: Merkle new root mismatch\n";
    return 1;
  }
  auto wrong_old_root = vm::CellBuilder{}.store_long(123, 32).finalize_novm();
  if (vm::MerkleUpdate::apply(wrong_old_root, update, nullptr).is_ok()) {
    std::cerr << "C04_REAL_STATE_FAILED: wrong Merkle predecessor was accepted\n";
    return 1;
  }
  auto state1_boc = require_ok(vm::std_boc_serialize(root1, 31), "state1 BOC");
  auto id1_state = BlockIdExt{masterchainId, shardIdAll, 1, td::Bits256(root1->get_hash().bits()),
                              block::compute_file_hash(state1_boc)};
  require_ok(MasterchainStateQ::fetch(id1_state, state1_boc.clone(), root1), "state1 fetch");
  std::cout << "C04_REAL_STATE_OK config34_hash=" << vset->get_validator_set_hash()
            << " old=" << root0->get_hash().bits().to_hex(256)
            << " new=" << root1->get_hash().bits().to_hex(256) << '\n';

  block::gen::BlockInfo::Record info{};
  info.version = 0;
  info.not_master = false;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = 1;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{ShardIdFull{masterchainId}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = target_time;
  info.start_lt = record.gen_lt - 1;
  info.end_lt = record.gen_lt;
  info.gen_validator_list_hash_short = vset->get_validator_set_hash();
  info.gen_catchain_seqno = cc;
  info.min_ref_mc_seqno = 0;
  info.prev_key_block_seqno = 0;
  vm::CellBuilder prev_ref;
  prev_ref.store_long(0, 64).store_long(0, 32).store_bits(id0.root_hash.cbits(), 256)
      .store_bits(id0.file_hash.cbits(), 256);
  info.prev_ref = prev_ref.finalize_novm();
  td::Ref<vm::Cell> info_cell;
  if (!block::gen::t_BlockInfo.cell_pack(info_cell, info)) {
    std::cerr << "C04_REAL_PROOF_FAILED: BlockInfo pack\n";
    return 1;
  }
  vm::CellBuilder empty_builder;
  empty_builder.store_bool_bool(false);
  auto empty = empty_builder.finalize_novm();
  vm::CellBuilder empty_fees_builder;
  empty_fees_builder.store_zeroes(11);
  auto empty_fees = empty_fees_builder.finalize_novm();
  block::gen::McBlockExtra::Record mc_extra{};
  mc_extra.key_block = false;
  mc_extra.shard_hashes = vm::load_cell_slice_ref(empty);
  mc_extra.shard_fees = vm::load_cell_slice_ref(empty_fees);
  mc_extra.r1.prev_blk_signatures = vm::load_cell_slice_ref(empty);
  mc_extra.r1.recover_create_msg = vm::load_cell_slice_ref(empty);
  mc_extra.r1.mint_msg = vm::load_cell_slice_ref(empty);
  td::Ref<vm::Cell> mc_extra_cell;
  if (!block::gen::t_McBlockExtra.cell_pack(mc_extra_cell, mc_extra)) {
    std::cerr << "C04_REAL_PROOF_FAILED: McBlockExtra pack\n";
    return 1;
  }
  block::gen::BlockExtra::Record extra{};
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = empty;
  vm::CellBuilder custom;
  custom.store_bool_bool(true);
  custom.store_ref_bool(mc_extra_cell);
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  if (!block::gen::t_BlockExtra.cell_pack(extra_cell, extra)) {
    std::cerr << "C04_REAL_PROOF_FAILED: BlockExtra pack\n";
    return 1;
  }
  block::ValueFlow flow{block::ValueFlow::SetZero{}};
  vm::CellBuilder flow_builder;
  if (!flow.store(flow_builder)) {
    std::cerr << "C04_REAL_PROOF_FAILED: ValueFlow pack\n";
    return 1;
  }
  auto block_root = vm::CellBuilder{}.store_long(0x11ef55aa, 32).store_long(0, 32).store_ref(info_cell)
                        .store_ref(flow_builder.finalize()).store_ref(update).store_ref(extra_cell).finalize_novm();
  auto block_boc = require_ok(vm::std_boc_serialize(block_root, 31), "block BOC");
  auto id1 = BlockIdExt{masterchainId, shardIdAll, 1, td::Bits256(block_root->get_hash().bits()),
                        block::compute_file_hash(block_boc)};
  // A proof that parses is not necessarily an applicable block. Pin the
  // production state transition before using this fixture in a DB-backed
  // Manager test.
  auto parsed_block = require_ok(create_block(id1, block_boc.clone()), "C04 apply preflight block");
  auto replay_state = require_ok(MasterchainStateQ::fetch(id0, boc.clone(), root0), "C04 apply preflight state");
  auto application = replay_state.write().apply_block(id1, parsed_block, nullptr);
  if (application.is_error()) {
    std::cerr << "C04_REAL_APPLY_FAILED: " << application.to_string() << '\n';
    return 1;
  }
  const auto expected_state_root = RootHash{root1->get_hash().bits()};
  if (replay_state->root_hash() != expected_state_root) {
    std::cerr << "C04_REAL_APPLY_FAILED: expected root " << expected_state_root.to_hex() << ", actual "
              << replay_state->root_hash().to_hex() << '\n';
    return 1;
  }
  std::cout << "C04_REAL_APPLY_OK root=" << replay_state->root_hash().to_hex() << '\n';
  auto context = require_ok(derive_pq_finality_context(*state0, vset, id1, 0, 0), "PQ session");
  auto candidate = pq_block_signature_test::candidate(id1);
  auto pairs = keys.sign({0, 1, 2}, context.expected_session_id, pq_block_signature_test::Fixture::slot,
                         candidate, true, id1);
  const ValidatorWeight quorum_weight = 51;
  auto good_cell = require_ok(block::BlockSignatureSet::serialize_simplex_pq(
      pq_block_signature_test::clone_pairs(pairs), cc, vset->get_validator_set_hash(), quorum_weight,
      context.expected_session_id, pq_block_signature_test::Fixture::slot, candidate), "good certificate cell");
  ValidatorWeight parsed_weight = 0;
  auto good = require_ok(block::BlockSignatureSet::fetch(good_cell, parsed_weight), "good certificate");
  require_ok(block::verify_pq_finality(context, *good, block::FinalityRole::Final), "good PQ verify");
  auto wrong_session = context;
  wrong_session.expected_session_id = pq_block_signature_test::hash_of("wrong-C04-session");
  if (block::verify_pq_finality(wrong_session, *good, block::FinalityRole::Final).is_ok()) {
    std::cerr << "C04_REAL_PROOF_FAILED: wrong trusted session was accepted\n";
    return 1;
  }
  PendingBlockProofFailureSource source{};
  auto proof = WaitBlockData::generate_proof(id1, block_root, good, state0, source);
  if (proof.is_error()) {
    std::cerr << "C04_REAL_PROOF_FAILED: " << proof.error().to_string() << '\n';
    return 1;
  }
  auto parsed_proof = require_ok(create_proof(id1, proof.ok().clone()), "parse generated BlockProof");
  auto header = require_ok(parsed_proof->get_basic_header_info(), "BlockProof header");
  auto envelope = require_ok(parse_block_proof_signature_envelope(
      require_ok(parsed_proof->get_root_cell(), "BlockProof root")), "BlockProof signatures");
  if (header.cc_seqno != cc || header.validator_set_hash != vset->get_validator_set_hash() ||
      header.prev_key_mc_seqno != 0 || envelope.block_id != id1 || envelope.signatures.is_null() ||
      envelope.signatures->get_validator_set_hash() != vset->get_validator_set_hash()) {
    std::cerr << "C04_REAL_PROOF_FAILED: generated BlockProof coordinates differ\n";
    return 1;
  }
  auto bad_cell = require_ok(block::BlockSignatureSet::serialize_simplex_pq(
      pq_block_signature_test::clone_pairs(pairs), cc, vset->get_validator_set_hash() ^ 1u, quorum_weight,
      context.expected_session_id, pq_block_signature_test::Fixture::slot, candidate), "bad certificate cell");
  auto bad = require_ok(block::BlockSignatureSet::fetch(bad_cell, parsed_weight), "bad certificate");
  auto bad_proof = WaitBlockData::generate_proof(id1, block_root, bad, state0, source);
  if (bad_proof.is_ok() || source != PendingBlockProofFailureSource::FinalityEvidence) {
    std::cerr << "C04_REAL_PROOF_FAILED: wrong hash certificate was not attributed to finality evidence\n";
    return 1;
  }
  if (n5_reopen || n5_joined_reopen || n5_cut3_reopen) {
    std::vector<block::PQBlockSignature> exact_cert_signatures;
    if (n5_joined_reopen || n5_cut3_reopen) {
      std::ifstream final_file(argv[5], std::ios::binary);
      std::ostringstream final_bytes;
      final_bytes << final_file.rdbuf();
      if (!final_file || final_bytes.str().empty()) {
        std::cerr << "N5_JOINED_COLD_FAILED: retained exact FinalCert TL absent\n";
        return 1;
      }
      BlockCandidate joined_block{nodes.front().validator_id, id1, sha256_bits256(td::Slice{}),
                                  block_boc.clone(), td::BufferSlice{}};
      const auto joined_id = consensus::CandidateHashData::create_full(joined_block, std::nullopt)
                                 .build_id_with(0);
      const auto journal_path = consensus::consensus_db_root(std::string(argv[3])) +
          consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                            context.expected_session_id, "") + "/db/";
      const auto original = final_bytes.str();
      if (!n5_cold_joined_journal(journal_path, context.expected_session_id, vset,
                                  joined_id, td::Slice(original), !n5_cut3_reopen,
                                  exact_cert_signatures)) {
        return 1;
      }
      if (std::string_view(argv[1]) == "--n5-joined-reopen-bad-signature") {
        // A positive proof-verification result alone cannot bind the proof to
        // this exact saved FinalCert. Perturb only the expected bytes after
        // the journal has been read and verified; the cold proof comparison
        // must reject the resulting mismatch by its own named assertion.
        if (exact_cert_signatures.empty()) {
          std::cerr << "N5_JOINED_COLD_FAILED: no signature available for negative control\n";
          return 1;
        }
        exact_cert_signatures.front().signature.data()[0] ^= 1;
      }
    }
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cold-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_n5_accept_cold, id0, id1,
                              expected_state_root, vset, context.expected_session_id, std::string(argv[4]),
                              std::move(exact_cert_signatures),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!result.has_value() && !deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    const auto mode = std::string_view(argv[1]);
    if (mode == "--n5-joined-reopen-bad-signature") {
      if (result.has_value() && result->is_error() &&
          result->error().to_string().find("N5 cold proof signature bytes differ from exact FinalCert") !=
              std::string::npos) {
        std::cout << "N5_JOINED_COLD_WRONG_SIGNATURE_REJECTED\n";
        scheduler.run_in_context([&] { manager.reset(); });
        scheduler.stop();
        return 0;
      }
      std::cerr << "N5_JOINED_COLD_FAILED: wrong-signature control missed exact proof comparison\n";
      return 1;
    }
    if (mode != "--n5-reopen" && mode != "--n5-joined-reopen" && mode != "--n5-cut3-reopen" &&
        result.has_value() && result->is_error()) {
      const auto detail = result->error().to_string();
      const auto expected = mode == "--n5-reopen-bad-hash"
                                ? "N5 cold BlockProof bytes differ from writer"
                                : "N5 cold handle: block handle not in db";
      if (detail.find(expected) != std::string::npos) {
        std::cout << "N5_ACCEPT_BLOCK_COLD_NEGATIVE_OK mode=" << mode << " error=" << detail << '\n';
        scheduler.run_in_context([&] { manager.reset(); });
        scheduler.stop();
        return 0;
      }
    }
    if (!result.has_value() || result->is_error() ||
        (mode != "--n5-reopen" && mode != "--n5-joined-reopen" && mode != "--n5-cut3-reopen")) {
      std::cerr << "N5_ACCEPT_BLOCK_COLD_FAILED: "
                << (result.has_value() ? (result->is_error() ? result->error().to_string() : "negative unexpectedly passed")
                                       : "actor timeout") << '\n';
      return 1;
    }
    std::cout << "N5_ACCEPT_BLOCK_COLD_OK block=" << id1.to_str() << " root=" << expected_state_root.to_hex() << '\n';
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
    return 0;
  }
  if (n5_cut4_resume) {
    std::ifstream final_file(argv[5], std::ios::binary);
    std::ostringstream final_bytes;
    final_bytes << final_file.rdbuf();
    if (!final_file || final_bytes.str().empty()) {
      std::cerr << "N5_CUT4_FAILED: retained FinalCert TL absent\n";
      return 1;
    }
    BlockCandidate replay_block{nodes.front().validator_id, id1, sha256_bits256(td::Slice{}),
                                block_boc.clone(), td::BufferSlice{}};
    const auto candidate_id = consensus::CandidateHashData::create_full(replay_block, std::nullopt)
                                  .build_id_with(0);
    const auto journal_path = consensus::consensus_db_root(std::string(argv[3])) +
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                         context.expected_session_id, "") + "/db/";
    const auto original = final_bytes.str();
    const auto exact_cert_hash = sha256_bits256(td::Slice(original));
    std::vector<block::PQBlockSignature> exact_signatures;
    if (!n5_cold_joined_journal(journal_path, context.expected_session_id, vset,
                                candidate_id, td::Slice(original), true, exact_signatures)) {
      return 1;
    }
    n5_replay_state = std::make_shared<N5ReplayState>();
    n5_replay_state->expected_id = candidate_id;
    n5_replay_state->expected_cert_hash = exact_cert_hash;
    auto accept_calls = std::make_shared<std::atomic<unsigned>>(0);
    td::actor::Scheduler scheduler({1});
    td::actor::Runtime runtime;
    sx::DefaultCollatorSchedule::provide_for(runtime);
    runtime.register_actor<N5ReplayObserver>("N5ReplayObserver");
    consensus::BlockAccepter::register_in(runtime);
    sx::StateResolver::register_in(runtime);
    sx::CandidateResolver::register_in(runtime);
    sx::Pool::register_in(runtime);
    sx::Db::register_in(runtime);
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    td::actor::ActorOwn<N5AcceptFacade> facade;
    sx::BusHandle bus;
    std::optional<td::Result<td::Unit>> restored;
    bool bus_stopped = false;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cut4-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::restore_zero_context,
                              id0, id0.root_hash,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                restored.emplace(std::move(outcome));
                              }));
    });
    const auto context_deadline = td::Timestamp::in(10.0);
    while (!restored.has_value() && !context_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!restored.has_value() || restored->is_error()) {
      std::cerr << "N5_CUT4_FAILED: genesis Manager context could not be cold-restored\n";
      return 1;
    }
    scheduler.run_in_context([&] {
      facade = td::actor::create_actor<N5AcceptFacade>("n5-cut4-facade", manager.get(), vset,
                                                        std::shared_ptr<std::atomic<bool>>{},
                                                        std::nullopt, accept_calls);
      auto trusted = n5_joined_bus(vset, context.expected_session_id, facade.get(), journal_path);
      trusted->stop_promise = td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
        bus_stopped = outcome.is_ok();
      });
      bus = runtime.start(std::move(trusted), "n5-cut4-simplex");
      bus.publish<consensus::Start>(td::make_ref<consensus::ChainState>(
          consensus::ChainState::ZerostateTip{id0, root0}, id0));
    });
    const auto replay_deadline = td::Timestamp::in(10.0);
    while (n5_replay_state->observed.load(std::memory_order_acquire) == 0 && !replay_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (n5_replay_state->observed.load(std::memory_order_acquire) != 1 ||
        n5_replay_state->mismatch.load(std::memory_order_acquire)) {
      std::cerr << "N5_CUT4_FAILED: exact saved FinalCert was not replayed once\n";
      return 1;
    }
    // Give the StateResolver's local RocksDB marker lookup time to settle.
    // A marker-bypass mutant must call the facade during this same interval.
    const auto settled = td::Timestamp::in(1.0);
    while (!settled.is_in_past()) {
      scheduler.run(0.01);
    }
    const auto duplicate = accept_calls->load(std::memory_order_acquire);
    scheduler.run_in_context([&] {
      bus.publish<consensus::StopRequested>();
      bus = {};
    });
    const auto stop_deadline = td::Timestamp::in(10.0);
    while (!bus_stopped && !stop_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    scheduler.run_in_context([&] { facade.reset(); manager.reset(); });
    scheduler.stop();
    n5_replay_state.reset();
    if (!bus_stopped || duplicate != 0) {
      std::cerr << "N5_CUT4_FAILED: duplicate AcceptBlock after exact FinalCert replay count=" << duplicate << '\n';
      return 1;
    }
    std::string mode = "--n5-joined-reopen";
    char *child_argv[] = {argv[0], mode.data(), argv[2], argv[3], argv[4], argv[5], nullptr};
    pid_t child = -1;
    const int spawned = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
    int status = 0;
    if (spawned != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      std::cerr << "N5_CUT4_FAILED: second cold proof/state read status=" << status << " spawn=" << spawned << '\n';
      return 1;
    }
    std::cout << "N5_CUT4_EXACT_REPLAY_NO_REAPPLY_OK cert=" << exact_cert_hash.to_hex()
              << " block=" << id1.to_str() << " proof_hash=" << argv[4] << '\n';
    return 0;
  }
  if (n5_cut1_resume || n5_cut2_resume || n5_cut3_resume) {
    std::ifstream final_file(argv[4], std::ios::binary);
    std::ostringstream final_bytes;
    final_bytes << final_file.rdbuf();
    if (!final_file || final_bytes.str().empty()) {
      std::cerr << "N5_CUT1_RESUME_FAILED: retained FinalCert TL absent\n";
      return 1;
    }
    BlockCandidate resumed_block{nodes.front().validator_id, id1, sha256_bits256(td::Slice{}),
                                 block_boc.clone(), td::BufferSlice{}};
    const auto candidate_id = consensus::CandidateHashData::create_full(resumed_block, std::nullopt)
                                  .build_id_with(0);
    const auto journal_path = consensus::consensus_db_root(std::string(argv[3])) +
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                          context.expected_session_id, "") + "/db/";
    td::actor::Scheduler scheduler({1});
    td::actor::Runtime runtime;
    sx::DefaultCollatorSchedule::provide_for(runtime);
    consensus::BlockAccepter::register_in(runtime);
    sx::StateResolver::register_in(runtime);
    sx::CandidateResolver::register_in(runtime);
    sx::Pool::register_in(runtime);
    sx::Db::register_in(runtime);
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    td::actor::ActorOwn<N5AcceptFacade> facade;
    td::actor::ActorOwn<N5RestartMarkerWaiter> waiter;
    sx::BusHandle bus;
    bool bus_stopped = false;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cut1-resumed-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::restore_zero_context,
                              id0, id0.root_hash,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    const auto context_deadline = td::Timestamp::in(30.0);
    while (!result.has_value() && !context_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!result.has_value() || result->is_error()) {
      std::cerr << "N5_CUT1_RESUME_FAILED: genesis RootDb context: "
                << (result.has_value() ? result->error().to_string() : "timeout") << '\n';
      return 1;
    }
    result.reset();
    scheduler.run_in_context([&] {
      facade = td::actor::create_actor<N5AcceptFacade>("n5-cut1-resumed-facade", manager.get(), vset);
      auto trusted = n5_joined_bus(vset, context.expected_session_id, facade.get(), journal_path);
      trusted->stop_promise = td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
        bus_stopped = outcome.is_ok();
      });
      bus = runtime.start(std::move(trusted), "n5-cut1-resumed-simplex");
      bus.publish<consensus::Start>(td::make_ref<consensus::ChainState>(
          consensus::ChainState::ZerostateTip{id0, root0}, id0));
      waiter = td::actor::create_actor<N5RestartMarkerWaiter>("n5-cut1-marker-waiter");
      td::actor::send_closure(waiter, &N5RestartMarkerWaiter::await_replay, bus, candidate_id,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    const auto marker_deadline = td::Timestamp::in(35.0);
    while (!result.has_value() && !marker_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!result.has_value() || result->is_error()) {
      std::cerr << "N5_CUT1_RESUME_FAILED: bootstrap replay: "
                << (result.has_value() ? result->error().to_string() : "timeout") << '\n';
      return 1;
    }
    // No certificate is re-published here: Pool must consume the FinalCert
    // recovered by the production Db bootstrap path from the first process.
    const auto expected_final_hash = sha256_bits256(td::Slice(final_bytes.str()));
    bool exact_bootstrap = false;
    for (const auto &cert : bus->bootstrap_certificates) {
      const auto serialized = serialize_tl_object(cert->to_tl(), true);
      exact_bootstrap |= sha256_bits256(serialized.as_slice()) == expected_final_hash;
    }
    if (!exact_bootstrap) {
      std::cerr << "N5_CUT1_RESUME_FAILED: exact FinalCert absent from Db bootstrap set\n";
      return 1;
    }
    std::optional<td::Result<std::string>> proof_hash;
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::n5_written_proof_hash,
                              id1, td::PromiseCreator::lambda([&](td::Result<std::string> outcome) {
                                proof_hash.emplace(std::move(outcome));
                              }));
    });
    const auto proof_deadline = td::Timestamp::in(30.0);
    while (!proof_hash.has_value() && !proof_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!proof_hash.has_value() || proof_hash->is_error()) {
      std::cerr << "N5_CUT1_RESUME_FAILED: production BlockProof absent after replay\n";
      return 1;
    }
    scheduler.run_in_context([&] {
      waiter.reset();
      bus.publish<consensus::StopRequested>();
      bus = {};
    });
    const auto stop_deadline = td::Timestamp::in(10.0);
    while (!bus_stopped && !stop_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!bus_stopped) {
      std::cerr << "N5_CUT1_RESUME_FAILED: consensus bus did not close\n";
      return 1;
    }
    scheduler.run_in_context([&] { facade.reset(); manager.reset(); });
    scheduler.stop();
    std::string mode = "--n5-joined-reopen";
    std::string proof = proof_hash->ok();
    char *child_argv[] = {argv[0], mode.data(), argv[2], argv[3], proof.data(), argv[4], nullptr};
    pid_t child = -1;
    const int spawned = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
    int status = 0;
    if (spawned != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      std::cerr << "N5_CUT1_RESUME_FAILED: cold proof child status=" << status << " spawn=" << spawned << '\n';
      return 1;
    }
    std::cout << (n5_cut3_resume ? "N5_CUT3_RECOVERY_OK block=" :
                  n5_cut2_resume ? "N5_CUT2_RECOVERY_OK block=" : "N5_CUT1_RECOVERY_OK block=")
              << id1.to_str() << " proof_hash=" << proof << '\n';
    return 0;
  }
  if (n5_cut2_reopen) {
    std::ifstream final_file(argv[4], std::ios::binary);
    std::ostringstream final_bytes;
    final_bytes << final_file.rdbuf();
    if (!final_file || final_bytes.str().empty()) {
      std::cerr << "N5_CUT2_COLD_FAILED: retained FinalCert TL absent\n";
      return 1;
    }
    BlockCandidate candidate_block{nodes.front().validator_id, id1, sha256_bits256(td::Slice{}),
                                   block_boc.clone(), td::BufferSlice{}};
    const auto candidate_id = consensus::CandidateHashData::create_full(candidate_block, std::nullopt)
                                  .build_id_with(0);
    const auto journal_path = consensus::consensus_db_root(std::string(argv[3])) +
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                          context.expected_session_id, "") + "/db/";
    std::vector<block::PQBlockSignature> exact_signatures;
    const auto original = final_bytes.str();
    if (!n5_cold_joined_journal(journal_path, context.expected_session_id, vset,
                                candidate_id, td::Slice(original), false, exact_signatures)) {
      return 1;
    }
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cut2-cold-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_n5_cut2_signatures,
                              id1, std::move(exact_signatures),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    const auto deadline = td::Timestamp::in(10.0);
    while (!result.has_value() && !deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    const bool valid = result.has_value() && result->is_ok();
    if (!valid) {
      std::cerr << "N5_CUT2_COLD_FAILED: #13 cold read: "
                << (result.has_value() ? result->error().to_string() : "timeout") << '\n';
    }
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
    return valid ? 0 : 1;
  }
  if (n5_cut1_reopen) {
    std::ifstream final_file(argv[4], std::ios::binary);
    std::ostringstream final_bytes;
    final_bytes << final_file.rdbuf();
    if (!final_file || final_bytes.str().empty()) {
      std::cerr << "N5_CUT1_COLD_FAILED: original FinalCert TL absent\n";
      return 1;
    }
    BlockCandidate joined_block{nodes.front().validator_id, id1, sha256_bits256(td::Slice{}),
                                block_boc.clone(), td::BufferSlice{}};
    const auto joined_id = consensus::CandidateHashData::create_full(joined_block, std::nullopt).build_id_with(0);
    const auto journal_path = consensus::consensus_db_root(std::string(argv[3])) +
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                          context.expected_session_id, "") + "/db/";
    std::vector<block::PQBlockSignature> exact_signatures;
    const auto original = final_bytes.str();
    if (!n5_cold_joined_journal(journal_path, context.expected_session_id, vset,
                                joined_id, td::Slice(original), false, exact_signatures)) {
      return 1;
    }
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cut1-cold-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_n5_accept_cold,
                              id0, id1, expected_state_root, vset, context.expected_session_id,
                              std::string(64, '0'), std::vector<block::PQBlockSignature>{},
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    const auto deadline = td::Timestamp::in(10.0);
    while (!result.has_value() && !deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    const bool absent = result.has_value() && result->is_error() &&
        result->error().to_string().find("N5 cold handle: block handle not in db") != std::string::npos;
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
    if (!absent) {
      std::cerr << "N5_CUT1_COLD_FAILED: target RootDb handle was not absent for the exact reason\n";
      return 1;
    }
    std::cout << "N5_CUT1_COLD_NO_TARGET_HANDLE_OK block=" << id1.to_str() << '\n';
    return 0;
  }
  if (n5_joined || n5_cut1 || n5_cut2 || n5_cut3 || n5_cut4) {
    auto db_root = require_ok(td::mkdtemp("", "n5-joined-finalcert-"), "N5 joined DB root");
    std::cout << "N5_JOINED_DB_ROOT=" << db_root << '\n';
    std::filesystem::create_directories(db_root + "/static");
    {
      std::ofstream static_zero(db_root + "/static/" + id0.file_hash.to_hex(), std::ios::binary);
      static_zero.write(boc.as_slice().data(), static_cast<std::streamsize>(boc.size()));
      if (!static_zero) {
        std::cerr << "N5_JOINED_FAILED: genesis StaticFilesDb provision\n";
        return 1;
      }
    }
    const auto journal_path = consensus::consensus_db_root(db_root) +
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc,
                                          context.expected_session_id, "") + "/db/";
    // StoreCandidate is a local fixture ingress, not a candidate transport
    // authentication proof. Pool's certificate ingress, persistence ordering,
    // StateResolver and BlockAccepter remain production actors.
    const auto collated_hash = sha256_bits256(td::Slice{});
    BlockCandidate candidate_block{nodes.front().validator_id, id1, collated_hash,
                                   block_boc.clone(), td::BufferSlice{}};
    constexpr td::uint32 joined_slot = 0;
    auto candidate_id = consensus::CandidateHashData::create_full(candidate_block, std::nullopt)
                            .build_id_with(joined_slot);
    auto leader_it = std::find(keys.validator_ids.begin(), keys.validator_ids.end(), nodes.front().validator_id);
    if (leader_it == keys.validator_ids.end()) {
      std::cerr << "N5_JOINED_FAILED: candidate leader not in signing fixture\n";
      return 1;
    }
    auto candidate_bytes = serialize_tl_object(candidate_id.to_tl(), true);
    auto candidate_envelope = create_serialize_tl_object<tos_api::consensus_dataToSign>(
        context.expected_session_id, candidate_bytes.clone());
    auto candidate_signature = keys.stores[static_cast<size_t>(leader_it - keys.validator_ids.begin())]
                                   .sign_consensus(std::string_view(candidate_envelope.data(), candidate_envelope.size()));
    if (!candidate_signature) {
      std::cerr << "N5_JOINED_FAILED: leader candidate signature unavailable\n";
      return 1;
    }
    auto candidate_ref = td::make_ref<consensus::Candidate>(
        candidate_id, std::nullopt, consensus::PeerValidatorId{0},
        std::variant<BlockIdExt, BlockCandidate>{std::move(candidate_block)},
        td::BufferSlice(candidate_signature->signature));

    td::actor::Scheduler scheduler({1});
    td::actor::Runtime runtime;
    if (!n5_cut1) {
      consensus::BlockAccepter::register_in(runtime);
      sx::StateResolver::register_in(runtime);
    }
    sx::CandidateResolver::register_in(runtime);
    sx::Pool::register_in(runtime);
    sx::Db::register_in(runtime);
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    td::actor::ActorOwn<N5AcceptFacade> facade;
    td::actor::ActorOwn<N5JoinedPublisher> publisher;
    sx::BusHandle bus;
    std::optional<td::Result<td::Unit>> result;
    bool bus_stopped = false;
    auto cut2_gate = n5_cut2 ? std::make_shared<std::atomic<bool>>(false)
                             : std::shared_ptr<std::atomic<bool>>{};
    auto cut3_gate = n5_cut3 ? std::make_shared<std::atomic<bool>>(false)
                             : std::shared_ptr<std::atomic<bool>>{};
    const auto finalcert_path = db_root + ".finalcert.tl";
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>(
          "n5-joined-manager", id0, db_root, cut2_gate,
          n5_cut2 ? std::optional<BlockIdExt>{id1} : std::nullopt);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::seed_zerostate,
                              id0, state0, boc.clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto wait_result = [&](const char *stage) {
      const auto deadline = td::Timestamp::in(30.0);
      while (!result.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!result.has_value() || result->is_error()) {
        std::cerr << "N5_JOINED_FAILED stage=" << stage << " error="
                  << (result.has_value() ? result->error().to_string() : "timeout") << '\n';
        return false;
      }
      result.reset();
      return true;
    };
    auto cancel_cut3_gate = [&] {
      if (!n5_cut3) {
        return true;
      }
      std::optional<td::Result<td::Unit>> cancelled;
      scheduler.run_in_context([&] {
        td::actor::send_closure(facade, &N5AcceptFacade::cancel_cut3,
                                td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                  cancelled.emplace(std::move(outcome));
                                }));
      });
      const auto deadline = td::Timestamp::in(5.0);
      while (!cancelled.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      return cancelled.has_value() && cancelled->is_ok();
    };
    if (!wait_result("seed")) {
      return 1;
    }
    scheduler.run_in_context([&] {
      facade = td::actor::create_actor<N5AcceptFacade>(
          "n5-joined-facade", manager.get(), vset, cut3_gate,
          n5_cut3 ? std::optional<BlockIdExt>{id1} : std::nullopt);
      auto trusted = n5_joined_bus(vset, context.expected_session_id, facade.get(), journal_path);
      trusted->stop_promise = td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
        bus_stopped = outcome.is_ok();
      });
      bus = runtime.start(std::move(trusted), "n5-joined-simplex");
      bus.publish<consensus::Start>(td::make_ref<consensus::ChainState>(
          consensus::ChainState::ZerostateTip{id0, root0}, id0));
      auto notar = n5_joined_cert(sx::NotarizeVote{candidate_id}, *bus, keys);
      auto final = n5_joined_cert(sx::FinalizeVote{candidate_id}, *bus, keys);
      if (notar.is_error() || final.is_error()) {
        result.emplace(td::Status::Error("N5 joined certificate fixture failed production verification"));
        return;
      }
      auto final_tl = serialize_tl_object(final.ok()->to_tl(), true);
      std::ofstream retained(finalcert_path, std::ios::binary);
      retained.write(final_tl.data(), static_cast<std::streamsize>(final_tl.size()));
      retained.close();
      if (!retained) {
        result.emplace(td::Status::Error("N5 exact FinalCert TL retention failed"));
        return;
      }
      publisher = td::actor::create_actor<N5JoinedPublisher>("n5-joined-publisher");
      td::actor::send_closure(publisher, &N5JoinedPublisher::publish, bus, candidate_ref,
                              notar.move_as_ok(), final.move_as_ok(), n5_cut1, cut2_gate, cut3_gate,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result(n5_cut3 ? "BlockProof-before-finalized-marker" : "Pool-to-finalized-marker")) {
      if (n5_cut3) {
        cancel_cut3_gate();
        scheduler.run_in_context([&] {
          publisher.reset();
          bus.publish<consensus::StopRequested>();
          bus = {};
        });
        const auto deadline = td::Timestamp::in(10.0);
        while (!bus_stopped && !deadline.is_in_past()) {
          scheduler.run(0.01);
        }
        scheduler.run_in_context([&] { facade.reset(); manager.reset(); });
        scheduler.stop();
      }
      return 1;
    }
    if (n5_cut1 || n5_cut2 || n5_cut3) {
      // Cut1 has no StateResolver/BlockAccepter, so only the FinalCert journal
      // can complete. Cut2 has both actors, but holds the proof promise after
      // production #13 storage and before BlockProof storage. Cut3 holds the
      // facade response after AcceptBlock and before StateResolver's marker.
      std::optional<td::Result<std::string>> cut3_proof_hash;
      if (n5_cut3) {
        scheduler.run_in_context([&] {
          td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::n5_written_proof_hash,
                                  id1, td::PromiseCreator::lambda([&](td::Result<std::string> outcome) {
                                    cut3_proof_hash.emplace(std::move(outcome));
                                  }));
        });
        const auto deadline = td::Timestamp::in(10.0);
        while (!cut3_proof_hash.has_value() && !deadline.is_in_past()) {
          scheduler.run(0.01);
        }
        if (!cut3_proof_hash.has_value() || cut3_proof_hash->is_error()) {
          std::cerr << "N5_CUT3_FAILED: production BlockProof absent at write-after gate\n";
          return 1;
        }
      }
      if (!cancel_cut3_gate()) {
        std::cerr << "N5_CUT3_FAILED: controlled facade cancellation did not complete\n";
        return 1;
      }
      scheduler.run_in_context([&] {
        publisher.reset();
        if (n5_cut2) {
          // The AcceptBlock promise is intentionally held at the proof gate.
          // Stop its Manager so the waiting StateResolver task can unwind.
          manager.reset();
        }
        bus.publish<consensus::StopRequested>();
        bus = {};
      });
      const auto stop_deadline = td::Timestamp::in(10.0);
      while (!bus_stopped && !stop_deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!bus_stopped) {
        std::cerr << "N5_CUT1_FAILED: Pool bus did not close after journal write\n";
        return 1;
      }
      scheduler.run_in_context([&] { facade.reset(); manager.reset(); });
      scheduler.stop();
      std::string mode = n5_cut3 ? "--n5-cut3-reopen" : n5_cut2 ? "--n5-cut2-reopen" : "--n5-cut1-reopen";
      std::string proof = n5_cut3 ? cut3_proof_hash->ok() : std::string{};
      char *child_argv[] = {argv[0], mode.data(), argv[2], db_root.data(),
                            n5_cut3 ? proof.data() : const_cast<char *>(finalcert_path.c_str()),
                            n5_cut3 ? const_cast<char *>(finalcert_path.c_str()) : nullptr, nullptr};
      pid_t child = -1;
      const int spawned = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
      int status = 0;
      if (spawned != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "N5_CUT1_COLD_FAILED: child status=" << status << " spawn=" << spawned << '\n';
        return 1;
      }
      mode = n5_cut3 ? "--n5-cut3-resume" : n5_cut2 ? "--n5-cut2-resume" : "--n5-cut1-resume";
      child_argv[1] = mode.data();
      child_argv[4] = const_cast<char *>(finalcert_path.c_str());
      child_argv[5] = nullptr;
      child = -1;
      const int resumed = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
      status = 0;
      if (resumed != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "N5_CUT1_FAILED: resume child status=" << status << " spawn=" << resumed << '\n';
        return 1;
      }
      std::cout << (n5_cut3 ? "N5_CUT3_WRITER_EXIT_OK root=" :
                    n5_cut2 ? "N5_CUT2_WRITER_EXIT_OK root=" : "N5_CUT1_WRITER_EXIT_OK root=") << db_root
                << " finalcert_tl=" << finalcert_path << '\n';
      return 0;
    }
    std::optional<td::Result<std::string>> proof_hash;
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::n5_written_proof_hash,
                              id1, td::PromiseCreator::lambda([&](td::Result<std::string> outcome) {
                                proof_hash.emplace(std::move(outcome));
                              }));
    });
    const auto proof_deadline = td::Timestamp::in(30.0);
    while (!proof_hash.has_value() && !proof_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!proof_hash.has_value() || proof_hash->is_error()) {
      std::cerr << "N5_JOINED_FAILED: production BlockProof absent after marker\n";
      return 1;
    }
    std::cout << "N5_JOINED_SAME_CERT_WRITTEN slot=" << candidate_id.slot
              << " candidate_hash=" << candidate_id.hash.to_hex()
              << " block=" << id1.to_str() << " proof_hash=" << proof_hash->ok() << '\n';
    scheduler.run_in_context([&] {
      publisher.reset();
      bus.publish<consensus::StopRequested>();
      bus = {};
    });
    const auto stop_deadline = td::Timestamp::in(10.0);
    while (!bus_stopped && !stop_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!bus_stopped) {
      std::cerr << "N5_JOINED_FAILED: consensus bus did not close before cold restart\n";
      return 1;
    }
    scheduler.run_in_context([&] { facade.reset(); manager.reset(); });
    scheduler.stop();
    std::string mode = "--n5-joined-reopen";
    std::string proof = proof_hash->ok();
    char *child_argv[] = {argv[0], mode.data(), argv[2], db_root.data(), proof.data(),
                          const_cast<char *>(finalcert_path.c_str()), nullptr};
    pid_t child = -1;
    const int spawned = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
    int status = 0;
    if (spawned != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      std::cerr << "N5_JOINED_COLD_FAILED: child status=" << status << " spawn=" << spawned << '\n';
      return 1;
    }
    mode = "--n5-joined-reopen-bad-signature";
    child_argv[1] = mode.data();
    child = -1;
    const int negative_spawned = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
    status = 0;
    if (negative_spawned != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      std::cerr << "N5_JOINED_COLD_FAILED: wrong-signature child status=" << status
                << " spawn=" << negative_spawned << '\n';
      return 1;
    }
    if (n5_cut4) {
      mode = "--n5-cut4-resume";
      child_argv[1] = mode.data();
      child = -1;
      const int replayed = posix_spawn(&child, argv[0], nullptr, nullptr, child_argv, environ);
      status = 0;
      if (replayed != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "N5_CUT4_FAILED: cold replay child status=" << status << " spawn=" << replayed << '\n';
        return 1;
      }
      std::cout << "N5_CUT4_WRITER_EXIT_OK root=" << db_root << " finalcert_tl=" << finalcert_path << '\n';
    }
    return 0;
  }
  if (n5_accept) {
    auto db_root = require_ok(td::mkdtemp("", "n5-accept-block-"), "N5 AcceptBlock DB directory");
    std::cout << "N5_ACCEPT_BLOCK_DB_ROOT=" << db_root << '\n';
    std::filesystem::create_directories(db_root + "/static");
    {
      std::ofstream static_zero(db_root + "/static/" + id0.file_hash.to_hex(), std::ios::binary);
      static_zero.write(boc.as_slice().data(), static_cast<std::streamsize>(boc.size()));
      if (!static_zero) {
        std::cerr << "N5_ACCEPT_BLOCK_FAILED: genesis StaticFilesDb provision\n";
        return 1;
      }
    }
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-accept-manager", id0, db_root);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::seed_zerostate, id0, state0, boc.clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto wait_result = [&]() {
      auto deadline = td::Timestamp::in(30.0);
      while (!result.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!result.has_value() || result->is_error()) {
        std::cerr << "N5_ACCEPT_BLOCK_FAILED: "
                  << (result.has_value() ? result->error().to_string() : "actor timeout") << '\n';
        return false;
      }
      return true;
    };
    if (!wait_result()) {
      return 1;
    }
    result.reset();
    scheduler.run_in_context([&] {
      run_accept_block_query(id1, parsed_block, {id0}, vset, good, context.expected_session_id,
                             0, 0, false, true, manager.get(),
                             td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                               result.emplace(std::move(outcome));
                             }));
    });
    if (!wait_result()) {
      return 1;
    }
    std::cout << "N5_ACCEPT_BLOCK_QUERY_OK block=" << id1.to_str() << '\n';
    std::optional<td::Result<std::string>> proof_result;
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::n5_written_proof_hash, id1,
                              td::PromiseCreator::lambda([&](td::Result<std::string> outcome) {
                                proof_result.emplace(std::move(outcome));
                              }));
    });
    auto proof_deadline = td::Timestamp::in(30.0);
    while (!proof_result.has_value() && !proof_deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!proof_result.has_value() || proof_result->is_error()) {
      std::cerr << "N5_ACCEPT_BLOCK_FAILED: writer proof hash "
                << (proof_result.has_value() ? proof_result->error().to_string() : "timeout") << '\n';
      return 1;
    }
    auto proof_hash = proof_result->move_as_ok();
    std::cout << "N5_ACCEPT_BLOCK_WRITTEN_PROOF_HASH=" << proof_hash << '\n';
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
    auto cold_child = [&](std::string mode, std::string root, std::string hash) {
      char *child_argv[] = {argv[0], mode.data(), argv[2], root.data(), hash.data(), nullptr};
      pid_t pid = -1;
      const int spawn_error = posix_spawn(&pid, argv[0], nullptr, nullptr, child_argv, environ);
      int status = 0;
      if (spawn_error != 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "N5_ACCEPT_BLOCK_FAILED: cold child mode=" << mode << " status=" << status
                  << " spawn=" << spawn_error << '\n';
        return false;
      }
      return true;
    };
    auto empty_root = require_ok(td::mkdtemp("", "n5-accept-absent-"), "N5 absent DB directory");
    if (!cold_child("--n5-reopen", db_root, proof_hash) ||
        !cold_child("--n5-reopen-bad-hash", db_root, std::string(64, '0')) ||
        !cold_child("--n5-reopen-absent", empty_root, proof_hash)) {
      return 1;
    }
    return 0;
  }
  // Signing may randomize the proof in another process. Bind cold readback to
  // the exact proof stored by this parent, not a newly generated equivalent.
  const auto proof_hash = block::compute_file_hash(proof.ok()).to_hex();
  if (reopen) {
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("c04-cold-reopen", id0, argv[3]);
      auto done = td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
        result.emplace(std::move(outcome));
      });
      if (std::string_view(argv[1]) == "--reopen-absent") {
        td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_target_absent, id1,
                                std::move(done));
      } else {
        td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_persisted, id0, id1,
                                expected_state_root, std::string(argv[4]), false, std::move(done));
      }
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!result.has_value() && !deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    if (!result.has_value() || result->is_error()) {
      std::cerr << "C04_MANAGER_COLD_DB_FAILED: "
                << (result.has_value() ? result->error().to_string() : "timeout") << '\n';
      return 1;
    }
    std::cout << (std::string_view(argv[1]) == "--reopen-absent" ? "C04_MANAGER_COLD_DB_ABSENT_OK"
                                                                    : "C04_MANAGER_COLD_DB_APPLIED_OK")
              << " root=" << argv[3] << '\n';
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
    return 0;
  }
  auto db_root = require_ok(td::mkdtemp("", "c04-manager-"), "C04 manager DB directory");
  std::cout << "C04_MANAGER_DB_ROOT=" << db_root << '\n';
  std::filesystem::create_directories(db_root + "/static");
  {
    std::ofstream static_zero(db_root + "/static/" + id0.file_hash.to_hex(), std::ios::binary);
    static_zero.write(boc.as_slice().data(), static_cast<std::streamsize>(boc.size()));
    if (!static_zero) {
      std::cerr << "C04_MANAGER_ACTOR_FAILED: cannot provision genesis in StaticFilesDb\n";
      return 1;
    }
  }
  {
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("c04-real-manager", id0, db_root);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::seed_zerostate, id0, state0, boc.clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto wait_result = [&]() {
      auto deadline = td::Timestamp::in(30.0);
      while (!result.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!result.has_value()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: actor step timed out\n";
        return false;
      }
      if (result->is_error()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: " << result->error().to_string() << '\n';
        return false;
      }
      return true;
    };
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_ZERO_STATE_STORED\n";
    result.reset();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::broadcast_bad_then_good, id1,
                              block_boc.clone(), bad, good,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_BAD_FRONT_GOOD_APPLIED_OK\n";
    result.reset();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_persisted, id0, id1,
                              expected_state_root, proof_hash, true,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_DB_APPLIED_OK block=" << id1.to_str() << " root=" << expected_state_root.to_hex()
              << '\n';
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
  }
  auto stale_nodes = nodes;
  ++stale_nodes[0].weight;
  td::Ref<block::ValidatorSet> stale_set{
      true, cc, ShardIdFull{masterchainId}, std::move(stale_nodes)};
  if (stale_set->get_validator_set_hash() == vset->get_validator_set_hash()) {
    std::cerr << "C04_MANAGER_ACTOR_FAILED: stale set did not change identity\n";
    return 1;
  }
  std::string recovery_root;
  std::string expiry_root;
  auto run_stale_case = [&](bool expire) {
    std::string prefix = expire ? "c04-manager-expiry-" : "c04-manager-recovery-";
    auto root = require_ok(td::mkdtemp("", prefix),
                           "C04 stale-context DB directory");
    std::cout << "C04_MANAGER_" << (expire ? "EXPIRY" : "RECOVERY") << "_DB_ROOT=" << root << '\n';
    std::filesystem::create_directories(root + "/static");
    {
      std::ofstream static_zero(root + "/static/" + id0.file_hash.to_hex(), std::ios::binary);
      static_zero.write(boc.as_slice().data(), static_cast<std::streamsize>(boc.size()));
      if (!static_zero) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: cannot provision stale-case genesis\n";
        return false;
      }
    }
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> actor;
    std::optional<td::Result<td::Unit>> result;
    auto wait_result = [&]() {
      auto deadline = td::Timestamp::in(expire ? 75.0 : 30.0);
      while (!result.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!result.has_value()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: stale-case actor step timed out\n";
        return false;
      }
      if (result->is_error()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: " << result->error().to_string() << '\n';
        return false;
      }
      return true;
    };
    scheduler.run_in_context([&] {
      actor = td::actor::create_actor<PendingFinalityManagerActorProbe>("c04-stale-manager", id0, root);
      td::actor::send_closure(actor, &PendingFinalityManagerActorProbe::seed_zerostate, id0, state0, boc.clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return false;
    }
    result.reset();
    scheduler.run_in_context([&] {
      td::actor::send_closure(actor, &PendingFinalityManagerActorProbe::start_stale_context_case, id1,
                              block_boc.clone(), good, stale_set, state0, expire,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return false;
    }
    std::cout << "C04_MANAGER_STALE_" << (expire ? "EXPIRY" : "RECOVERY") << "_OK\n";
    if (!expire) {
      result.reset();
      scheduler.run_in_context([&] {
        td::actor::send_closure(actor, &PendingFinalityManagerActorProbe::verify_persisted, id0, id1,
                                expected_state_root, proof_hash, true,
                                td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                  result.emplace(std::move(outcome));
                                }));
      });
      if (!wait_result()) {
        return false;
      }
      std::cout << "C04_MANAGER_STALE_RECOVERY_DB_APPLIED_OK\n";
    }
    scheduler.run_in_context([&] { actor.reset(); });
    scheduler.stop();
    (expire ? expiry_root : recovery_root) = root;
    return true;
  };
  if (!run_stale_case(false) || !run_stale_case(true)) {
    return 1;
  }
  auto cold_reopen = [&](std::string_view mode, const std::string &root) {
    std::string mode_arg(mode);
    char *child_argv[] = {argv[0], mode_arg.data(), argv[1], const_cast<char *>(root.c_str()),
                          const_cast<char *>(proof_hash.c_str()), nullptr};
    pid_t pid = -1;
    const int spawn_error = posix_spawn(&pid, argv[0], nullptr, nullptr, child_argv, environ);
    if (spawn_error != 0) {
      std::cerr << "C04_MANAGER_COLD_DB_FAILED: posix_spawn error=" << spawn_error << '\n';
      return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      std::cerr << "C04_MANAGER_COLD_DB_FAILED: child status=" << status << " root=" << root << '\n';
      return false;
    }
    return true;
  };
  if (!cold_reopen("--reopen", db_root) || !cold_reopen("--reopen", recovery_root) ||
      !cold_reopen("--reopen-absent", expiry_root)) {
    return 1;
  }
  std::cout << "C04_REAL_PROOF_OK session=" << context.expected_session_id.to_hex()
            << " block=" << id1.to_str() << " proof_bytes=" << proof.ok().size() << '\n';
  return 0;
}
