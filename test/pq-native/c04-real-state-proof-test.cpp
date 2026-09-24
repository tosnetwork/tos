// Offline C04 candidate: real PQ Config34 genesis -> seqno-1 Merkle/proof.
#include <filesystem>
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
  PendingFinalityManagerActorProbe(BlockIdExt zero_id, std::string root)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(zero_id, zero_id), std::move(root), {}, {}, {}, {}, {}) {
  }

  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("c04-ext-messages", opts_, actor_id(this));
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
                             td::Promise<td::Unit> promise) {
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, target_id,
                            td::PromiseCreator::lambda(
        [db, zero_id, target_id, expected_root, vset, session,
         expected_proof_hash = std::move(expected_proof_hash), promise = std::move(promise)]
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
             expected_proof_hash = std::move(expected_proof_hash), promise = std::move(promise)]
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
};

}  // namespace tos::validator

int main(int argc, char **argv) {
  const bool n5_accept = argc == 3 && std::string_view(argv[1]) == "--n5-accept";
  const bool n5_reopen = argc == 5 && (std::string_view(argv[1]) == "--n5-reopen" ||
                                           std::string_view(argv[1]) == "--n5-reopen-bad-hash" ||
                                           std::string_view(argv[1]) == "--n5-reopen-absent");
  const bool reopen = argc == 5 && (std::string_view(argv[1]) == "--reopen" ||
                                      std::string_view(argv[1]) == "--reopen-absent");
  if (!(argc == 2 || reopen || n5_accept || n5_reopen)) {
    std::cerr << "usage: c04-real-state-proof-test GENESIS_BOC | --n5-accept GENESIS_BOC | --n5-reopen GENESIS_BOC DB_ROOT PROOF_HASH | --reopen[|-absent] GENESIS_BOC DB_ROOT PROOF_HASH\n";
    return 2;
  }
  std::ifstream input((reopen || n5_accept || n5_reopen) ? argv[2] : argv[1], std::ios::binary);
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
  if (n5_reopen) {
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("n5-cold-manager", id0, argv[3]);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_n5_accept_cold, id0, id1,
                              expected_state_root, vset, context.expected_session_id, std::string(argv[4]),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!result.has_value() && !deadline.is_in_past()) {
      scheduler.run(0.01);
    }
    const auto mode = std::string_view(argv[1]);
    if (mode != "--n5-reopen" && result.has_value() && result->is_error()) {
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
    if (!result.has_value() || result->is_error() || mode != "--n5-reopen") {
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
