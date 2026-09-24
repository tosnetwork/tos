#pragma once

#include <string>

#include "quic/quic-sender.h"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"

namespace tos::validator {

// Shared actor/RootDb seam for the N5 restart cuts. Only network-heavy
// Manager startup is suppressed; the production DB actor and its write/read
// methods remain in the path. Individual cuts must still drive their own
// production persistence operations, not substitute successful callbacks.
class N5ManagerDbFixture : public ValidatorManagerImpl {
 public:
  N5ManagerDbFixture(BlockIdExt zero_id, std::string root)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(zero_id, zero_id), std::move(root), {}, {}, {}, {}, {}) {
  }

  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("n5-ext-messages", opts_, actor_id(this));
  }

  void seed_zerostate(BlockIdExt id, td::Ref<MasterchainStateQ> state, td::BufferSlice boc,
                      td::Promise<td::Unit> promise) {
    auto after_file = [self = actor_id(this), id, state, promise = std::move(promise)](
                          td::Result<td::Unit> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error());
      }
      td::actor::send_closure(self, &N5ManagerDbFixture::seed_state, id, state, std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_zero_state_file, id, std::move(boc),
                            td::PromiseCreator::lambda(std::move(after_file)));
  }

  void read_zerostate(BlockIdExt id, RootHash expected_root, bool expect_present,
                      td::Promise<td::Unit> promise) {
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, id,
                            td::PromiseCreator::lambda(
                                [db, id, expected_root, expect_present, promise = std::move(promise)](
                                    td::Result<BlockHandle> result) mutable {
      if (!expect_present) {
        if (result.is_ok() || result.error().code() != ErrorCode::notready) {
          return promise.set_error(td::Status::Error("N5 empty DB unexpectedly has the zerostate handle"));
        }
        return promise.set_value(td::Unit());
      }
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("N5 persisted handle: "));
      }
      auto handle = result.move_as_ok();
      if (handle->id() != id || !handle->received_state() || handle->state() != expected_root) {
        return promise.set_error(td::Status::Error("N5 persisted handle lost zerostate root or state flag"));
      }
      td::actor::send_closure(db, &Db::get_block_state, ConstBlockHandle{handle},
                              td::PromiseCreator::lambda(
                                  [expected_root, promise = std::move(promise)](
                                      td::Result<td::Ref<ShardState>> state_result) mutable {
        if (state_result.is_error() || state_result.ok()->root_hash() != expected_root) {
          return promise.set_error(td::Status::Error("N5 persisted state root is unavailable or changed"));
        }
        promise.set_value(td::Unit());
      }));
    }));
  }

 private:
  void seed_state(BlockIdExt id, td::Ref<MasterchainStateQ> state, td::Promise<td::Unit> promise) {
    auto handle = create_empty_block_handle(id);
    handle->set_logical_time(state->get_logical_time());
    handle->set_unix_time(state->get_unix_time());
    handle->set_split(false);
    handle->set_merge(false);
    handle->set_is_key_block(true);
    handle->set_applied();
    handle->set_applied_stored();
    handle->set_processed();
    last_masterchain_state_ = state;
    last_masterchain_block_id_ = id;
    last_masterchain_block_handle_ = handle;
    last_key_block_handle_ = handle;
    last_known_key_block_handle_ = handle;
    auto after_state = [self = actor_id(this), handle, promise = std::move(promise)](
                           td::Result<td::Ref<ShardState>> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error());
      }
      td::actor::send_closure(self, &N5ManagerDbFixture::seed_handle, handle, std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_block_state, handle, td::Ref<ShardState>{state}, vm::StoreCellHint{},
                            td::PromiseCreator::lambda(std::move(after_state)));
  }

  void seed_handle(BlockHandle handle, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::store_block_handle, std::move(handle), std::move(promise));
  }
};

}  // namespace tos::validator
