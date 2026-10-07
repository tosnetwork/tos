/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>

#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"

#include "control-getter-service.h"

namespace tos::control_getter {
namespace {
constexpr td::uint32 kReadPermission = 1;
constexpr double kQueryTimeout = 30;

td::BufferSlice error(td::Status status) {
  return create_serialize_tl_object<tos_api::engine_validator_controlQueryError>(status.code(), status.message().str());
}

class Query final : public td::actor::Actor {
 public:
  Query(std::shared_ptr<Executor> executor, std::unique_ptr<Executor::Admission> admission, Lookup lookup,
        td::optional<BlockIdExt> requested, Request request, td::Promise<td::BufferSlice> promise)
      : executor_(std::move(executor))
      , admission_(std::move(admission))
      , lookup_(std::move(lookup))
      , requested_(requested)
      , request_(std::move(request))
      , promise_(std::move(promise)) {
  }
  void loaded(td::Result<LoadedState> state) {
    if (state.is_error()) {
      fail(state.move_as_error());
      return;
    }
    auto value = state.move_as_ok();
    if (!value.block.is_masterchain() || (requested_ && requested_.value() != value.block)) {
      fail(td::Status::Error("control getter state answers for another block"));
      return;
    }
    // Executor threads have no actor scheduler context. Publish a flat result;
    // the query actor completes its promise on its own scheduler.
    struct Output {
      td::BufferSlice bytes;
      td::Status status;
      std::atomic<bool> done{false};
    };
    auto output = std::make_shared<Output>();
    completed_ = [output]() -> td::optional<std::pair<td::Status, td::BufferSlice>> {
      if (!output->done.load(std::memory_order_acquire)) {
        return {};
      }
      return std::make_pair(std::move(output->status), std::move(output->bytes));
    };
    auto status = admission_->dispatch(
        [value = std::move(value), request = std::move(request_), output]() -> td::Status {
          TRY_RESULT(snapshot, Snapshot::create(value.block, value.root));
          TRY_RESULT(reply, read(*snapshot, request));
          output->bytes = std::move(reply);
          return td::Status::OK();
        },
        [output](td::Status status) {
          output->status = std::move(status);
          output->done.store(true, std::memory_order_release);
        });
    if (status.is_error()) {
      fail(std::move(status));
    }
  }
  void completed(td::Status status, td::BufferSlice bytes) {
    if (status.is_error()) {
      fail(std::move(status));
      return;
    }
    promise_.set_value(std::move(bytes));
    stop();
  }

 private:
  void start_up() override {
    deadline_ = td::Timestamp::in(kQueryTimeout);
    alarm_timestamp() = td::Timestamp::in(0.01);
    lookup_(requested_, [self = actor_id(this)](td::Result<LoadedState> result) {
      td::actor::send_closure(self, &Query::loaded, std::move(result));
    });
  }
  void alarm() override {
    if (completed_) {
      auto result = completed_();
      if (result) {
        auto value = std::move(result.value());
        completed(std::move(value.first), std::move(value.second));
        return;
      }
    }
    if (deadline_.is_in_past()) {
      fail(td::Status::Error("control getter query timed out"));
      return;
    }
    alarm_timestamp() = td::Timestamp::in(0.01);
  }
  void fail(td::Status status) {
    admission_->cancel();
    promise_.set_value(error(std::move(status)));
    stop();
  }
  td::Timestamp deadline_;
  std::function<td::optional<std::pair<td::Status, td::BufferSlice>>()> completed_;
  std::shared_ptr<Executor> executor_;
  std::unique_ptr<Executor::Admission> admission_;
  Lookup lookup_;
  td::optional<BlockIdExt> requested_;
  Request request_;
  td::Promise<td::BufferSlice> promise_;
};
}  // namespace

Service::Service(Lookup lookup) : lookup_(std::move(lookup)) {
}
void Service::start_up() {
  auto created = Executor::create();
  if (created.is_error()) {
    executor_ = created.move_as_error();
  } else {
    executor_ = std::shared_ptr<Executor>{created.move_as_ok()};
  }
}
void Service::query(td::uint32 permissions, td::int32 flags, td::optional<BlockIdExt> block, Request request,
                    td::Promise<td::BufferSlice> promise) {
  if (!(permissions & kReadPermission)) {
    promise.set_value(error(td::Status::Error("not authorized")));
    return;
  }
  if ((flags & ~1) || static_cast<bool>(flags & 1) != static_cast<bool>(block) ||
      (block && (!block.value().is_valid_full() || !block.value().is_masterchain() ||
                 block.value().shard_full() != ShardIdFull{masterchainId, shardIdAll}))) {
    promise.set_value(error(td::Status::Error("invalid control getter flags or block")));
    return;
  }
  if (request.kind == ReadKind::Elector) {
    auto valid = validate_wallets(request.wallets);
    if (valid.is_error()) {
      promise.set_value(error(std::move(valid)));
      return;
    }
  }
  if (executor_.is_error()) {
    promise.set_value(error(executor_.error().clone()));
    return;
  }
  auto admission = executor_.ok()->admit();
  if (admission.is_error()) {
    promise.set_value(error(admission.move_as_error()));
    return;
  }
  td::actor::create_actor<Query>("control-getter-query", executor_.ok(), admission.move_as_ok(), lookup_, block,
                                 std::move(request), std::move(promise))
      .release();
}
}  // namespace tos::control_getter
