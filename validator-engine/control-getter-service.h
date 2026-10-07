/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "td/actor/actor.h"

#include "control-getter-executor.h"
#include "control-getter-read.h"

namespace tos::control_getter {
struct LoadedState {
  BlockIdExt block;
  td::Ref<vm::Cell> root;
};
using Lookup = std::function<void(td::optional<BlockIdExt>, td::Promise<LoadedState>)>;

// Uses the authenticated control permission mask supplied by the engine. Lookup
// is lazy: no state is requested or retained until an executor slot is reserved.
class Service final : public td::actor::Actor {
 public:
  explicit Service(Lookup lookup);
  void query(td::uint32 permissions, td::int32 flags, td::optional<BlockIdExt> block, Request request,
             td::Promise<td::BufferSlice> promise);

 private:
  void start_up() override;
  Lookup lookup_;
  td::Result<std::shared_ptr<Executor>> executor_{td::Status::Error("control getter executor not started")};
};
}  // namespace tos::control_getter
