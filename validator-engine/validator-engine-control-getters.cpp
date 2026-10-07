/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "tos/tos-tl.hpp"

#include "validator-engine.hpp"

namespace {
td::Status ready(td::uint32 permissions, td::int32 flags,
                 const tos::tl_object_ptr<tos::tos_api::tosNode_blockIdExt>& block) {
  if (!(permissions & ValidatorEnginePermissions::vep_default)) {
    return td::Status::Error("not authorized");
  }
  if ((flags & ~1) || static_cast<bool>(flags & 1) != static_cast<bool>(block)) {
    return td::Status::Error("invalid control getter flags or block");
  }
  return td::Status::OK();
}
}  // namespace

void ValidatorEngine::start_control_getters() {
  auto manager = validator_manager_.get();
  tos::control_getter::Lookup lookup = [manager](td::optional<tos::BlockIdExt> requested,
                                                 td::Promise<tos::control_getter::LoadedState> promise) {
    if (requested) {
      td::actor::send_closure(
          manager, &tos::validator::ValidatorManagerInterface::get_shard_state_from_db_short, requested.value(),
          [promise = std::move(promise)](td::Result<td::Ref<tos::validator::ShardState>> state) mutable {
            if (state.is_error()) {
              promise.set_error(state.move_as_error());
              return;
            }
            auto value = state.move_as_ok();
            if (value.is_null()) {
              promise.set_error(td::Status::Error("requested masterchain state is unavailable"));
              return;
            }
            promise.set_value(tos::control_getter::LoadedState{value->get_block_id(), value->root_cell()});
          });
    } else {
      td::actor::send_closure(
          manager, &tos::validator::ValidatorManagerInterface::get_top_masterchain_state_block,
          [promise = std::move(promise)](
              td::Result<std::pair<td::Ref<tos::validator::MasterchainState>, tos::BlockIdExt>> state) mutable {
            if (state.is_error()) {
              promise.set_error(state.move_as_error());
              return;
            }
            auto value = state.move_as_ok();
            if (value.first.is_null() || value.first->get_block_id() != value.second) {
              promise.set_error(td::Status::Error("incoherent applied masterchain state"));
              return;
            }
            promise.set_value(tos::control_getter::LoadedState{value.second, value.first->root_cell()});
          });
    }
  };
  control_getters_ = td::actor::create_actor<tos::control_getter::Service>("control-getters", std::move(lookup));
}

void ValidatorEngine::run_control_query(tos::tos_api::engine_validator_getElectorState& query, td::BufferSlice,
                                        tos::PublicKeyHash, td::uint32 permissions,
                                        td::Promise<td::BufferSlice> promise) {
  auto status = ready(permissions, query.flags_, query.block_);
  if (status.is_error()) {
    promise.set_value(create_control_query_error(std::move(status)));
    return;
  }
  if (!started_ || control_getters_.empty()) {
    promise.set_value(create_control_query_error(td::Status::Error("control getter service not started")));
    return;
  }
  td::optional<tos::BlockIdExt> block;
  if (query.flags_ & 1) {
    block = tos::create_block_id(query.block_);
  }
  tos::control_getter::Request request{tos::control_getter::ReadKind::Elector, std::move(query.wallets_), {}};
  td::actor::send_closure(control_getters_, &tos::control_getter::Service::query, permissions, query.flags_, block,
                          std::move(request), std::move(promise));
}
void ValidatorEngine::run_control_query(tos::tos_api::engine_validator_getConfigProposals& query, td::BufferSlice,
                                        tos::PublicKeyHash, td::uint32 permissions,
                                        td::Promise<td::BufferSlice> promise) {
  auto status = ready(permissions, query.flags_, query.block_);
  if (status.is_error()) {
    promise.set_value(create_control_query_error(std::move(status)));
    return;
  }
  if (!started_ || control_getters_.empty()) {
    promise.set_value(create_control_query_error(td::Status::Error("control getter service not started")));
    return;
  }
  td::optional<tos::BlockIdExt> block;
  if (query.flags_ & 1) {
    block = tos::create_block_id(query.block_);
  }
  tos::control_getter::Request request{tos::control_getter::ReadKind::Proposals, {}, {}};
  td::actor::send_closure(control_getters_, &tos::control_getter::Service::query, permissions, query.flags_, block,
                          std::move(request), std::move(promise));
}
void ValidatorEngine::run_control_query(tos::tos_api::engine_validator_getConfigProposal& query, td::BufferSlice,
                                        tos::PublicKeyHash, td::uint32 permissions,
                                        td::Promise<td::BufferSlice> promise) {
  auto status = ready(permissions, query.flags_, query.block_);
  if (status.is_error()) {
    promise.set_value(create_control_query_error(std::move(status)));
    return;
  }
  if (!started_ || control_getters_.empty()) {
    promise.set_value(create_control_query_error(td::Status::Error("control getter service not started")));
    return;
  }
  td::optional<tos::BlockIdExt> block;
  if (query.flags_ & 1) {
    block = tos::create_block_id(query.block_);
  }
  tos::control_getter::Request request{tos::control_getter::ReadKind::Proposal, {}, query.hash_};
  td::actor::send_closure(control_getters_, &tos::control_getter::Service::query, permissions, query.flags_, block,
                          std::move(request), std::move(promise));
}
