/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "startup-probe.hpp"

#include "common/checksum.h"
#include "tos/tos-io.hpp"
#include "tos/tos-tl.hpp"
#include "validator/full-node-serializer.hpp"
#include "validator/full-node.h"

namespace tos {

namespace validator {

namespace fullnode {

using startup_catchup::ProbeAnswer;

ProbeNextMasterchainBlock::ProbeNextMasterchainBlock(adnl::AdnlNodeIdShort local_id,
                                                     overlay::OverlayIdShort overlay_id, BlockIdExt prev,
                                                     adnl::AdnlNodeIdShort peer, td::Timestamp deadline,
                                                     td::actor::ActorId<ValidatorManagerInterface> manager,
                                                     td::actor::ActorId<adnl::AdnlSenderInterface> rldp,
                                                     td::actor::ActorId<overlay::Overlays> overlays,
                                                     td::Promise<ProbeAnswer> promise)
    : local_id_(local_id)
    , overlay_id_(overlay_id)
    , prev_(prev)
    , peer_(peer)
    , deadline_(deadline)
    , manager_(manager)
    , rldp_(rldp)
    , overlays_(overlays)
    , promise_(std::move(promise)) {
}

size_t ProbeNextMasterchainBlock::max_answer_size() {
  return FullNode::max_proof_size() + FullNode::max_block_size() + 128;
}

double ProbeNextMasterchainBlock::clock_now() const {
  return td::Time::now();
}

std::optional<td::Timestamp> ProbeNextMasterchainBlock::bounded_timeout(double cap_seconds) const {
  double left = deadline_.at() - clock_now();
  if (left <= 0) {
    return std::nullopt;
  }
  return td::Timestamp::in(left < cap_seconds ? left : cap_seconds);
}

void ProbeNextMasterchainBlock::send_query(td::BufferSlice query, size_t max_size, td::Timestamp timeout,
                                           td::Promise<td::BufferSlice> promise) {
  td::actor::send_closure(overlays_, &overlay::Overlays::send_query_via, peer_, local_id_, overlay_id_,
                          "startup_probe_next_block", std::move(promise), timeout, std::move(query), max_size, rldp_);
}

void ProbeNextMasterchainBlock::wait_prev_state(td::Timestamp timeout, td::Promise<td::Ref<ShardState>> promise) {
  td::actor::send_closure(manager_, &ValidatorManagerInterface::wait_block_state_short, prev_, 0, timeout, true,
                          std::move(promise));
}

void ProbeNextMasterchainBlock::verify_successor(BlockIdExt next, td::BufferSlice proof,
                                                 td::Promise<startup_catchup::SuccessorVerdict> promise) {
  td::actor::send_closure(manager_, &ValidatorManagerInterface::verify_startup_probe_successor, prev_, next,
                          std::move(proof), deadline_, std::move(promise));
}

void ProbeNextMasterchainBlock::start_up() {
  [](ProbeNextMasterchainBlock *self) -> td::actor::Task<> {
    auto answer = co_await self->run();
    VLOG(FULL_NODE_DEBUG) << "startup successor probe of " << self->peer_ << " after " << self->prev_.id << ": "
                          << startup_catchup::probe_answer_name(answer.kind)
                          << (answer.detail.empty() ? "" : " (" + answer.detail + ")");
    self->promise_.set_value(std::move(answer));
    self->stop();
    co_return td::Unit{};
  }(this)
                                             .start()
                                             .detach();
}

td::actor::Task<ProbeAnswer> ProbeNextMasterchainBlock::run() {
  auto query_timeout = bounded_timeout(startup_catchup::kProbeQueryTimeoutSeconds);
  if (!query_timeout) {
    co_return ProbeAnswer::inconclusive("discovery window closed before the query");
  }
  auto query = create_serialize_tl_object<tos_api::tosNode_downloadNextBlockFull>(create_tl_block_id(prev_));
  auto [task, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
  send_query(std::move(query), max_answer_size(), *query_timeout, std::move(promise));
  auto response = co_await std::move(task).wrap();
  if (response.is_error()) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "query: " << response.error());
  }
  auto fetched = fetch_tl_object<tos_api::tosNode_DataFull>(response.move_as_ok(), true);
  if (fetched.is_error()) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "malformed answer: " << fetched.error());
  }
  auto obj = fetched.move_as_ok();
  if (obj->get_id() == tos_api::tosNode_dataFullEmpty::ID) {
    co_return ProbeAnswer::empty();
  }
  auto requires_state = need_state_for_decompression(*obj);
  if (requires_state.is_error()) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "malformed answer: " << requires_state.error());
  }
  td::Ref<vm::Cell> prev_state_root;
  if (requires_state.ok()) {
    if (obj->get_id() != tos_api::tosNode_dataFullCompressedV2::ID) {
      co_return ProbeAnswer::inconclusive("malformed answer: state-dependent encoding of an unexpected kind");
    }
    auto compressed_v2 = static_cast<const tos_api::tosNode_dataFullCompressedV2 *>(obj.get());
    BlockIdExt claimed = create_block_id(compressed_v2->id_);
    auto prev_blocks = extract_prev_blocks_from_proof(compressed_v2->proof_.as_slice(), claimed);
    if (prev_blocks.is_error()) {
      co_return ProbeAnswer::inconclusive(PSTRING() << "malformed proof: " << prev_blocks.error());
    }
    if (prev_blocks.ok() != std::vector<BlockIdExt>{prev_}) {
      co_return ProbeAnswer::inconclusive("a successor of a different block");
    }
    auto state_timeout = bounded_timeout(startup_catchup::kProbeQueryTimeoutSeconds);
    if (!state_timeout) {
      co_return ProbeAnswer::inconclusive("discovery window closed before the predecessor state");
    }
    auto [state_task, state_promise] = td::actor::StartedTask<td::Ref<ShardState>>::make_bridge();
    wait_prev_state(*state_timeout, std::move(state_promise));
    auto state = co_await std::move(state_task).wrap();
    if (state.is_error()) {
      co_return ProbeAnswer::inconclusive(PSTRING() << "predecessor state: " << state.error());
    }
    prev_state_root = state.ok()->root_cell();
  }
  BlockIdExt id;
  td::BufferSlice proof;
  td::BufferSlice data;
  bool is_link = false;
  auto decoded = deserialize_block_full(*obj, id, proof, data, is_link, overlay::Overlays::max_fec_broadcast_size(),
                                        prev_state_root);
  if (decoded.is_error()) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "malformed answer: " << decoded);
  }
  if (is_link) {
    co_return ProbeAnswer::inconclusive("a proof link, not a proof");
  }
  if (td::sha256_bits256(data.as_slice()) != id.file_hash) {
    co_return ProbeAnswer::inconclusive("block data does not match its file hash");
  }
  if (!id.is_masterchain() || id.seqno() != prev_.seqno() + 1) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "not the next masterchain block: " << id.to_str());
  }
  auto [verdict_task, verdict_promise] = td::actor::StartedTask<startup_catchup::SuccessorVerdict>::make_bridge();
  verify_successor(id, std::move(proof), std::move(verdict_promise));
  auto verdict = co_await std::move(verdict_task).wrap();
  if (verdict.is_error()) {
    co_return ProbeAnswer::inconclusive(PSTRING() << "proof: " << verdict.error());
  }
  if (verdict.ok() == startup_catchup::SuccessorVerdict::FrontierMoved) {
    co_return ProbeAnswer::frontier_moved();
  }
  co_return ProbeAnswer::verified(id);
}

StartupDiscoveryRound::StartupDiscoveryRound(BlockIdExt prev, td::Timestamp deadline, td::uint32 probe_budget,
                                             std::unique_ptr<Transport> transport,
                                             td::Promise<startup_catchup::RoundResult> promise)
    : prev_(prev)
    , deadline_(deadline)
    , transport_(std::move(transport))
    , promise_(std::move(promise))
    , round_(deadline.at(), startup_catchup::kProbePeers, probe_budget) {
}

void StartupDiscoveryRound::start_up() {
  request_peers();
  arm();
}

void StartupDiscoveryRound::arm() {
  auto at = deadline_;
  if (next_reselect_ && next_reselect_.at() < at.at()) {
    at = next_reselect_;
  }
  alarm_timestamp() = at;
}

void StartupDiscoveryRound::request_peers() {
  if (peers_requested_ || !round_.wants_peers(td::Time::now())) {
    return;
  }
  peers_requested_ = true;
  transport_->get_peers(2 * startup_catchup::kProbePeers,
                        [SelfId = actor_id(this)](td::Result<std::vector<adnl::AdnlNodeIdShort>> R) {
                          td::actor::send_closure(SelfId, &StartupDiscoveryRound::got_peers, std::move(R));
                        });
}

void StartupDiscoveryRound::got_peers(td::Result<std::vector<adnl::AdnlNodeIdShort>> R) {
  peers_requested_ = false;
  std::vector<adnl::AdnlNodeIdShort> chosen;
  if (R.is_ok()) {
    chosen = round_.select(td::Time::now(), R.ok());
  }
  for (auto &peer : chosen) {
    transport_->probe(peer, prev_, deadline_,
                      [SelfId = actor_id(this), peer](td::Result<startup_catchup::ProbeAnswer> answer) {
                        td::actor::send_closure(SelfId, &StartupDiscoveryRound::got_answer, peer, std::move(answer));
                      });
  }
  if (round_.wants_peers(td::Time::now())) {
    // Too few peers so far: the overlay may still be filling right after start.
    next_reselect_ = td::Timestamp::in(startup_catchup::kPeerReselectSeconds);
    arm();
  }
  maybe_decide();
}

void StartupDiscoveryRound::got_answer(adnl::AdnlNodeIdShort peer, td::Result<startup_catchup::ProbeAnswer> R) {
  if (R.is_error()) {
    round_.on_answer(peer, startup_catchup::ProbeAnswer::inconclusive(R.error().to_string()));
  } else {
    round_.on_answer(peer, R.ok());
  }
  maybe_decide();
  if (!promise_) {
    return;
  }
  // An inconclusive answer freed its slot: draw a new peer now.
  request_peers();
}

void StartupDiscoveryRound::alarm() {
  if (next_reselect_ && next_reselect_.is_in_past()) {
    next_reselect_ = td::Timestamp::never();
    request_peers();
  }
  maybe_decide();
  if (promise_) {
    arm();
  }
}

void StartupDiscoveryRound::maybe_decide() {
  if (!promise_) {
    return;
  }
  auto now = td::Time::now();
  if (!round_.decided(now)) {
    return;
  }
  auto result = round_.result(now);
  promise_.set_value(std::move(result));
  stop();
}

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
