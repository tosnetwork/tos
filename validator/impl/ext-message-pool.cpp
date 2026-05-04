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
*/
#include "td/utils/Random.h"

#include "block/workchain-execution-dispatch.h"
#include "config.hpp"
#include "ext-message-pool.hpp"
#include "external-message.hpp"
#include "fabric.h"
#include "transaction.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <vector>

namespace tos::validator {

namespace {

// The pre-registry Uno short-circuit in `check_message`
// previously admitted ANY structurally-valid Uno ext_in_msg without rate
// limiting. The MineUno limiter in `uno/rpc/handlers.cpp` only fires on the
// `uno_sendMineUno` JSON-RPC path; raw `sendBoc` and `liteServer_sendMessage`
// reach `mine_uno::verify` (~50ms STARK verify each) with no throttle. Add a
// process-global token bucket here that gates ALL Uno ext-message ingress
// regardless of how the message arrives.
//
// Bucket shape mirrors `g_send_mine_uno_limiter` (5/s sustained, 20 burst)
// — same threat model. Defined locally to avoid creating a downward link
// from `validator` to `uno_workchain`. Token consumption happens before the
// expensive collator-side verify, so a flood is rejected with a cheap
// `co_return td::Status::Error` before any STARK work.
//
// We deliberately rate-limit ALL Uno ext-msg ingress (Transfer + MineUno)
// from a single bucket here rather than discriminating by body byte 0:
//   - The CellSlice walk to peek the body byte from a `vm::Cell` ref adds
//     parsing complexity inside an actor task.
//   - In production, `uno_sendTransfer` is currently unwired, so legitimate
//     Transfer ingress at this layer is rare.
//   - The JSON-RPC layer still applies its own per-method bucket before
//     this one, so honest RPC traffic is unaffected.
struct WcExtMsgRateLimiter {
    std::mutex mutex;
    uint64_t   tokens;
    uint64_t   max_tokens;
    uint64_t   refill_rate;
    uint64_t   last_refill;

    WcExtMsgRateLimiter(uint64_t max_tok, uint64_t rate)
        : tokens(max_tok), max_tokens(max_tok), refill_rate(rate),
          last_refill(now_sec()) {}

    static uint64_t now_sec() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    bool try_consume() {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t now = now_sec();
        if (now > last_refill) {
            tokens = std::min(tokens + (now - last_refill) * refill_rate, max_tokens);
            last_refill = now;
        }
        if (tokens == 0) return false;
        --tokens;
        return true;
    }
};

constexpr uint64_t kWc2IngressBurst  = 20;
constexpr uint64_t kWc2IngressPerSec = 5;
WcExtMsgRateLimiter g_wc2_ingress_limiter{kWc2IngressBurst, kWc2IngressPerSec};

// Security audit (round 16, finding #1): Transfers also run a Plonky3 STARK
// verify on the collator side (uno/core/parallel-verify.cpp:250 →
// transfer_air verify), comparable in cost to MineUno. The round-15 #3
// fix made Transfer bypass the MineUno bucket entirely, leaving
// raw-sendBoc Transfer flooding uncapped at this layer. Add a
// dedicated Transfer bucket — same shape (5/s sustained, 20 burst).
// Independent from the MineUno bucket so neither path can starve the
// other; honest RPC traffic still goes through the per-method limiter
// in uno/rpc/handlers.cpp first.
constexpr uint64_t kWc2TransferBurst  = 20;
constexpr uint64_t kWc2TransferPerSec = 5;
WcExtMsgRateLimiter g_wc2_transfer_limiter{kWc2TransferBurst, kWc2TransferPerSec};

// Per-peer Uno ingress bucket. Process-global limiters above prevent
// total Uno throughput from exceeding the configured rate, but on
// their own they let a single noisy peer drain the entire shared
// budget and starve every honest user. The per-peer bucket below is
// consumed BEFORE the global bucket: if any one peer exceeds its own
// rate, it is rejected without burning a global token, so honest peers
// keep paying the same baseline rate even while a flooder is being
// throttled.
//
// Bucket shape: 10 burst, 2 tokens/sec — strictly tighter than the
// global limiters (so the global stays a useful backstop for the
// many-peer-in-aggregate case) but still generous enough for normal
// wallet / miner traffic from one source.
//
// Storage: the map is bounded at kMaxTrackedPeers; on insert when
// full, the oldest-touched entry is evicted. Lookup is O(n) on
// eviction but expected n is very small (only peers actively sending
// Uno messages stay tracked).
constexpr uint64_t kWc2PerPeerBurst   = 10;
constexpr uint64_t kWc2PerPeerPerSec  = 2;
constexpr size_t   kMaxTrackedPeers   = 4096;

struct PublicKeyHashHasher {
  size_t operator()(const PublicKeyHash& h) const noexcept {
    // First 8 bytes of the 32-byte hash provide ~64 bits of entropy
    // and avoid pulling in a SipHash dep just for this map.
    auto s = h.as_slice();
    size_t v = 0;
    std::memcpy(&v, s.data(), sizeof(v));
    return v;
  }
};

class WcExtMsgPerPeerLimiter {
 public:
  bool try_consume(const PublicKeyHash& peer) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = buckets_.find(peer);
    if (it == buckets_.end()) {
      if (buckets_.size() >= kMaxTrackedPeers) {
        evict_oldest_locked();
      }
      it = buckets_.try_emplace(peer, kWc2PerPeerBurst, kWc2PerPeerPerSec).first;
    }
    return it->second.try_consume();
  }

 private:
  void evict_oldest_locked() {
    // Linear scan: with kMaxTrackedPeers = 4096 this is at most ~10us
    // per eviction and only fires when a new peer arrives at a full
    // map. A full LRU would be sleeker but the map churn is dominated
    // by sustained-rate honest traffic, not eviction.
    auto oldest = buckets_.begin();
    uint64_t oldest_t = oldest->second.last_refill;
    for (auto it = std::next(buckets_.begin()); it != buckets_.end(); ++it) {
      if (it->second.last_refill < oldest_t) {
        oldest = it;
        oldest_t = it->second.last_refill;
      }
    }
    buckets_.erase(oldest);
  }

  std::mutex mutex_;
  std::unordered_map<PublicKeyHash, WcExtMsgRateLimiter, PublicKeyHashHasher> buckets_;
};

WcExtMsgPerPeerLimiter g_wc2_per_peer_limiter;

td::Result<std::optional<block::ResolvedWorkchainExecution>> resolve_message_workchain_execution(
    const td::Ref<MasterchainState>& state, WorkchainId wc) {
  if (state.is_null()) {
    return td::Status::Error(ErrorCode::notready, "masterchain state is not ready");
  }
  TRY_RESULT(holder, state->get_config_holder());
  auto* holder_q = dynamic_cast<const ConfigHolderQ*>(holder.get());
  if (holder_q == nullptr || holder_q->get_config() == nullptr) {
    return td::Status::Error("masterchain config holder does not expose block::Config");
  }
  const block::Config& config = *holder_q->get_config();
  return block::default_workchain_execution_registry().resolve_workchain(
      config.get_workchain_list(), wc, config);
}

bool is_uno_execution(const block::ResolvedWorkchainExecution& execution) {
  auto key = block::workchain_engine_key_from_descriptor(execution.descriptor);
  return block::workchain_engine_key_is_uno(key);
}

td::Status reject_special_cells_for_custom_compute(td::Ref<vm::Cell> root,
                                                   block::SizeLimitsConfig::ExtMsgLimits limits) {
  std::unordered_set<const vm::Cell*> visited;
  std::vector<td::Ref<vm::Cell>> stack{std::move(root)};
  const size_t cells_from_size = static_cast<size_t>(limits.max_size) / 64u;
  const size_t max_scanned_cells =
      std::min(static_cast<size_t>(65536), std::max(static_cast<size_t>(4096), cells_from_size));
  size_t popped = 0;
  while (!stack.empty()) {
    auto cell = std::move(stack.back());
    stack.pop_back();
    if (cell.is_null() || !visited.insert(cell.get()).second) {
      continue;
    }
    if (++popped > max_scanned_cells) {
      return td::Status::Error("external message tree too large for special-cell scan");
    }
    bool special = false;
    vm::CellSlice cs;
    try {
      cs = vm::load_cell_slice_special(cell, special);
    } catch (...) {
      return td::Status::Error("external message tree contains an unloadable cell");
    }
    if (special) {
      return td::Status::Error("external message tree contains a special cell");
    }
    for (unsigned i = 0, n = cs.size_refs(); i < n; ++i) {
      stack.push_back(cs.prefetch_ref(i));
    }
  }
  return td::Status::OK();
}

}  // namespace

td::actor::Task<ExtMessagePool::CheckResult> ExtMessagePool::check_add_external_message(td::BufferSlice data,
                                                                                        int priority,
                                                                                        bool add_to_mempool,
                                                                                        td::optional<PublicKeyHash> source_peer) {
  if (last_masterchain_state_.is_null()) {
    co_return td::Status::Error(ErrorCode::notready, "not ready");
  }
  auto message = co_await create_ext_message(std::move(data), last_masterchain_state_->get_ext_msg_limits());
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();
  if (checked_ext_msg_counter_.get_msg_count(wc, addr) >= MAX_EXT_MSG_PER_ADDR) {
    co_return td::Status::Error(PSTRING() << "too many external messages to address " << wc << ":" << addr.to_hex());
  }
  td::optional<td::uint32> msg_seqno;
  auto result = co_await check_message(message, msg_seqno, std::move(source_peer)).wrap();
  ++(result.is_ok() ? total_check_ext_messages_ok_ : total_check_ext_messages_error_);
  if (result.is_error()) {
    co_return result.move_as_error();
  }
  if (checked_ext_msg_counter_.inc_msg_count(wc, addr) > MAX_EXT_MSG_PER_ADDR) {
    co_return td::Status::Error(PSTRING() << "too many external messages to address " << wc << ":" << addr.to_hex());
  }
  if (add_to_mempool) {
    add_message_to_mempool(message, priority, msg_seqno);
  }
  co_return result.move_as_ok();
}

void ExtMessagePool::install_collator_queue(ShardIdFull shard, std::unique_ptr<ExtMsgCallback> callback) {
  // Compute shard key range [lo, hi) for splitting
  td::uint64 lo_prefix = shard.shard & (shard.shard - 1);
  td::uint64 hi_prefix_plus1 = (shard.shard | (shard.shard - 1)) + 1;  // may overflow to 0
  MessageId shard_lo{AccountIdPrefixFull{shard.workchain, lo_prefix}, Bits256::zero()};
  MessageId shard_hi{AccountIdPrefixFull{hi_prefix_plus1 == 0 ? shard.workchain + 1 : shard.workchain, hi_prefix_plus1},
                     Bits256::zero()};

  // Take O(log n) shard slices from each priority level
  using Treap = td::PersistentTreap<MessageId, std::shared_ptr<MempoolMsg>>;
  using Snapshot = std::vector<std::pair<int, Treap>>;
  Snapshot snapshot;
  for (auto it = ext_msgs_.rbegin(); it != ext_msgs_.rend(); ++it) {
    auto [_, in_shard, __] = it->second.ext_messages_.split_range(shard_lo, shard_hi);
    if (!in_shard.empty()) {
      snapshot.emplace_back(it->first, std::move(in_shard));
    }
  }

  // Spawn a coroutine that drains the shard slices randomly into the queue
  auto push_existing = [](ExtMsgQueue queue, td::CancellationToken token, ShardIdFull shard, Snapshot snapshot,
                          bool sync_only) -> td::actor::Task<> {
    SCOPE_EXIT {
      if (sync_only) {
        queue.close();
      }
    };
    td::Timer t;
    size_t pushed = 0;
    for (auto &[priority, treap] : snapshot) {
      while (!treap.empty()) {
        if (token.check().is_error()) {
          co_return td::Unit{};
        }
        size_t idx = td::Random::fast_uint32() % treap.size();
        auto [key, msg] = treap.at(idx);
        treap = treap.erase_at(idx);  // local snapshot only
        if (msg->expired() || !msg->is_active()) {
          continue;
        }
        bool ok = co_await queue.push(std::make_pair(msg->message, priority));
        if (!ok) {
          co_return td::Unit{};
        }
        ++pushed;
      }
    }
    LOG(WARNING) << "install_collator_queue: pushed " << pushed << " existing messages to shard " << shard.to_str()
                 << " in " << t.elapsed() << "s";
    co_return td::Unit{};
  };
  push_existing(callback->queue, callback->cancellation_token, shard, std::move(snapshot), callback->sync_only)
      .start()
      .detach();

  if (!callback->sync_only) {
    alarm_timestamp().relax(callback->timeout);
    callbacks_.push_back(std::move(callback));
  }
}

void ExtMessagePool::cleanup_external_messages(ShardIdFull shard) {
  // Clean up expired messages
  for (auto &[priority, msgs] : ext_msgs_) {
    std::vector<MessageId> to_erase;
    for (size_t i = 0; i < msgs.ext_messages_.size(); i++) {
      auto [key, msg] = msgs.ext_messages_.at(i);
      if (shard_contains(shard, key.dst) && msg->expired()) {
        to_erase.push_back(key);
      }
    }
    for (auto &id : to_erase) {
      erase_message(priority, id);
    }
  }
}

void ExtMessagePool::cleanup_expired_messages_all_workchains() {
  // The alarm previously called
  // `cleanup_external_messages` only for masterchain (-1) and basechain (0),
  // so wc=1 (EVM) and wc=2 (UNO) ext-msgs accepted via the
  // `check_message` short-circuit never expired and accumulated forever.
  // Sweep ALL workchains here by message expiry alone, not shard.
  for (auto &[priority, msgs] : ext_msgs_) {
    std::vector<MessageId> to_erase;
    for (size_t i = 0; i < msgs.ext_messages_.size(); i++) {
      auto [key, msg] = msgs.ext_messages_.at(i);
      if (msg->expired()) {
        to_erase.push_back(key);
      }
    }
    for (auto &id : to_erase) {
      erase_message(priority, id);
    }
  }
}

void ExtMessagePool::complete_external_messages(std::vector<ExtMessage::Hash> to_delay,
                                                std::vector<ExtMessage::Hash> to_delete) {
  for (auto &hash : to_delete) {
    auto it = ext_messages_hashes_.find(hash);
    if (it != ext_messages_hashes_.end()) {
      erase_message(it->second.first, it->second.second);
    }
  }
  for (auto &hash : to_delay) {
    auto it = ext_messages_hashes_.find(hash);
    if (it != ext_messages_hashes_.end()) {
      int priority = it->second.first;
      auto msg_id = it->second.second;
      auto &msgs = ext_msgs_[priority];
      auto msg_opt = msgs.ext_messages_.find(msg_id);
      if (msg_opt && msgs.ext_messages_.size() < SOFT_MEMPOOL_LIMIT && msg_opt.value()->can_postpone()) {
        msg_opt.value()->postpone();
      } else {
        erase_message(priority, msg_id);
      }
    }
  }
}

void ExtMessagePool::erase_external_messages(std::vector<ExtMessage::Hash> to_delete) {
  applied_ext_msgs_delete_requests_ += to_delete.size();
  for (auto &hash : to_delete) {
    auto it = ext_messages_hashes_norm_.find(hash);
    if (it != ext_messages_hashes_norm_.end()) {
      auto ids = it->second;
      for (const auto &message_id : ids) {
        if (erase_message(message_id.priority, message_id.id)) {
          ++applied_ext_msgs_deleted_;
        }
      }
    }
  }
}

bool ExtMessagePool::erase_message(int priority, const MessageId &id) {
  auto it_priority = ext_msgs_.find(priority);
  if (it_priority == ext_msgs_.end()) {
    return false;
  }
  auto &msgs = it_priority->second;
  auto msg_opt = msgs.ext_messages_.find(id);
  if (!msg_opt) {
    return false;
  }

  auto address = msg_opt.value()->address();
  auto hash_norm = msg_opt.value()->hash_norm;
  // Remove the outer per-address index
  // entry once its inner hash-set drains to empty. Without this, a stream
  // of accepted-then-erased messages to distinct destinations grew the
  // `ext_addr_messages_` map without bound.
  auto addr_it = msgs.ext_addr_messages_.find(address);
  if (addr_it != msgs.ext_addr_messages_.end()) {
    addr_it->second.erase(id.hash);
    if (addr_it->second.empty()) {
      msgs.ext_addr_messages_.erase(addr_it);
    }
  }
  msgs.ext_messages_ = msgs.ext_messages_.erase(id);
  ext_messages_hashes_.erase(id.hash);

  auto it_norm = ext_messages_hashes_norm_.find(hash_norm);
  if (it_norm != ext_messages_hashes_norm_.end()) {
    it_norm->second.erase(NormalizedMessageId{priority, id});
    if (it_norm->second.empty()) {
      ext_messages_hashes_norm_.erase(it_norm);
    }
  }
  return true;
}

std::vector<std::pair<std::string, std::string>> ExtMessagePool::prepare_stats() {
  std::vector<std::pair<std::string, std::string>> vec;
  vec.emplace_back("total.ext_msg_check",
                   PSTRING() << "ok:" << total_check_ext_messages_ok_ << " error:" << total_check_ext_messages_error_);
  vec.emplace_back("total.ext_msg_applied_cleanup", PSTRING() << "requested:" << applied_ext_msgs_delete_requests_
                                                              << " deleted:" << applied_ext_msgs_deleted_);
  return vec;
}

void ExtMessagePool::alarm() {
  if (cleanup_mempool_at_.is_in_past()) {
    // The previous alarm only swept
    // masterchain (-1) and basechain (0). Use the workchain-agnostic
    // sweep so wc=1 / wc=2 messages also expire after their 600s TTL.
    cleanup_expired_messages_all_workchains();
    cleanup_mempool_at_ = td::Timestamp::in(250.0);
  }
  alarm_timestamp().relax(cleanup_mempool_at_);
  std::erase_if(callbacks_, [&](const std::unique_ptr<ExtMsgCallback> &callback) -> bool {
    if (callback->timeout && callback->timeout.is_in_past()) {
      return true;
    }
    alarm_timestamp().relax(callback->timeout);
    return false;
  });
}

void ExtMessagePool::add_message_to_mempool(td::Ref<ExtMessage> message, int priority,
                                            td::optional<td::uint32> msg_seqno) {
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();
  auto &msgs = ext_msgs_[priority];
  if (msgs.ext_messages_.size() > opts_->max_mempool_num()) {
    LOG(INFO) << "cannot add message addr=" << wc << ":" << addr.to_hex() << " prio=" << priority
              << " to mempool: mempool is full (limit=" << opts_->max_mempool_num() << ")";
    return;
  }
  auto msg = std::make_shared<MempoolMsg>(message);
  msg->msg_seqno = msg_seqno;
  MessageId id{message->shard(), message->hash()};
  auto address = msg->address();
  auto it = msgs.ext_addr_messages_.find(address);
  if (it != msgs.ext_addr_messages_.end() && it->second.size() >= PER_ADDRESS_LIMIT) {
    LOG(INFO) << "cannot add message addr=" << wc << ":" << addr.to_hex() << " prio=" << priority
              << " to mempool: per address limit reached (limit=" << PER_ADDRESS_LIMIT << ")";
    return;
  }
  auto it2 = ext_messages_hashes_.find(id.hash);
  if (it2 != ext_messages_hashes_.end()) {
    int old_priority = it2->second.first;
    if (old_priority >= priority) {
      LOG(INFO) << "cannot add message addr=" << wc << ":" << addr.to_hex() << " prio=" << priority
                << " to mempool: already exists";
      return;
    }
    erase_message(old_priority, id);
  }
  auto hash_norm = msg->hash_norm;
  msgs.ext_messages_ = msgs.ext_messages_.insert(id, std::move(msg));
  msgs.ext_addr_messages_[address].emplace(id.hash, id);
  ext_messages_hashes_[id.hash] = {priority, id};
  ext_messages_hashes_norm_[hash_norm].insert(NormalizedMessageId{priority, id});
  LOG(INFO) << "adding message addr=" << wc << ":" << addr.to_hex() << " prio=" << priority << " to mempool";
  std::erase_if(callbacks_, [&](const std::unique_ptr<ExtMsgCallback> &callback) -> bool {
    if (callback->cancellation_token.check().is_error()) {
      return true;
    }
    if (shard_contains(callback->shard, message->shard())) {
      callback->queue.try_push(std::make_pair(message, priority)).detach();
    }
    return false;
  });
}

td::actor::Task<ExtMessagePool::CheckResult> ExtMessagePool::check_message(td::Ref<ExtMessage> message,
                                                                           td::optional<td::uint32> &msg_seqno,
                                                                           td::optional<PublicKeyHash> source_peer) {
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();

  auto execution_res = resolve_message_workchain_execution(last_masterchain_state_, wc);
  if (execution_res.is_error()) {
    co_return execution_res.move_as_error_prefix("cannot resolve workchain execution for external message: ");
  }
  auto execution = execution_res.move_as_ok();
  if (execution.has_value() &&
      !block::workchain_engine_key_is_tvm(block::workchain_engine_key_from_descriptor(execution->descriptor))) {
    auto special_scan = reject_special_cells_for_custom_compute(
        message->root_cell(), last_masterchain_state_->get_ext_msg_limits());
    if (special_scan.is_error()) {
      co_return special_scan.move_as_error();
    }
    auto policy = execution->executor->account_policy(execution->descriptor, *execution->engine_config);
    if (!policy.accepts_external_inbound) {
      co_return td::Status::Error("configured workchain engine does not accept external inbound messages");
    }
    auto policy_status = block::validate_account_execution_policy_supported(policy);
    if (policy_status.is_error()) {
      co_return policy_status.move_as_error_prefix("configured workchain engine policy is not supported: ");
    }
    if (policy.kind == block::AccountExecutionPolicyKind::SingletonExecutor) {
      if (std::memcmp(addr.data(), policy.singleton_address.value().data(), 32) != 0) {
        co_return td::Status::Error(
            PSTRING() << "ext-msg destination is not the configured singleton executor for workchain " << wc);
      }
    }

    // Rate-limit Uno ingress to bound
    // forged-MineUno DoS via raw sendBoc / liteServer_sendMessage paths.
    // EVM is left unchanged here — its compute phase does not run
    // STARK verification, and the EVM RPC layer already has a dedicated
    // limiter; an additional gate would burden the legitimate path more
    // than the (cheaper) attack.
    // Security audit (round 15, finding #3): the round-2 single-bucket
    // limiter on wc=2 conflated cheap Transfer admission with expensive
    // MineUno STARK-verify, letting either path starve the other. Peek
    // the body's first byte to discriminate (UNO wire-format §1: byte 0
    // == 0x01 → Transfer, 0x02 → MineUno) and only consume the bucket
    // for MineUno bodies. Transfer admission is cheap and doesn't need
    // throttling at this layer; the per-method JSON-RPC limiter still
    // applies on the RPC path. ExtMessage itself does not expose the
    // body byte, so re-walk the cell tree here. Failure to peek (e.g.
    // body decode error) defaults to consuming the bucket — fail-closed.
    if (is_uno_execution(*execution)) {
      // Security audit (round 15 #3 + round 16 #1): Uno has TWO expensive
      // body kinds at the collator: MineUno (STARK proof verify) and
      // Transfer (Plonky3 transfer_air verify). Discriminate by body
      // byte 0 (UNO wire-format §1: 0x01 → Transfer, 0x02 → MineUno)
      // and charge each to its own independent bucket so a flood of
      // one kind cannot starve the other. Body decode failure / unknown
      // discriminator falls back to charging the MineUno bucket
      // (fail-closed; matches the round-15 default).
      enum BodyKind : uint8_t { kUnknown = 0, kTransfer = 1, kMineUno = 2 };
      BodyKind kind = kUnknown;
      try {
        auto root = message->root_cell();
        if (root.not_null()) {
          bool root_special = false;
          auto cs = vm::load_cell_slice_special(root, root_special);
          if (!root_special) {
            block::gen::Message::Record m;
            if (block::gen::t_Message_Any.unpack(cs, m)) {
              auto body_cs = m.body.write();
              td::Ref<vm::Cell> body_ref;
              vm::CellSlice body_inline;
              bool body_inline_valid = false;
              if (body_cs.fetch_ulong(1) == 1) {
                if (body_cs.size_refs() >= 1) {
                  body_ref = body_cs.fetch_ref();
                }
              } else {
                body_inline = body_cs;
                body_inline_valid = true;
              }
              auto peek_byte = [&](vm::CellSlice& s, uint8_t& out) -> bool {
                if (!s.have(8)) return false;
                out = static_cast<uint8_t>(s.prefetch_ulong(8));
                return true;
              };
              uint8_t disc = 0xff;
              bool got_disc = false;
              if (body_ref.not_null()) {
                bool body_special = false;
                auto body_cs2 = vm::load_cell_slice_special(body_ref, body_special);
                if (!body_special) {
                  got_disc = peek_byte(body_cs2, disc);
                }
              } else if (body_inline_valid) {
                got_disc = peek_byte(body_inline, disc);
              }
              if (got_disc) {
                if (disc == 0x01) kind = kTransfer;
                else if (disc == 0x02) kind = kMineUno;
              }
            }
          }
        }
      } catch (...) {
        // peek failed; fall through with kind=kUnknown (charged to MineUno bucket).
      }
      // Per-peer bucket runs FIRST, before any global bucket consume,
      // so a noisy peer is throttled without burning shared tokens that
      // honest peers would otherwise use. When the caller did not
      // supply a source peer (e.g. local-node-originated submissions),
      // the per-peer step is skipped and the global bucket alone gates.
      if (source_peer) {
        if (!g_wc2_per_peer_limiter.try_consume(source_peer.value())) {
          co_return td::Status::Error("Uno ext-msg per-peer rate-limited");
        }
      }
      if (kind == kTransfer) {
        if (!g_wc2_transfer_limiter.try_consume()) {
          co_return td::Status::Error("Uno transfer ingress rate-limited");
        }
      } else {
        // MineUno or unknown — fail-closed onto the MineUno bucket.
        if (!g_wc2_ingress_limiter.try_consume()) {
          co_return td::Status::Error("Uno ext-msg ingress rate-limited");
        }
      }
    }
    auto [wait, promise] = td::actor::StartedTask<>::make_bridge();
    promise.set_value(td::Unit{});
    co_return CheckResult{.message = message, .wait_allow_broadcast = std::move(wait)};
  }

  auto [shard_acc, utime, lt, config] = co_await run_fetch_account_state(wc, addr, manager_);
  bool special = wc == masterchainId && config->is_special_smartcontract(addr);
  block::Account acc;
  if (!acc.unpack(shard_acc, utime, special)) {
    co_return td::Status::Error(PSLICE() << "Failed to unpack account state");
  }
  acc.block_lt = lt;

  auto [wait_allow_broadcast, allow_broadcast_promise] = td::actor::StartedTask<>::make_bridge();
  CheckResult check_result{.message = message, .wait_allow_broadcast = std::move(wait_allow_broadcast)};

  const WalletMessageProcessor *wallet =
      acc.code.not_null() ? WalletMessageProcessor::get(acc.code->get_hash().bits()) : nullptr;
  if (wallet != nullptr) {
    msg_seqno = co_await check_message_to_wallet(message, wallet, std::move(acc), utime, lt, std::move(config),
                                                 std::move(allow_broadcast_promise));
    co_return check_result;
  }
  wallets_.erase({wc, addr});
  co_await ExtMessageQ::run_message_on_account(wc, &acc, utime, lt + 1, message->root_cell(), std::move(config));
  allow_broadcast_promise.set_value(td::Unit{});
  co_return check_result;
}

td::Result<td::uint32> ExtMessagePool::check_message_to_wallet(td::Ref<ExtMessage> message,
                                                               const WalletMessageProcessor *wallet, block::Account acc,
                                                               UnixTime utime, LogicalTime lt,
                                                               std::unique_ptr<block::ConfigInfo> config,
                                                               td::Promise<td::Unit> allow_broadcast_promise) {
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();
  LOG(DEBUG) << "Checking external message to " << wc << ":" << addr.to_hex() << ", " << wallet->name();
  TRY_RESULT(wallet_seqno, wallet->get_wallet_seqno(acc.data));
  auto &wallet_info = wallets_[{wc, addr}];
  SCOPE_EXIT {
    if (wallet_info.messages.empty()) {
      wallets_.erase({wc, addr});
    }
  };
  wallet_info.process_messages(wallet_seqno, utime);
  TRY_RESULT(parsed_message, wallet->parse_message(message->root_cell()));
  auto [msg_seqno, msg_valid_until] = parsed_message;
  LOG(DEBUG) << "External message to " << wallet->name() << ": msg_seqno=" << msg_seqno
             << ", msg_ttl=" << msg_valid_until << ", wallet_seqno=" << wallet_seqno;
  if (msg_valid_until <= (UnixTime)td::Clocks::system()) {
    return td::Status::Error("valid_until is in the past");
  }
  if (msg_seqno < wallet_seqno) {
    return td::Status::Error(PSTRING() << "Too old seqno: msg_seqno=" << msg_seqno
                                       << ", wallet_seqno=" << wallet_seqno);
  }
  if (msg_seqno - wallet_seqno > MAX_WALLET_SEQNO_DIFF) {
    return td::Status::Error(PSTRING() << "Too new seqno: msg_seqno=" << msg_seqno
                                       << ", wallet_seqno=" << wallet_seqno);
  }
  if (wallet_info.messages.contains(msg_seqno)) {
    return td::Status::Error(PSTRING() << "Duplicate msg_seqno " << msg_seqno);
  }
  TRY_RESULT_ASSIGN(acc.data, wallet->set_wallet_seqno(acc.data, msg_seqno));
  acc.storage_dict_hash = acc.orig_storage_dict_hash = {};
  TRY_STATUS(ExtMessageQ::run_message_on_account(wc, &acc, utime, lt + 1, message->root_cell(), std::move(config)));
  wallet_info.messages[msg_seqno] =
      WalletMessageInfo{.valid_until = msg_valid_until, .allow_broadcast_promise = std::move(allow_broadcast_promise)};
  wallet_info.process_messages(wallet_seqno, utime);
  LOG(DEBUG) << "Checked external message to " << wc << ":" << addr.to_hex() << ", " << wallet->name();
  return msg_seqno;
}

void ExtMessagePool::WalletInfo::process_messages(td::uint32 wallet_seqno, UnixTime utime) {
  for (auto it = messages.begin(); it != messages.end();) {
    auto &[seqno, message] = *it;
    if (seqno < wallet_seqno) {
      if (message.allow_broadcast_promise) {
        message.allow_broadcast_promise.set_error(
            td::Status::Error(PSTRING() << "Too old seqno: msg_seqno=" << seqno << ", wallet_seqno=" << wallet_seqno));
      }
      it = messages.erase(it);
      continue;
    }
    if (message.valid_until <= utime) {
      if (message.allow_broadcast_promise) {
        message.allow_broadcast_promise.set_error(td::Status::Error("valid_until is in the past"));
      }
      it = messages.erase(it);
      continue;
    }
    ++it;
  }
  for (td::uint32 seqno = wallet_seqno;; ++seqno) {
    auto it = messages.find(seqno);
    if (it == messages.end()) {
      break;
    }
    if (it->second.allow_broadcast_promise) {
      it->second.allow_broadcast_promise.set_value(td::Unit{});
    }
  }
}

size_t ExtMessagePool::CheckedExtMsgCounter::get_msg_count(WorkchainId wc, StdSmcAddress addr) {
  before_query();
  auto it1 = counter_cur_.find({wc, addr});
  auto it2 = counter_prev_.find({wc, addr});
  return (it1 == counter_cur_.end() ? 0 : it1->second) + (it2 == counter_prev_.end() ? 0 : it2->second);
}

size_t ExtMessagePool::CheckedExtMsgCounter::inc_msg_count(WorkchainId wc, StdSmcAddress addr) {
  before_query();
  auto it2 = counter_prev_.find({wc, addr});
  return (it2 == counter_prev_.end() ? 0 : it2->second) + ++counter_cur_[{wc, addr}];
}

void ExtMessagePool::CheckedExtMsgCounter::before_query() {
  while (cleanup_at_.is_in_past()) {
    counter_prev_ = std::move(counter_cur_);
    counter_cur_.clear();
    if (counter_prev_.empty()) {
      cleanup_at_ = td::Timestamp::in(MAX_EXT_MSG_PER_ADDR_TIME_WINDOW / 2.0);
      break;
    }
    cleanup_at_ += MAX_EXT_MSG_PER_ADDR_TIME_WINDOW / 2.0;
  }
}

}  // namespace tos::validator
