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
#include <algorithm>
#include <vector>

#include "td/utils/Random.h"
#include "td/utils/Timer.h"

#include "ext-message-pool.hpp"
#include "external-message.hpp"
#include "fabric.h"

namespace tos::validator {

void ExtMessagePool::init_checkers() {
  checker_inflight_.assign(NUM_CHECKERS, 0);
  for (size_t i = 0; i < NUM_CHECKERS; ++i) {
    checkers_.push_back(td::actor::create_actor<ExtMessageChecker>(PSTRING() << "extmsgcheck" << i, manager_));
  }
}

td::actor::Task<ExtMessagePool::CheckResult> ExtMessagePool::check_add_external_message(
    td::BufferSlice data, int priority, bool add_to_mempool, td::optional<PublicKeyHash> source_peer) {
  ++admission_window_.in;
  if (!admit_source(source_peer, td::Timestamp::now())) {
    ++admission_window_.rejected;
    co_return td::Status::Error(ErrorCode::notready, "external message source rate limit exceeded");
  }
  if (last_masterchain_state_.is_null()) {
    ++admission_window_.rejected;
    co_return td::Status::Error(ErrorCode::notready, "not ready");
  }
  auto ext_msg_limits = last_masterchain_state_->get_ext_msg_limits();
  if (data.size() > ext_msg_limits.max_size) {
    ++admission_window_.rejected;
    co_return td::Status::Error("external message too large, rejecting");
  }
  if (checkers_.empty()) {
    init_checkers();
  }
  while (inflight_checks_ >= MAX_INFLIGHT_CHECKS) {
    if (admission_waiters_.size() >= max_admission_waiters()) {
      ++admission_window_.rejected;
      co_return td::Status::Error(ErrorCode::notready, "too many pending external message checks");
    }
    auto [task, promise] = td::actor::StartedTask<>::make_bridge();
    admission_waiters_.push_back(std::move(promise));
    co_await std::move(task);
  }
  ++inflight_checks_;
  SCOPE_EXIT {
    release_check_slot();
  };

  size_t worker = next_checker_++ % checkers_.size();
  ++checker_inflight_[worker];
  td::Timer check_timer;
  auto checked_result = co_await td::actor::ask(checkers_[worker].get(), &ExtMessageChecker::check, std::move(data),
                                                ext_msg_limits, last_masterchain_state_)
                            .wrap();
  --checker_inflight_[worker];
  admission_window_.check_time += check_timer.elapsed();
  ++admission_window_.checked;
  if (checked_result.is_error()) {
    ++total_check_ext_messages_error_;
    ++admission_window_.rejected;
    co_return checked_result.move_as_error();
  }
  auto checked = checked_result.move_as_ok();
  admission_window_.timings.parse += checked.timings.parse;
  admission_window_.timings.fetch_state += checked.timings.fetch_state;
  admission_window_.timings.lookup += checked.timings.lookup;
  admission_window_.timings.vm += checked.timings.vm;

  auto message = checked.message;
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();
  auto finalize = [&]() -> td::Result<CheckResult> {
    if (checked_ext_msg_counter_.get_msg_count(wc, addr) >= MAX_EXT_MSG_PER_ADDR) {
      return td::Status::Error(PSTRING() << "too many external messages to address " << wc << ":" << addr.to_hex());
    }
    auto [wait_allow_broadcast, allow_broadcast_promise] = td::actor::StartedTask<>::make_bridge();
    allow_broadcast_promise.set_value(td::Unit{});
    if (checked_ext_msg_counter_.inc_msg_count(wc, addr) > MAX_EXT_MSG_PER_ADDR) {
      return td::Status::Error(PSTRING() << "too many external messages to address " << wc << ":" << addr.to_hex());
    }
    return CheckResult{std::move(message), std::move(wait_allow_broadcast)};
  };
  auto result = finalize();
  ++(result.is_ok() ? total_check_ext_messages_ok_ : total_check_ext_messages_error_);
  ++(result.is_ok() ? admission_window_.admitted : admission_window_.rejected);
  if (result.is_error()) {
    co_return result.move_as_error();
  }
  if (add_to_mempool) {
    add_message_to_mempool(checked.message, priority);
  }
  co_return result.move_as_ok();
}

bool ExtMessagePool::admit_source(const td::optional<PublicKeyHash> &source_peer, td::Timestamp now) {
  if (!source_peer) {
    return true;
  }
  auto it = peer_admission_.find(source_peer.value());
  if (it == peer_admission_.end()) {
    if (peer_admission_.size() >= MAX_TRACKED_ADMISSION_PEERS) {
      auto oldest = std::min_element(peer_admission_.begin(), peer_admission_.end(), [](const auto &a, const auto &b) {
        return a.second.last_seen.at() < b.second.last_seen.at();
      });
      peer_admission_.erase(oldest);
    }
    it = peer_admission_.emplace(source_peer.value(), PeerAdmission{}).first;
  }
  it->second.last_seen = now;
  if (!it->second.rate.check(now)) {
    return false;
  }
  it->second.rate.insert(now);
  return true;
}

size_t ExtMessagePool::max_admission_waiters() {
  double now = td::Time::now();
  double window = now - rate_window_start_;
  if (window >= 1.0) {
    if (window <= 10.0) {
      check_completion_rate_ =
          0.5 * check_completion_rate_ + 0.5 * static_cast<double>(completions_in_rate_window_) / window;
    }
    completions_in_rate_window_ = 0;
    rate_window_start_ = now;
  }
  double cap = check_completion_rate_ * MAX_ADMISSION_QUEUE_DELAY;
  return static_cast<size_t>(td::clamp(cap, 512.0, static_cast<double>(MAX_ADMISSION_WAITERS)));
}

void ExtMessagePool::release_check_slot() {
  ++completions_in_rate_window_;
  --inflight_checks_;
  if (!admission_waiters_.empty()) {
    auto waiter = std::move(admission_waiters_.front());
    admission_waiters_.pop_front();
    waiter.set_value(td::Unit{});
  }
}

void ExtMessagePool::log_admission_stats() {
  auto &window = admission_window_;
  double elapsed = td::Time::now() - window.window_start.at();
  if (window.in > 0 && elapsed > 0) {
    size_t busy_workers = 0;
    size_t inflight = 0;
    for (size_t count : checker_inflight_) {
      busy_workers += count > 0;
      inflight += count;
    }
    char buffer[320];
    snprintf(buffer, sizeof(buffer),
             "ext admission: in=%.0f/s admitted=%.0f/s rejected=%.0f/s busy_workers=%zu/%zu inflight=%zu wait_q=%zu "
             "avg_check_ms=%.2f (parse=%.2f state=%.2f lookup=%.2f vm=%.2f)",
             static_cast<double>(window.in) / elapsed, static_cast<double>(window.admitted) / elapsed,
             static_cast<double>(window.rejected) / elapsed, busy_workers, checkers_.size(), inflight,
             admission_waiters_.size(),
             window.checked ? window.check_time / static_cast<double>(window.checked) * 1e3 : 0.0,
             window.checked ? window.timings.parse / static_cast<double>(window.checked) * 1e3 : 0.0,
             window.checked ? window.timings.fetch_state / static_cast<double>(window.checked) * 1e3 : 0.0,
             window.checked ? window.timings.lookup / static_cast<double>(window.checked) * 1e3 : 0.0,
             window.checked ? window.timings.vm / static_cast<double>(window.checked) * 1e3 : 0.0);
    LOG(INFO) << buffer;
  }
  window = AdmissionWindowStats{};
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
  // `cleanup_external_messages` only for masterchain (-1) and basechain (0).
  // Sweep all workchains here by message expiry alone, not shard.
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
  if (admission_stats_at_.is_in_past()) {
    log_admission_stats();
    admission_stats_at_ = td::Timestamp::in(ADMISSION_STATS_PERIOD);
  }
  alarm_timestamp().relax(admission_stats_at_);
  if (cleanup_mempool_at_.is_in_past()) {
    // The previous alarm only swept
    // masterchain (-1) and basechain (0). Use the workchain-agnostic
    // sweep so messages outside those shards also expire after their TTL.
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

void ExtMessagePool::add_message_to_mempool(td::Ref<ExtMessage> message, int priority) {
  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();
  auto &msgs = ext_msgs_[priority];
  if (msgs.ext_messages_.size() > opts_->max_mempool_num()) {
    LOG(INFO) << "cannot add message addr=" << wc << ":" << addr.to_hex() << " prio=" << priority
              << " to mempool: mempool is full (limit=" << opts_->max_mempool_num() << ")";
    return;
  }
  auto msg = std::make_shared<MempoolMsg>(message);
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
