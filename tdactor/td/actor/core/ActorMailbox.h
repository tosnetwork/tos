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
#pragma once

#include <atomic>
#include <limits>

#include "td/actor/core/ActorMessage.h"
#include "td/utils/MpscLinkQueue.h"
#include "td/utils/memory-tracker.h"

namespace td {
namespace actor {
namespace core {

class ActorMailbox;

namespace gdb {

#ifdef TOS_INSERT_GDB_HOOKS
[[gnu::noinline]] inline auto hook_message_pushed_to_mailbox(ActorMailbox &mailbox, ActorMessage &message,
                                                             auto &&continuation) {
  asm volatile("" : : "r"(&message) : "memory");
  asm volatile("" : : "r"(&mailbox) : "memory");
  return continuation();
}
#else
inline auto hook_message_pushed_to_mailbox(ActorMailbox &, ActorMessage &, auto &&continuation) {
  return continuation();
}
#endif

}  // namespace gdb

class ActorMailbox {
 public:
  ActorMailbox() = default;
  ActorMailbox(const ActorMailbox &) = delete;
  ActorMailbox &operator=(const ActorMailbox &) = delete;
  ActorMailbox(ActorMailbox &&other) = delete;
  ActorMailbox &operator=(ActorMailbox &&other) = delete;
  ~ActorMailbox() {
    clear();
  }
  bool push(ActorMessage message) {
    auto log_growth = on_push();
    gdb::hook_message_pushed_to_mailbox(*this, message, [&] { queue_.push(std::move(message)); });
    return log_growth;
  }
  bool push_unsafe(ActorMessage message) {
    auto log_growth = on_push();
    gdb::hook_message_pushed_to_mailbox(*this, message, [&] { queue_.push_unsafe(std::move(message)); });
    return log_growth;
  }

  td::MpscLinkQueue<ActorMessage>::Reader &reader() {
    return reader_;
  }

  ActorMessage read() {
    auto message = reader_.read();
    if (message && td::memory_tracker_enabled()) {
      auto previous = current_messages_.fetch_sub(1, std::memory_order_relaxed);
      if (previous == 1 && growth_since_drain_.exchange(false, std::memory_order_relaxed)) {
        drained_since_log_.store(true, std::memory_order_relaxed);
      }
    }
    return message;
  }

  bool delay(ActorMessage message) {
    auto log_growth = on_push();
    reader_.delay(std::move(message));
    return log_growth;
  }

  uint64 current_messages() const {
    return current_messages_.load(std::memory_order_relaxed);
  }

  uint64 peak_messages() const {
    return peak_messages_.load(std::memory_order_relaxed);
  }

  bool take_drained_since_log() {
    return drained_since_log_.exchange(false, std::memory_order_relaxed);
  }

  void pop_all() {
    queue_.pop_all(reader_);
  }
  void pop_all_unsafe() {
    queue_.pop_all_unsafe(reader_);
  }

  void clear() {
    pop_all();
    while (read()) {
      // skip
    }
  }

 private:
  bool on_push() {
    if (!td::memory_tracker_enabled()) {
      return false;
    }
    auto current = current_messages_.fetch_add(1, std::memory_order_relaxed) + 1;
    auto peak = peak_messages_.load(std::memory_order_relaxed);
    while (current > peak &&
           !peak_messages_.compare_exchange_weak(peak, current, std::memory_order_relaxed)) {
    }
    auto threshold = next_log_threshold_.load(std::memory_order_relaxed);
    while (current >= threshold) {
      auto next = threshold > (std::numeric_limits<uint64>::max() / 2)
                      ? std::numeric_limits<uint64>::max()
                      : threshold * 2;
      if (next_log_threshold_.compare_exchange_weak(threshold, next, std::memory_order_relaxed)) {
        growth_since_drain_.store(true, std::memory_order_relaxed);
        return true;
      }
    }
    return false;
  }

  td::MpscLinkQueue<ActorMessage> queue_;
  td::MpscLinkQueue<ActorMessage>::Reader reader_;
  std::atomic<uint64> current_messages_{0};
  std::atomic<uint64> peak_messages_{0};
  std::atomic<uint64> next_log_threshold_{64};
  std::atomic<bool> growth_since_drain_{false};
  std::atomic<bool> drained_since_log_{false};
};
}  // namespace core
}  // namespace actor
}  // namespace td
