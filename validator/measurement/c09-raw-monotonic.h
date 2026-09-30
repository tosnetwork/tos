/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <span>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

namespace tos::validator::measurement::c09 {

// A fixed vocabulary. No candidate, session or peer identifiers enter this
// bounded test instrument. A stage is supported only after a real native call
// site brackets both ends of that operation.
enum class Stage : std::uint8_t {
  proposal_generation,
  vote_intent_commit,
  vote_sign,
  signed_vote_commit,
  vote_local_apply,
  vote_broadcast_enqueue,
  finality_verify,
  storage_ack,
  count,
};

enum class Outcome : std::uint8_t { ok, error, cancelled };
constexpr std::uint32_t clock_domain = 1;  // Linux CLOCK_MONOTONIC_RAW only.
constexpr std::uint64_t max_duration_ns = 60ULL * 60 * 1000 * 1000 * 1000;

namespace detail {
inline bool checked_raw_ns(const timespec& value, std::int64_t& result) noexcept {
  constexpr auto max = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  constexpr std::uint64_t billion = 1000000000ULL;
  if (value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= static_cast<long>(billion)) {
    return false;
  }
  const auto seconds = static_cast<std::uint64_t>(value.tv_sec);
  const auto nanos = static_cast<std::uint64_t>(value.tv_nsec);
  if (seconds > max / billion || (seconds == max / billion && nanos > max % billion)) {
    return false;
  }
  result = static_cast<std::int64_t>(seconds * billion + nanos);
  return true;
}
}  // namespace detail

struct Point {
  std::uint64_t process_nonce = 0;
  std::int64_t monotonic_ns = 0;
  pid_t pid = 0;
  std::uint32_t domain = 0;
  Stage stage = Stage::count;
};

struct Record {
  Point start;
  std::int64_t finish_ns = 0;
  std::uint64_t duration_ns = 0;
  Outcome outcome = Outcome::error;
};

struct Counters {
  std::uint64_t started = 0;
  std::uint64_t retained = 0;
  std::uint64_t dropped_full = 0;
  std::uint64_t dropped_contention = 0;
  std::uint64_t rejected_identity = 0;
  std::uint64_t rejected_time = 0;
  std::uint64_t clock_error = 0;
  bool complete = true;
};

// Fixed resident storage, no file/network path and no wait for another writer.
// Construct off the business hot path. getrandom failure disables capture.
template <std::size_t Capacity = 1024>
class Capture final {
  static_assert(Capacity > 0 && Capacity <= 1024);

 public:
  Capture() noexcept : pid_(getpid()) {
    const auto result = getrandom(&nonce_, sizeof(nonce_), GRND_NONBLOCK);
    ready_ = result == static_cast<ssize_t>(sizeof(nonce_)) && nonce_ != 0;
  }

  Capture(const Capture&) = delete;
  Capture& operator=(const Capture&) = delete;

  bool ready() const noexcept { return ready_; }
  pid_t pid() const noexcept { return pid_; }
  std::uint64_t process_nonce() const noexcept { return nonce_; }

  bool start(Stage stage, Point& point) noexcept {
    if (!ready_ || getpid() != pid_ || stage >= Stage::count) {
      add(rejected_identity_);
      return false;
    }
    std::int64_t now = 0;
    if (!raw_now(now)) {
      add(clock_error_);
      return false;
    }
    point = {nonce_, now, pid_, clock_domain, stage};
    add(started_);
    return true;
  }

  bool finish(const Point& point, Outcome outcome) noexcept {
    // Capture the endpoint before accounting, validation and lock attempts.
    std::int64_t end = 0;
    if (!raw_now(end)) {
      add(clock_error_);
      return false;
    }
    if (!ready_ || getpid() != pid_ || point.pid != pid_ || point.process_nonce != nonce_ ||
        point.domain != clock_domain || point.stage >= Stage::count || outcome > Outcome::cancelled) {
      add(rejected_identity_);
      return false;
    }
    if (point.monotonic_ns < 0 || end < point.monotonic_ns ||
        static_cast<std::uint64_t>(end - point.monotonic_ns) > max_duration_ns) {
      add(rejected_time_);
      return false;
    }
    if (!mutex_.try_lock()) {
      drop(dropped_contention_);
      return false;
    }
    const std::lock_guard<std::mutex> guard(mutex_, std::adopt_lock);
    if (size_ == Capacity) {
      drop(dropped_full_);
      return false;
    }
    records_[size_++] = {point, end, static_cast<std::uint64_t>(end - point.monotonic_ns), outcome};
    add(retained_);
    return true;
  }

  // Export is explicit and outside the hot path. A busy writer makes the
  // snapshot unavailable; it never waits on a validator actor.
  bool snapshot(std::span<Record> output, std::size_t& count, Counters& counters) noexcept {
    if (!mutex_.try_lock()) {
      return false;
    }
    const std::lock_guard<std::mutex> guard(mutex_, std::adopt_lock);
    if (output.size() < size_) {
      return false;
    }
    for (std::size_t i = 0; i < size_; ++i) {
      output[i] = records_[i];
    }
    count = size_;
    counters = {started_.load(), retained_.load(), dropped_full_.load(), dropped_contention_.load(),
                rejected_identity_.load(), rejected_time_.load(), clock_error_.load(), complete_.load()};
    return true;
  }

 private:
  static bool raw_now(std::int64_t& result) noexcept {
    timespec value{};
    return clock_gettime(CLOCK_MONOTONIC_RAW, &value) == 0 && detail::checked_raw_ns(value, result);
  }

  void drop(std::atomic<std::uint64_t>& counter) noexcept {
    complete_.store(false, std::memory_order_relaxed);
    add(counter);
  }

  void add(std::atomic<std::uint64_t>& counter) noexcept {
    auto old = counter.load(std::memory_order_relaxed);
    for (int tries = 0; tries < 4; ++tries) {
      if (old == std::numeric_limits<std::uint64_t>::max()) {
        complete_.store(false, std::memory_order_relaxed);
        return;
      }
      if (counter.compare_exchange_weak(old, old + 1, std::memory_order_relaxed)) {
        return;
      }
    }
    complete_.store(false, std::memory_order_relaxed);
  }

  pid_t pid_ = 0;
  std::uint64_t nonce_ = 0;
  bool ready_ = false;
  std::mutex mutex_;
  std::array<Record, Capacity> records_{};
  std::size_t size_ = 0;
  std::atomic<std::uint64_t> started_{0};
  std::atomic<std::uint64_t> retained_{0};
  std::atomic<std::uint64_t> dropped_full_{0};
  std::atomic<std::uint64_t> dropped_contention_{0};
  std::atomic<std::uint64_t> rejected_identity_{0};
  std::atomic<std::uint64_t> rejected_time_{0};
  std::atomic<std::uint64_t> clock_error_{0};
  std::atomic<bool> complete_{true};
};

}  // namespace tos::validator::measurement::c09
