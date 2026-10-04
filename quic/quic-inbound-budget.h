#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>

#include "td/utils/logging.h"

namespace tos::quic {

// Peer-initiated streams, and the bytes they buffer before they complete,
// across every QUIC server of the process.
//
// Each connection may open thousands of streams and each stream may buffer up
// to a peer MTU, and thousands of connections may be live, so the product of
// the per-connection limits is tens of GiB. These budgets bound the product: a
// stream slot is reserved before a peer's stream gets any state here, each
// chunk's bytes before they are buffered, and both come back when the stream
// completes, fails, times out, or its connection or server goes away.
//
// Defaults: 512 MiB of buffered inbound stream bytes, the same ceiling as the
// other network reassembly budgets, which together stay inside the 4 GB
// testnet minimum host. 65536 streams: the inbound budget test measures 2632
// heap bytes per open, idle inbound stream on a live server, counting the
// transport and callback state of both endpoints in one process; 65536 such
// streams hold about 165 MiB on top of the byte budget, and are sixteen full
// connections' worth of concurrent streams at the per-connection limit.
inline constexpr std::size_t kQuicMaxInboundStreams = 65536;
inline constexpr std::size_t kQuicMaxInboundStreamBytes = std::size_t{512} << 20;

class QuicInboundStreamBudget {
 public:
  QuicInboundStreamBudget(std::size_t max_streams, std::size_t max_bytes)
      : max_streams_(max_streams), max_bytes_(max_bytes) {
  }

  // The budget every server shares unless given another.
  static std::shared_ptr<QuicInboundStreamBudget> process_default() {
    static auto budget = std::make_shared<QuicInboundStreamBudget>(kQuicMaxInboundStreams, kQuicMaxInboundStreamBytes);
    return budget;
  }

  bool try_acquire_stream() {
    return try_add(streams_, max_streams_, 1);
  }
  bool try_reserve_bytes(std::size_t bytes) {
    return try_add(bytes_, max_bytes_, bytes);
  }
  // False if more is given back than is held, which is an accounting error;
  // the counter is then left unchanged.
  bool release_stream() {
    return sub(streams_, 1);
  }
  bool release_bytes(std::size_t bytes) {
    return sub(bytes_, bytes);
  }

  std::size_t streams() const {
    return streams_.load();
  }
  std::size_t bytes() const {
    return bytes_.load();
  }
  std::size_t max_streams() const {
    return max_streams_;
  }
  std::size_t max_bytes() const {
    return max_bytes_;
  }

 private:
  static bool try_add(std::atomic<std::size_t> &counter, std::size_t limit, std::size_t amount) {
    auto used = counter.load();
    do {
      if (used > limit || amount > limit - used) {
        return false;
      }
    } while (!counter.compare_exchange_weak(used, used + amount));
    return true;
  }
  static bool sub(std::atomic<std::size_t> &counter, std::size_t amount) {
    auto used = counter.load();
    do {
      if (amount > used) {
        return false;
      }
    } while (!counter.compare_exchange_weak(used, used - amount));
    return true;
  }

  const std::size_t max_streams_;
  const std::size_t max_bytes_;
  std::atomic<std::size_t> streams_{0};
  std::atomic<std::size_t> bytes_{0};
};

// One inbound stream's slot and buffered bytes, given back when destroyed.
class QuicInboundStreamReservation {
 public:
  QuicInboundStreamReservation() = default;
  static std::optional<QuicInboundStreamReservation> acquire_stream(std::shared_ptr<QuicInboundStreamBudget> budget) {
    if (!budget || !budget->try_acquire_stream()) {
      return std::nullopt;
    }
    QuicInboundStreamReservation reservation;
    reservation.budget_ = std::move(budget);
    return reservation;
  }
  QuicInboundStreamReservation(QuicInboundStreamReservation &&other) noexcept
      : budget_(std::move(other.budget_)), bytes_(other.bytes_) {
    other.bytes_ = 0;
  }
  QuicInboundStreamReservation &operator=(QuicInboundStreamReservation &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      bytes_ = other.bytes_;
      other.bytes_ = 0;
    }
    return *this;
  }
  QuicInboundStreamReservation(const QuicInboundStreamReservation &) = delete;
  QuicInboundStreamReservation &operator=(const QuicInboundStreamReservation &) = delete;
  ~QuicInboundStreamReservation() {
    reset();
  }

  bool holds_stream() const {
    return budget_ != nullptr;
  }
  // Reserve `bytes` more for this stream's buffer; all or nothing.
  bool try_reserve_bytes(std::size_t bytes) {
    if (!budget_ || !budget_->try_reserve_bytes(bytes)) {
      return false;
    }
    bytes_ += bytes;
    return true;
  }
  // Give back every buffered byte, keeping the stream slot.
  void release_bytes() {
    if (budget_ && bytes_ > 0) {
      if (!budget_->release_bytes(bytes_)) {
        LOG(ERROR) << "QUIC inbound stream budget: released more bytes than were reserved";
      }
    }
    bytes_ = 0;
  }

 private:
  void reset() {
    release_bytes();
    if (budget_) {
      if (!budget_->release_stream()) {
        LOG(ERROR) << "QUIC inbound stream budget: released more streams than were reserved";
      }
      budget_.reset();
    }
  }

  std::shared_ptr<QuicInboundStreamBudget> budget_;
  std::size_t bytes_{0};
};

}  // namespace tos::quic
