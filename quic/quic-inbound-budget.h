#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>

#include "td/utils/logging.h"

namespace tos::quic {

// Peer-initiated streams, and the stream bytes delivered by the transport,
// across every QUIC server of the process.
//
// Each connection may open thousands of streams and each stream may buffer up
// to a peer MTU, and thousands of connections may be live, so the product of
// the per-connection limits is tens of GiB. These budgets bound the product: a
// stream slot is reserved before a peer's stream gets any state here, and each
// delivered chunk's bytes before they are buffered, whether they belong to a
// peer's request or to the answer to one of our own queries. A completed
// payload carries its bytes' charge on to whoever consumes it: an inbound
// query's charge lasts until its handler has answered. Slots come back when
// the stream goes away for any reason. What the transport holds before it
// delivers anything, data received out of order included, is bounded by the
// transport memory budget below.
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

// Bytes of a completed stream's payload, still charged while the payload
// travels to and through whatever consumes it. Given back when destroyed.
class QuicInboundByteCharge {
 public:
  QuicInboundByteCharge() = default;
  QuicInboundByteCharge(std::shared_ptr<QuicInboundStreamBudget> budget, std::size_t bytes)
      : budget_(std::move(budget)), bytes_(bytes) {
  }
  QuicInboundByteCharge(QuicInboundByteCharge &&other) noexcept
      : budget_(std::move(other.budget_)), bytes_(other.bytes_) {
    other.bytes_ = 0;
  }
  QuicInboundByteCharge &operator=(QuicInboundByteCharge &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      bytes_ = other.bytes_;
      other.bytes_ = 0;
    }
    return *this;
  }
  QuicInboundByteCharge(const QuicInboundByteCharge &) = delete;
  QuicInboundByteCharge &operator=(const QuicInboundByteCharge &) = delete;
  ~QuicInboundByteCharge() {
    reset();
  }
  std::size_t bytes() const {
    return bytes_;
  }
  void reset() {
    if (budget_ && bytes_ > 0) {
      if (!budget_->release_bytes(bytes_)) {
        LOG(ERROR) << "QUIC inbound stream budget: released more bytes than were reserved";
      }
    }
    bytes_ = 0;
    budget_.reset();
  }

 private:
  std::shared_ptr<QuicInboundStreamBudget> budget_;
  std::size_t bytes_{0};
};

// A stream's buffered bytes and, for a stream the peer opened, its slot. Given
// back when destroyed.
class QuicInboundStreamReservation {
 public:
  QuicInboundStreamReservation() = default;
  // A stream the peer opened: one slot, and bytes as they are reserved.
  static std::optional<QuicInboundStreamReservation> acquire_stream(std::shared_ptr<QuicInboundStreamBudget> budget) {
    if (!budget || !budget->try_acquire_stream()) {
      return std::nullopt;
    }
    QuicInboundStreamReservation reservation;
    reservation.budget_ = std::move(budget);
    reservation.holds_slot_ = true;
    return reservation;
  }
  // A stream this side opened for its own query: the answer's bytes are
  // charged, the stream itself is counted by the queries that opened it.
  static QuicInboundStreamReservation bytes_only(std::shared_ptr<QuicInboundStreamBudget> budget) {
    QuicInboundStreamReservation reservation;
    reservation.budget_ = std::move(budget);
    return reservation;
  }
  QuicInboundStreamReservation(QuicInboundStreamReservation &&other) noexcept
      : budget_(std::move(other.budget_)), bytes_(other.bytes_), holds_slot_(other.holds_slot_) {
    other.bytes_ = 0;
    other.holds_slot_ = false;
  }
  QuicInboundStreamReservation &operator=(QuicInboundStreamReservation &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      bytes_ = other.bytes_;
      holds_slot_ = other.holds_slot_;
      other.bytes_ = 0;
      other.holds_slot_ = false;
    }
    return *this;
  }
  QuicInboundStreamReservation(const QuicInboundStreamReservation &) = delete;
  QuicInboundStreamReservation &operator=(const QuicInboundStreamReservation &) = delete;
  ~QuicInboundStreamReservation() {
    reset();
  }

  bool holds_stream() const {
    return holds_slot_;
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
  // Hand the buffered bytes' charge to the payload leaving the stream, keeping
  // the stream slot.
  QuicInboundByteCharge take_bytes() {
    QuicInboundByteCharge charge(budget_, bytes_);
    bytes_ = 0;
    return charge;
  }

 private:
  void reset() {
    release_bytes();
    if (budget_ && holds_slot_) {
      if (!budget_->release_stream()) {
        LOG(ERROR) << "QUIC inbound stream budget: released more streams than were reserved";
      }
    }
    holds_slot_ = false;
    budget_.reset();
  }

  std::shared_ptr<QuicInboundStreamBudget> budget_;
  std::size_t bytes_{0};
  bool holds_slot_{false};
};

// Heap allocated by the QUIC transport for every connection of the process:
// reassembly of data received out of order, stream state, frames awaiting
// acknowledgement, packet and key buffers. Every transport allocation is
// reserved here first and refused when it does not fit, which the transport
// reports as a fatal error that closes the one connection that asked; closing
// it frees, and gives back, everything it held.
//
// Default 1 GiB: the transport budget test measures 24,380 bytes held by an
// established, idle server connection and a peak of 44,180 bytes while it was
// being established, so the 8192-connection cap fits about three times over,
// while the reassembly a connection's receive window allows (4 MiB at first,
// growing to 24 MiB, in 8 KiB chunks) can no longer be multiplied by the
// connection cap.
inline constexpr std::size_t kQuicMaxTransportBytes = std::size_t{1} << 30;

class QuicTransportMemoryBudget {
 public:
  explicit QuicTransportMemoryBudget(std::size_t limit) : limit_(limit) {
  }
  static std::shared_ptr<QuicTransportMemoryBudget> process_default() {
    static auto budget = std::make_shared<QuicTransportMemoryBudget>(kQuicMaxTransportBytes);
    return budget;
  }
  bool try_reserve(std::size_t bytes) {
    auto used = used_.load();
    do {
      if (used > limit_ || bytes > limit_ - used) {
        return false;
      }
    } while (!used_.compare_exchange_weak(used, used + bytes));
    auto now = used + bytes;
    auto peak = peak_.load();
    while (now > peak && !peak_.compare_exchange_weak(peak, now)) {
    }
    return true;
  }
  bool release(std::size_t bytes) {
    auto used = used_.load();
    do {
      if (bytes > used) {
        return false;
      }
    } while (!used_.compare_exchange_weak(used, used - bytes));
    return true;
  }
  std::size_t used() const {
    return used_.load();
  }
  std::size_t limit() const {
    return limit_;
  }
  // The highest use seen, for measurement.
  std::size_t peak() const {
    return peak_.load();
  }

 private:
  const std::size_t limit_;
  std::atomic<std::size_t> used_{0};
  std::atomic<std::size_t> peak_{0};
};

}  // namespace tos::quic
