#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "adnl/adnl-source-share.h"
#include "td/utils/logging.h"

namespace tos::quic {

using adnl::SourceShareLedger;

// The source an inbound stream's slot and bytes are charged to: the connection
// peer's network_source_key. Empty for what this side asked for itself (the
// answers to our own queries), which is charged to the global budget only:
// their count and size are set by our own queries, not by the peer.
using QuicBudgetSource = std::string;

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
// Each source address (IPv4 address or IPv6 /64) may hold at most one eighth
// of the streams and of the bytes, summed across all of its connections, so
// one ordinary source cannot take the slots or bytes another source needs. A
// stream or chunk past its source's share is refused exactly as one past the
// global budget is: that stream is reset, nothing else is touched. This is not
// a Sybil-resistant availability guarantee: eight sources can still together
// hold the whole budget.
//
// Defaults: 512 MiB of buffered inbound stream bytes, the same ceiling as the
// other network reassembly budgets. 65536 streams: the inbound budget test
// measures 2632 heap bytes per open, idle inbound stream on a live server,
// counting the transport and callback state of both endpoints in one process;
// 65536 such streams hold about 165 MiB on top of the byte budget, and are
// sixteen full connections' worth of concurrent streams at the per-connection
// limit. These bound the inbound stream state and bytes counted here, not the
// process's total memory.
inline constexpr std::size_t kQuicMaxInboundStreams = 65536;
inline constexpr std::size_t kQuicMaxInboundStreamBytes = std::size_t{512} << 20;

class QuicInboundStreamBudget {
 public:
  // Each source's share defaults to one eighth of each global limit.
  QuicInboundStreamBudget(std::size_t max_streams, std::size_t max_bytes)
      : QuicInboundStreamBudget(max_streams, max_bytes, adnl::default_source_share(max_streams),
                                adnl::default_source_share(max_bytes)) {
  }
  QuicInboundStreamBudget(std::size_t max_streams, std::size_t max_bytes, std::size_t max_streams_per_source,
                          std::size_t max_bytes_per_source)
      : max_streams_(max_streams)
      , max_bytes_(max_bytes)
      , source_streams_(max_streams_per_source)
      , source_bytes_(max_bytes_per_source) {
  }

  // The budget every server shares unless given another.
  static std::shared_ptr<QuicInboundStreamBudget> process_default() {
    static auto budget = std::make_shared<QuicInboundStreamBudget>(kQuicMaxInboundStreams, kQuicMaxInboundStreamBytes);
    return budget;
  }

  // One stream slot for `source`; all or nothing across the source's share and
  // the global budget.
  bool try_acquire_stream(const QuicBudgetSource &source) {
    if (!source.empty() && !source_streams_.try_reserve(source, 1)) {
      return false;
    }
    if (!try_add(streams_, max_streams_, 1)) {
      give_back(source_streams_, source, 1, "streams");
      return false;
    }
    return true;
  }
  // `bytes` for `source`; all or nothing across the source's share and the
  // global budget.
  bool try_reserve_bytes(const QuicBudgetSource &source, std::size_t bytes) {
    if (!source.empty() && !source_bytes_.try_reserve(source, bytes)) {
      return false;
    }
    if (!try_add(bytes_, max_bytes_, bytes)) {
      give_back(source_bytes_, source, bytes, "bytes");
      return false;
    }
    return true;
  }
  // False if more is given back than is held, which is an accounting error;
  // the counter is then left unchanged.
  bool release_stream(const QuicBudgetSource &source) {
    bool ok = sub(streams_, 1);
    if (!source.empty()) {
      ok = source_streams_.release(source, 1) && ok;
    }
    return ok;
  }
  bool release_bytes(const QuicBudgetSource &source, std::size_t bytes) {
    bool ok = sub(bytes_, bytes);
    if (!source.empty()) {
      ok = source_bytes_.release(source, bytes) && ok;
    }
    return ok;
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
  std::size_t source_streams(const QuicBudgetSource &source) const {
    return source_streams_.used(source);
  }
  std::size_t source_bytes(const QuicBudgetSource &source) const {
    return source_bytes_.used(source);
  }
  std::size_t max_streams_per_source() const {
    return source_streams_.per_source_limit();
  }
  std::size_t max_bytes_per_source() const {
    return source_bytes_.per_source_limit();
  }
  // Sources holding any stream slot or byte, for checking the ledgers stay bounded.
  std::size_t tracked_sources() const {
    return source_streams_.sources() + source_bytes_.sources();
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
  static void give_back(SourceShareLedger &ledger, const QuicBudgetSource &source, std::size_t amount,
                        const char *what) {
    if (!source.empty() && !ledger.release(source, amount)) {
      LOG(ERROR) << "QUIC inbound stream budget: released more source " << what << " than were reserved";
    }
  }

  const std::size_t max_streams_;
  const std::size_t max_bytes_;
  std::atomic<std::size_t> streams_{0};
  std::atomic<std::size_t> bytes_{0};
  SourceShareLedger source_streams_;
  SourceShareLedger source_bytes_;
};

// Bytes of a completed stream's payload, still charged while the payload
// travels to and through whatever consumes it. Given back when destroyed.
class QuicInboundByteCharge {
 public:
  QuicInboundByteCharge() = default;
  QuicInboundByteCharge(std::shared_ptr<QuicInboundStreamBudget> budget, QuicBudgetSource source, std::size_t bytes)
      : budget_(std::move(budget)), source_(std::move(source)), bytes_(bytes) {
  }
  QuicInboundByteCharge(QuicInboundByteCharge &&other) noexcept
      : budget_(std::move(other.budget_)), source_(std::move(other.source_)), bytes_(other.bytes_) {
    other.bytes_ = 0;
  }
  QuicInboundByteCharge &operator=(QuicInboundByteCharge &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      source_ = std::move(other.source_);
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
      if (!budget_->release_bytes(source_, bytes_)) {
        LOG(ERROR) << "QUIC inbound stream budget: released more bytes than were reserved";
      }
    }
    bytes_ = 0;
    budget_.reset();
  }

 private:
  std::shared_ptr<QuicInboundStreamBudget> budget_;
  QuicBudgetSource source_;
  std::size_t bytes_{0};
};

// A stream's buffered bytes and, for a stream the peer opened, its slot. Given
// back when destroyed.
class QuicInboundStreamReservation {
 public:
  QuicInboundStreamReservation() = default;
  // A stream the peer opened: one slot, and bytes as they are reserved, all
  // charged to `source` as well as to the global budget.
  static std::optional<QuicInboundStreamReservation> acquire_stream(std::shared_ptr<QuicInboundStreamBudget> budget,
                                                                    QuicBudgetSource source) {
    if (!budget || !budget->try_acquire_stream(source)) {
      return std::nullopt;
    }
    QuicInboundStreamReservation reservation;
    reservation.budget_ = std::move(budget);
    reservation.source_ = std::move(source);
    reservation.holds_slot_ = true;
    return reservation;
  }
  // A stream this side opened for its own query: the answer's bytes are
  // charged to the global budget, the stream itself is counted by the queries
  // that opened it.
  static QuicInboundStreamReservation bytes_only(std::shared_ptr<QuicInboundStreamBudget> budget) {
    QuicInboundStreamReservation reservation;
    reservation.budget_ = std::move(budget);
    return reservation;
  }
  QuicInboundStreamReservation(QuicInboundStreamReservation &&other) noexcept
      : budget_(std::move(other.budget_))
      , source_(std::move(other.source_))
      , bytes_(other.bytes_)
      , holds_slot_(other.holds_slot_) {
    other.bytes_ = 0;
    other.holds_slot_ = false;
  }
  QuicInboundStreamReservation &operator=(QuicInboundStreamReservation &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      source_ = std::move(other.source_);
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
  const QuicBudgetSource &source() const {
    return source_;
  }
  // Reserve `bytes` more for this stream's buffer; all or nothing.
  bool try_reserve_bytes(std::size_t bytes) {
    if (!budget_ || !budget_->try_reserve_bytes(source_, bytes)) {
      return false;
    }
    bytes_ += bytes;
    return true;
  }
  // Give back every buffered byte, keeping the stream slot.
  void release_bytes() {
    if (budget_ && bytes_ > 0) {
      if (!budget_->release_bytes(source_, bytes_)) {
        LOG(ERROR) << "QUIC inbound stream budget: released more bytes than were reserved";
      }
    }
    bytes_ = 0;
  }
  // Hand the buffered bytes' charge to the payload leaving the stream, keeping
  // the stream slot.
  QuicInboundByteCharge take_bytes() {
    QuicInboundByteCharge charge(budget_, source_, bytes_);
    bytes_ = 0;
    return charge;
  }

 private:
  void reset() {
    release_bytes();
    if (budget_ && holds_slot_) {
      if (!budget_->release_stream(source_)) {
        LOG(ERROR) << "QUIC inbound stream budget: released more streams than were reserved";
      }
    }
    holds_slot_ = false;
    budget_.reset();
  }

  std::shared_ptr<QuicInboundStreamBudget> budget_;
  QuicBudgetSource source_;
  std::size_t bytes_{0};
  bool holds_slot_{false};
};

// Heap allocated by the QUIC transport library itself for every connection of
// the process: reassembly of data received out of order, stream state, frames
// awaiting acknowledgement. Every such allocation is reserved here first and
// refused when it does not fit, which the transport reports as a fatal error
// that closes the one connection that asked; closing it frees, and gives back,
// everything it held. This is not a ceiling on a connection's total memory or
// on the process's: TLS state allocated by OpenSSL, the server's own per-
// connection bookkeeping and stream buffers outside the transport are not
// counted here (stream buffers have the budget above).
//
// Each connection's allocations are also charged to its peer's source address
// (IPv4 address or IPv6 /64), and each source may hold at most one eighth of
// the budget across all of its connections; the connection whose allocation
// does not fit its source's share is closed, as one past the global budget is.
// One source cannot then fill the budget with out-of-order data on many
// connections. Many sources together still can: there is no Sybil-resistant
// availability guarantee.
//
// Default 1 GiB: the transport budget test measures 24,380 bytes held by an
// established, idle server connection and a peak of 44,180 bytes while it was
// being established, so the 8192-connection cap fits about three times over,
// while the reassembly a connection's receive window allows (4 MiB at first,
// growing to 24 MiB, in 8 KiB chunks) can no longer be multiplied by the
// connection cap. A source's 128 MiB share holds the 1024 connections the
// per-source connection cap admits about five times over.
inline constexpr std::size_t kQuicMaxTransportBytes = std::size_t{1} << 30;

class QuicTransportMemoryBudget {
 public:
  // Each source's share defaults to one eighth of the limit.
  explicit QuicTransportMemoryBudget(std::size_t limit)
      : QuicTransportMemoryBudget(limit, adnl::default_source_share(limit)) {
  }
  QuicTransportMemoryBudget(std::size_t limit, std::size_t per_source_limit)
      : limit_(limit), source_shares_(per_source_limit) {
  }
  static std::shared_ptr<QuicTransportMemoryBudget> process_default() {
    static auto budget = std::make_shared<QuicTransportMemoryBudget>(kQuicMaxTransportBytes);
    return budget;
  }
  // Reserve `bytes` charged to no source.
  bool try_reserve(std::size_t bytes) {
    return try_reserve(QuicBudgetSource{}, bytes);
  }
  // Reserve `bytes` for `source`; all or nothing across the source's share and
  // the global budget. An empty source is charged to the global budget only.
  bool try_reserve(const QuicBudgetSource &source, std::size_t bytes) {
    if (!source.empty() && !source_shares_.try_reserve(source, bytes)) {
      return false;
    }
    auto used = used_.load();
    do {
      if (used > limit_ || bytes > limit_ - used) {
        if (!source.empty() && !source_shares_.release(source, bytes)) {
          LOG(ERROR) << "QUIC transport budget: released more source bytes than were reserved";
        }
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
    return release(QuicBudgetSource{}, bytes);
  }
  bool release(const QuicBudgetSource &source, std::size_t bytes) {
    bool ok = true;
    auto used = used_.load();
    do {
      if (bytes > used) {
        ok = false;
        break;
      }
    } while (!used_.compare_exchange_weak(used, used - bytes));
    if (!source.empty()) {
      ok = source_shares_.release(source, bytes) && ok;
    }
    return ok;
  }
  std::size_t used() const {
    return used_.load();
  }
  std::size_t limit() const {
    return limit_;
  }
  std::size_t source_used(const QuicBudgetSource &source) const {
    return source_shares_.used(source);
  }
  std::size_t per_source_limit() const {
    return source_shares_.per_source_limit();
  }
  // Sources holding any transport memory, for checking the ledger stays bounded.
  std::size_t tracked_sources() const {
    return source_shares_.sources();
  }
  // The highest use seen, for measurement.
  std::size_t peak() const {
    return peak_.load();
  }

 private:
  const std::size_t limit_;
  std::atomic<std::size_t> used_{0};
  std::atomic<std::size_t> peak_{0};
  SourceShareLedger source_shares_;
};

}  // namespace tos::quic
