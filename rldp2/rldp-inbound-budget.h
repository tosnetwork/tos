/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

#include "td/utils/logging.h"

namespace tos::rldp2 {

// Inbound reassembly across every RLDP2 connection of the process.
//
// Each connection bounds how many transfers one peer may have open, but the
// connection table holds thousands of peers, so the per-connection bound times
// the table is over a million decoders. These budgets bound the product: a
// decoder, and the bytes it may come to hold, are reserved before the decoder
// is created, and given back when the transfer finishes, expires, or its
// connection goes away.
//
// Costs below were measured by test-rldp2-decoder-heap
// (test/rldp2-decoder-heap-measure.cpp), which counts heap bytes around a
// RaptorQ decoder driven as RLDP2 drives it (symbols added one at a time, a
// decode attempted as soon as one may succeed), for parts of 64 B, 7680 B,
// 100 kB and 2 MB fed either source symbols or repair symbols only, and fails
// if a measurement exceeds the charges below:
//
//   - each retained symbol costs its 768 bytes plus about 130 bytes of
//     bookkeeping (2,339,936 bytes for 2604 symbols of a 2 MB part); the most a
//     2 MB part's decoder can hold, 2K+10 symbols with no decode attempted,
//     measured 4,585,144 bytes;
//   - a decode from repair symbols, which runs the solver, peaked at 98,208 /
//     106,616 / 677,304 / 11,452,984 bytes above the symbols already held for
//     the four sizes, each within `rldp_solver_working_bytes` below; a decode
//     from source symbols alone peaked at a third of that or less.
//
// An unsolicited transfer (at most one 7680-byte part at the default MTU) is
// therefore charged about 38 KiB while it is open: 8192 decoders, the
// unsolicited half, fill about 300 MiB, so the byte budget, not the count, is
// what binds first at that size. A maximal 2 MB
// part is charged about 6.4 MiB, so 512 MiB still holds some eighty large
// answer parts at once. 512 MiB is sized to leave room for the rest of the
// node on the 4 GB testnet minimum host; it bounds the reassembly state
// charged here, not the process's total memory. Half of it is kept from
// unsolicited transfers for answers to the node's own requests: see
// RldpInboundLimits below.
inline constexpr std::size_t rldp_max_active_decoders = 16384;
inline constexpr std::size_t rldp_max_inbound_bytes = std::size_t{512} << 20;

// Bookkeeping per retained symbol beyond its bytes: its vector entry, its
// buffer header and its place in the decoder's sets of seen ids.
inline constexpr std::size_t rldp_symbol_overhead_bytes = 128;

// Fixed bookkeeping per decoder beyond its symbols and output: the part entry,
// the receiver's acknowledgement state, the decoder object and its masks.
inline constexpr std::size_t rldp_decoder_fixed_bytes = std::size_t{4} << 10;

// Fixed part of the solver's working memory, measured at about 100 KB even
// for a single-symbol part.
inline constexpr std::size_t rldp_solver_fixed_bytes = std::size_t{128} << 10;

namespace detail {
inline std::optional<std::size_t> checked_mul(std::size_t a, std::size_t b) {
  if (a != 0 && b > std::numeric_limits<std::size_t>::max() / a) {
    return std::nullopt;
  }
  return a * b;
}
inline std::optional<std::size_t> checked_add(std::size_t a, std::size_t b) {
  if (b > std::numeric_limits<std::size_t>::max() - a) {
    return std::nullopt;
  }
  return a + b;
}
}  // namespace detail

// What one part's decoder may come to hold while it exists, charged before it
// is created.
//
// The decoder keeps every distinct source symbol (at most `symbols_count`) and
// accepts repair symbols until it holds `symbols_count + 10`, so it can hold up
// to `2 * symbols_count + 10` symbols. Decoding produces `data_size` bytes,
// which stay held once the part is finished. Returns nothing if the size
// cannot be represented.
inline std::optional<std::size_t> rldp_decoder_reservation_bytes(std::size_t data_size, std::size_t symbol_size,
                                                                 std::size_t symbols_count) {
  auto twice = detail::checked_mul(symbols_count, 2);
  if (!twice) {
    return std::nullopt;
  }
  auto symbols = detail::checked_add(*twice, 10);
  auto per_symbol = detail::checked_add(symbol_size, rldp_symbol_overhead_bytes);
  if (!symbols || !per_symbol) {
    return std::nullopt;
  }
  auto symbol_bytes = detail::checked_mul(*symbols, *per_symbol);
  if (!symbol_bytes) {
    return std::nullopt;
  }
  auto with_fixed = detail::checked_add(*symbol_bytes, rldp_decoder_fixed_bytes);
  if (!with_fixed) {
    return std::nullopt;
  }
  return detail::checked_add(*with_fixed, data_size);
}

// Working memory a decode attempt may take on top of what the decoder holds:
// the solver's matrices, about six symbols' worth per source symbol plus a
// fixed part. It exists only during the attempt, so it is reserved just
// before and released just after. Returns nothing if it cannot be represented.
inline std::optional<std::size_t> rldp_solver_working_bytes(std::size_t symbol_size, std::size_t symbols_count) {
  auto per_symbol = detail::checked_mul(symbol_size, 6);
  if (!per_symbol) {
    return std::nullopt;
  }
  auto matrices = detail::checked_mul(symbols_count, *per_symbol);
  if (!matrices) {
    return std::nullopt;
  }
  return detail::checked_add(*matrices, rldp_solver_fixed_bytes);
}

// Whether an inbound transfer answers a request this node made.
//
// A transfer is solicited only when its connection holds an outstanding local
// request for exactly that transfer id: the id the node chose and expects the
// answer under, on the connection to the peer the request went to, and no
// larger than the answer size the request declared. Nothing the peer sends can
// make a transfer solicited; every other transfer is unsolicited.
enum class RldpInboundKind { solicited, unsolicited };

// The authenticated ADNL identity of the peer a transfer comes from: the 32
// bytes of its short id.
using RldpPeerIdentity = std::array<unsigned char, 32>;

// How the process-wide budget is divided.
//
// Half of the decoder slots and half of the bytes are a reserve only solicited
// transfers may use. Solicited transfers may also use the other half;
// unsolicited transfers never use the reserve, so no amount of unsolicited
// traffic can take it. That is all the reserve guarantees: it is not divided
// between the peers the node queries, so one queried peer answering every
// outstanding request at its declared size, or many competing requests, can
// exhaust it themselves. Isolating queried peers from each other would need
// admission of requests by the bytes their answers may take; bounding the
// number of outstanding requests, as Rldp and RldpConnection do, does not
// provide it.
//
// Within the unsolicited half, one peer identity may hold at most an eighth of
// the decoder slots and half of the bytes: 1024 decoders and 128 MiB of the
// production budget.
//
// The byte share is sized to the largest unsolicited transfer the node
// accepts, not to an average peer. A peer whose MTU an overlay raised may send
// a transfer of 16 MiB plus a small envelope; the sender keeps every part of
// it in flight at once, and the receiver charges, all at once, a decoder for
// each of its nine parts (about 53.5 MB for the eight full ones), the buffer
// they are assembled into (16 MiB) and one decode attempt's working memory
// (about 12.1 MB): about 81 MiB. A share of 32 MiB could not hold that even
// after the earlier parts finished, so such a transfer was refused part by
// part until it outlived the ten-second unsolicited lifetime. 128 MiB holds it
// with room for smaller transfers from the same peer beside it. The share is
// a fixed number, never derived from a size the peer advertises.
//
// The decoder share, 1024, is above what an honest peer uses on one local id:
// RldpConnection::MAX_INBOUND_TRANSFERS (256).
//
// None of this is a Sybil-resistant availability guarantee. ADNL identities
// cost nothing to generate: two of them at their byte share exhaust the bytes
// of the unsolicited half, and eight at their decoder share exhaust its
// decoders, starving every other peer's unsolicited transfers. What the
// division guarantees is only that they cannot take the reserve, and that a
// single identity cannot take more than its share. These are budgets for RLDP2
// reassembly state, charged against measured decoder costs; they are not a
// bound on the total memory of the process.
struct RldpInboundLimits {
  std::size_t max_decoders{0};
  std::size_t max_bytes{0};
  // The most unsolicited transfers may hold together.
  std::size_t unsolicited_decoders{0};
  std::size_t unsolicited_bytes{0};
  // The most one peer identity's unsolicited transfers may hold together.
  std::size_t per_identity_decoders{0};
  std::size_t per_identity_bytes{0};
  // The most peer identities tracked at once. An identity is tracked only
  // while it holds something; the production cap is the unsolicited decoder
  // count, so the ledger cannot outgrow what the unsolicited half could hold.
  std::size_t max_identities{0};

  static constexpr std::size_t identity_decoder_share_divisor = 8;
  static constexpr std::size_t identity_byte_share_divisor = 2;

  // The production division of `max_decoders` and `max_bytes`.
  static RldpInboundLimits split(std::size_t max_decoders, std::size_t max_bytes) {
    RldpInboundLimits limits;
    limits.max_decoders = max_decoders;
    limits.max_bytes = max_bytes;
    // Rounded down, so the reserve is never less than half.
    limits.unsolicited_decoders = max_decoders / 2;
    limits.unsolicited_bytes = max_bytes / 2;
    limits.per_identity_decoders = limits.unsolicited_decoders / identity_decoder_share_divisor;
    limits.per_identity_bytes = limits.unsolicited_bytes / identity_byte_share_divisor;
    limits.max_identities = limits.unsolicited_decoders;
    return limits;
  }
};

class RldpInboundBudget {
 public:
  // The production division of `max_decoders` and `max_bytes`.
  RldpInboundBudget(std::size_t max_decoders, std::size_t max_bytes)
      : RldpInboundBudget(RldpInboundLimits::split(max_decoders, max_bytes)) {
  }

  // An explicit division. A share larger than what contains it is reduced to
  // it, so the unsolicited half never exceeds the total and one identity never
  // exceeds the unsolicited half.
  explicit RldpInboundBudget(RldpInboundLimits limits) : limits_(normalized(limits)) {
  }

  // The budget every connection shares unless given another.
  static std::shared_ptr<RldpInboundBudget> process_default() {
    static auto budget = std::make_shared<RldpInboundBudget>(rldp_max_active_decoders, rldp_max_inbound_bytes);
    return budget;
  }

  // Take `decoders` decoder slots and `bytes` bytes for a transfer of `kind`
  // from `peer`: all of it or none.
  //
  // `headroom` more bytes must also fit under every limit that applies, but
  // are not taken. A decoder is reserved with its decode attempt's working
  // memory as headroom. Without it a share could fill with decoders none of
  // which ever has room to decode, and a single large transfer would stall on
  // itself; with it, the room the most recently reserved decoder needs was
  // free when it was reserved, and every part that finishes gives back more
  // than it keeps.
  bool try_acquire(RldpInboundKind kind, const RldpPeerIdentity &peer, std::size_t decoders, std::size_t bytes,
                   std::size_t headroom = 0) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto total_decoders = within(decoders_, decoders, limits_.max_decoders);
    auto total_bytes = take(bytes_, bytes, headroom, limits_.max_bytes);
    if (!total_decoders || !total_bytes) {
      return false;
    }
    if (kind == RldpInboundKind::solicited) {
      decoders_ = *total_decoders;
      bytes_ = *total_bytes;
      return true;
    }
    // Unsolicited: never into the reserve.
    auto pool_decoders = within(unsolicited_decoders_, decoders, limits_.unsolicited_decoders);
    auto pool_bytes = take(unsolicited_bytes_, bytes, headroom, limits_.unsolicited_bytes);
    if (!pool_decoders || !pool_bytes) {
      return false;
    }
    if (decoders == 0 && bytes == 0) {
      return true;
    }
    // And never more than this identity's share of it.
    auto it = identities_.find(peer);
    if (it == identities_.end() && identities_.size() >= limits_.max_identities) {
      return false;
    }
    auto held = it == identities_.end() ? Usage{} : it->second;
    auto identity_decoders = within(held.decoders, decoders, limits_.per_identity_decoders);
    auto identity_bytes = take(held.bytes, bytes, headroom, limits_.per_identity_bytes);
    if (!identity_decoders || !identity_bytes) {
      return false;
    }
    identities_[peer] = Usage{*identity_decoders, *identity_bytes};
    unsolicited_decoders_ = *pool_decoders;
    unsolicited_bytes_ = *pool_bytes;
    decoders_ = *total_decoders;
    bytes_ = *total_bytes;
    return true;
  }

  // Give back what was acquired with the same kind and peer. False, with
  // nothing changed, if more is given back than is held, which is an
  // accounting error.
  bool release(RldpInboundKind kind, const RldpPeerIdentity &peer, std::size_t decoders, std::size_t bytes) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (decoders > decoders_ || bytes > bytes_) {
      return false;
    }
    if (kind == RldpInboundKind::unsolicited && (decoders != 0 || bytes != 0)) {
      auto it = identities_.find(peer);
      if (it == identities_.end() || decoders > it->second.decoders || bytes > it->second.bytes ||
          decoders > unsolicited_decoders_ || bytes > unsolicited_bytes_) {
        return false;
      }
      it->second.decoders -= decoders;
      it->second.bytes -= bytes;
      if (it->second.decoders == 0 && it->second.bytes == 0) {
        identities_.erase(it);
      }
      unsolicited_decoders_ -= decoders;
      unsolicited_bytes_ -= bytes;
    }
    decoders_ -= decoders;
    bytes_ -= bytes;
    return true;
  }

  std::size_t active_decoders() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return decoders_;
  }
  std::size_t reserved_bytes() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return bytes_;
  }
  // What unsolicited transfers hold together.
  std::size_t unsolicited_decoders() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return unsolicited_decoders_;
  }
  std::size_t unsolicited_bytes() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return unsolicited_bytes_;
  }
  // What one identity's unsolicited transfers hold.
  std::size_t identity_decoders(const RldpPeerIdentity &peer) const {
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = identities_.find(peer);
    return it == identities_.end() ? 0 : it->second.decoders;
  }
  std::size_t identity_bytes(const RldpPeerIdentity &peer) const {
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = identities_.find(peer);
    return it == identities_.end() ? 0 : it->second.bytes;
  }
  // Identities currently holding unsolicited reservations.
  std::size_t tracked_identities() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return identities_.size();
  }
  std::size_t max_decoders() const {
    return limits_.max_decoders;
  }
  std::size_t max_bytes() const {
    return limits_.max_bytes;
  }
  const RldpInboundLimits &limits() const {
    return limits_;
  }

 private:
  struct Usage {
    std::size_t decoders{0};
    std::size_t bytes{0};
  };

  static RldpInboundLimits normalized(RldpInboundLimits limits) {
    limits.unsolicited_decoders = std::min(limits.unsolicited_decoders, limits.max_decoders);
    limits.unsolicited_bytes = std::min(limits.unsolicited_bytes, limits.max_bytes);
    limits.per_identity_decoders = std::min(limits.per_identity_decoders, limits.unsolicited_decoders);
    limits.per_identity_bytes = std::min(limits.per_identity_bytes, limits.unsolicited_bytes);
    return limits;
  }

  // `used + amount`, if that is representable and at most `limit`.
  static std::optional<std::size_t> within(std::size_t used, std::size_t amount, std::size_t limit) {
    auto sum = detail::checked_add(used, amount);
    if (!sum || *sum > limit) {
      return std::nullopt;
    }
    return sum;
  }

  // `used + amount`, if `used + amount + headroom` is representable and at
  // most `limit`.
  static std::optional<std::size_t> take(std::size_t used, std::size_t amount, std::size_t headroom,
                                         std::size_t limit) {
    auto needed = detail::checked_add(amount, headroom);
    if (!needed || !within(used, *needed, limit)) {
      return std::nullopt;
    }
    return detail::checked_add(used, amount);
  }

  const RldpInboundLimits limits_;
  // Every connection actor shares the budget, and one reservation moves
  // several counters together, so they change under one lock.
  mutable std::mutex mutex_;
  std::size_t decoders_{0};
  std::size_t bytes_{0};
  std::size_t unsolicited_decoders_{0};
  std::size_t unsolicited_bytes_{0};
  std::map<RldpPeerIdentity, Usage> identities_;
};

// Decoder slots and bytes held from a budget, given back when destroyed.
class RldpInboundReservation {
 public:
  RldpInboundReservation() = default;
  // See RldpInboundBudget::try_acquire for `headroom`.
  static std::optional<RldpInboundReservation> acquire(std::shared_ptr<RldpInboundBudget> budget, RldpInboundKind kind,
                                                       const RldpPeerIdentity &peer, std::size_t decoders,
                                                       std::size_t bytes, std::size_t headroom = 0) {
    if (!budget || !budget->try_acquire(kind, peer, decoders, bytes, headroom)) {
      return std::nullopt;
    }
    RldpInboundReservation reservation;
    reservation.budget_ = std::move(budget);
    reservation.kind_ = kind;
    reservation.peer_ = peer;
    reservation.decoders_ = decoders;
    reservation.bytes_ = bytes;
    return reservation;
  }
  RldpInboundReservation(RldpInboundReservation &&other) noexcept
      : budget_(std::move(other.budget_))
      , kind_(other.kind_)
      , peer_(other.peer_)
      , decoders_(other.decoders_)
      , bytes_(other.bytes_) {
    other.decoders_ = 0;
    other.bytes_ = 0;
  }
  RldpInboundReservation &operator=(RldpInboundReservation &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
      kind_ = other.kind_;
      peer_ = other.peer_;
      decoders_ = other.decoders_;
      bytes_ = other.bytes_;
      other.decoders_ = 0;
      other.bytes_ = 0;
    }
    return *this;
  }
  RldpInboundReservation(const RldpInboundReservation &) = delete;
  RldpInboundReservation &operator=(const RldpInboundReservation &) = delete;
  ~RldpInboundReservation() {
    reset();
  }

  // Keep only `decoders` slots and `bytes` bytes, giving back the rest.
  // Never grows the reservation.
  void shrink_to(std::size_t decoders, std::size_t bytes) {
    if (!budget_) {
      return;
    }
    auto give_decoders = decoders < decoders_ ? decoders_ - decoders : 0;
    auto give_bytes = bytes < bytes_ ? bytes_ - bytes : 0;
    if (!budget_->release(kind_, peer_, give_decoders, give_bytes)) {
      LOG(ERROR) << "RLDP2 inbound budget: released more than was reserved";
      return;
    }
    decoders_ -= give_decoders;
    bytes_ -= give_bytes;
  }

  std::size_t decoders() const {
    return decoders_;
  }
  std::size_t bytes() const {
    return bytes_;
  }

 private:
  void reset() {
    if (budget_) {
      if (!budget_->release(kind_, peer_, decoders_, bytes_)) {
        LOG(ERROR) << "RLDP2 inbound budget: released more than was reserved";
      }
      budget_.reset();
    }
    decoders_ = 0;
    bytes_ = 0;
  }

  std::shared_ptr<RldpInboundBudget> budget_;
  RldpInboundKind kind_{RldpInboundKind::unsolicited};
  RldpPeerIdentity peer_{};
  std::size_t decoders_{0};
  std::size_t bytes_{0};
};

}  // namespace tos::rldp2
