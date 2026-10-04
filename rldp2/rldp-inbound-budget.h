/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <atomic>
#include <cstddef>
#include <limits>
#include <memory>
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
// An unsolicited transfer (at most one 7680-byte part) is therefore charged
// about 38 KiB while it is open: 16384 decoders fill about 600 MiB, so the
// byte budget, not the count, is what binds first at that size. A maximal 2 MB
// part is charged about 6.4 MiB, so 512 MiB still holds some eighty large
// answer parts at once. 512 MiB keeps RLDP2 reassembly inside the 4 GB
// testnet minimum host alongside the other network budgets.
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

class RldpInboundBudget {
 public:
  RldpInboundBudget(std::size_t max_decoders, std::size_t max_bytes)
      : max_decoders_(max_decoders), max_bytes_(max_bytes) {
  }

  // The budget every connection shares unless given another.
  static std::shared_ptr<RldpInboundBudget> process_default() {
    static auto budget = std::make_shared<RldpInboundBudget>(rldp_max_active_decoders, rldp_max_inbound_bytes);
    return budget;
  }

  // Take `decoders` decoder slots and `bytes` bytes, both or neither.
  bool try_acquire(std::size_t decoders, std::size_t bytes) {
    if (!try_add(decoders_, max_decoders_, decoders)) {
      return false;
    }
    if (!try_add(bytes_, max_bytes_, bytes)) {
      sub(decoders_, decoders);
      return false;
    }
    return true;
  }

  // Give back what was acquired. False if more is given back than is held,
  // which is an accounting error; that counter is then left unchanged.
  bool release(std::size_t decoders, std::size_t bytes) {
    bool decoders_ok = sub(decoders_, decoders);
    bool bytes_ok = sub(bytes_, bytes);
    return decoders_ok && bytes_ok;
  }

  std::size_t active_decoders() const {
    return decoders_.load();
  }
  std::size_t reserved_bytes() const {
    return bytes_.load();
  }
  std::size_t max_decoders() const {
    return max_decoders_;
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

  const std::size_t max_decoders_;
  const std::size_t max_bytes_;
  std::atomic<std::size_t> decoders_{0};
  std::atomic<std::size_t> bytes_{0};
};

// Decoder slots and bytes held from a budget, given back when destroyed.
class RldpInboundReservation {
 public:
  RldpInboundReservation() = default;
  static std::optional<RldpInboundReservation> acquire(std::shared_ptr<RldpInboundBudget> budget, std::size_t decoders,
                                                       std::size_t bytes) {
    if (!budget || !budget->try_acquire(decoders, bytes)) {
      return std::nullopt;
    }
    RldpInboundReservation reservation;
    reservation.budget_ = std::move(budget);
    reservation.decoders_ = decoders;
    reservation.bytes_ = bytes;
    return reservation;
  }
  RldpInboundReservation(RldpInboundReservation &&other) noexcept
      : budget_(std::move(other.budget_)), decoders_(other.decoders_), bytes_(other.bytes_) {
    other.decoders_ = 0;
    other.bytes_ = 0;
  }
  RldpInboundReservation &operator=(RldpInboundReservation &&other) noexcept {
    if (this != &other) {
      reset();
      budget_ = std::move(other.budget_);
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
    if (!budget_->release(give_decoders, give_bytes)) {
      LOG(ERROR) << "RLDP2 inbound budget: released more than was reserved";
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
      if (!budget_->release(decoders_, bytes_)) {
        LOG(ERROR) << "RLDP2 inbound budget: released more than was reserved";
      }
      budget_.reset();
    }
    decoders_ = 0;
    bytes_ = 0;
  }

  std::shared_ptr<RldpInboundBudget> budget_;
  std::size_t decoders_{0};
  std::size_t bytes_{0};
};

}  // namespace tos::rldp2
