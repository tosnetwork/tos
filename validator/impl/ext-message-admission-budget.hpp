// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <memory>
#include <utility>

#include "adnl/adnl-ext-limits.h"

namespace tos::validator {

// Hard bound for serialized inputs retained by admission coroutines, including
// waiters and in-flight checks. Transport mailboxes and parsed cells are separate.
inline constexpr std::size_t ext_message_admission_bytes = std::size_t{64} << 20;

class ExtMessageAdmissionReservation {
 public:
  static td::Result<ExtMessageAdmissionReservation> acquire(std::shared_ptr<adnl::AdnlExtByteBudget> budget,
                                                            std::size_t bytes) {
    CHECK(budget != nullptr);
    if (!budget->try_reserve(bytes)) {
      return td::Status::Error(ErrorCode::notready, "external message admission byte budget exhausted");
    }
    return ExtMessageAdmissionReservation(std::move(budget), bytes);
  }

  ExtMessageAdmissionReservation(const ExtMessageAdmissionReservation &) = delete;
  ExtMessageAdmissionReservation &operator=(const ExtMessageAdmissionReservation &) = delete;
  ExtMessageAdmissionReservation(ExtMessageAdmissionReservation &&other) noexcept
      : budget_(std::move(other.budget_)), bytes_(std::exchange(other.bytes_, 0)) {
  }
  ExtMessageAdmissionReservation &operator=(ExtMessageAdmissionReservation &&) = delete;
  ~ExtMessageAdmissionReservation() {
    if (budget_) {
      CHECK(budget_->release(bytes_));
    }
  }

 private:
  ExtMessageAdmissionReservation(std::shared_ptr<adnl::AdnlExtByteBudget> budget, std::size_t bytes)
      : budget_(std::move(budget)), bytes_(bytes) {
  }
  std::shared_ptr<adnl::AdnlExtByteBudget> budget_;
  std::size_t bytes_;
};

}  // namespace tos::validator
