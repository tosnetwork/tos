#pragma once

// C3 host contract only: compiled by an opt-in private test, no production
// call site. It does not close concrete-engine preflight work or memory bounds.
// EXPIRY: when the first production proof_work implementation appears, make
// this contract its sole budget entry, remove the private-only qualification,
// and retarget controls to the actual production call site.
// GUARD: default test-workchain-preflight-expiry rejects new production
// implementations; it does not depend on the optional native fixture module.
// LIMIT: this detects arrival without integration, not whether the integrated
// engine charges every operation correctly. That is the engine unit's duty.

#include "td/utils/Status.h"
#include <cstdint>
#include <exception>
#include <optional>
#include <type_traits>
#include <utility>

namespace block {

// Mechanism inputs, NOT authenticated policy or a new wire/profile identity.
// The eventual host must obtain this allowance before invoking proof_work,
// from the authenticated profile and an independently bounded admission step.
// It cannot use proof_work's return value to bound that same invocation.
struct WorkchainPreflightAllowance {
  explicit WorkchainPreflightAllowance(std::uint64_t value) : units(value) {}
  const std::uint64_t units;
};

enum class WorkchainPreflightReservation { Reserved, BlockLimitExceeded, LocalUnavailable };

// C2 seam: transport an explicit request and a reservation outcome only.
// Collator accumulation and validator independent recomputation must have
// separate implementations. No shared total, candidate verdict or wire value
// is derived here. Successful reservation is permanent even if inspection
// fails or uses less than its allowance. There is deliberately no refund API.
class WorkchainPreflightReservations {
 public:
  virtual ~WorkchainPreflightReservations() = default;
  virtual WorkchainPreflightReservation reserve_preflight(std::uint64_t units) = 0;
};

enum class WorkchainPreflightMeterState { Ready, Exhausted, InvalidCharge };
enum class WorkchainPreflightReason {
  Complete, InvalidAllowance, BlockLimitExceeded, ReservationUnavailable, InvalidReservation,
  ReservationException, OperationLimitExceeded, InvalidCharge,
  InspectionFailure, InspectionException
};

// These are mechanism reasons, not consensus verdicts:
// InvalidAllowance/InvalidCharge/InvalidReservation: local host/engine contract.
// ReservationUnavailable/ReservationException: local reservation failure.
// BlockLimitExceeded: a capacity observation; collator stopping or validator
// rejection needs that host's independently authenticated limit derivation.
// OperationLimitExceeded: no candidate verdict by itself. An incorrect local
// bound/weight table can also cause it; independent evidence of a candidate
// violation is required before rejecting instead of reporting a local fault.
// InspectionFailure/InspectionException: preserve the supplied failure and
// establish its acquisition provenance; no generic status/class inference.
struct WorkchainPreflightResult {
  // Inspect reason first. A swallowed meter refusal cannot authorize the
  // callback's apparently successful result. Exceptions retain their original
  // type/payload; no exception class or generic Status is a provenance verdict.
  WorkchainPreflightReason reason;
  std::uint64_t consumed;
  std::optional<td::Result<std::uint64_t>> inspection;
  // Consume within this synchronous owner's lifetime, not an actor continuation:
  // an arbitrary exception may retain borrowed objects. Combine its nature with
  // the acquisition source before assigning CandidateInvalid/LocalUnavailable.
  std::exception_ptr exception;
};

class WorkchainPreflightRunner;
class WorkchainPreflightMeter {
 public:
  WorkchainPreflightMeter(const WorkchainPreflightMeter&) = delete;
  WorkchainPreflightMeter& operator=(const WorkchainPreflightMeter&) = delete;
  WorkchainPreflightMeter(WorkchainPreflightMeter&&) = delete;
  WorkchainPreflightMeter& operator=(WorkchainPreflightMeter&&) = delete;

  // Only operations routed here are charged. This is not a C++ sandbox:
  // a production engine must separately prove its operation weights and that
  // every input-dependent loop/allocation/read is covered. Native arbitrary
  // work outside this entry, or undercharging inside it, is not prevented by
  // possessing a meter. The concrete production preflight does not yet exist.
  template <class Operation>
  bool perform(std::uint64_t units, Operation&& operation) {
    static_assert(std::is_same_v<std::invoke_result_t<Operation>, void>);
    if (state_ != WorkchainPreflightMeterState::Ready) return false;
    // No implicit free operation. Empty inspection may perform no operations;
    // a zero-priced operation is instead an explicit local contract fault.
    if (!units) {
      state_ = WorkchainPreflightMeterState::InvalidCharge;
      return false;
    }
    // Invariant consumed_ <= limit_: only this checked precharge increases it.
    // Compare by subtraction so a UINT64_MAX request cannot wrap the sum.
    if (units > limit_ - consumed_) {
      state_ = WorkchainPreflightMeterState::Exhausted;
      return false;
    }
    consumed_ += units;
    std::forward<Operation>(operation)();
    return true;
  }
  std::uint64_t consumed() const { return consumed_; }
  WorkchainPreflightMeterState state() const { return state_; }

 private:
  friend class WorkchainPreflightRunner;
  explicit WorkchainPreflightMeter(std::uint64_t limit) : limit_(limit) {}
  const std::uint64_t limit_;
  std::uint64_t consumed_{0};
  WorkchainPreflightMeterState state_{WorkchainPreflightMeterState::Ready};
};

class WorkchainPreflightRunner {
 public:
  // Synchronous inspection only. No old-state view, execution, settlement,
  // token for later execution, or active production call site is installed.
  // The inspector returns its usual declared verification work, not the work
  // spent producing that declaration. The latter is measured separately here.
  // The borrowed meter must not escape this call or be retained across a
  // coroutine suspension. Noncopyability does not prevent stashing a pointer.
  template <class Inspector>
  static WorkchainPreflightResult run(WorkchainPreflightReservations& reservations,
                                     WorkchainPreflightAllowance allowance, Inspector&& inspector) {
    static_assert(std::is_same_v<std::invoke_result_t<Inspector, WorkchainPreflightMeter&>,
                                 td::Result<std::uint64_t>>);
    using Reason = WorkchainPreflightReason;
    // No zero-cost callback entry. Representing a zero scalar is not proof of
    // an empty inspection; reject it before either reservation or callback.
    if (!allowance.units) return {Reason::InvalidAllowance, 0, std::nullopt, {}};
    try {
      switch (reservations.reserve_preflight(allowance.units)) {
        case WorkchainPreflightReservation::BlockLimitExceeded:
          return {Reason::BlockLimitExceeded, 0, std::nullopt, {}};
        case WorkchainPreflightReservation::LocalUnavailable:
          return {Reason::ReservationUnavailable, 0, std::nullopt, {}};
        case WorkchainPreflightReservation::Reserved:
          break;
        default:
          return {Reason::InvalidReservation, 0, std::nullopt, {}};
      }
    } catch (...) {
      return {Reason::ReservationException, 0, std::nullopt, std::current_exception()};
    }
    // No last-call grace: the whole allowance is reserved BEFORE inspection.
    // This differs from the legacy validator gas hard+transaction allowance
    // (validate-query.cpp). No-grace covers preflight only when its advance
    // allowance and complete operation coverage exist; the old proof_work
    // path checks a returned declaration AFTER inspection and does not meet
    // that condition. C2 alone therefore still leaves a preflight-sized hole.
    WorkchainPreflightMeter meter(allowance.units);
    std::optional<td::Result<std::uint64_t>> result;
    std::exception_ptr exception;
    try {
      result.emplace(std::forward<Inspector>(inspector)(meter));
    } catch (...) {
      exception = std::current_exception();
    }
    Reason reason;
    if (meter.state() == WorkchainPreflightMeterState::Exhausted) {
      reason = Reason::OperationLimitExceeded;
    } else if (meter.state() == WorkchainPreflightMeterState::InvalidCharge) {
      reason = Reason::InvalidCharge;
    } else if (exception) {
      reason = Reason::InspectionException;
    } else if (result->is_error()) {
      reason = Reason::InspectionFailure;
    } else {
      reason = Reason::Complete;
    }
    return {reason, meter.consumed(), std::move(result), std::move(exception)};
  }
};

}  // namespace block
