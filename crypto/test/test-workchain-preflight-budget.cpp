#include "block/workchain-preflight-budget.h"
#include <cstdlib>
#include <array>
#include <iostream>
#include <limits>
#include <new>
#include <string>

namespace {
using Reason = block::WorkchainPreflightReason;
using Reservation = block::WorkchainPreflightReservation;
using Meter = block::WorkchainPreflightMeter;
using Runner = block::WorkchainPreflightRunner;
using Allowance = block::WorkchainPreflightAllowance;
static_assert(!std::is_default_constructible_v<Allowance>);
static_assert(!std::is_constructible_v<Meter, std::uint64_t>);
static_assert(!std::is_copy_constructible_v<Meter> && !std::is_move_constructible_v<Meter>);

void require(bool condition, const char* identity) {
  if (!condition) {
    std::cerr << identity << '\n';
    std::exit(1);
  }
}

// Synthetic C2 consumer only; NOT shared collator/validator derivation or a
// substitute for authenticating the future preflight policy/units/version.
struct PrivateBlock final : block::WorkchainPreflightReservations {
  explicit PrivateBlock(std::uint64_t value) : hard(value) {}
  const std::uint64_t hard;
  std::uint64_t used = 0;
  unsigned calls = 0;
  Reservation reserve_preflight(std::uint64_t units) override {
    ++calls;
    if (units > hard - used) return Reservation::BlockLimitExceeded;
    used += units;
    return Reservation::Reserved;
  }
};
struct FailureReservations final : block::WorkchainPreflightReservations {
  Reservation answer = Reservation::LocalUnavailable;
  bool throws = false;
  Reservation reserve_preflight(std::uint64_t) override {
    if (throws) throw std::bad_alloc();
    return answer;
  }
};

struct Inspected {
  unsigned bodies = 0;
  unsigned operations = 0;
  std::uint64_t independent_units = 0;
  void operation(std::uint64_t units) { ++operations; independent_units += units; }
};

void positive() {
  PrivateBlock budget(12);
  Inspected observed;
  auto result = Runner::run(budget, Allowance(7), [&](Meter& meter) -> td::Result<std::uint64_t> {
    ++observed.bodies;
    require(budget.used == 7 && budget.calls == 1, "reserve.before_body");
    require(meter.perform(3, [&] {
      require(meter.consumed() == 3, "charge.before_operation");
      observed.operation(3);
    }), "positive.first");
    require(meter.perform(4, [&] { observed.operation(4); }), "positive.exact");
    return 91;  // Deliberately distinct from spent preflight units.
  });
  require(result.reason == Reason::Complete, "positive.complete");
  require(result.inspection && result.inspection->is_ok() && result.inspection->ok() == 91,
          "positive.declaration_retained");
  require(result.consumed == 7 && observed.independent_units == 7 && observed.operations == 2,
          "positive.independent_count");
  require(observed.bodies == 1 && budget.used == 7, "positive.once");
}

void block_bound() {
  PrivateBlock budget(10);
  Inspected observed;
  auto inspect = [&](Meter& meter) -> td::Result<std::uint64_t> {
    ++observed.bodies;
    require(meter.perform(1, [&] { observed.operation(1); }), "block.operation");
    return 2;
  };
  auto first = Runner::run(budget, Allowance(4), inspect);
  auto second = Runner::run(budget, Allowance(6), inspect);
  auto third = Runner::run(budget, Allowance(1), inspect);
  require(first.reason == Reason::Complete && second.reason == Reason::Complete, "block.exact_allowed");
  require(third.reason == Reason::BlockLimitExceeded && !third.inspection && third.consumed == 0,
          "block.no_grace");
  require(observed.bodies == 2 && observed.operations == 2 && budget.used == 10,
          "block.no_extra_inspection");
  PrivateBlock independent(10);
  require(Runner::run(independent, Allowance(10), inspect).reason == Reason::Complete,
          "block.independent_scope");
}

void sticky() {
  PrivateBlock budget(8);
  Inspected observed;
  auto result = Runner::run(budget, Allowance(5), [&](Meter& meter) -> td::Result<std::uint64_t> {
    require(meter.perform(3, [&] { observed.operation(3); }), "sticky.first");
    require(!meter.perform(3, [&] { observed.operation(3); }), "sticky.over_limit");
    require(!meter.perform(1, [&] { observed.operation(1); }), "sticky.no_resume");
    return 0;  // Swallow both refusals; host must still deny completion.
  });
  require(result.reason == Reason::OperationLimitExceeded, "sticky.host_overrides_success");
  require(result.consumed == 3 && observed.operations == 1 && budget.used == 5,
          "sticky.no_work_or_refund");
}

void failure() {
  PrivateBlock budget(5);
  auto result = Runner::run(budget, Allowance(5), [](Meter& meter) -> td::Result<std::uint64_t> {
    require(meter.perform(2, [] {}), "failure.charge");
    return td::Status::Error("private parser failure");
  });
  require(result.reason == Reason::InspectionFailure && result.inspection && result.inspection->is_error(),
          "failure.retains_status");
  require(result.inspection->error().message() == "private parser failure", "failure.original_message");
  unsigned called = 0;
  auto retry = Runner::run(budget, Allowance(1), [&](Meter&) -> td::Result<std::uint64_t> { ++called; return 0; });
  require(budget.used == 5 && result.consumed == 2 && retry.reason == Reason::BlockLimitExceeded && called == 0,
          "failure.no_refund");
}

struct ParserFault { int identity; };
void exception() {
  PrivateBlock budget(9);
  auto result = Runner::run(budget, Allowance(5), [](Meter& meter) -> td::Result<std::uint64_t> {
    meter.perform(2, [] { throw ParserFault{47}; });
    return 0;
  });
  require(result.reason == Reason::InspectionException && !result.inspection && result.exception,
          "exception.original_present");
  bool matched = false;
  try { std::rethrow_exception(result.exception); }
  catch (const ParserFault& fault) { matched = fault.identity == 47; }
  catch (...) {}  // A changed payload must fail the specific identity assertion.
  require(matched && result.consumed == 2 && budget.used == 5, "exception.type_and_charge_retained");
  auto secondary = Runner::run(budget, Allowance(4), [](Meter& meter) -> td::Result<std::uint64_t> {
    meter.perform(5, [] {});
    throw ParserFault{48};
  });
  require(secondary.reason == Reason::OperationLimitExceeded && secondary.exception,
          "exception.meter_reason_first");
}

void reservation_failure() {
  FailureReservations budget;
  unsigned called = 0;
  auto body = [&](Meter&) -> td::Result<std::uint64_t> { ++called; return 0; };
  auto local = Runner::run(budget, Allowance(1), body);
  require(local.reason == Reason::ReservationUnavailable && !local.inspection && called == 0,
          "reservation.local_no_body");
  budget.answer = static_cast<Reservation>(87);
  auto unknown = Runner::run(budget, Allowance(1), body);
  require(unknown.reason == Reason::InvalidReservation && !unknown.inspection && called == 0,
          "reservation.unknown_no_default");
  budget.throws = true;
  auto thrown = Runner::run(budget, Allowance(1), body);
  require(thrown.reason == Reason::ReservationException && thrown.exception && called == 0,
          "reservation.throw_no_body");
  bool matched = false;
  try { std::rethrow_exception(thrown.exception); }
  catch (const std::bad_alloc&) { matched = true; }
  catch (...) {}  // Do not replace a failed type check with process termination.
  require(matched, "reservation.original_allocation_exception");
}

void overflow() {
  constexpr auto max = std::numeric_limits<std::uint64_t>::max();
  PrivateBlock budget(max);
  unsigned operations = 0;
  auto result = Runner::run(budget, Allowance(max), [&](Meter& meter) -> td::Result<std::uint64_t> {
    require(meter.perform(max - 1, [&] { ++operations; }), "overflow.near_max");
    require(!meter.perform(2, [&] { ++operations; }), "overflow.no_wrap");
    return 3;
  });
  require(result.reason == Reason::OperationLimitExceeded && result.consumed == max - 1 && operations == 1,
          "overflow.host_result");
}

void zero() {
  PrivateBlock budget(3);
  unsigned operations = 0;
  auto result = Runner::run(budget, Allowance(1), [&](Meter& meter) -> td::Result<std::uint64_t> {
    require(!meter.perform(0, [&] { ++operations; }), "zero.not_free");
    return 0;
  });
  require(result.reason == Reason::InvalidCharge && operations == 0, "zero.host_result");
  auto thrown = Runner::run(budget, Allowance(1), [](Meter& meter) -> td::Result<std::uint64_t> {
    meter.perform(0, [] {});
    throw ParserFault{49};
  });
  require(thrown.reason == Reason::InvalidCharge && thrown.exception, "zero.precedes_exception");
  auto failed = Runner::run(budget, Allowance(1), [](Meter& meter) -> td::Result<std::uint64_t> {
    meter.perform(0, [] {});
    return td::Status::Error("secondary error");
  });
  require(failed.reason == Reason::InvalidCharge && failed.inspection && failed.inspection->is_error(),
          "zero.precedes_status_error");
}

void allowance() {
  PrivateBlock budget(2);
  unsigned bodies = 0;
  auto body = [&](Meter&) -> td::Result<std::uint64_t> { ++bodies; return 0; };
  auto zero = Runner::run(budget, Allowance(0), body);
  require(zero.reason == Reason::InvalidAllowance && !zero.inspection && !zero.exception && zero.consumed == 0,
          "allowance.zero_rejected");
  require(bodies == 0 && budget.calls == 0, "allowance.before_reservation_and_body");
  // A nonzero allowance with no metered operations still costs the full
  // block reservation. Complete here does not prove native operation coverage.
  auto empty = Runner::run(budget, Allowance(2), body);
  require(empty.reason == Reason::Complete && empty.consumed == 0 && budget.used == 2 && bodies == 1,
          "allowance.empty_body_not_free_reservation");
}

struct Case { const char* name; void (*run)(); };
const std::array cases = {
    Case{"positive", positive}, Case{"block-bound", block_bound}, Case{"sticky", sticky},
    Case{"failure", failure}, Case{"exception", exception}, Case{"reservation-failure", reservation_failure},
    Case{"overflow", overflow}, Case{"zero", zero}, Case{"allowance", allowance}};
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const std::string name = argv[1];
  if (name == "--list") {
    for (const auto& test : cases) std::cout << test.name << '\n';
    return 0;
  }
  for (const auto& test : cases) {
    if (name != test.name) continue;
    test.run();
    std::cout << "completed preflight host case: " << name << '\n';
    return 0;
  }
  return 2;
}
