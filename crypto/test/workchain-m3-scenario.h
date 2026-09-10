// TEST SCENARIO ONLY. Orchestration is independent of pure execution or block publication.
#pragma once
#include <array>
#include <iostream>

#include "workchain-m3-assertions.h"

namespace block::m3_test {
struct ScenarioState {
  Root coordinator;
  std::array<Root, 2> accounts;
  std::array<std::uint64_t, 2> native_balances;
};
// Backends publish results atomically. A live backend must return read-back roots
// from accepted blocks, not the effects it hoped to publish. seed is explicitly
// test funding, not a claimed M4 deposit. No mode silently bypasses verification.
class ScenarioBackend {
 public:
  virtual ~ScenarioBackend() = default;
  virtual const ScenarioState& state() const = 0;
  virtual Point wallet_secret(unsigned owner) const = 0;
  virtual std::uint64_t fee(unsigned kind) const = 0;
  virtual td::Status register_account(unsigned owner) = 0;
  virtual td::Status seed(unsigned owner, std::uint64_t value) = 0;
  virtual td::Result<Root> send(unsigned owner, unsigned receiver, std::uint64_t value) = 0;
  virtual td::Result<Root> collect(unsigned owner, const std::vector<td::Bits256>& selected) = 0;
  virtual td::Result<RefundObserved> close(unsigned owner) = 0;
};
inline td::Result<std::string> run_m3_scenario(ScenarioBackend& backend) {
  auto decoded = [](const Root& r) { return decode_workchain_confidential_account(r); };
  TRY_RESULT(initial, decode_workchain_coordinator_state(backend.state().coordinator));
  if (initial.system.registered_accounts != 0)
    return alarm("scenario must start without registrations");
  for (unsigned owner : {0u, 1u}) {
    auto before = backend.state();
    TRY_STATUS(backend.register_account(owner));
    const auto& after = backend.state();
    TRY_STATUS(assert_registration(before.coordinator, after.coordinator, after.accounts[owner]));
    TRY_RESULT(account, decoded(after.accounts[owner]));
    if (account.funding.paid_deposit > before.native_balances[owner])
      return alarm("registration payer underflow");
    TRY_STATUS(
        assert_balance(after.native_balances[owner], before.native_balances[owner] - account.funding.paid_deposit));
    std::cout << "registered " << owner << "\n";
  }
  TRY_STATUS(backend.seed(0, 50000));
  TRY_RESULT(seeded, decoded(backend.state().accounts[0]));
  TRY_RESULT(seed_value, decrypt(seeded.available, backend.wallet_secret(0), 1000000));
  TRY_STATUS(assert_balance(seed_value, 50000));
  std::array<std::uint64_t, 2> balances{50000, 0};
  auto send = [&](unsigned from, unsigned to, std::uint64_t amount) -> td::Result<td::Bits256> {
    auto before = backend.state();
    TRY_RESULT(candidate, backend.send(from, to, amount));
    TRY_RESULT(debit, checked_sum(amount, backend.fee(1)));
    if (debit > balances[from])
      return alarm("scenario SEND underflow");
    auto expected = balances[from] - debit;
    TRY_RESULT(observed, assert_transfer(candidate, before.accounts[from], backend.state().accounts[from],
                                         backend.wallet_secret(from), 1000000, balances[from], expected,
                                         before.accounts[to], backend.state().accounts[to], backend.wallet_secret(to)));
    balances[from] = observed.after;
    TRY_RESULT(input, decode_workchain_transfer_input(candidate));
    TRY_RESULT(a, decoded(before.accounts[from]));
    TRY_RESULT(id, derive_workchain_receipt_id(a.address.instance, input.claimed_operation_id, 0));
    std::cout << "SEND " << from << "->" << to << " amount=" << observed.transferred << " source=" << observed.after
              << "\n";
    return id;
  };
  auto collect = [&](std::vector<td::Bits256> ids, std::uint64_t total) -> td::Status {
    std::sort(ids.begin(), ids.end());
    auto before = backend.state();
    TRY_RESULT(candidate, backend.collect(1, ids));
    TRY_RESULT(sum, checked_sum(balances[1], total));
    if (backend.fee(2) > sum)
      return alarm("scenario COLLECT underflow");
    auto expected = sum - backend.fee(2);
    TRY_RESULT(observed, assert_transfer(candidate, before.accounts[1], backend.state().accounts[1],
                                         backend.wallet_secret(1), 1000000, balances[1], expected));
    balances[1] = observed.after;
    std::cout << "COLLECT k=" << ids.size() << " balance=" << observed.after
              << " retained=" << observed.retained_pending << "\n";
    return td::Status::OK();
  };
  // The extra first-round SEND makes "unselected remains" non-vacuous.
  TRY_RESULT(first, send(0, 1, 137));
  TRY_RESULT(retained, send(0, 1, 251));
  TRY_STATUS(collect({first}, 137));
  TRY_RESULT(third, send(0, 1, 89));
  TRY_STATUS(collect({retained, third}, 340));
  if (balances[1] <= backend.fee(1))
    return alarm("B cannot send its remaining balance");
  TRY_RESULT(final_receipt, send(1, 0, balances[1] - backend.fee(1)));
  (void)final_receipt;
  TRY_STATUS(assert_balance(balances[1], 0));
  auto before = backend.state();
  TRY_RESULT(refund, backend.close(1));
  TRY_STATUS(assert_closure(before.coordinator, backend.state().coordinator, before.accounts[1],
                            backend.state().accounts[1], backend.wallet_secret(1), 1000000, refund));
  TRY_RESULT(native, checked_sum(before.native_balances[1], refund.amount));
  TRY_STATUS(assert_balance(backend.state().native_balances[1], native));
  TRY_RESULT(end, decode_workchain_coordinator_state(backend.state().coordinator));
  TRY_STATUS(assert_balance(end.system.registered_accounts, 2));
  std::cout << "CLOSED B; historical refund=" << refund.amount << " registered_accounts=2\n";
  return std::string("M3_SEQUENCE_PASS: registration; test funding; SEND; COLLECT k=1/k=2; zero-balance closure");
}
}  // namespace block::m3_test
