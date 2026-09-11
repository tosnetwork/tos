#pragma once

#include "block/workchain-deposit-transition.h"
#include "workchain-proof-test-access.h"

// Called by the existing real-backend executable, not a substitute backend.
inline void test_metered_deposit_transition() {
  using namespace block;
  auto key = [](unsigned n) { td::Bits256 b = td::Bits256::zero(); b.as_slice()[31] = static_cast<char>(n); return b; };
  auto bytes = td::hex_decode("b6ec3baa39a7357ab9ca16c61373385f7cfb04ab10c4bc20c8bd3cc6db9a6100").move_as_ok();
  td::Bits256 point;
  point.as_slice().copy_from(bytes);
  WorkchainConfidentialAccount account{2, 1, 4, -23903, key(1), {2, key(2), key(3)},
      {key(4), key(5), key(6)}, {10000000000ULL, 0, key(7)}, point, 0,
      {td::Bits256::zero(), td::Bits256::zero()}, 0, 0, {}, WorkchainAccountActive{}, {}};
  auto empty = encode_workchain_unexpected_bucket({{}, {}, td::make_refint(0), {}, 0}, {256, 256}, 100).move_as_ok();
  WorkchainCoordinatorState coordinator{3, {1, 0, 1, 4}, 10000000000ULL, 0, empty};
  WorkchainDepositPolicy policy{1000000000, (std::uint64_t{1} << 62) - 1, 3000000, 16, 4};
  std::array<unsigned char, 80> domain{};
  auto run = [&](const WorkchainConfidentialAccount& prior, const WorkchainCoordinatorState& system,
                 const CurrencyCollection& backing, const CurrencyCollection& operating,
                 WorkchainProofVerifier& meter) {
    return prepare_workchain_deposit_transition(policy, domain, key(8), key(5), key(4), key(9), prior.address,
        1000000000, CurrencyCollection(1003000000), std::optional<WorkchainConfidentialAccount>{prior},
        system, backing, operating, {256, 256}, 100, meter);
  };
  auto generate = WorkchainProofTestAccess::create(7);
  auto replay = WorkchainProofTestAccess::create(7);
  auto produced = run(account, coordinator, CurrencyCollection(0), CurrencyCollection(10000000000ULL), generate);
  auto verified = run(account, coordinator, CurrencyCollection(0), CurrencyCollection(10000000000ULL), replay);
  require(produced.is_ok() && verified.is_ok(), "real Deposit encryption or reconstruction failed");
  require(std::holds_alternative<WorkchainDepositTransition>(produced.ok()) &&
          std::holds_alternative<WorkchainDepositTransition>(verified.ok()), "valid Deposit was rejected");
  auto a = std::get<WorkchainDepositTransition>(produced.move_as_ok());
  const auto& b = std::get<WorkchainDepositTransition>(verified.ok());
  require(a.account_data->get_hash() == b.account_data->get_hash() &&
          a.coordinator_data->get_hash() == b.coordinator_data->get_hash(), "Deposit replay state differs");
  require(generate.consumed() == 7 && replay.consumed() == 7, "Deposit paired metering differs");
  require(td::cmp(a.custody_balance.tomis, 1000000000) == 0 &&
          td::cmp(a.coordinator_balance.tomis, 10003000000ULL) == 0 &&
          td::cmp(a.principal_transfer.value.tomis, 1000000000) == 0,
          "Deposit slot fee contaminated custody or principal");
  auto installed = decode_workchain_confidential_account(a.account_data).move_as_ok();
  auto system = decode_workchain_coordinator_state(a.coordinator_data).move_as_ok();
  require(system.deposit_sequence == 1 && installed.system_pending.size() == 1 &&
          installed.system_pending.front().amount == 1000000000 && coordinator.deposit_sequence == 0 &&
          account.system_pending.empty(), "Deposit sequence/receipt installation is not atomic");
  auto short_budget = WorkchainProofTestAccess::create(6);
  auto stopped = run(account, coordinator, CurrencyCollection(0), CurrencyCollection(10000000000ULL), short_budget);
  require(stopped.is_error() && stopped.error().code() == -7201 && short_budget.consumed() == 0,
          "Deposit bypassed precharge");
  auto changed_price = WorkchainProofTestAccess::create(7);
  policy.slot_fee = 5000000;
  auto rejection = run(account, coordinator, CurrencyCollection(0), CurrencyCollection(10000000000ULL), changed_price);
  require(rejection.is_ok() && std::holds_alternative<WorkchainDepositRejection>(rejection.ok()) &&
          changed_price.consumed() == 0 && coordinator.deposit_sequence == 0,
          "rejected Deposit executed crypto or installed a sequence");
  std::cout << "Deposit transition: principal=1000000000 operating_fee=3000000 sequence=1; paired units=7/7; no partial install\n";
}
