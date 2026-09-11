#pragma once
// Test registered-host prepare plumbing. Native pricing is the ordinary
// transaction implementation, never an independent fee formula.
#include "block/transaction.h"
#include "block/workchain-operation-fees.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-participant-lt.h"

namespace block::m3_test {
inline td::Result<ActionPhaseConfig> m5_payout_prices(const Config& config, std::uint32_t now) {
  td::Ref<vm::Cell> old;
  std::vector<StoragePrices> prices;
  StoragePhaseConfig storage;
  ComputePhaseConfig compute;
  ActionPhaseConfig action;
  SerializeConfig serialize;
  td::Bits256 seed = td::Bits256::zero();
  seed.as_slice().back() = 1; // Pricing has no random input; avoid generating an unused seed.
  td::RefInt256 mc, wc;
  TRY_STATUS(FetchConfigParams::fetch_config_params(config, td::Ref<vm::Tuple>{}, &old, &prices,
      &storage, &seed, &compute, &action, &serialize, &mc, &wc, 2, now));
  return action;
}
inline td::Result<td::Ref<vm::Cell>> m5_payout_request(const WorkchainWithdrawalInput& input) {
  if (input.data.destination.workchain < -128 || input.data.destination.workchain > 127)
    return td::Status::Error(-7200, "test payout destination does not fit standard address");
  vm::CellBuilder b;
  // Internal, bounceable, src=addr_none (Native replaces it with custody).
  b.store_long(6, 4).store_zeroes(2).store_long(4, 3)
      .store_long(input.data.destination.workchain, 8).store_bits(input.data.destination.account.bits(), 256);
  if (!CurrencyCollection(workchain_unsigned_fee(input.data.amounts.principal)).store(b) ||
      !tlb::t_Tomis.store_integer_ref(b, td::make_refint(3)))
    return td::Status::Error(-7201, "cannot construct test payout value");
  // No StateInit; inline original body is exactly the confidential account ID.
  b.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(input.data.claims.source.account.bits(), 256);
  auto request = b.finalize();
  if (!gen::t_MessageRelaxed_Any.validate_ref(4096, request))
    return td::Status::Error(-7201, "constructed test payout is not MessageRelaxed");
  return request;
}
} // namespace block::m3_test
