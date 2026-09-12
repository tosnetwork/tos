#pragma once
// Shape NOT frozen. Test-scope only. The production business-config codec is
// a separate, undecided unit; do not treat this layout as a precedent.
#include "crypto/test/workchain-m3-genesis-cells.h"
#include "crypto/test/workchain-m3-state-fixture.h"

inline td::Result<td::Ref<vm::Cell>> prepare_m3_live_configuration(td::Ref<vm::Cell> root, bool m4 = false, bool debit = false,
                                                              bool funded_return = false) {
  using namespace block;
  using namespace block::m3_test;
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                      root->get_hash().bits(), td::Bits256::zero()};
  TRY_RESULT(config, ConfigInfo::extract_config(root, zero,
      Config::needWorkchainInfo | Config::needCapabilities));
  TRY_RESULT(table, load_workchain_native_ingress_table(*config));
  auto found = table.find(2);
  if (found == table.end() || !found->second.custody_address)
    return td::Status::Error("M3 test genesis lacks wc=2 coordinator/custody identity");
  auto ingress = found->second;
  TRY_RESULT(old, decode_workchain_engine_parameters(ingress.engine_configuration));
  // Retain the already issued descriptor and instance identity. Only this
  // test-owned Param84 payload changes; the production parser remains unchanged.
  ingress.engine_configuration.clear();
  auto label = [](unsigned char value) {
    td::Bits256 result;
    result.as_slice().fill(value);
    return result;
  };
  std::array<unsigned char, 80> domain;
  domain.fill(0x2a);
  M3TestBusinessParameters business{{1000000, 10000, 8, 1024, 4096}, domain, 11, 17,
      {label(1), *ingress.custody_address, label(3)}, label(4), label(5), label(6), 0, 1, 1, 2};
  // Explicit TEST allowances, not capacity measurements or production defaults.
  // The finality witness contains authenticated masterchain state, so its input
  // allowance is deliberately larger than the tiny earlier readiness probe.
  WorkchainResourcePolicy resources{4, {65536, 16777216, 32, 3, 3, 1},
      {65536, 16777216, 4096, 1048576, 128},
      {100000, 4096, 1048576, 65536, 16777216, 2}, {0, 2, 2}, 1};
  WorkchainCoordinatorState coordinator{2, {1, 1, 0, 0}, 0};
  if (m4) {
    // Explicit authenticated TEST inputs, not defaults or the coordinator's
    // separately scheduled independent-prediction experiment. D28 is absent.
    const auto maximum = (std::uint64_t{1} << 62) - 1;
    business.limits.max_balance = business.limits.max_value = maximum;
    business.send_fee = business.collect_fee = 0;
    business.account_schema = 2;
    business.proof_profile = 4;
    business.deposit = WorkchainDepositPolicy{1000000000, maximum, 3000000, 16, 4};
    business.operation_tariff = WorkchainStaticOperationTariff{2, 5, 7};
    if (debit) business.prepare = M5TestPrepareParameters{250, 4, 30};  // Explicit test inputs, not frozen defaults.
    if (funded_return) {
      business.prepare = M5TestPrepareParameters{250, 4, 30};
      business.failed = M5TestFailedParameters{4, 4}; // Explicit D70 test input, NOT seven proof-work units.
    }
    resources.input.max_reads = resources.input.max_writes = 4;
    auto bucket = encode_workchain_unexpected_bucket({{}, {}, td::make_refint(0), {}, 0},
                                                     {256, 256}, 4096);
    TRY_RESULT(empty_bucket, std::move(bucket));
    coordinator = WorkchainCoordinatorState{3, {1, 1, 0, 0}, 0, 0, empty_bucket};
  }
  TRY_RESULT(cells, make_m3_test_genesis_cells(business, resources,
      old.k_accepted_target_rate_ms, old.instance_id, old.registration_deposit,
      ingress, coordinator));
  TRY_RESULT(updated, replace_m3_test_param84(root, cells.param84));
  if (!updated.config_account_updated)
    return td::Status::Error("M3 fixture requires synchronized Native configuration account");
  return updated.root;
}
