#pragma once
// Shape NOT frozen. Test-scope only. The production business-config codec is
// a separate, undecided unit; do not treat this layout as a precedent.
#include "crypto/test/workchain-m3-genesis-cells.h"
#include "crypto/test/workchain-m3-state-fixture.h"

inline td::Result<td::Ref<vm::Cell>> prepare_m3_live_configuration(td::Ref<vm::Cell> root) {
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
  TRY_RESULT(cells, make_m3_test_genesis_cells(business, resources,
      old.k_accepted_target_rate_ms, old.instance_id, old.registration_deposit,
      ingress, WorkchainCoordinatorState{2, {1, 1, 0, 0}, 0}));
  TRY_RESULT(updated, replace_m3_test_param84(root, cells.param84));
  if (!updated.config_account_updated)
    return td::Status::Error("M3 fixture requires synchronized Native configuration account");
  return updated.root;
}
