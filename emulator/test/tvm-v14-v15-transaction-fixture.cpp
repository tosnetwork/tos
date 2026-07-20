/*
    Copyright (C) 2025-2026 TOS Network.

    TVM v14/v15 transaction-layer conformance tests.
*/

#include "block/block-auto.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"

namespace {

block::gen::SizeLimitsConfig::Record_size_limits_config_v3 make_size_limits_v3(
    td::Ref<vm::CellSlice> max_transaction_library_loads) {
  return {/*max_msg_bits=*/1000,
          /*max_msg_cells=*/100,
          /*max_library_cells=*/1000,
          /*max_vm_data_depth=*/512,
          /*max_ext_msg_size=*/65535,
          /*max_ext_msg_depth=*/512,
          /*max_acc_state_cells=*/5000,
          /*max_mc_acc_state_cells=*/10000,
          /*max_acc_public_libraries=*/256,
          /*defer_out_queue_size_limit=*/256,
          /*max_msg_extra_currencies=*/32,
          /*max_acc_fixed_prefix_length=*/8,
          /*acc_state_cells_for_storage_dict=*/1024,
          std::move(max_transaction_library_loads),
          /*max_total_msg_bits=*/2000,
          /*max_total_msg_cells=*/200};
}

td::Ref<vm::CellSlice> make_maybe_uint32(td::optional<td::uint32> value) {
  vm::CellBuilder builder;
  if (value) {
    builder.store_long(1, 1).store_long(*value, 32);
  } else {
    builder.store_long(0, 1);
  }
  return builder.as_cellslice_ref();
}

block::SizeLimitsConfig parse_size_limits_v3(td::optional<td::uint32> max_transaction_library_loads) {
  auto record = make_size_limits_v3(make_maybe_uint32(max_transaction_library_loads));
  td::Ref<vm::Cell> cell;
  CHECK(block::gen::t_SizeLimitsConfig.cell_pack(cell, record));
  return block::Config::do_get_size_limits_config(vm::load_cell_slice_ref(cell)).move_as_ok();
}

}  // namespace

TEST(TvmV15Transaction, ChangeLibraryVersionGate) {
  using block::transaction::check_change_library_action;
  CHECK(check_change_library_action(1, false, 14) == 0);
  CHECK(check_change_library_action(1, true, 15) == 46);
  CHECK(check_change_library_action(2, false, 15) == 46);
  CHECK(check_change_library_action(0, false, 15) == 46);
  CHECK(check_change_library_action(2, true, 15) == 0);
  CHECK(check_change_library_action(0, true, 15) == 0);
  CHECK(check_change_library_action(3, true, 14) == -1);
  CHECK(check_change_library_action(3, true, 15) == -1);
}

TEST(TvmV15Transaction, TotalMessageSizeVersionGateAndBoundaries) {
  block::SizeLimitsConfig limits;
  limits.max_total_msg_bits = 100;
  limits.max_total_msg_cells = 10;
  using block::transaction::exceeds_total_message_size;

  CHECK(!exceeds_total_message_size(1000, 1000, 1000, 1000, limits, 14));
  CHECK(!exceeds_total_message_size(40, 4, 60, 6, limits, 15));
  CHECK(exceeds_total_message_size(40, 4, 61, 6, limits, 15));
  CHECK(exceeds_total_message_size(40, 4, 60, 7, limits, 15));
}

TEST(TvmV15Transaction, FailedActionFineIsCappedAtBalance) {
  using block::transaction::cap_failed_action_fine;
  CHECK(cap_failed_action_fine(td::make_refint(40), td::make_refint(70), td::make_refint(50))->to_long() == 50);
  CHECK(cap_failed_action_fine(td::make_refint(10), td::make_refint(20), td::make_refint(50))->to_long() == 30);
}

TEST(TvmV15Transaction, DeployLibraryVersionGate) {
  using block::transaction::reject_deploy_with_libraries;
  CHECK(!reject_deploy_with_libraries(true, true, 14));
  CHECK(reject_deploy_with_libraries(true, true, 15));
  CHECK(!reject_deploy_with_libraries(true, false, 15));
  CHECK(!reject_deploy_with_libraries(false, true, 15));
}

TEST(TvmV15Config, SizeLimitsV3ParsesTransactionLibraryLimit) {
  auto limits = parse_size_limits_v3(77);
  CHECK(limits.max_transaction_library_loads);
  CHECK(*limits.max_transaction_library_loads == 77);
  CHECK(limits.max_total_msg_bits == 2000);
  CHECK(limits.max_total_msg_cells == 200);
}

TEST(TvmV15Config, SizeLimitsV3AllowsNoTransactionLibraryLimit) {
  auto limits = parse_size_limits_v3({});
  CHECK(!limits.max_transaction_library_loads);
  CHECK(limits.max_total_msg_bits == 2000);
  CHECK(limits.max_total_msg_cells == 200);
}
