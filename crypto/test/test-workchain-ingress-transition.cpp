#include <iostream>
#include "block/workchain-execution-dispatch.h"
#include "block/block.h"
#include "block/block-auto.h"
#include "block/mc-config.h"

namespace {
// Minimal real configuration roots for the transition and presence predicates.
// Identity is an explicit representable fixture value, not an installation claim.
td::Ref<vm::Cell> config(unsigned version, int ingress, bool dual = false) {
  vm::Dictionary dictionary(32), workchains(32);
  vm::CellBuilder version_cell;
  CHECK(block::gen::t_GlobalVersion.pack_capabilities(version_cell, version, tos::capBlockTransition));
  CHECK(dictionary.set_ref(td::BitArray<32>{8}, version_cell.finalize()));
  std::vector<block::WorkchainNativeIngressPolicy> policies;
  for (int wc : {2, 3}) {
    auto descriptor = vm::CellBuilder().store_long(0xa6, 8).store_zeroes(32 + 24)
        .store_long(6, 3).store_zeroes(13 + 512).store_long(0, 32)
        .store_long(1, 4).store_long(0x434e5431, 32).store_long(0, 64).finalize();
    CHECK(block::gen::t_WorkchainDescr.validate_ref(10000, descriptor));
    CHECK(workchains.set(td::BitArray<32>{wc}, vm::load_cell_slice_ref(descriptor)));
    if (ingress == 0 || (ingress == 1 && wc == 2)) continue;
    block::WorkchainNativeIngressPolicy policy;
    policy.workchain_id = wc;
    policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
    policy.executor_address.set_zero();
    if (dual) policy.custody_address = td::Bits256::ones();
    block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
        {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
    policy.engine_configuration = block::encode_workchain_engine_parameters(
        {400, td::Bits256::ones(), resources, vm::CellBuilder().finalize()}).move_as_ok();
    policies.push_back(std::move(policy));
  }
  vm::CellBuilder list;
  CHECK(workchains.append_dict_to_bool(list));
  CHECK(dictionary.set_ref(td::BitArray<32>{12}, list.finalize()));
  if (ingress != 0) {
    auto table = block::encode_workchain_native_ingress_table(policies).move_as_ok();
    CHECK(block::decode_workchain_native_ingress_table(table).is_ok());
    CHECK(dictionary.set_ref(td::BitArray<32>{84}, table));
  }
  return dictionary.get_root_cell();
}
bool presence(td::Ref<vm::Cell> root) {
  vm::Dictionary dictionary(root, 32);
  return block::validate_native_ingress_presence(dictionary).is_ok();
}
}

int main() {
  auto original = config(16, 2);
  auto hash = original->get_hash();
  unsigned failures = 0;
  auto check = [&](unsigned id, bool actual, bool expected) {
    bool pass = actual == expected;
    std::cout << id << '\t' << actual << '\t' << expected << '\t' << pass << '\n';
    failures += !pass;
  };
  check(1230, block::valid_config_transition(original, original).is_ok(), true);
  check(1231, block::valid_config_transition(original, config(16, 0)).is_ok(), false);
  check(1232, block::valid_config_transition(original, config(16, 1)).is_ok(), false);
  // Transition continuity does not impose a global-version monotonicity rule.
  check(1233, block::valid_config_transition(original, config(15, 2)).is_ok(), true);
  check(1234, presence(config(15, 2)), true);
  check(1235, block::valid_config_transition(original, config(14, 2)).is_ok(), true);
  check(1236, presence(config(14, 2)), false);
  auto dual = config(16, 2, true);
  check(1237, presence(dual), true);
  check(1238, block::valid_config_transition(dual, config(15, 2, true)).is_ok(), true);
  check(1239, presence(config(15, 2, true)), false);
  // Param12 membership alone is not the ingress-continuity premise.
  auto no_ingress = config(14, 0);
  check(1240, block::valid_config_transition(no_ingress, no_ingress).is_ok(), true);
  check(1241, presence(no_ingress), true);
  check(1242, original->get_hash() == hash, true);
  return failures ? 1 : 0;
}
