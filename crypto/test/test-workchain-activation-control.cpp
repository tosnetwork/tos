#include <iostream>
#include "td/utils/misc.h"
#include "workchain-counter-engine.h"
#include "block/block-auto.h"
#include "block/mc-config.h"

// Resolver-only calibration. No collator, transaction counter or candidate
// exporter is simulated here. Configuration cells are constructed afresh in
// memory; this executable accepts no configuration paths and opens no fixtures.
int main() {
  for (bool registered : {false, true}) {
    for (bool enabled : {false, true}) {
      vm::Dictionary dictionary(32);
      vm::CellBuilder version;
      if (!block::gen::t_GlobalVersion.pack_capabilities(version, 15,
              enabled ? tos::capBlockTransition : 0) ||
          !dictionary.set_ref(td::BitArray<32>{8}, version.finalize())) return 320;
      auto descriptor = vm::CellBuilder().store_long(0xa6, 8).store_zeroes(32 + 24)
          .store_long(7, 3).store_zeroes(13 + 512).store_long(0, 32)
          .store_long(1, 4).store_long(0x434e5431, 32).store_long(0, 64).finalize();
      if (!block::gen::t_WorkchainDescr.validate_ref(10000, descriptor)) return 324;
      vm::Dictionary workchains(32);
      if (!workchains.set(td::BitArray<32>{2}, vm::load_cell_slice_ref(descriptor))) return 325;
      vm::CellBuilder list;
      if (!workchains.append_dict_to_bool(list) ||
          !dictionary.set_ref(td::BitArray<32>{12}, list.finalize())) return 326;
      block::WorkchainNativeIngressPolicy policy;
      policy.workchain_id = 2;
      policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
      policy.executor_address.set_zero();
      // Explicit resolver-only identity values, not an authenticated
      // installation. The same shell is used for both capability settings.
      block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
          {256,16384,128,8192,64}, {32,128,8192,256,16384,16}};
      auto shell = block::encode_workchain_engine_parameters(
          {400, td::Bits256::ones(), resources, vm::CellBuilder().finalize()});
      if (shell.is_error()) return 329;
      policy.engine_configuration = shell.move_as_ok();
      auto ingress = block::encode_workchain_native_ingress_table({policy});
      if (ingress.is_error() || !dictionary.set_ref(td::BitArray<32>{84}, ingress.move_as_ok())) return 327;
      auto config = block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
                                                block::Config::needCapabilities | block::Config::needWorkchainInfo);
      if (config.is_error()) return 321;
      block::WorkchainExecutionRegistry registry;
      if (registered && registry.register_block_engine(std::make_unique<block::test::CounterEngine>()).is_error())
        return 322;
      auto result = registry.resolve_scoped_workchain(2, *config.ok());
      // A disabled configuration resolving successfully is an immediate stop.
      if (!enabled && result.is_ok()) return 323;
      if (result.is_ok() && (!registered || !result.ok().has_value() ||
          !std::holds_alternative<block::ResolvedWorkchainBlockExecution>(*result.ok()))) return 328;
      std::cout << registered << '\t' << enabled << '\t' << (result.is_error() ? result.error().code() : 0) << '\t'
                << (result.is_error() ? result.error().message().str() : std::string{}) << '\t'
                << td::hex_encode(dictionary.get_root_cell()->get_hash().as_slice()) << '\n';
    }
  }
}
