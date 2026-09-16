#include <fstream>
#include <iostream>

#include "block/mc-config.h"
#include "smc-envelope/SmartContract.h"
#include "vm/boc.h"

#include "native-fixture.h"
using namespace auth_fixture;

int main(int argc, char** argv) {
  try {
    check(argc == 2, "fixture-argument");
    SET_VERBOSITY_LEVEL(0);
    std::string prefix = std::string(argv[1]) + "/0/";
    auto read = [&](const char* file) {
      std::ifstream stream(prefix + file, std::ios::binary);
      check(stream.good(), "fixture-file");
      return std::string(std::istreambuf_iterator<char>(stream), {});
    };
    auto message = vm::std_boc_deserialize(read("message.boc"));
    auto signature = vm::std_boc_deserialize(read("signature.boc"));
    check(message.is_ok() && signature.is_ok(), "fixture-cells");
    auto raw_key = read("key");
    auto public_key = td::make_refint(0);
    check(raw_key.size() == 32 &&
              public_key.write().import_bytes(reinterpret_cast<const unsigned char*>(raw_key.data()), 32, false),
          "fixture-key");
    auto code = vm::CellBuilder().store_long(0x30, 8).store_long(0xf917, 16).finalize();
    auto contract = tos::SmartContract::create({code, vm::CellBuilder().finalize()});
    for (unsigned capability : {1024U, 0U}) {
      auto loaded =
          block::Config::extract_from_state(masterchain(state(), 0, capability), block::Config::needCapabilities);
      check(loaded.is_ok(), "native-config-extraction");
      std::shared_ptr<const block::Config> config(loaded.move_as_ok());
      check(config->get_global_version() == 16 && config->get_capabilities() == capability, "native-config-values");
      td::Ref<vm::Stack> stack{true};
      stack.write().push_cell(message.ok());
      stack.write().push_cellslice(vm::load_cell_slice_ref(signature.ok()));
      stack.write().push_int(public_key);
      // Even an explicitly supplied C7 cannot override the native capability.
      auto c7 = td::make_ref<vm::Tuple>(std::vector<vm::StackEntry>{vm::StackEntry(td::make_refint(1024))});
      auto result = contract->run_get_method(tos::SmartContract::Args{}
                                                 .set_config(config)
                                                 .set_method_id(0)
                                                 .set_stack(stack)
                                                 .set_limits(vm::GasLimits{1000000, 1000000})
                                                 .set_c7(c7));
      check(result.code == (capability ? 0 : 6), "native-getter-capability");
      if (capability)
        check(result.stack->depth() == 1 && result.stack.write().pop_int_finite()->to_long() == -1,
              "native-getter-signature");
    }
    std::cout << "PASS native SmartContract configuration and immutable capability\n";
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
