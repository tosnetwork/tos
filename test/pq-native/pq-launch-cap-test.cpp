#include <cstdlib>
#include <iostream>

#include "crypto/block/mc-config.h"
#include "crypto/pq/pq-launch-limits.h"

namespace {

[[noreturn]] void fail(const char *message) {
  std::cerr << "PQ_LAUNCH_CAP_FAILURE: " << message << '\n';
  std::exit(1);
}

td::Ref<vm::Cell> validator_limits(unsigned maximum, unsigned main, unsigned minimum) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(maximum, 16) && builder.store_long_bool(main, 16) &&
        builder.store_long_bool(minimum, 16))) {
    fail("could not build ConfigParam16");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> catchain_limits(unsigned shard_validators) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xc2, 8) && builder.store_long_bool(0, 7) && builder.store_bool_bool(true) &&
        builder.store_long_bool(250, 32) && builder.store_long_bool(250, 32) && builder.store_long_bool(1000, 32) &&
        builder.store_long_bool(shard_validators, 32))) {
    fail("could not build ConfigParam28");
  }
  return builder.finalize_novm();
}

std::unique_ptr<block::Config> config(unsigned maximum, unsigned main, unsigned shard_validators) {
  vm::Dictionary dictionary{32};
  if (!(dictionary.set_ref(td::BitArray<32>{16}, validator_limits(maximum, main, 4)) &&
        dictionary.set_ref(td::BitArray<32>{28}, catchain_limits(shard_validators)))) {
    fail("could not build configuration dictionary");
  }
  auto parsed = block::Config::unpack_config(std::move(dictionary).extract_root_cell());
  if (parsed.is_error()) {
    fail("could not parse configuration dictionary");
  }
  return parsed.move_as_ok();
}

}  // namespace

int main() {
  static_assert(tos::pq::launch_limits::max_total_validators == 21);
  static_assert(tos::pq::launch_limits::max_masterchain_committee == 21);
  static_assert(tos::pq::launch_limits::max_shard_committee == 21);

  if (config(21, 21, 21)->validate_pq_launch_resource_config().is_error()) {
    fail("the exact 21-validator launch boundary was refused");
  }
  auto total = config(22, 21, 21)->validate_pq_launch_resource_config();
  if (total.is_ok() || total.error().message().str().find("max_validators") == std::string::npos) {
    fail("ConfigParam16.max_validators above 21 was admitted");
  }
  auto main = config(21, 22, 21)->validate_pq_launch_resource_config();
  if (main.is_ok() || main.error().message().str().find("ordering") == std::string::npos) {
    fail("ConfigParam16.max_main_validators above 21 was admitted");
  }
  auto shard = config(21, 21, 22)->validate_pq_launch_resource_config();
  if (shard.is_ok() || shard.error().message().str().find("shard_validators_num") == std::string::npos) {
    fail("ConfigParam28.shard_validators_num above 21 was admitted");
  }

  std::cout << "PQ_LAUNCH_CAP_OK: node admission accepts 21 and refuses every 22-validator ceiling\n";
  return 0;
}
