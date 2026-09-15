// Read a ValidatorSet BOC with the production unpacker and report its bindings.
//
// The genesis writer and the node reader are two implementations of one
// encoding. A genesis that only its own writer can read would install a
// committee no validator could derive, and nothing in either implementation
// would notice on its own.
#include <iostream>
#include <string>

#include "block/mc-config.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "ASSERTION: arguments\n";
    return 1;
  }
  auto raw = td::read_file(td::CSlice(argv[1]));
  if (raw.is_error()) {
    std::cerr << "ASSERTION: read\n";
    return 1;
  }
  auto cell = vm::std_boc_deserialize(raw.move_as_ok());
  if (cell.is_error()) {
    std::cerr << "ASSERTION: boc\n";
    return 1;
  }
  auto set = block::Config::unpack_validator_set(cell.move_as_ok());
  if (set.is_error()) {
    std::cerr << "ASSERTION: unpack: " << set.error().message().str() << '\n';
    return 1;
  }
  const auto& value = *set.ok();
  std::cout << "total=" << value.total << " main=" << value.main << " weight=" << value.total_weight << '\n';
  unsigned bound = 0;
  for (const auto& member : value.list) {
    std::cout << "  key=" << member.pubkey.as_bits256().to_hex().substr(0, 16) << " weight=" << member.weight;
    if (member.auth_binding) {
      ++bound;
      std::cout << " identity=" << member.auth_binding->identity.to_hex().substr(0, 16)
                << " stake=" << member.auth_binding->stake_id.to_hex().substr(0, 16);
    } else {
      std::cout << " (no binding)";
    }
    std::cout << '\n';
  }
  if (bound != value.list.size()) {
    std::cerr << "ASSERTION: unbound-members\n";
    return 1;
  }
  std::cout << "PASS: production unpacker read " << bound << " authenticated descriptors\n";
  return 0;
}
