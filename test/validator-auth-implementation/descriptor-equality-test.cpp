#include <iostream>

#include "tos/tos-types.h"
int main() {
  std::array<unsigned char, 32> raw{};
  tos::ValidatorDescr first(tos::Ed25519_PublicKey(tos::Bits256(raw)), 1);
  auto other = first;
  if (first != other) {
    std::cerr << "ASSERTION: historical-descriptor-equality\n";
    return 1;
  }
  raw[31] = 1;
  auto id = tos::Bits256(raw);
  raw[31] = 2;
  auto stake = tos::Bits256(raw);
  first.auth_binding = tos::ValidatorAuthBinding{id, stake};
  if (first == other) {
    std::cerr << "ASSERTION: descriptor-equality\n";
    return 1;
  }
  other = first;
  other.auth_binding->stake_id = id;
  if (first == other) {
    std::cerr << "ASSERTION: descriptor-equality\n";
    return 1;
  }
  other = first;
  other.auth_binding->identity = stake;
  if (first == other) {
    std::cerr << "ASSERTION: descriptor-equality\n";
    return 1;
  }
  other = first;
  if (first != other) {
    std::cerr << "ASSERTION: descriptor-equality\n";
    return 1;
  }
  std::cout << "PASS: native descriptor equality includes identity and stake\n";
}
