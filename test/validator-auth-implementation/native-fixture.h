#pragma once
#include <sodium.h>
#include <stdexcept>

#include "validator/auth/state.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"
namespace p0_fixture {
using namespace tos::auth;
inline void check(bool ok, const char* label) {
  if (!ok)
    throw std::runtime_error(label);
}
inline Hash h(unsigned n) {
  Hash hash{};
  hash[30] = static_cast<std::uint8_t>(n >> 8);
  hash[31] = static_cast<std::uint8_t>(n);
  return hash;
}
template <class T>
T value(Result<T> r, const char* label) {
  if (!r.ok())
    throw std::runtime_error(std::string(label) + ": " + r.error().code);
  return std::move(r.value());
}
inline RegistryState state(unsigned count = 3) {
  check(sodium_init() >= 0, "sodium");
  auto seed = h(7);
  Hash public_key{};
  std::array<unsigned char, 64> secret{};
  check(crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) == 0, "keygen");
  Policy policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096, 524288};
  std::vector<Identity> identities;
  std::vector<Key> keys;
  for (unsigned n = 1; n <= count; ++n) {
    Identity id;
    id.identity_ = h(n);
    id.stake_id_ = h(n + 1000);
    id.owner_workchain_ = -1;
    id.owner_address_ = h(n + 2000);
    for (unsigned role = 1; role <= 5; ++role) {
      Key key{id.identity_,
              static_cast<std::uint8_t>(role),
              1,
              1,
              1,
              0,
              1000,
              Bytes(public_key.begin(), public_key.end()),
              {},
              0};
      id.active_.push_back({static_cast<std::uint8_t>(role), value(key_reference(key), "keyref")});
      keys.push_back(key);
    }
    identities.push_back(id);
  }
  return value(RegistryState::genesis(h(5000), policy, identities, keys), "genesis");
}
inline td::Ref<vm::Cell> masterchain(const RegistryState& state, std::uint32_t coordinate = 0,
                                     std::uint64_t capability = 1024) {
  vm::Dictionary config(32), required(32);
  vm::CellBuilder empty;
  auto empty_cell = empty.finalize();
  auto key = [](std::uint8_t index) { return std::array<std::uint8_t, 4>{0, 0, 0, index}; };
  for (std::uint8_t index : std::array<std::uint8_t, 5>{8, 9, 10, 16, 46}) {
    auto bits = key(index);
    check(required.set(td::ConstBitPtr(bits.data()), 32, td::make_ref<vm::CellSlice>(vm::NoVm{}, empty_cell)),
          "mandatory");
  }
  auto put = [&](std::uint8_t index, td::Ref<vm::Cell> cell) {
    auto bits = key(index);
    check(config.set_ref(td::ConstBitPtr(bits.data()), 32, cell), "config-entry");
  };
  vm::CellBuilder capabilities;
  capabilities.store_long(0xc4, 8).store_long(16, 32).store_long(capability, 64);
  put(8, capabilities.finalize());
  put(9, required.get_root_cell());
  put(10, required.get_root_cell());
  vm::CellBuilder validators;
  validators.store_long(400, 16).store_long(100, 16).store_long(1, 16);
  put(16, validators.finalize());
  put(46, value(state.encode_cell(), "config46"));
  // Empty native dictionaries include their actual augmentation values.
  vm::CellBuilder queue;
  queue.store_zeroes(1 + 64 + 1 + 1);
  vm::CellBuilder accounts;
  accounts.store_long(0, 1 + 5 + 5);
  vm::CellBuilder balances;
  balances.store_long(0, 64).store_long(0, 64).store_long(0, 5 + 5 + 1 + 1);
  vm::CellBuilder history;
  history.store_long(0, 16)
      .store_long(0, 32)
      .store_long(0, 32)
      .store_long(0, 1)
      .store_zeroes(1 + 1 + 64)
      .store_long(0, 1 + 1);
  vm::CellBuilder extra;
  extra.store_long(0xcc26, 16)
      .store_long(0, 1)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(h(900).data()), 32))
      .store_ref(config.get_root_cell())
      .store_ref(history.finalize())
      .store_long(0, 5);
  vm::CellBuilder root;
  root.store_long(0x9023afe2, 32)
      .store_long(-239, 32)
      .store_long(0, 2 + 6)
      .store_long(-1, 32)
      .store_long(0, 64)
      .store_long(coordinate, 32)
      .store_long(0, 32 + 32)
      .store_long(0, 64)
      .store_long(0, 32)
      .store_ref(queue.finalize())
      .store_long(0, 1)
      .store_ref(accounts.finalize())
      .store_ref(balances.finalize())
      .store_long(1, 1)
      .store_ref(extra.finalize());
  return root.finalize();
}
inline Anchor anchor(const td::Ref<vm::Cell>& root, std::uint32_t coordinate = 0) {
  Hash hash{};
  auto raw = root->get_hash().as_slice();
  std::copy(raw.ubegin(), raw.uend(), hash.begin());
  return {coordinate, h(6000), h(6001), hash};
}
}  // namespace p0_fixture
