#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "validator/auth/context.h"
#include "validator/auth/state.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
using namespace tos::auth;
void check(bool ok, const char* label) {
  if (!ok)
    throw std::runtime_error(label);
}
Hash h(unsigned n) {
  Hash hash{};
  hash[30] = static_cast<std::uint8_t>(n >> 8);
  hash[31] = static_cast<std::uint8_t>(n);
  return hash;
}
template <class T>
T value(Result<T> r, const char* label) {
  check(r.ok(), label);
  return std::move(r.value());
}
class Authority final : public LifecycleAuthority {
 public:
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return true;
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return true;
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return true;
  }
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t) const override {
    return Error{"fixture-governance"};
  }
};
Authorizations evidence(const Identity& state, const Update& update, const Key& key) {
  auto uid = value(object_id("update", update), "update-id");
  Authorizations proofs;
  proofs.owner_.push_back({uid, state.stake_id_, state.owner_workchain_, state.owner_address_, {}});
  proofs.possession_.push_back({uid, value(key_reference(key), "keyref"), {}});
  proofs.administration_.push_back({uid, state.identity_, {}});
  return proofs;
}
int main() {
  try {
    check(sodium_init() >= 0, "sodium");
    Hash seed = h(99);
    std::array<unsigned char, 64> secret{};
    Hash public_key{};
    check(crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) == 0, "keygen");
    Policy policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096, 524288};
    std::vector<Identity> identities;
    std::vector<Key> keys;
    // Registry identities are not silently truncated to the committee ceiling.
    for (unsigned n = 1; n <= 501; ++n) {
      Identity state;
      state.identity_ = h(n);
      state.stake_id_ = h(n + 1000);
      state.owner_workchain_ = -1;
      state.owner_address_ = h(n + 2000);
      for (unsigned role = 1; role <= 5; ++role) {
        Key key{state.identity_,
                static_cast<std::uint8_t>(role),
                1,
                1,
                1,
                0,
                1000,
                Bytes(public_key.begin(), public_key.end()),
                {},
                0};
        state.active_.push_back({static_cast<std::uint8_t>(role), value(key_reference(key), "keyref")});
        keys.push_back(key);
      }
      identities.push_back(state);
    }
    auto archived = keys[0];
    archived.epoch_ = 2;
    keys.push_back(archived);
    auto ambiguous = keys;
    auto duplicate = archived;
    duplicate.valid_until_++;
    ambiguous.push_back(duplicate);
    check(!RegistryState::genesis(h(5000), policy, identities, ambiguous).ok(), "duplicate-key-epoch");
    auto state = value(RegistryState::genesis(h(5000), policy, identities, keys), "genesis");
    auto root = value(state.encode_cell(), "native-config");
    auto restored = value(RegistryState::decode_cell(root, 0), "native-restore");
    check(restored.identities().size() == 501 && restored.keys().size() == 2506, "archive-not-committee-bound");
    check(value(restored.encode_cell(), "roundtrip")->get_hash() == root->get_hash(), "native-roundtrip");
    check(!RegistryState::decode_cell(root, 0, {1, 268435456}).ok(), "state-resource-entries");
    check(!RegistryState::decode_cell(root, 0, {1000000, 1}).ok(), "state-resource-bytes");
    auto old = state.identities().at(h(1));
    Key next = keys[0];
    next.epoch_ = 3;
    next.valid_from_ = 3;
    Update rotate{2,
                  h(1),
                  0,
                  value(object_id("identity", old), "predecessor"),
                  3,
                  old.active_[0].key_.key_id_,
                  value(encode(next), "encode-key"),
                  {},
                  {}};
    Authority authority;
    auto staged = value(state.apply_block(1, {{rotate, evidence(old, rotate, next)}}, authority), "stage");
    check(staged.revision() == 1 && state.revision() == 0, "apply-owned-state");
    auto before = value(staged.apply_block(2, {}, authority), "before-boundary");
    check(before.revision() == 1, "unchanged-revision");
    auto due = value(before.apply_block(3, {}, authority), "due-boundary");
    check(due.revision() == 2 && due.identities().at(h(1)).pending_.empty(), "due-revision");
    check(due.identities().at(h(1)).active_[0].key_.epoch_ == 3 &&
              state.identities().at(h(1)).active_[0].key_.epoch_ == 1,
          "old-snapshot-retention");
    auto restart =
        value(RegistryState::decode_cell(value(before.encode_cell(), "persist-pending"), 2), "restart-pending");
    auto replay = value(restart.apply_block(3, {}, authority), "restart-replay");
    check(value(replay.encode_cell(), "replay-root")->get_hash() == value(due.encode_cell(), "due-root")->get_hash(),
          "replay-root-binding");
    check(!state.apply_block(3, {}, authority).ok(), "block-gap");
    check(!RegistryState::decode_cell(value(before.encode_cell(), "pending"), 3).ok(), "overdue-state");
    auto invalid = rotate;
    invalid.previous_ = h(9999);
    check(!state.apply_block(1, {{invalid, evidence(old, invalid, next)}}, authority).ok(), "rejected-block-atomicity");
    check(value(state.encode_cell(), "unchanged")->get_hash() == root->get_hash(), "rejected-parent-unchanged");
    // Substitute a valid, unreferenced historical key under another key's ID.
    vm::CellSlice s{vm::NoVm{}, root};
    auto identities_cell = s.fetch_ref(), keys_cell = s.fetch_ref(), policies_cell = s.fetch_ref(),
         control = s.fetch_ref();
    vm::CellSlice kd{vm::NoVm{}, keys_cell};
    vm::Dictionary dict(kd, 256);
    auto archived_id = value(object_id("key", archived), "archived-id");
    archived.epoch_ = 4;
    auto tampered = value(pack_bytes(value(encode(archived), "archived-bytes")), "archived-cell");
    check(dict.set_ref(td::ConstBitPtr(archived_id.data()), 256, tampered), "replace-key");
    vm::CellBuilder dict_root;
    check(dict.append_dict_to_bool(dict_root), "dictionary");
    vm::CellBuilder replacement;
    replacement.append_cellslice(s.prefetch_subslice(880, 0))
        .store_ref(identities_cell)
        .store_ref(dict_root.finalize())
        .store_ref(policies_cell)
        .store_ref(control);
    check(!RegistryState::decode_cell(replacement.finalize(), 0).ok(), "key-hash-binding");
    std::cout << "PASS: native state, 501 identities, pending replay and atomicity\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
