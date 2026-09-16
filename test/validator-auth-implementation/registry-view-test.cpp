#include <filesystem>
#include <fstream>
#include <iostream>

#include "validator/auth/registry-view.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "native-fixture.h"
using namespace auth_fixture;
namespace {
td::Ref<vm::Cell> replace_ref(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> replacement) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size()));
  for (unsigned i = 0; s.size_refs(); ++i) {
    auto ref = s.fetch_ref();
    b.store_ref(i == index ? replacement : ref);
  }
  return b.finalize();
}
td::Ref<vm::Cell> put(td::Ref<vm::Cell> root, unsigned index, const Hash& id, const Bytes& raw, bool tail = false) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellSlice wrapper(vm::NoVm{}, s.prefetch_ref(index));
  vm::Dictionary dict(wrapper, 256);
  vm::CellBuilder leaf;
  if (tail)
    leaf.store_long(0, 1);
  leaf.store_ref(value(pack_bytes(raw), "pack-entry"));
  check(dict.set(td::ConstBitPtr(id.data()), 256, td::make_ref<vm::CellSlice>(vm::NoVm{}, leaf.finalize())),
        "put-entry");
  vm::CellBuilder out;
  check(dict.append_dict_to_bool(out), "wrap-dictionary");
  return replace_ref(root, index, out.finalize());
}
Result<Bytes> lookup(RegistryView& view, unsigned mode, const Hash& id) {
  if (mode == 0)
    return encode(view.policy());
  if (mode == 1) {
    auto identity = view.identity(id);
    if (!identity.ok())
      return identity.error();
    return encode(identity.value());
  }
  auto key = view.find(id);
  if (!key.ok())
    return key.error();
  return encode(key.value());
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 1 || argc == 2, "arguments");
    std::filesystem::path output;
    if (argc == 2) {
      output = argv[1];
      check(std::filesystem::create_directory(output), "fresh-output");
    }
    unsigned cases = 0;
    auto run = [&](td::Ref<vm::Cell> root, unsigned mode, Hash id, StateReadBudget budget, const char* label,
                   bool accepted, bool proof = false) {
      auto virtualized = proof ? vm::MerkleProof::virtualize(root) : td::Result<td::Ref<vm::Cell>>(root);
      check(virtualized.is_ok(), "fixture-virtualize");
      auto view = RegistryView::open(virtualized.move_as_ok(), 0, budget);
      auto result = view.ok() ? lookup(view.value(), mode, id) : Result<Bytes>(view.error());
      check(result.ok() == accepted, label);
      StateReadBudget remaining{};
      if (result.ok()) {
        remaining = view.value().remaining();
        auto repeated = lookup(view.value(), mode, id);
        check(repeated.ok() && repeated.value() == result.value() &&
                  view.value().remaining().entries == remaining.entries &&
                  view.value().remaining().bytes == remaining.bytes,
              "view-cache");
        check(!view.value().ever_registered(id).ok() && !view.value().latest_epoch(id, {1, 1, 1}).ok(),
              "view-read-only");
      }
      if (!output.empty()) {
        auto path = output / std::to_string(cases);
        auto boc = vm::std_boc_serialize(root, 31);
        check(boc.is_ok(), "fixture-boc");
        std::ofstream b(path.string() + ".boc", std::ios::binary);
        b.write(boc.ok().data(), boc.ok().size());
        check(b.good(), "fixture-write");
        std::ofstream meta(path.string() + ".case");
        meta << mode << ' ' << budget.entries << ' ' << budget.bytes << ' ' << accepted << ' ' << proof << ' '
             << remaining.entries << ' ' << remaining.bytes << ' ' << label << '\n';
        std::ofstream key(path.string() + ".id", std::ios::binary);
        key.write(reinterpret_cast<const char*>(id.data()), id.size());
        check(key.good(), "fixture-write");
        if (result.ok()) {
          std::ofstream raw(path.string() + ".value", std::ios::binary);
          raw.write(reinterpret_cast<const char*>(result.value().data()), result.value().size());
          check(raw.good(), "fixture-write");
        }
      }
      ++cases;
      return remaining;
    };
    auto registry = state(4);
    auto root = value(registry.encode_cell(), "registry");
    const auto& identity = registry.identities().begin()->second;
    const auto& [key_id, key] = *registry.keys().begin();
    auto pbytes = value(encode(registry.policies().begin()->second), "policy");
    auto ibytes = value(encode(identity), "identity");
    auto kbytes = value(encode(key), "key");
    run(root, 0, {}, {1, pbytes.size()}, "policy", true);
    run(root, 1, identity.identity_, {2, pbytes.size() + ibytes.size()}, "identity", true);
    auto remaining = run(root, 2, key_id, {2, pbytes.size() + kbytes.size()}, "key", true);
    check(remaining.entries == 0 && remaining.bytes == 0, "view-budget-charge");
    run(root, 2, key_id, {1, 10000}, "view-entry-budget", false);
    run(root, 2, key_id, {2, pbytes.size() + kbytes.size() - 1}, "view-byte-budget", false);
    run(root, 0, {}, {0, 10000}, "policy-entry-budget", false);
    run(root, 0, {}, {1, pbytes.size() - 1}, "policy-byte-budget", false);
    run(root, 1, h(65500), {}, "missing-identity", false);
    run(root, 2, h(65500), {}, "missing-key", false);
    auto invalid = identity;
    invalid.identity_ = h(99);
    run(put(root, 0, identity.identity_, value(encode(invalid), "identity")), 1, identity.identity_, {},
        "identity-binding", false);
    invalid = identity;
    invalid.stake_id_ = {};
    run(put(root, 0, identity.identity_, value(encode(invalid), "identity")), 1, identity.identity_, {},
        "identity-stake", false);
    run(put(root, 0, identity.identity_, ibytes, true), 1, identity.identity_, {}, "entry-tail", false);
    auto other = key;
    other.valid_until_ += 1;
    run(put(root, 1, key_id, value(encode(other), "key")), 2, key_id, {}, "key-hash", false);
    other = key;
    other.capacity_limit_ = 1;
    auto other_id = value(object_id("key", other), "key-id");
    run(put(root, 1, other_id, value(encode(other), "key")), 2, other_id, {}, "key-descriptor", false);
    other = key;
    other.public_key_ = Bytes(32);
    other_id = value(object_id("key", other), "key-id");
    run(put(root, 1, other_id, value(encode(other), "key")), 2, other_id, {}, "key-admission", false);
    auto policy = registry.policies().begin()->second;
    policy.revision_ += 1;
    run(put(root, 2, registry.current_policy(), value(encode(policy), "policy")), 0, {}, {}, "policy-hash", false);
    vm::CellBuilder malformed;
    vm::CellSlice root_slice(vm::NoVm{}, root);
    vm::CellSlice valid_wrapper(vm::NoVm{}, root_slice.prefetch_ref(0));
    malformed.store_long(2, 2).store_ref(valid_wrapper.prefetch_ref());
    run(replace_ref(root, 0, malformed.finalize()), 1, identity.identity_, {}, "dictionary-shape", false);
    // Unrelated archive entries do not consume lookup budget. They remain
    // authenticated by the registry root and validated by the state authority.
    auto large = root;
    for (unsigned epoch = 2; epoch <= 10001; ++epoch) {
      auto archived = key;
      archived.epoch_ = epoch;
      auto id = value(object_id("key", archived), "archive-id");
      large = put(large, 1, id, value(encode(archived), "archive-key"));
    }
    run(large, 2, key_id, {2, pbytes.size() + kbytes.size()}, "archive-independent", true);
    vm::MerkleProofBuilder builder(large);
    auto view = value(RegistryView::open(builder.root(), 0), "proof-view");
    value(view.find(key_id), "proof-key");
    auto proof = builder.extract_proof();
    check(proof.is_ok(), "proof-extract");
    run(proof.ok(), 2, key_id, {2, pbytes.size() + kbytes.size()}, "pruned-archive", true, true);
    run(proof.ok(), 1, identity.identity_, {}, "required-identity-pruned", false, true);
    auto unused = key;
    unused.epoch_ = 10001;
    run(proof.ok(), 2, value(object_id("key", unused), "unused-id"), {}, "required-key-pruned", false, true);
    if (!output.empty()) {
      std::ofstream complete(output / "complete");
      complete << cases << '\n';
    }
    std::cout << "PASS: bounded authenticated registry view " << cases << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
