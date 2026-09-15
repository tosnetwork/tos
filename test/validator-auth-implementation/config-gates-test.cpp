#include "block/validator-auth-config.h"
#include "validator/auth/native-registry.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
td::Ref<vm::Cell> put(td::Ref<vm::Cell> root, int key, td::Ref<vm::Cell> val) {
  vm::Dictionary d(root, 32);
  if (val.is_null())
    check(d.lookup_delete_ref(td::BitArray<32>{key}).not_null(), "fixture-delete");
  else
    check(d.set_ref(td::BitArray<32>{key}, val), "fixture-set");
  return d.get_root_cell();
}
td::Ref<vm::Cell> get(td::Ref<vm::Cell> root, int key) {
  vm::Dictionary d(root, 32);
  return d.lookup_ref(td::BitArray<32>{key});
}
td::Ref<vm::Cell> cap(unsigned version, std::uint64_t bits = 1070) {
  return vm::CellBuilder().store_long(0xc4, 8).store_long(version, 32).store_long(bits, 64).finalize();
}
td::Ref<vm::Cell> counts(unsigned max, unsigned main = 100, unsigned min = 1) {
  return vm::CellBuilder().store_long(max, 16).store_long(main, 16).store_long(min, 16).finalize();
}
td::Ref<vm::Cell> required(td::Ref<vm::Cell> config, int index, bool add, bool invalid = false) {
  vm::Dictionary d(get(config, index), 32);
  if (add) {
    vm::CellBuilder value;
    if (invalid)
      value.store_long(1, 1);
    check(d.set_builder(td::BitArray<32>{46}, value), "required-put");
  } else
    check(d.lookup_delete(td::BitArray<32>{46}).not_null(), "required-remove");
  return put(config, index, d.get_root_cell());
}
td::Ref<vm::Cell> change_registry(td::Ref<vm::Cell> root, unsigned offset, unsigned width, const Bytes& raw) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(offset));
  check(s.advance(width), "registry-field");
  b.store_bits(td::ConstBitPtr(raw.data()), width);
  b.append_cellslice(s);
  return b.finalize();
}
td::Ref<vm::Cell> replace_child(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> value) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size()));
  for (unsigned i = 0; s.size_refs(); ++i) {
    auto old = s.fetch_ref();
    b.store_ref(i == index ? value : old);
  }
  return b.finalize();
}
Bytes integer(std::uint64_t n, unsigned width) {
  Bytes raw(width / 8);
  for (unsigned i = 0; i < raw.size(); ++i)
    raw[raw.size() - i - 1] = static_cast<std::uint8_t>(n >> (8 * i));
  return raw;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3, "arguments");
    auto empty_tuple = vm::CellBuilder().finalize();
    vm::CellSlice tuple_slice(vm::NoVm{}, empty_tuple);
    check(!tlb::TupleT(0x80000000U, tlb::t_uint32).skip(tuple_slice), "tuple-unsigned-overflow");

    std::filesystem::path input(argv[1]), out(argv[2]);
    check(std::filesystem::create_directory(out), "fresh-output");
    auto raw = read(input);
    auto parsed = vm::std_boc_deserialize(td::Slice(raw.data(), raw.size()));
    check(parsed.is_ok(), "fixture-config");
    auto legacy = parsed.move_as_ok();
    auto registry = state(3);
    auto registry_root = value(registry.encode_cell(), "registry");
    check(block::gen::t_ValidatorAuthConfig.validate_ref(100000, registry_root), "compiled-config46-schema");
    auto leaf = vm::CellBuilder().store_long(0, 1).store_long(1, 7).store_long(42, 8).finalize();
    auto bad_branch = vm::CellBuilder().store_long(1, 1).store_long(1, 3).store_long(1, 32).store_ref(leaf).finalize();
    check(!block::gen::t_AuthByteNode.validate_ref(bad_branch), "compiled-auth-branch-minimum");

    auto base = put(put(put(legacy, 8, cap(16)), 16, counts(400)), 46, registry_root);
    base = required(required(base, 9, true), 10, true);
    unsigned n = 0;
    auto run = [&](td::Ref<vm::Cell> old, td::Ref<vm::Cell> next, const char* label, const char* error, bool data) {
      auto before = hash(old), after = hash(next);
      auto result = block::valid_config_transition(old, next);
      if ((std::string(error) == "-" && result.is_error()) ||
          (std::string(error) != "-" && (result.is_ok() || result.message().str() != error))) {
        std::cerr << "DETAIL " << label << " expected=" << error
                  << " actual=" << (result.is_ok() ? std::string("accepted") : result.message().str()) << '\n';
        check(false, label);
      }
      vm::CellSlice address(vm::NoVm{}, get(next, 0));
      td::Bits256 addr;
      check(address.fetch_bits_to(addr), "config-address");
      check(block::valid_config_data(next, addr, true) == data, (std::string("config-data-") + label).c_str());
      check(hash(old) == before && hash(next) == after, "config-check-read-only");
      auto folder = out / std::to_string(n++);
      check(std::filesystem::create_directory(folder), "case-folder");
      write(folder / "old", boc(old));
      write(folder / "new", boc(next));
      std::ofstream(folder / "case") << label << ' ' << error << ' ' << data << '\n';
    };
    run(legacy, legacy, "legacy-stable", "-", true);
    run(base, base, "p0-stable", "-", true);
    run(legacy, base, "activation", "validator-auth-transition-unapproved", true);
    run(base, put(base, 8, cap(16, 46)), "downgrade", "validator-auth-downgrade", true);
    run(base, put(base, 8, {}), "missing-capability", "validator-auth-downgrade", true);
    run(base, put(base, 8, cap(15)), "version", "validator-auth-version", false);
    run(base, put(base, 8, cap(17)), "later-vm", "-", true);
    run(base, put(base, 8, vm::CellBuilder().store_long(0, 8).store_long(16, 32).store_long(1070, 64).finalize()),
        "capability-shape", "validator-auth-config8", false);
    run(base, put(base, 16, counts(401)), "count", "validator-auth-count", false);
    run(base, put(base, 16, counts(100, 100)), "lower-count", "-", true);
    run(base, put(base, 16, counts(100, 101)), "main-count", "validator-auth-count", false);
    run(base, put(base, 16, counts(100, 100, 0)), "minimum-count", "validator-auth-count", false);
    run(base, put(base, 16, counts(100, 90, 91)), "minimum-main", "validator-auth-count", false);
    run(base, put(base, 16, {}), "missing-count", "validator-auth-count", false);
    for (int index : {9, 10}) {
      run(base, required(base, index, false), index == 9 ? "mandatory" : "critical", "validator-auth-required", false);
      run(base, put(base, index, {}), index == 9 ? "missing-mandatory" : "missing-critical", "validator-auth-required",
          false);
      run(base, required(base, index, true, true), index == 9 ? "mandatory-value" : "critical-value",
          "validator-auth-required", false);
    }
    run(base, put(base, 46, {}), "missing-registry", "validator-auth-registry", false);
    auto alias = put(put(base, 46, {}), -46, registry_root);
    run(base, alias, "negative-registry-alias", "validator-auth-registry", false);
    run(base, put(base, 46, vm::CellBuilder().finalize()), "registry-shape", "validator-auth-registry", false);
    run(base, put(base, 46, change_registry(registry_root, 0, 32, integer(0x76617132, 32))), "registry-magic",
        "validator-auth-registry", false);
    run(base, put(base, 46, change_registry(registry_root, 32, 16, integer(2, 16))), "registry-version",
        "validator-auth-registry", false);
    run(base, put(base, 46, change_registry(registry_root, 48, 256, Bytes(32))), "zero-domain",
        "validator-auth-profile", false);
    run(base, put(base, 46, change_registry(registry_root, 304, 256, Bytes(32))), "fingerprint",
        "validator-auth-profile", false);
    run(base, put(base, 46, change_registry(registry_root, 624, 256, Bytes(32))), "zero-policy",
        "validator-auth-registry", false);
    auto domain = h(909);
    run(base, put(base, 46, change_registry(registry_root, 48, 256, Bytes(domain.begin(), domain.end()))), "domain",
        "validator-auth-domain", true);
    auto rev1 = change_registry(registry_root, 560, 64, integer(1, 64));
    run(base, put(base, 46, rev1), "unchanged-revision", "validator-auth-revision", true);
    run(put(base, 46, rev1), base, "revision-rollback", "validator-auth-revision", true);
    auto changed = value(registry.apply_block(1, {}, AcceptedFixtureRequests{}), "empty");
    auto identity = registry.identities().begin()->second;
    Update retire{3,  identity.identity_,
                  0,  value(object_id("identity", identity), "id"),
                  0,  identity.active_[0].key_.key_id_,
                  {}, {},
                  {}};
    Authorizations auth;
    auth.administration_.push_back({value(object_id("update", retire), "update"), identity.identity_, {}});
    changed = value(registry.apply_block(1, {{retire, auth}}, AcceptedFixtureRequests{}), "retire");
    auto changed_root = value(changed.encode_cell(), "changed");
    run(base, put(base, 46, changed_root), "identity-change", "-", true);
    run(base, put(base, 46, change_registry(changed_root, 560, 64, integer(0, 64))), "unrecorded-change",
        "validator-auth-revision", true);
    run(base, put(base, 46, change_registry(changed_root, 560, 64, integer(2, 64))), "revision-jump",
        "validator-auth-revision", true);
    auto max = change_registry(registry_root, 560, 64, integer(UINT64_MAX, 64));
    run(put(base, 46, max), put(base, 46, max), "maximum-stable", "-", true);
    run(put(base, 46, max), put(base, 46, change_registry(changed_root, 560, 64, integer(0, 64))), "revision-wrap",
        "validator-auth-revision", true);

    auto reserved = put(put(base, 8, cap(16, 46)), 46, change_registry(registry_root, 304, 256, Bytes(32)));
    run(reserved, reserved, "legacy-reserved-registry", "-", false);
    auto only_keys = replace_child(registry_root, 1, vm::CellBuilder().store_long(0, 1).finalize());
    run(base, put(base, 46, only_keys), "unrecorded-key-change", "validator-auth-revision", true);
    auto large = put(base, 46, value(state(501).encode_cell(), "large-archive"));
    run(large, large, "large-archive", "-", true);
    for (unsigned index = 0; index < 3; ++index) {
      auto malformed = replace_child(registry_root, index, vm::CellBuilder().store_long(1, 1).finalize());
      run(put(base, 46, malformed), put(base, 46, malformed),
          index == 0   ? "identity-wrapper"
          : index == 1 ? "key-wrapper"
                       : "policy-wrapper",
          "validator-auth-dictionary", false);
    }
    auto control = vm::CellBuilder()
                       .store_long(0, 32)
                       .store_ref(vm::CellBuilder().store_long(0, 1).finalize())
                       .store_ref(vm::CellBuilder().store_long(0, 1).finalize())
                       .finalize();
    run(base, put(base, 46, replace_child(registry_root, 3, control)), "control-magic", "validator-auth-control",
        false);
    std::ofstream(out / "complete") << n << '\n';
    std::cout << "PASS: native configuration gates " << n << " cases through production admission and transition\n";
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
