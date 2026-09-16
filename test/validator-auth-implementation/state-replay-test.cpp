#include <filesystem>
#include <fstream>
#include <iostream>

#include "vm/boc.h"

#include "native-fixture.h"
using namespace p0_fixture;
namespace {
using Updates = std::vector<std::pair<Update, Authorizations>>;
class Authority final : public LifecycleAuthority {
 public:
  unsigned deny;
  explicit Authority(unsigned n = 0) : deny(n) {
  }
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return deny != 1;
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return deny != 2;
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return deny != 3;
  }
  // The anchor a governing snapshot was derived from. It is exported with the
  // case rather than recomputed on each side: the independent implementation
  // has to stamp the activation with the same one, and two derivations of it
  // would be the second source this corpus exists to rule out.
  static Anchor anchor() {
    return Anchor{4, h(7001), h(7101), h(7201)};
  }
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t) const override {
    if (deny == 4)
      return Error{"fixture-governance"};
    return anchor();
  }
};
std::pair<Update, Authorizations> request(const RegistryState& registry, unsigned identity, unsigned role,
                                          unsigned effective, unsigned epoch = 2) {
  const auto& state = registry.identities().at(h(identity));
  const auto& ref = state.active_.at(role - 1).key_;
  auto key = value(registry.find(ref.key_id_), "request-key");
  key.epoch_ = epoch;
  key.valid_from_ = effective;
  Update u{2,
           state.identity_,
           state.next_nonce_,
           value(object_id("identity", state), "predecessor"),
           effective,
           ref.key_id_,
           value(encode(key), "new-key"),
           {},
           {}};
  auto uid = value(object_id("update", u), "update-id");
  Authorizations a;
  a.owner_.push_back({uid, state.stake_id_, state.owner_workchain_, state.owner_address_, {}});
  a.possession_.push_back({uid, value(key_reference(key), "keyref"), {}});
  a.administration_.push_back({uid, state.identity_, {}});
  return {u, a};
}
std::pair<Update, Authorizations> cancel(const RegistryState& registry, unsigned identity) {
  const auto& state = registry.identities().at(h(identity));
  auto id = value(object_id("transition", state.pending_.at(0)), "transition-id");
  Update u{7,
           state.identity_,
           state.next_nonce_,
           value(object_id("identity", state), "predecessor"),
           0,
           {},
           {},
           {},
           Bytes(id.begin(), id.end())};
  auto uid = value(object_id("update", u), "cancel-id");
  Authorizations a;
  a.administration_.push_back({uid, state.identity_, {}});
  return {u, a};
}
void write(const std::filesystem::path& path, const Bytes& raw) {
  std::ofstream out(path, std::ios::binary);
  out.write(reinterpret_cast<const char*>(raw.data()), raw.size());
  check(out.good(), "fixture-write");
}
Bytes boc(td::Ref<vm::Cell> root) {
  auto raw = vm::std_boc_serialize(root, 31);
  check(raw.is_ok(), "fixture-boc");
  auto bytes = raw.ok().as_slice();
  return Bytes(bytes.begin(), bytes.end());
}
td::Ref<vm::Cell> replace_ref(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> ref) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size()));
  for (unsigned i = 0; s.size_refs(); ++i) {
    auto v = s.fetch_ref();
    b.store_ref(i == index ? ref : v);
  }
  return b.finalize();
}
template <class T>
td::Ref<vm::Cell> put(td::Ref<vm::Cell> wrapped, const Hash& id, const T& item) {
  vm::CellSlice s(vm::NoVm{}, wrapped);
  vm::Dictionary d(s, 256);
  check(d.set_ref(td::ConstBitPtr(id.data()), 256, value(pack_bytes(value(encode(item), "item")), "item-cell")),
        "item-put");
  vm::CellBuilder b;
  check(d.append_dict_to_bool(b), "dictionary");
  return b.finalize();
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 1 || argc == 2, "arguments");
    std::filesystem::path out;
    if (argc == 2) {
      out = argv[1];
      check(std::filesystem::create_directory(out), "fresh-output");
    }
    unsigned count = 0;
    auto save = [&](unsigned mode, const RegistryState* parent, td::Ref<vm::Cell> input, unsigned coordinate,
                    unsigned at, unsigned deny, const Updates& updates, bool accepted, const char* label,
                    td::Ref<vm::Cell> result) {
      if (!out.empty()) {
        auto prefix = (out / std::to_string(count)).string();
        write(prefix + ".boc", boc(input));
        if (result.not_null())
          write(prefix + ".result", boc(result));
        std::ofstream meta(prefix + ".case");
        meta << mode << ' ' << coordinate << ' ' << at << ' ' << deny << ' ' << updates.size() << ' ' << accepted << ' '
             << label << '\n';
        if (parent)
          meta << parent->revision() << '\n';
        check(meta.good(), "fixture-meta");
        for (unsigned i = 0; i < updates.size(); ++i) {
          write(prefix + ".update" + std::to_string(i), value(encode(updates[i].first), "update"));
          write(prefix + ".auth" + std::to_string(i), value(encode(updates[i].second), "evidence"));
          // Written only for the cases that need it, so a replay that reads one
          // is a replay that had a global operation to authorize.
          if (updates[i].first.identity_ == Hash{})
            write(prefix + ".governance", value(encode(Authority::anchor()), "governance-anchor"));
        }
      }
      ++count;
    };
    auto run = [&](const RegistryState& parent, unsigned at, const Updates& updates, bool accepted, const char* label,
                   unsigned deny = 0) {
      auto input = value(parent.encode_cell(), "parent-cell");
      auto result = parent.apply_block(at, updates, Authority{deny});
      check(result.ok() == accepted, label);
      if (std::string(label) == "coordinate-overflow")
        check(result.error().code == "block-gap", "coordinate-overflow-early-admission");
      check(value(parent.encode_cell(), "parent-unchanged")->get_hash() == input->get_hash(), "immutable-parent");
      td::Ref<vm::Cell> cell;
      if (result.ok()) {
        cell = value(result.value().encode_cell(), "result-cell");
        auto restored = value(RegistryState::decode_cell(cell, at), "successor-valid");
        check(value(restored.encode_cell(), "successor-roundtrip")->get_hash() == cell->get_hash(),
              "checkpoint-roundtrip");
      }
      save(0, &parent, input, parent.coordinate(), at, deny, updates, accepted, label, cell);
      return result.ok() ? result.value() : parent;
    };
    auto decode_case = [&](td::Ref<vm::Cell> cell, unsigned coordinate, bool accepted, const char* label) {
      auto result = RegistryState::decode_cell(cell, coordinate);
      check(result.ok() == accepted, label);
      td::Ref<vm::Cell> encoded;
      if (result.ok()) {
        encoded = value(result.value().encode_cell(), "decoded-cell");
        check(encoded->get_hash() == cell->get_hash(), "decode-preserves-control");
      }
      save(1, nullptr, cell, coordinate, 0, 0, {}, accepted, label, encoded);
    };
    auto large = state(501);
    decode_case(value(large.encode_cell(), "large-root"), 0, true, "native-roundtrip");
    run(large, 1, {request(large, 501, 5, 1)}, true, "large-registry-apply");
    auto initial = state(3);
    auto genesis = value(initial.encode_cell(), "genesis-cell");
    decode_case(genesis, 0, true, "native-roundtrip");
    auto first = request(initial, 1, 1, 4);
    auto second = request(initial, 2, 1, 4);
    auto both = run(initial, 1, {first, second}, true, "multi-identity-stage");
    for (unsigned deny = 1; deny <= 3; ++deny)
      run(initial, 1, {first}, false, deny == 1 ? "owner-refusal" : deny == 2 ? "pop-refusal" : "admin-refusal", deny);
    run(initial, 2, {}, false, "block-gap");
    run(initial, 0, {}, false, "same-block");
    auto cancel_first = cancel(both, 1);
    auto canceled = run(both, 2, {cancel_first}, true, "cancel-one-identity");
    auto before = run(canceled, 3, {}, true, "empty-block");
    auto due = run(before, 4, {}, true, "due-other-identity");
    check(
        due.identities().at(h(1)).active_[0].key_.epoch_ == 1 && due.identities().at(h(2)).active_[0].key_.epoch_ == 2,
        "cancel-preserves-other-due");
    check(due.revision() == 3, "one-revision-per-block");
    decode_case(value(before.encode_cell(), "before"), 4, false, "overdue-state");
    auto cancel_second = cancel(canceled, 2);
    auto no_due = run(canceled, 3, {cancel_second}, true, "cancel-last-due");
    auto no_effect = run(no_due, 4, {}, true, "canceled-empty-boundary");
    check(no_effect.revision() == no_due.revision(), "canceled-due-index");
    auto too_late = cancel(before, 2);
    run(before, 4, {too_late}, false, "due-before-cancel");
    auto later = request(canceled, 1, 1, 5, 2);
    run(canceled, 3, {later}, false, "canceled-epoch-retained");
    later = request(canceled, 1, 1, 5, 3);
    auto restaged = run(canceled, 3, {later}, true, "canceled-next-epoch");
    auto restaged4 = run(restaged, 4, {}, true, "restaged-first-boundary");
    run(restaged4, 5, {}, true, "restaged-second-boundary");
    auto immediate = request(initial, 1, 1, 1);
    auto step1 = value(initial.apply_block(1, {immediate}, Authority{}), "ordered-preview");
    auto next_immediate = request(step1, 1, 2, 1);
    run(initial, 1, {immediate, next_immediate}, true, "ordered-same-identity");
    run(initial, 1, {next_immediate, immediate}, false, "reversed-transaction-order");
    run(initial, 1, {immediate, immediate}, false, "failed-tail-atomicity");
    auto after_due = value(before.apply_block(4, {}, Authority{}), "due-preview");
    auto after_update = request(after_due, 2, 1, 4, 3);
    run(before, 4, {after_update}, true, "due-before-request");
    // A zero-identity policy operation, so the independent implementation
    // replays one too. Its activation is stamped with the exported anchor,
    // which is the only value both sides can read rather than derive.
    {
      auto policy = value(initial.policy_at(0), "global-current-policy");
      policy.revision_ += 1;
      policy.previous_ = initial.current_policy();
      policy.effective_from_ = Authority::anchor().seqno_ + 2;
      Update global;
      global.operation_ = 4;
      global.nonce_ = 0;
      global.previous_ = initial.current_policy();
      global.effective_from_ = policy.effective_from_;
      global.new_policy_ = value(encode(policy), "global-policy-bytes");
      run(initial, 1, {{global, {}}}, true, "global-policy-operation");
      run(initial, 1, {{global, {}}}, false, "global-policy-refused-authority", 4);
    }
    // Externally authenticated checkpoints retain control records and policy history.
    auto p = initial.policies().begin()->second;
    p.revision_ = 2;
    p.previous_ = initial.current_policy();
    p.effective_from_ = 7;
    auto pid = value(object_id("policy", p), "policy-id");
    vm::CellSlice root(vm::NoVm{}, genesis);
    auto with_policy = replace_ref(genesis, 2, put(root.prefetch_ref(2), pid, p));
    Activation a{1, {}, pid, 7, 1, h(81), h(82), h(83)};
    vm::Dictionary acts(32);
    std::array<std::uint8_t, 4> at{0, 0, 0, 7};
    check(acts.set_ref(td::ConstBitPtr(at.data()), 32,
                       value(pack_bytes(value(encode(a), "activation")), "activation-cell")),
          "activation-put");
    vm::CellBuilder actsw;
    check(acts.append_dict_to_bool(actsw), "activation-wrapper");
    Observation o{3, 1, h(90), 0, 9, 0};
    auto oid = value(object_id("observation", o), "observation-id");
    vm::CellBuilder empty;
    empty.store_long(0, 1);
    vm::CellBuilder control;
    control.store_long(0x76616331, 32).store_ref(actsw.finalize()).store_ref(put(empty.finalize(), oid, o));
    auto controlled = replace_ref(with_policy, 3, control.finalize());
    decode_case(controlled, 0, true, "control-retention");
    auto controlled_state = value(RegistryState::decode_cell(controlled, 0), "control-state");
    for (unsigned n = 1; n <= 7; ++n)
      controlled_state = run(controlled_state, n, {}, true, n == 7 ? "policy-boundary" : "control-empty-block");
    // A revision overflow must refuse the entire successor, including due effects.
    vm::CellSlice bits(vm::NoVm{}, value(before.encode_cell(), "before-overflow"));
    vm::CellBuilder max;
    max.store_bits(bits.fetch_bits(560)).store_long(-1, 64);
    bits.advance(64);
    max.append_cellslice(bits);
    auto overflow = value(RegistryState::decode_cell(max.finalize(), 3), "overflow-parent");
    run(overflow, 4, {}, false, "registry-revision-overflow");
    auto last = value(RegistryState::decode_cell(genesis, 0xfffffffe), "last-parent");
    run(last, 0xffffffff, {}, false, "coordinate-overflow");
    if (!out.empty()) {
      std::ofstream complete(out / "complete");
      complete << count << '\n';
      check(complete.good(), "complete");
    }
    std::cout << "PASS: native registry replay " << count << " cases\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
