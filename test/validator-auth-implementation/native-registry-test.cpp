#include "validator/auth/native-registry.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
class Authority final : public LifecycleAuthority {
  unsigned deny_;

 public:
  explicit Authority(unsigned deny = 0) : deny_(deny) {
  }
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return deny_ != 1;
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return deny_ != 2;
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return deny_ != 3;
  }
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t) const override {
    return Error{"fixture-governance"};
  }
};
td::Ref<vm::Cell> root(const std::filesystem::path& path) {
  auto bytes = read(path);
  auto cell = vm::std_boc_deserialize(td::Slice(bytes.data(), bytes.size()));
  check(cell.is_ok(), "fixture-boc");
  return cell.move_as_ok();
}
td::Ref<vm::Cell> ref(td::Ref<vm::Cell> input, unsigned n, td::Ref<vm::Cell> value) {
  vm::CellSlice s(vm::NoVm{}, input);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size()));
  for (unsigned i = 0; s.size_refs(); ++i) {
    auto cell = s.fetch_ref();
    b.store_ref(i == n ? value : cell);
  }
  return b.finalize();
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3 || (argc == 4 && std::string(argv[3]) == "--guards"), "arguments");
    bool guards = argc == 4;
    std::filesystem::path input(argv[1]), out(argv[2]);
    check(std::filesystem::create_directory(out), "fresh-output");
    unsigned count = 0;
    std::ifstream(input / "complete") >> count;
    check(count >= 30, "complete-corpus");
    std::map<std::pair<std::uint32_t, Hash>, NativeRegistry> continuous;
    unsigned negative_count = 0;
    std::ofstream negatives(out / "negative-cases");
    auto negative = [&](td::Ref<vm::Cell> checkpoint, Hash expected, std::uint32_t at, const char* error,
                        const char* label) {
      auto result = NativeRegistry::restore(checkpoint, expected, at);
      check(!result.ok() && result.error().code == error, label);
      auto name = "negative" + std::to_string(negative_count++);
      write(out / (name + ".boc"), boc(checkpoint));
      write(out / (name + ".hash"), Bytes(expected.begin(), expected.end()));
      negatives << name << ' ' << at << ' ' << error << ' ' << label << '\n';
    };
    for (unsigned i = 0; i < count; ++i) {
      if (guards && i < 2)
        continue;
      auto prefix = (input / std::to_string(i)).string();
      std::ifstream meta(prefix + ".case");
      unsigned mode, coordinate, at, deny, n, accepted;
      std::string label;
      meta >> mode >> coordinate >> at >> deny >> n >> accepted >> label;
      check(!meta.fail(), "fixture-meta");
      auto cell = root(prefix + ".boc");
      auto loaded = NativeRegistry::bootstrap(cell, coordinate);
      auto result = loaded;
      if (mode == 0) {
        check(loaded.ok(), "parent-setup");
        auto key = std::make_pair(coordinate, hash(cell));
        auto found = continuous.find(key);
        auto parent = found == continuous.end() ? loaded.value() : found->second;
        auto checkpoint = value(parent.checkpoint(), "parent-checkpoint");
        std::vector<std::pair<Update, Authorizations>> updates;
        for (unsigned j = 0; j < n; ++j)
          updates.emplace_back(value(decode<Update>(read(prefix + ".update" + std::to_string(j))), "update"),
                               value(decode<Authorizations>(read(prefix + ".auth" + std::to_string(j))), "auth"));
        result = parent.apply_block(at, updates, Authority(deny));
        auto restored = value(NativeRegistry::restore(checkpoint, hash(cell), coordinate), "checkpoint-load");
        auto replay = restored.apply_block(at, updates, Authority(deny));
        check(result.ok() == replay.ok(), "persistent-restart-acceptance");
        if (result.ok())
          check(hash(value(result.value().checkpoint(), "continuous")) ==
                    hash(value(replay.value().checkpoint(), "restart")),
                "persistent-restart-bytes");
        else
          check(result.error().code == replay.error().code, "persistent-restart-error");
        check(hash(value(parent.checkpoint(), "parent-after")) == hash(checkpoint), "persistent-atomic-parent");
        if (label == "large-registry-apply") {
          auto bounded = parent.apply_block(at, updates, Authority(deny), {256, 65536});
          check(bounded.ok(), "persistent-bounded-archive");
          auto empty = value(parent.apply_block(at, {}, Authority{}, {2, 32}), "persistent-constant-empty");
          check(empty.remaining().entries == 0 && empty.remaining().bytes == 0, "persistent-empty-cost");
          auto no_entries = parent.apply_block(at, {}, Authority{}, {0, 65536});
          check(!no_entries.ok() && no_entries.error().code == "state-resource", "persistent-entry-budget");
          auto no_bytes = parent.apply_block(at, {}, Authority{}, {256, 0});
          check(!no_bytes.ok() && no_bytes.error().code == "state-resource", "persistent-byte-budget");
        }
      }
      check(result.ok() == bool(accepted), label.c_str());
      if (!result.ok())
        continue;
      auto& next = result.value();
      auto expected = root(prefix + ".result");
      check(boc(value(next.encode_cell(), "result")) == boc(expected), (label + "-bytes").c_str());
      auto checkpoint = value(next.checkpoint(), "checkpoint");
      write(out / (std::to_string(i) + ".checkpoint"), boc(checkpoint));
      continuous.insert_or_assign({next.coordinate(), hash(expected)}, next);
      auto restored =
          value(NativeRegistry::restore(checkpoint, hash(expected), next.coordinate()), "checkpoint-roundtrip");
      check(hash(value(restored.checkpoint(), "restored")) == hash(checkpoint), "persistent-index-roundtrip");
      if (i == 2) {
        auto no_entries = next.apply_block(next.coordinate() + 1, {}, Authority{}, {0, 65536});
        check(!no_entries.ok() && no_entries.error().code == "state-resource", "persistent-entry-budget");
        auto no_bytes = next.apply_block(next.coordinate() + 1, {}, Authority{}, {256, 0});
        check(!no_bytes.ok() && no_bytes.error().code == "state-resource", "persistent-byte-budget");
        check(value(next.ever_registered(h(1)), "registered"), "persistent-ever-registered");
        check(!value(next.ever_registered(h(9999)), "unregistered"), "persistent-neighbor-registration");
        check(value(next.latest_epoch(h(1), {1, 1, 1}), "epoch") == 1, "persistent-initial-epoch");
        check(value(next.latest_epoch(h(1), {1, 2, 1}), "other-slot") == 0, "persistent-slot-isolation");
        auto denied = NativeRegistry::bootstrap(cell, coordinate, {0, 65536});
        check(!denied.ok() && denied.error().code == "state-resource", "persistent-bootstrap-budget");
        for (unsigned mode = 0; mode < 3; ++mode) {
          vm::CellSlice header(vm::NoVm{}, checkpoint);
          vm::CellBuilder changed;
          changed.store_long(mode == 0 ? 0x76616e32 : header.prefetch_ulong(32), 32);
          header.advance(32);
          changed.store_long(mode == 1 ? 2 : header.prefetch_ulong(16), 16);
          header.advance(16);
          changed.append_cellslice(header);
          if (mode == 2)
            changed.store_long(0, 1);
          negative(changed.finalize(), hash(expected), next.coordinate(), "checkpoint-shape",
                   mode == 0   ? "persistent-checkpoint-magic"
                   : mode == 1 ? "persistent-checkpoint-version"
                               : "persistent-checkpoint-trailing");
        }
        negative(checkpoint, h(987), next.coordinate(), "checkpoint-registry", "persistent-checkpoint-root");
        negative(checkpoint, hash(expected), next.coordinate() + 1, "checkpoint-coordinate",
                 "persistent-checkpoint-coordinate");
        negative(ref(checkpoint, 1, vm::CellBuilder().store_long(0, 1).finalize()), hash(expected), next.coordinate(),
                 "checkpoint-index", "persistent-checkpoint-epochs");
        negative(ref(checkpoint, 3, vm::CellBuilder().store_long(0, 1).finalize()), hash(expected), next.coordinate(),
                 "checkpoint-index", "persistent-checkpoint-policy");
        auto sibling = value(NativeRegistry::bootstrap(value(state(3).encode_cell(), "sibling"), 0), "sibling");
        auto low = value(sibling.apply_block(1, {}, Authority{}, {2, 32}), "persistent-small-empty");
        check(low.remaining().entries == 0 && low.remaining().bytes == 0, "persistent-small-cost");
      }
      if (label == "multi-identity-stage")
        negative(ref(checkpoint, 2, vm::CellBuilder().store_long(0, 1).finalize()), hash(expected), next.coordinate(),
                 "checkpoint-index", "persistent-checkpoint-due");
    }
    check(negative_count == 8 && negatives.good(), "negative-completeness");
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: persistent native registry " << count
              << " replay cases, 8 checkpoint attacks and bounded archive work\n";
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
