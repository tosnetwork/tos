#include <charconv>
#include <filesystem>

#include "validator/auth/lifecycle.h"
class MemoryHistory final : public KeyHistory {
 public:
  std::map<Hash, Key> values;
  bool load_directory(const char* directory) {
    for (const auto& p : std::filesystem::directory_iterator(directory)) {
      auto key = decode<Key>(load(p.path().c_str()));
      if (!key.ok())
        return false;
      auto id = object_id("key", key.value());
      if (!id.ok())
        return false;
      values.emplace(id.value(), key.value());
    }
    return true;
  }
  Result<Key> find(const Hash& id) const override {
    auto i = values.find(id);
    if (i == values.end())
      return Error{"unknown-key"};
    return i->second;
  }
  Result<std::uint64_t> latest_epoch(const Hash& identity, KeySlot wanted) const override {
    std::uint64_t max = 0;
    for (const auto& [id, k] : values)
      if (k.identity_ == identity && KeySlot{k.role_, k.suite_, k.parameters_} == wanted)
        max = std::max(max, k.epoch_);
    return max;
  }
  Result<bool> ever_registered(const Hash& identity) const override {
    for (const auto& [id, k] : values)
      if (k.identity_ == identity)
        return true;
    return false;
  }
};
// Controlled authorization results exercise state transitions, not native proofs.
class TestAuthority final : public LifecycleAuthority {
  std::string deny_;

 public:
  explicit TestAuthority(std::string deny) : deny_(std::move(deny)) {
  }
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return deny_ != "owner";
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return deny_ != "possession";
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return deny_ != "administration";
  }
  // Global operations are outside what this fixture authorizes. Refusing
  // explicitly rather than inheriting a default keeps a fixture from silently
  // admitting an operation it was never built to reason about.
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t) const override {
    return Error{"fixture-governance"};
  }
};
Result<std::uint32_t> coordinate(std::string_view text) {
  std::uint32_t value = 0;
  auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    return Error{"arguments"};
  return value;
}
int lifecycle_main(int argc, char** argv) {
  MemoryHistory archive;
  if (!archive.load_directory(argv[3]))
    return 2;
  auto state = decode<Identity>(load(argv[2]));
  if (!state.ok())
    return 2;
  if (argc == 7 && std::string(argv[1]) == "select") {
    auto at = coordinate(argv[4]), role = coordinate(argv[5]);
    if (!at.ok() || !role.ok() || role.value() > 255)
      return 2;
    auto keys =
        select_identity_keys(state.value(), archive, at.value(), {{static_cast<std::uint8_t>(role.value()), 1, 1}});
    if (!keys.ok()) {
      std::cerr << keys.error().code << '\n';
      return 1;
    }
    if (keys.value().size() != 1)
      return 2;
    auto bytes = encode(keys.value()[0]);
    if (!bytes.ok())
      return 2;
    std::ofstream out(argv[6], std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
    return out.good() ? 0 : 2;
  }
  Result<Identity> next = Error{"arguments"};
  if (argc == 7 && std::string(argv[1]) == "due") {
    auto parent = coordinate(argv[4]), at = coordinate(argv[5]);
    if (!parent.ok() || !at.ok())
      return 2;
    next = apply_due_transitions(state.value(), archive, parent.value(), at.value());
  }
  if (argc == 9 && std::string(argv[1]) == "apply") {
    auto update = decode<Update>(load(argv[4]));
    auto evidence = decode<Authorizations>(load(argv[5]));
    if (!update.ok() || !evidence.ok())
      return 2;
    auto at = coordinate(argv[6]);
    if (!at.ok())
      return 2;
    auto accepted = apply_identity_update(state.value(), archive, update.value(), evidence.value(), at.value(),
                                          TestAuthority(argv[8]));
    if (!accepted.ok()) {
      std::cerr << accepted.error().code << '\n';
      return 1;
    }
    next = accepted.value().identity;
  }
  if (!next.ok()) {
    std::cerr << next.error().code << '\n';
    return 1;
  }
  auto encoded = encode(next.value());
  if (!encoded.ok())
    return 2;
  std::ofstream out(argv[argc == 7 ? 6 : 7], std::ios::binary);
  out.write(reinterpret_cast<const char*>(encoded.value().data()), encoded.value().size());
  return out.good() ? 0 : 2;
}
