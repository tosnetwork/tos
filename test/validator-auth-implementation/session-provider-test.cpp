#include "validator/auth/native-session-provider.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "session-continuity-test-fixture.h"

namespace {
using namespace tos::auth;
using namespace owner_fixture;
using namespace session_continuity_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
T require_value(Result<T> value, const std::string& assertion) {
  require(value.ok(), assertion);
  return std::move(value.value());
}

void expect_error(const auto& result, std::string_view code,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == code, assertion);
}

class InventoryProvider final : public C0SigningProvider {
 public:
  std::vector<OpaqueKey> keys;
  std::map<Hash, Key> descriptors;

  Result<std::vector<OpaqueKey>> inventory() const override {
    return keys;
  }
  Result<Key> descriptor(const Hash& handle) const override {
    auto found = descriptors.find(handle);
    if (found == descriptors.end())
      return Error{"unknown-key"};
    return found->second;
  }
  Result<Record> sign(const SignRequest&) override {
    return Error{"fixture-sign-unused"};
  }
};

struct ProviderFixture {
  InventoryProvider provider;
  Hash identity{};
  std::array<Hash, 5> handles{};
  std::array<Keyref, 5> references{};
};

ProviderFixture provider_for(
    const std::shared_ptr<const NativeSessionCommitteeContext>& context) {
  ProviderFixture result;
  const auto& members = context->committee().snapshot().committee().members_;
  require(!members.empty(), "provider-fixture-member");
  const auto& member = members.front();
  require(member.keys_.size() == 5, "provider-fixture-keys");
  result.identity = member.identity_;
  for (std::size_t i = 0; i < 5; ++i) {
    result.handles[i] = h(50000 + static_cast<unsigned>(i));
    result.references[i] = require_value(
        key_reference(member.keys_[i]), "provider-fixture-reference");
    result.provider.keys.push_back({member.keys_[i], result.handles[i]});
    result.provider.descriptors.emplace(result.handles[i], member.keys_[i]);
  }
  return result;
}

std::filesystem::path store_path(
    const std::filesystem::path& work, const std::string& name) {
  auto path = work / (name + ".commitments");
  std::filesystem::remove(path);
  std::filesystem::remove(path.string() + ".frontier");
  return path;
}

std::shared_ptr<CommittedNativeSession> commit_session(
    const HistoryFixture& fixture,
    const std::shared_ptr<const NativeSessionCommitteeContext>& context,
    const std::filesystem::path& path, const std::string& assertion) {
  auto store = NativeSessionCommitmentStore::initialize(path.string());
  require(store.ok(), assertion);
  return require_value(
      CommittedNativeSession::commit_new(*store.value(), context, fixture.chain),
      assertion);
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(const std::filesystem::path& owner,
                        const std::filesystem::path& committee,
                        const std::filesystem::path& work) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("exact_birth_inventory_installed", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "exact_birth_inventory_installed");
    auto local = provider_for(context);
    auto session = commit_session(
        fixture, context, store_path(work, "exact"),
        "exact_birth_inventory_installed");
    auto authority = NativeSessionC0Authority::install(
        session, fixture.birth_state, local.provider, local.identity);
    // The authority exposes both identities distinctly: the native session id
    // for live-session lifetime binding, and the canonical P0 session id for the
    // signer permit context. They are different values, and the P0 one is the
    // H(session, ...) the snapshot and birth origin produce, never the native id.
    const auto& birth_epoch = context->birth().selected().epoch;
    auto expected_p0 = require_value(
        session_id(fixture.chain, context->committee().snapshot(),
                   SessionOrigin{birth_epoch.native_options_hash,
                                 birth_epoch.vertical_seqno,
                                 birth_epoch.key_block_seqno}),
        "exact_birth_inventory_installed");
    require(authority.ok() && authority.value().identity() == local.identity &&
                authority.value().coordinate() == fixture.birth.seqno_ &&
                authority.value().native_session_id() == birth_epoch.native_session_id &&
                authority.value().p0_session_id() == expected_p0 &&
                expected_p0 != birth_epoch.native_session_id,
            "exact_birth_inventory_installed");
    for (std::uint8_t role = 1; role <= 5; ++role) {
      auto route = authority.value().route(role);
      require(route.ok() && route.value().key == local.references[role - 1] &&
                  route.value().handle == local.handles[role - 1],
              "exact_birth_inventory_installed");
    }
  });

  add("missing_provider_key_refused", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "missing_provider_key_refused");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "missing"),
                                  "missing_provider_key_refused");
    local.provider.descriptors.erase(local.provider.keys.back().handle);
    local.provider.keys.pop_back();
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.birth_state, local.provider, local.identity),
                 "provider-inventory-missing", "missing_provider_key_refused");
  });

  add("extra_provider_key_refused", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "extra_provider_key_refused");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "extra"),
                                  "extra_provider_key_refused");
    auto extra = local.provider.keys.front();
    extra.handle = h(50999);
    local.provider.keys.push_back(extra);
    local.provider.descriptors.emplace(extra.handle, extra.descriptor);
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.birth_state, local.provider, local.identity),
                 "provider-inventory-extra", "extra_provider_key_refused");
  });

  add("provider_descriptor_must_match_inventory", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "provider_descriptor_must_match_inventory");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "descriptor"),
                                  "provider_descriptor_must_match_inventory");
    local.provider.descriptors[local.handles[0]] = local.provider.keys[1].descriptor;
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.birth_state, local.provider, local.identity),
                 "provider-inventory-descriptor",
                 "provider_descriptor_must_match_inventory");
  });

  add("later_state_cannot_replace_birth", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "later_state_cannot_replace_birth");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "later"),
                                  "later_state_cannot_replace_birth");
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.head_state, local.provider, local.identity),
                 "session-c0-birth-state", "later_state_cannot_replace_birth");
  });

  add("session_chain_must_match_birth_registry", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "session_chain_must_match_birth_registry");
    auto local = provider_for(context);
    auto wrong_chain = fixture.chain;
    wrong_chain.chain_domain[0] ^= 1;
    auto path = store_path(work, "wrong-chain");
    auto store = NativeSessionCommitmentStore::initialize(path.string());
    require(store.ok(), "session_chain_must_match_birth_registry");
    auto session = require_value(
        CommittedNativeSession::commit_new(*store.value(), context, wrong_chain),
        "session_chain_must_match_birth_registry");
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.birth_state, local.provider, local.identity),
                 "session-c0-chain", "session_chain_must_match_birth_registry");
  });

  add("nonmember_identity_refused", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "nonmember_identity_refused");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "nonmember"),
                                  "nonmember_identity_refused");
    expect_error(NativeSessionC0Authority::install(
                     session, fixture.birth_state, local.provider, h(59999)),
                 "session-member-nonmember", "nonmember_identity_refused");
  });

  add("invalid_role_has_no_fallback", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "invalid_role_has_no_fallback");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "role"),
                                  "invalid_role_has_no_fallback");
    auto authority = require_value(NativeSessionC0Authority::install(
        session, fixture.birth_state, local.provider, local.identity),
        "invalid_role_has_no_fallback");
    expect_error(authority.route(0), "session-c0-role", "invalid_role_has_no_fallback");
    expect_error(authority.route(6), "session-c0-role", "invalid_role_has_no_fallback");
  });

  add("restart_reconciles_provider_again", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "restart_reconciles_provider_again");
    auto local = provider_for(context);
    auto path = store_path(work, "restart");
    {
      auto store = NativeSessionCommitmentStore::initialize(path.string());
      require(store.ok(), "restart_reconciles_provider_again");
      auto first = CommittedNativeSession::commit_new(*store.value(), context, fixture.chain);
      require(first.ok(), "restart_reconciles_provider_again");
    }
    auto reopened = NativeSessionCommitmentStore::open(path.string());
    require(reopened.ok(), "restart_reconciles_provider_again");
    auto rederived = require_value(make_context(fixture, identity_input()),
                                   "restart_reconciles_provider_again");
    auto restarted = require_value(
        CommittedNativeSession::restart(*reopened.value(), rederived, fixture.chain),
        "restart_reconciles_provider_again");
    local.provider.descriptors.erase(local.provider.keys.back().handle);
    local.provider.keys.pop_back();
    expect_error(NativeSessionC0Authority::install(
                     restarted, fixture.birth_state, local.provider, local.identity),
                 "provider-inventory-missing", "restart_reconciles_provider_again");
  });

  add("release_revokes_c0_route", [=] {
    auto fixture = make_history(owner, committee);
    auto context = require_value(make_context(fixture, identity_input()),
                                 "release_revokes_c0_route");
    auto local = provider_for(context);
    auto session = commit_session(fixture, context, store_path(work, "release"),
                                  "release_revokes_c0_route");
    auto authority = require_value(NativeSessionC0Authority::install(
        session, fixture.birth_state, local.provider, local.identity),
        "release_revokes_c0_route");
    auto released = session->release_if_terminated(
        fixture.head_state, fixture.head, identity_input(731));
    require(released.ok() && released.value().released,
            "release_revokes_c0_route");
    expect_error(authority.route(1), "session-context-released",
                 "release_revokes_c0_route");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 5) {
    std::cerr << "USAGE: test-p0-native-session-provider OWNER_INPUTS "
                 "COMMITTEE_FIXTURES WORKDIR [case-name|--list]\n";
    return 2;
  }
  const std::filesystem::path owner(argv[1]);
  const std::filesystem::path committee(argv[2]);
  const std::filesystem::path work(argv[3]);
  std::filesystem::create_directories(work);
  const auto all = tests(owner, committee, work);

  if (argc == 5 && std::string_view(argv[4]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::optional<std::string_view> selected;
  if (argc == 5)
    selected = argv[4];
  unsigned passed = 0;
  bool found = false;
  for (const auto& [name, test] : all) {
    if (selected && *selected != name)
      continue;
    found = true;
    std::cout << "SETUP_OK " << name << '\n';
    try {
      test();
      ++passed;
      std::cout << "CASE_PASS " << name << '\n';
    } catch (const std::exception& error) {
      std::cerr << "DETAIL " << name << " " << error.what() << '\n';
      std::cerr << "ASSERTION_FAILED " << name << '\n';
      return 1;
    }
  }
  if (!found)
    return 2;
  std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
  return 0;
}
