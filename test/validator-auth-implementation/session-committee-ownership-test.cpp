#include "validator/auth/native-session-committee.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "native-history-fixture.h"

namespace {
using namespace tos::auth;
using namespace p0_owner_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

void expect_error(const auto& result, std::string_view code,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == code, assertion);
}

ChainContext read_chain(const std::filesystem::path& folder) {
  auto bytes = read(folder / "0.chain");
  Reader reader(bytes);
  ChainContext chain;
  reader.integer(chain.network);
  reader.hash(chain.genesis_root);
  reader.hash(chain.genesis_file);
  reader.hash(chain.chain_domain);
  require(reader.ok() && reader.remaining() == 0, "fixture_chain");
  return chain;
}

NativeSessionIdInput identity_input(std::uint64_t marker = 730) {
  return {h(marker), tos::masterchainId, tos::shardIdAll, 17u, 41u,
          NativeSessionIdForm::group_new};
}

td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}

struct HistoryFixture {
  td::Ref<vm::Cell> head_state;
  td::Ref<vm::Cell> birth_state;
  td::Ref<vm::Cell> predecessor_state;
  Anchor head;
  Anchor birth;
  Anchor predecessor;
  ChainContext chain;
  Bytes birth_block;
  Bytes predecessor_block;
  NativeSessionIdInput supplied_identity = identity_input();

  Result<Bytes> block(const tos::BlockIdExt& id,
                      std::size_t maximum) const {
    const Anchor* expected = nullptr;
    const Bytes* bytes = nullptr;
    if (id.seqno() == birth.seqno_) {
      expected = &birth;
      bytes = &birth_block;
    } else if (id.seqno() == predecessor.seqno_) {
      expected = &predecessor;
      bytes = &predecessor_block;
    } else {
      return Error{"fixture-block-request"};
    }
    if (id.root_hash.as_slice() !=
            td::Slice(expected->root_.data(), expected->root_.size()) ||
        id.file_hash.as_slice() !=
            td::Slice(expected->file_.data(), expected->file_.size()) ||
        maximum < bytes->size())
      return Error{"fixture-block-request"};
    return *bytes;
  }

  Result<td::Ref<vm::Cell>> state(const Anchor& anchor) const {
    if (anchor == birth)
      return birth_state;
    if (anchor == predecessor)
      return predecessor_state;
    return Error{"fixture-state-request"};
  }

  Result<NativeSessionIdInput> identity(
      const Anchor& anchor, td::Ref<vm::Cell> state,
      tos::ShardIdFull target) const {
    if (state.is_null() || hash(state) != anchor.state_)
      return Error{"fixture-identity-state"};
    if (target.workchain != supplied_identity.workchain ||
        target.shard != supplied_identity.shard)
      return Error{"fixture-identity-target"};
    return supplied_identity;
  }

  NativeBlockReader blocks() const {
    return [this](const tos::BlockIdExt& id,
                  std::size_t maximum) -> Result<Bytes> {
      return block(id, maximum);
    };
  }

  NativeSessionStateReader states() const {
    return [this](const Anchor& anchor) -> Result<td::Ref<vm::Cell>> {
      return state(anchor);
    };
  }

  NativeSessionIdentityInputReader identities() const {
    return [this](const Anchor& anchor, td::Ref<vm::Cell> state,
                  tos::ShardIdFull target) -> Result<NativeSessionIdInput> {
      return identity(anchor, std::move(state), target);
    };
  }
};

HistoryFixture make_history(const std::filesystem::path& owner_inputs,
                            const std::filesystem::path& committee_fixtures,
                            NativeSessionIdInput input = identity_input()) {
  auto active = cell(read(committee_fixtures / "0.boc"));
  auto chain = read_chain(committee_fixtures);
  auto zero_state = history_state(active, 0, {});
  Anchor zero{0, hash(zero_state), file_hash(boc(zero_state)),
              hash(zero_state)};
  chain.genesis_root = zero.root_;
  chain.genesis_file = zero.file_;
  Entry zero_entry{0, 0, zero.root_, zero.file_};

  auto birth_state = history_state(active, 99, {zero_entry});
  auto predecessor_state =
      capabilities(history_state(active, 98, {zero_entry}), 16, 0);

  auto owner = fixture(owner_inputs);
  owner.chain.network = chain.network;
  auto transaction = cell(read(owner_inputs / "accept.boc"));
  auto birth_cell = block_for(transaction, birth_state, owner);
  auto birth_bytes = boc(birth_cell);
  Anchor birth{99, hash(birth_cell), file_hash(birth_bytes),
               hash(birth_state)};

  auto predecessor_cell = block_for(transaction, predecessor_state, owner);
  predecessor_cell = alter_block(predecessor_cell, 2);
  auto predecessor_bytes = boc(predecessor_cell);
  Anchor predecessor{98, hash(predecessor_cell),
                     file_hash(predecessor_bytes),
                     hash(predecessor_state)};

  auto head_state = history_state(
      active, 100,
      {zero_entry, Entry{98, 98, predecessor.root_, predecessor.file_},
       Entry{99, 99, birth.root_, birth.file_}});
  Anchor head{100, h(800), h(801), hash(head_state)};
  HistoryFixture result{head_state,
                        birth_state,
                        predecessor_state,
                        head,
                        birth,
                        predecessor,
                        chain,
                        std::move(birth_bytes),
                        std::move(predecessor_bytes)};
  result.supplied_identity = input;
  return result;
}

Result<NativeSessionBirth> resolve_birth(const HistoryFixture& fixture,
                                         const NativeSessionIdInput& input) {
  return NativeSessionBirth::resolve(
      fixture.head_state, fixture.head, fixture.chain, input,
      fixture.blocks(), fixture.states(), fixture.identities());
}

std::string request_name(const NativeSessionCommitteeRequest& request) {
  if (const auto* block =
          std::get_if<NativeSessionBlockRequest>(&request))
    return "block:" + std::to_string(block->id.seqno());
  if (const auto* state =
          std::get_if<NativeSessionStateRequest>(&request))
    return "state:" + std::to_string(state->anchor.seqno_);
  const auto& identity = std::get<NativeSessionIdentityRequest>(request);
  return "identity:" + std::to_string(identity.anchor.seqno_);
}

Result<std::shared_ptr<const NativeSessionCommitteeContext>> drive(
    NativeSessionCommitteeAdmission& admission, const HistoryFixture& fixture,
    std::vector<std::string>* requests = nullptr) {
  for (unsigned turn = 0; turn < 16; ++turn) {
    auto progress = admission.advance();
    if (!progress.ok())
      return progress.error();
    if (!progress.value())
      return admission.context();

    const auto& request = *progress.value();
    if (requests)
      requests->push_back(request_name(request));

    if (const auto* block =
            std::get_if<NativeSessionBlockRequest>(&request)) {
      auto bytes = fixture.block(block->id, block->maximum_bytes);
      if (!bytes.ok())
        return bytes.error();
      auto accepted = admission.provide_block(block->id, bytes.value());
      if (!accepted.ok())
        return accepted.error();
      continue;
    }
    if (const auto* state =
            std::get_if<NativeSessionStateRequest>(&request)) {
      auto value = fixture.state(state->anchor);
      if (!value.ok())
        return value.error();
      auto accepted =
          admission.provide_state(state->anchor, value.value());
      if (!accepted.ok())
        return accepted.error();
      continue;
    }
    const auto& identity =
        std::get<NativeSessionIdentityRequest>(request);
    auto value = fixture.identity(identity.anchor, identity.state,
                                  identity.target);
    if (!value.ok())
      return value.error();
    auto accepted = admission.provide_identity(
        identity.anchor, identity.target, value.value());
    if (!accepted.ok())
      return accepted.error();
  }
  return Error{"fixture-handoff-loop"};
}

void setup(const std::filesystem::path& owner_inputs,
           const std::filesystem::path& committee_fixtures) {
  require(std::filesystem::is_regular_file(owner_inputs / "accept.boc"),
          "fixture_accept");
  require(std::filesystem::is_regular_file(committee_fixtures / "0.boc") &&
              std::filesystem::is_regular_file(
                  committee_fixtures / "0.chain"),
          "fixture_committee");
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(const std::filesystem::path& owner_inputs,
                        const std::filesystem::path& committee_fixtures) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("committee_at_birth", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input());
    auto admitted = drive(admission, fixture);
    require(admitted.ok(), "committee_at_birth");
    const auto& context = *admitted.value();
    require(context.birth().selected().block.seqno == fixture.birth.seqno_ &&
                context.committee().anchor() == fixture.birth &&
                context.committee().snapshot().committee().anchor_mc_ ==
                    fixture.birth.seqno_ &&
                context.committee().snapshot().committee().catchain_ ==
                    context.birth().selected().epoch.catchain,
            "committee_at_birth");
  });

  add("exact_async_handoff", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input());
    std::vector<std::string> requests;
    auto admitted = drive(admission, fixture, &requests);
    require(admitted.ok() &&
                requests ==
                    std::vector<std::string>{"block:99", "state:99",
                                             "identity:99", "block:98",
                                             "state:98"},
            "exact_async_handoff");
  });

  add("same_session_reuses_owned_context", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto birth = resolve_birth(fixture, identity_input());
    require(birth.ok(), "same_session_reuses_owned_context");
    auto first = admit_native_session_committee(
        {}, birth.value(), fixture.chain);
    require(first.ok(), "same_session_reuses_owned_context");
    auto deliberately_wrong_chain = fixture.chain;
    deliberately_wrong_chain.chain_domain[0] ^= 1;
    auto reused = admit_native_session_committee(
        first.value(), birth.value(), deliberately_wrong_chain);
    require(reused.ok() && reused.value().get() == first.value().get(),
            "same_session_reuses_owned_context");
  });

  add("new_identity_creates_new_context", [=] {
    auto first_fixture =
        make_history(owner_inputs, committee_fixtures, identity_input(730));
    auto second_fixture =
        make_history(owner_inputs, committee_fixtures, identity_input(731));
    auto first_birth = resolve_birth(first_fixture, identity_input(730));
    auto second_birth = resolve_birth(second_fixture, identity_input(731));
    require(first_birth.ok() && second_birth.ok(),
            "new_identity_creates_new_context");
    auto first = admit_native_session_committee(
        {}, first_birth.value(), first_fixture.chain);
    require(first.ok(), "new_identity_creates_new_context");
    auto second = admit_native_session_committee(
        first.value(), second_birth.value(), second_fixture.chain);
    require(second.ok() && second.value().get() != first.value().get() &&
                second.value()->birth().selected().epoch.native_session_id !=
                    first.value()->birth().selected().epoch.native_session_id,
            "new_identity_creates_new_context");
  });

  add("derive_failure_keeps_existing", [=] {
    auto first_fixture =
        make_history(owner_inputs, committee_fixtures, identity_input(730));
    auto second_fixture =
        make_history(owner_inputs, committee_fixtures, identity_input(731));
    auto first_birth = resolve_birth(first_fixture, identity_input(730));
    auto second_birth = resolve_birth(second_fixture, identity_input(731));
    require(first_birth.ok() && second_birth.ok(),
            "derive_failure_keeps_existing");
    auto first = admit_native_session_committee(
        {}, first_birth.value(), first_fixture.chain);
    require(first.ok(), "derive_failure_keeps_existing");
    auto held = first.value()->committee().snapshot().committee();

    auto wrong_chain = second_fixture.chain;
    wrong_chain.chain_domain[0] ^= 1;
    auto refused = admit_native_session_committee(
        first.value(), second_birth.value(), wrong_chain);
    require(!refused.ok() &&
                first.value()->committee().snapshot().committee() == held,
            "derive_failure_keeps_existing");
  });

  add("wrong_response_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input());
    auto first = admission.advance();
    require(first.ok() && first.value() &&
                std::holds_alternative<NativeSessionBlockRequest>(
                    *first.value()),
            "wrong_response_refused");
    const auto request =
        std::get<NativeSessionBlockRequest>(*first.value());
    auto wrong = request.id;
    ++wrong.id.seqno;
    expect_error(admission.provide_block(wrong, fixture.birth_block),
                 "session-handoff-response-mismatch",
                 "wrong_response_refused");
    auto again = admission.advance();
    require(again.ok() && again.value() &&
                std::get<NativeSessionBlockRequest>(*again.value()).id ==
                    request.id,
            "wrong_response_refused");
  });

  add("wrong_identity_response_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input());
    for (unsigned turn = 0; turn < 4; ++turn) {
      auto progress = admission.advance();
      require(progress.ok() && progress.value(),
              "wrong_identity_response_refused");
      const auto& request = *progress.value();
      if (const auto* block =
              std::get_if<NativeSessionBlockRequest>(&request)) {
        auto bytes = fixture.block(block->id, block->maximum_bytes);
        require(bytes.ok() &&
                    admission.provide_block(block->id, bytes.value()).ok(),
                "wrong_identity_response_refused");
        continue;
      }
      if (const auto* state =
              std::get_if<NativeSessionStateRequest>(&request)) {
        auto value = fixture.state(state->anchor);
        require(value.ok() &&
                    admission.provide_state(state->anchor, value.value()).ok(),
                "wrong_identity_response_refused");
        continue;
      }
      const auto& identity =
          std::get<NativeSessionIdentityRequest>(request);
      auto wrong = identity.target;
      wrong.shard ^= std::uint64_t{1} << 62;
      expect_error(admission.provide_identity(
                       identity.anchor, wrong, identity_input()),
                   "session-handoff-response-mismatch",
                   "wrong_identity_response_refused");
      auto again = admission.advance();
      require(again.ok() && again.value() &&
                  std::holds_alternative<NativeSessionIdentityRequest>(
                      *again.value()),
              "wrong_identity_response_refused");
      return;
    }
    require(false, "wrong_identity_response_refused");
  });

  add("oversize_response_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionHistoryBudget budget;
    budget.finalized.bytes = 1;
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input(),
        {}, budget);
    auto progress = admission.advance();
    require(progress.ok() && progress.value() &&
                std::holds_alternative<NativeSessionBlockRequest>(
                    *progress.value()),
            "oversize_response_refused");
    const auto request =
        std::get<NativeSessionBlockRequest>(*progress.value());
    require(request.maximum_bytes == 1, "oversize_response_refused");
    expect_error(admission.provide_block(request.id, Bytes{1, 2}),
                 "session-handoff-block-bound",
                 "oversize_response_refused");
  });

  add("history_budget_preserved", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    NativeSessionHistoryBudget budget;
    budget.finalized.blocks = 1;
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input(),
        {}, budget);
    auto result = drive(admission, fixture);
    expect_error(result, "history-resource", "history_budget_preserved");
    require(!admission.ready(), "history_budget_preserved");
  });

  add("committee_budget_preserved", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    StateReadBudget committee_budget{1, 268435456};
    NativeSessionCommitteeAdmission admission(
        fixture.head_state, fixture.head, fixture.chain, identity_input(),
        {}, {}, committee_budget);
    auto result = drive(admission, fixture);
    require(!result.ok() && !admission.ready(),
            "committee_budget_preserved");
  });

  add("interrupted_handoff_has_no_commit", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto birth = resolve_birth(fixture, identity_input());
    require(birth.ok(), "interrupted_handoff_has_no_commit");
    auto existing = admit_native_session_committee(
        {}, birth.value(), fixture.chain);
    require(existing.ok(), "interrupted_handoff_has_no_commit");
    auto held = existing.value();
    {
      NativeSessionCommitteeAdmission admission(
          fixture.head_state, fixture.head, fixture.chain,
          identity_input(731), held);
      auto progress = admission.advance();
      require(progress.ok() && progress.value() && !admission.ready(),
              "interrupted_handoff_has_no_commit");
    }
    require(held.get() == existing.value().get() &&
                held->committee().anchor() == fixture.birth,
            "interrupted_handoff_has_no_commit");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr
        << "USAGE: test-p0-native-session-committee OWNER_INPUTS "
           "COMMITTEE_FIXTURES [case-name|--list]\n";
    return 2;
  }
  const std::filesystem::path owner_inputs(argv[1]);
  const std::filesystem::path committee_fixtures(argv[2]);
  const auto all = tests(owner_inputs, committee_fixtures);

  if (argc == 4 && std::string_view(argv[3]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (argc == 4 && name != argv[3])
      continue;
    try {
      setup(owner_inputs, committee_fixtures);
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": "
                << error.what() << '\n';
      return 2;
    }
  }
  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }
  std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
  return 0;
}
