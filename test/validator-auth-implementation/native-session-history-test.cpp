#include "validator/auth/native-session-history.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "native-history-fixture.h"

namespace {
using namespace tos::auth;
using namespace owner_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

void expect_error(const auto& result, std::string_view error,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == error, assertion);
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

NativeSessionIdInput identity_input(
    NativeSessionIdForm form = NativeSessionIdForm::group_new) {
  return {h(730), tos::masterchainId, tos::shardIdAll,
          form == NativeSessionIdForm::group ? 0u : 17u, 41u, form};
}

td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}

SessionBirthEpoch independently_expected_epoch(
    td::Ref<vm::Cell> state, const Anchor& anchor,
    const ChainContext& chain, const NativeSessionIdInput& input,
    const std::string& assertion) {
  tos::BlockIdExt block_id{{tos::masterchainId, tos::shardIdAll,
                            anchor.seqno_},
                           bits(anchor.root_), bits(anchor.file_)};
  auto config = block::ConfigInfo::extract_config(
      state, block_id,
      block::ConfigInfo::needValidatorSet |
          block::ConfigInfo::needShardHashes |
          block::Config::needCapabilities);
  require(config.is_ok(), assertion);
  const auto& cfg = *config.ok();
  const auto& total = cfg.get_cur_validator_set();
  require(total != nullptr, assertion);
  tos::ShardIdFull shard{input.workchain, input.shard};
  tos::CatchainSeqno catchain = 0;
  auto members = cfg.compute_validator_set_cc(shard, *total, cfg.utime,
                                              &catchain);
  require(!members.empty(), assertion);
  auto identity = derive_native_session_identity(
      td::make_ref<block::ValidatorSet>(catchain, shard, std::move(members)),
      input);
  require(identity.ok(), assertion);
  auto election = cfg.get_config_param(35, 34);
  require(election.not_null(), assertion);
  const auto& established = identity.value();
  return {established.native_session_id, hash(election),
          established.native_options_hash, established.workchain,
          established.shard, established.catchain,
          established.vertical_seqno, established.key_block_seqno};
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
  unsigned block_reads = 0;
  unsigned state_reads = 0;
  unsigned identity_reads = 0;
  bool fail_block = false;
  bool fail_state = false;
  bool fail_identity = false;
  bool fail_identity_at_predecessor = false;
  bool changed_predecessor_options = false;
  bool wrong_identity_shard = false;
  bool wrong_state = false;
  bool null_state = false;

  NativeBlockReader blocks() {
    return [this](const tos::BlockIdExt& id,
                  std::size_t maximum) -> Result<Bytes> {
      ++block_reads;
      if (fail_block)
        return Error{"archive-offline"};
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
    };
  }

  NativeSessionStateReader states() {
    return [this](const Anchor& anchor) -> Result<td::Ref<vm::Cell>> {
      ++state_reads;
      if (fail_state)
        return Error{"state-db-offline"};
      if (null_state)
        return td::Ref<vm::Cell>{};
      if (wrong_state)
        return head_state;
      if (anchor == birth)
        return birth_state;
      if (anchor == predecessor)
        return predecessor_state;
      return Error{"fixture-state-request"};
    };
  }

  NativeSessionIdentityInputReader identities() {
    return [this](const Anchor& anchor, td::Ref<vm::Cell> state,
                  tos::ShardIdFull target) -> Result<NativeSessionIdInput> {
      ++identity_reads;
      if (fail_identity ||
          (fail_identity_at_predecessor && anchor == predecessor))
        return Error{"identity-input-offline"};
      if (state.is_null() || hash(state) != anchor.state_)
        return Error{"fixture-identity-state"};
      auto input = identity_input();
      if (target.workchain != input.workchain || target.shard != input.shard)
        return Error{"fixture-identity-target"};
      if (changed_predecessor_options && anchor == predecessor)
        input.native_options_hash = h(731);
      if (wrong_identity_shard)
        input.shard ^= std::uint64_t{1} << 62;
      return input;
    };
  }
};

HistoryFixture make_history(const std::filesystem::path& owner_inputs,
                            const std::filesystem::path& committee_fixtures,
                            bool wrong_birth_sequence = false,
                            bool active_predecessor = false) {
  auto active = cell(read(committee_fixtures / "0.boc"));
  auto chain = read_chain(committee_fixtures);
  auto zero_state = history_state(active, 0, {});
  Anchor zero{0, hash(zero_state), file_hash(boc(zero_state)),
              hash(zero_state)};
  chain.genesis_root = zero.root_;
  chain.genesis_file = zero.file_;
  Entry zero_entry{0, 0, zero.root_, zero.file_};

  auto birth_state = history_state(active, wrong_birth_sequence ? 98 : 99,
                                   {zero_entry});
  auto predecessor_state = history_state(active, 98, {zero_entry});
  if (!active_predecessor)
    predecessor_state = capabilities(predecessor_state, 16, 0);

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
                     file_hash(predecessor_bytes), hash(predecessor_state)};

  auto head_state = history_state(
      active, 100,
      {zero_entry, Entry{98, 98, predecessor.root_, predecessor.file_},
       Entry{99, 99, birth.root_, birth.file_}});
  Anchor head{100, h(800), h(801), hash(head_state)};
  return {head_state,
          birth_state,
          predecessor_state,
          head,
          birth,
          predecessor,
          chain,
          std::move(birth_bytes),
          std::move(predecessor_bytes)};
}

void setup(const std::filesystem::path& owner_inputs,
           const std::filesystem::path& committee_fixtures) {
  require(std::filesystem::is_regular_file(owner_inputs / "accept.boc"),
          "fixture_accept");
  require(std::filesystem::is_regular_file(committee_fixtures / "0.boc") &&
              std::filesystem::is_regular_file(committee_fixtures / "0.chain"),
          "fixture_committee");
}

using Test = std::pair<std::string, std::function<void()>>;
std::vector<Test> tests(const std::filesystem::path& owner_inputs,
                        const std::filesystem::path& committee_fixtures) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("authenticated_birth_state", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(), f.states(), f.identities());
    require(selected.ok(), "authenticated_birth_state");
    require(selected.value().birth().selected().block.seqno == 99,
            "authenticated_birth_state");
    require(hash(selected.value().state()) == f.birth.state_,
            "authenticated_birth_state");
  });
  add("exact_reader_sequence", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(), f.states(), f.identities());
    require(selected.ok() && f.block_reads == 2 && f.state_reads == 2 &&
                f.identity_reads == 1,
            "exact_reader_sequence");
  });
  add("epoch_uses_native_identity", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto expected = independently_expected_epoch(
        f.head_state, f.head, f.chain, identity_input(),
        "epoch_uses_native_identity");
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(),
        f.states(), f.identities());
    require(selected.ok() &&
                selected.value().birth().selected().epoch == expected,
            "epoch_uses_native_identity");
  });
  add("preactivation_is_boundary", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.fail_identity_at_predecessor = true;
    auto previous = derive_native_session_epoch(
        f.predecessor_state, f.predecessor, f.chain, identity_input());
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(),
        f.states(), f.identities());
    require(previous.ok() && !previous.value() && selected.ok() &&
                selected.value().birth().selected().block.seqno == 99 &&
                f.identity_reads == 1,
            "preactivation_is_boundary");
  });
  add("state_reader_error", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.fail_state = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "state-db-offline", "state_reader_error");
  });
  add("state_reader_missing", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), {}, f.identities()),
                 "session-history-state-unavailable", "state_reader_missing");
  });
  add("identity_reader_error", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.fail_identity = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "identity-input-offline", "identity_reader_error");
  });
  add("identity_reader_missing", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), {}),
                 "session-history-identity-unavailable",
                 "identity_reader_missing");
  });
  add("identity_shard_binding", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.wrong_identity_shard = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "session-history-identity-shard",
                 "identity_shard_binding");
  });
  add("options_transition_is_boundary", [=] {
    auto f = make_history(owner_inputs, committee_fixtures, false, true);
    f.changed_predecessor_options = true;
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(),
        f.states(), f.identities());
    require(selected.ok() &&
                selected.value().birth().selected().block.seqno == 99,
            "options_transition_is_boundary");
  });
  add("state_hash_binding", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.wrong_state = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "session-history-state-binding", "state_hash_binding");
  });
  add("null_state_binding", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.null_state = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "session-history-state-binding", "null_state_binding");
  });
  add("state_coordinate_binding", [=] {
    auto f = make_history(owner_inputs, committee_fixtures, true);
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "session-history-state-context", "state_coordinate_binding");
  });
  add("block_reader_error", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    f.fail_block = true;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities()),
                 "archive-offline", "block_reader_error");
    require(f.state_reads == 0, "block_reader_error");
  });
  add("finalized_budget_no_fallback", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    NativeSessionHistoryBudget budget;
    budget.finalized.blocks = 0;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities(), budget),
                 "history-resource", "finalized_budget_no_fallback");
    require(f.state_reads == 0, "finalized_budget_no_fallback");
  });
  add("observation_budget_no_fallback", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    NativeSessionHistoryBudget budget;
    budget.observations = 1;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities(), budget),
                 "session-birth-budget", "observation_budget_no_fallback");
    require(f.state_reads == 0, "observation_budget_no_fallback");
  });
  add("zero_observation_budget", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    NativeSessionHistoryBudget budget;
    budget.observations = 0;
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, identity_input(),
                     f.blocks(), f.states(), f.identities(), budget),
                 "session-birth-budget", "zero_observation_budget");
    require(f.block_reads == 0 && f.state_reads == 0,
            "zero_observation_budget");
  });
  add("zero_options_refused", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto input = identity_input();
    input.native_options_hash = {};
    expect_error(NativeSessionBirth::resolve(
                     f.head_state, f.head, f.chain, input, f.blocks(),
                     f.states(), f.identities()),
                 "native-session-options", "zero_options_refused");
    require(f.block_reads == 0 && f.state_reads == 0,
            "zero_options_refused");
  });
  add("invalid_coordinate_refused", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto input = identity_input();
    input.shard = 0;
    expect_error(derive_native_session_epoch(
                     f.head_state, f.head, f.chain, input),
                 "native-session-coordinate", "invalid_coordinate_refused");
  });
  add("legacy_key_coordinate_normalized", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto left = identity_input(NativeSessionIdForm::group_ex);
    auto right = left;
    left.last_key_block_seqno = 41;
    right.last_key_block_seqno = 99;
    auto a = derive_native_session_epoch(f.head_state, f.head, f.chain, left);
    auto b = derive_native_session_epoch(f.head_state, f.head, f.chain, right);
    require(a.ok() && b.ok() && a.value() && b.value() &&
                a.value()->key_block_seqno == 0 && *a.value() == *b.value(),
            "legacy_key_coordinate_normalized");
  });
  add("selected_state_is_owned", [=] {
    auto f = make_history(owner_inputs, committee_fixtures);
    auto selected = NativeSessionBirth::resolve(
        f.head_state, f.head, f.chain, identity_input(), f.blocks(), f.states(), f.identities());
    require(selected.ok(), "selected_state_is_owned");
    auto expected = selected.value().birth().selected().block.state;
    f.head_state = {};
    f.birth_state = {};
    f.predecessor_state = {};
    require(hash(selected.value().state()) == expected,
            "selected_state_is_owned");
  });
  return result;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr << "USAGE: test-p0-native-session-history OWNER_INPUTS COMMITTEE_FIXTURES [case-name|--list]\n";
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
