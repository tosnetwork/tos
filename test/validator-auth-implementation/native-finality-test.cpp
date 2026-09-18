#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "validator/auth/native-finality.h"
#include "node-history-adapter-fixture.h"

namespace {
namespace auth = tos::auth;
namespace history_fixture = node_history_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
T require_value(auth::Result<T> result, const std::string& assertion) {
  require(result.ok(), assertion);
  return std::move(result.value());
}

template <class T>
T canonical(const T& value, const std::string& assertion) {
  auto raw = require_value(auth::encode(value), assertion);
  auto decoded = require_value(auth::decode<T>(raw), assertion);
  auto roundtrip = require_value(auth::encode(decoded), assertion);
  require(roundtrip == raw, assertion);
  return decoded;
}

auth::Hash hash_of(const td::Ref<vm::Cell>& cell) {
  auth::Hash out{};
  auto hash = cell->get_hash();
  auto bytes = hash.as_slice();
  std::copy(bytes.ubegin(), bytes.uend(), out.begin());
  return out;
}

tos::BlockIdExt genesis_id(const auth::ChainContext& chain) {
  return {{tos::masterchainId, tos::shardIdAll, 0},
          td::Bits256(td::ConstBitPtr(chain.genesis_root.data())),
          td::Bits256(td::ConstBitPtr(chain.genesis_file.data()))};
}

auth::NativeHeadCandidate candidate(
    const auth::Bytes& block, td::Ref<vm::Cell> state,
    const auth::ChainContext& chain, const auth::Anchor& expected,
    const std::string& assertion) {
  auto parsed = require_value(
      auth::native_masterchain_block_anchor(block, chain.network),
      assertion);
  parsed = canonical(parsed, assertion);
  require(parsed == expected, assertion);
  return {block, std::move(state)};
}

class Source final : public auth::NativeFinalizedHeadSource {
 public:
  auth::NativeHeadObservation observation;
  auth::NativeSignatureSetKind kind =
      auth::NativeSignatureSetKind::final;
  mutable unsigned verify_calls = 0;

  auth::Result<auth::NativeHeadObservation> observe() const override {
    return observation;
  }

  auth::Result<auth::NativeFinalityVerification> verify_signatures(
      const tos::BlockIdExt& block) const override {
    ++verify_calls;
    return auth::NativeFinalityVerification{
        block, kind, 7, 11, 2, 3};
  }
};

std::unique_ptr<auth::NativeFinalizedHeadEstablisher> establisher(
    const auth::ChainContext& chain, Source& source,
    const std::string& assertion) {
  return require_value(
      auth::NativeFinalizedHeadEstablisher::create(chain, source),
      assertion);
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(
    const std::filesystem::path& owner,
    const std::filesystem::path& committee) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("configured_genesis_is_the_unsigned_initial_head", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    auto state = vm::CellBuilder().store_long(0x51, 8).finalize();
    auto chain = data.chain;
    chain.genesis_root = hash_of(state);
    chain.genesis_file = history_fixture::h(201);
    Source source;
    source.observation.configured_genesis =
        auth::NativeGenesisHeadCandidate{genesis_id(chain), state};
    auto value = establisher(
        chain, source, "configured_genesis_is_the_unsigned_initial_head");
    auto established = value->establish();
    require(
        established.ok() &&
            established.value().anchor() ==
                auth::Anchor{0, chain.genesis_root, chain.genesis_file,
                             chain.genesis_root} &&
            established.value().state()->get_hash() == state->get_hash() &&
            source.verify_calls == 0,
        "configured_genesis_is_the_unsigned_initial_head");
  });

  add("configured_genesis_must_name_exact_zero_block", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    auto state = vm::CellBuilder().store_long(0x52, 8).finalize();
    auto chain = data.chain;
    chain.genesis_root = hash_of(state);
    chain.genesis_file = history_fixture::h(202);
    auto id = genesis_id(chain);
    id.id.seqno = 1;
    Source source;
    source.observation.configured_genesis =
        auth::NativeGenesisHeadCandidate{id, state};
    auto value = establisher(
        chain, source, "configured_genesis_must_name_exact_zero_block");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-genesis-binding" &&
            source.verify_calls == 0,
        "configured_genesis_must_name_exact_zero_block");
  });

  add("configured_genesis_must_match_chain_coordinates", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    auto state = vm::CellBuilder().store_long(0x53, 8).finalize();
    auto chain = data.chain;
    chain.genesis_root = hash_of(state);
    chain.genesis_file = history_fixture::h(203);
    auto id = genesis_id(chain);
    id.file_hash.as_mutable_slice()[0] ^= 1;
    Source source;
    source.observation.configured_genesis =
        auth::NativeGenesisHeadCandidate{id, state};
    auto value = establisher(
        chain, source, "configured_genesis_must_match_chain_coordinates");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-genesis-binding" &&
            source.verify_calls == 0,
        "configured_genesis_must_match_chain_coordinates");
  });

  add("configured_genesis_must_match_state_root", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    auto state = vm::CellBuilder().store_long(0x54, 8).finalize();
    auto other = vm::CellBuilder().store_long(0x55, 8).finalize();
    auto chain = data.chain;
    chain.genesis_root = hash_of(state);
    chain.genesis_file = history_fixture::h(204);
    Source source;
    source.observation.configured_genesis =
        auth::NativeGenesisHeadCandidate{genesis_id(chain), other};
    auto value = establisher(
        chain, source, "configured_genesis_must_match_state_root");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-genesis-state" &&
            source.verify_calls == 0,
        "configured_genesis_must_match_state_root");
  });

  add("final_signature_set_required", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    Source source;
    source.kind = auth::NativeSignatureSetKind::approval;
    source.observation.finality_candidate =
        candidate(data.old_block, data.old_state, data.chain, data.old,
                  "final_signature_set_required");
    auto value = establisher(
        data.chain, source, "final_signature_set_required");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-approval-only" &&
            source.verify_calls == 1,
        "final_signature_set_required");
  });

  add("peer_claim_refused", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    Source source;
    source.observation.finality_candidate =
        candidate(data.old_block, data.old_state, data.chain, data.old,
                  "peer_claim_refused");
    source.observation.peer_claim =
        canonical(data.old, "peer_claim_refused");
    auto value = establisher(data.chain, source, "peer_claim_refused");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-peer-claim" &&
            source.verify_calls == 0,
        "peer_claim_refused");
  });

  add("complete_anchor_state_binding", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    Source source;
    auto valid = candidate(
        data.old_block, data.old_state, data.chain, data.old,
        "complete_anchor_state_binding");
    valid.resulting_state = data.predecessor_state;
    source.observation.finality_candidate = std::move(valid);
    auto value = establisher(
        data.chain, source, "complete_anchor_state_binding");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-state-binding" &&
            source.verify_calls == 0,
        "complete_anchor_state_binding");
  });

  add("head_regression_refused", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    Source source;
    source.observation.finality_candidate =
        candidate(data.old_block, data.old_state, data.chain, data.old,
                  "head_regression_refused");
    auto value = establisher(
        data.chain, source, "head_regression_refused");
    auto first = value->establish();
    require(
        first.ok() && first.value().anchor() == data.old,
        "head_regression_refused");

    source.observation.finality_candidate =
        candidate(data.predecessor_block, data.predecessor_state,
                  data.chain, data.predecessor,
                  "head_regression_refused");
    auto second = value->establish();
    require(
        !second.ok() &&
            second.error().code == "finalized-head-regression" &&
            source.verify_calls == 2,
        "head_regression_refused");
  });

  add("no_latest_fallback", [=] {
    auto data = history_fixture::make_fixture(owner, committee);
    Source source;
    source.observation.latest_candidate =
        candidate(data.old_block, data.old_state, data.chain, data.old,
                  "no_latest_fallback");
    auto value = establisher(
        data.chain, source, "no_latest_fallback");
    auto established = value->establish();
    require(
        !established.ok() &&
            established.error().code == "finalized-head-unavailable" &&
            source.verify_calls == 0,
        "no_latest_fallback");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr << "USAGE: test-p0-native-finality OWNER_INPUTS "
                 "COMMITTEE_FIXTURES [case-name|--list|--exclude=case]\n";
    return 2;
  }

  const std::filesystem::path owner(argv[1]);
  const std::filesystem::path committee(argv[2]);
  const auto all = tests(owner, committee);

  if (argc == 4 && std::string_view(argv[3]) == "--list") {
    for (const auto& item : all)
      std::cout << item.first << '\n';
    return 0;
  }

  std::string selected;
  std::string excluded;
  if (argc == 4) {
    std::string argument(argv[3]);
    constexpr std::string_view prefix = "--exclude=";
    if (argument.starts_with(prefix))
      excluded = argument.substr(prefix.size());
    else
      selected = std::move(argument);
  }

  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (!selected.empty() && name != selected)
      continue;
    if (!excluded.empty() && name == excluded)
      continue;
    try {
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
