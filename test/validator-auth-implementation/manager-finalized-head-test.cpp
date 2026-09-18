#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

#include "validator/auth/manager-finalized-head.h"
#include "node-history-adapter-fixture.h"

namespace {
namespace auth = tos::auth;
namespace fixture = node_history_fixture;

struct Failure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool value, const char* name) {
  if (!value)
    throw Failure(name);
}

tos::BlockIdExt id_of(const auth::Anchor& anchor) {
  return {{tos::masterchainId, tos::shardIdAll, anchor.seqno_},
          td::Bits256(td::ConstBitPtr(anchor.root_.data())),
          td::Bits256(td::ConstBitPtr(anchor.file_.data()))};
}

auth::NativeFinalityVerification verification(const auth::Anchor& anchor) {
  return {id_of(anchor), auth::NativeSignatureSetKind::final, 7, 11, 2, 3};
}

std::unique_ptr<auth::ManagerFinalizedHeadSource> source(
    const fixture::Fixture& data) {
  auto zero = vm::CellBuilder().store_long(0x61, 8).finalize();
  auto chain = data.chain;
  chain.genesis_root = fixture::hash(zero);
  chain.genesis_file = fixture::h(9001);
  auto zero_id = id_of(
      auth::Anchor{0, chain.genesis_root, chain.genesis_file,
                   chain.genesis_root});
  auto made =
      auth::ManagerFinalizedHeadSource::create(chain, zero_id, zero);
  require(made.ok(), "source-create");
  return std::move(made.value());
}

using Case = std::pair<std::string, std::function<void()>>;

std::vector<Case> cases(const std::filesystem::path& owner,
                        const std::filesystem::path& committee) {
  std::vector<Case> out;
  auto add = [&](std::string name, std::function<void()> fn) {
    out.emplace_back(std::move(name), std::move(fn));
  };

  add("genesis_is_published_before_a_signed_head", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    auto observed = feed->observe();
    require(observed.ok() && observed.value().configured_genesis.has_value() &&
                !observed.value().finality_candidate,
            "genesis_is_published_before_a_signed_head");
  });

  add("verified_only_publishes_nothing_new", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    auto recorded = feed->note_verified(verification(data.old));
    require(recorded.ok() && !recorded.value(),
            "verified_only_publishes_nothing_new");
    auto observed = feed->observe();
    require(observed.ok() && observed.value().configured_genesis.has_value() &&
                !observed.value().finality_candidate,
            "verified_only_publishes_nothing_new");
  });

  add("same_block_may_accumulate_more_final_signatures", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    auto first = verification(data.old);
    auto second = first;
    second.signed_weight = 3;
    require(feed->note_verified(first).ok(),
            "same_block_may_accumulate_more_final_signatures");
    require(feed->note_verified(second).ok(),
            "same_block_may_accumulate_more_final_signatures");
    auto receipt = feed->verify_signatures(id_of(data.old));
    require(receipt.ok() && receipt.value().signed_weight == 3,
            "same_block_may_accumulate_more_final_signatures");
  });

  add("applied_only_publishes_nothing_new", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    auto recorded =
        feed->note_applied(id_of(data.old), data.old_block, data.old_state);
    require(recorded.ok() && !recorded.value(),
            "applied_only_publishes_nothing_new");
    auto observed = feed->observe();
    require(observed.ok() && observed.value().configured_genesis.has_value() &&
                !observed.value().finality_candidate,
            "applied_only_publishes_nothing_new");
  });

  add("matching_halves_publish_exact_head_in_either_order", [=] {
    auto data = fixture::make_fixture(owner, committee);
    for (bool verification_first : {false, true}) {
      auto feed = source(data);
      auth::Result<bool> first = verification_first
          ? feed->note_verified(verification(data.old))
          : feed->note_applied(id_of(data.old), data.old_block, data.old_state);
      require(first.ok() && !first.value(),
              "matching_halves_publish_exact_head_in_either_order");
      auth::Result<bool> second = verification_first
          ? feed->note_applied(id_of(data.old), data.old_block, data.old_state)
          : feed->note_verified(verification(data.old));
      require(second.ok() && second.value(),
              "matching_halves_publish_exact_head_in_either_order");
      auto observed = feed->observe();
      require(observed.ok() && !observed.value().configured_genesis &&
                  observed.value().finality_candidate.has_value() &&
                  feed->latest_complete() == id_of(data.old),
              "matching_halves_publish_exact_head_in_either_order");
      auto receipt = feed->verify_signatures(id_of(data.old));
      require(receipt.ok() &&
                  receipt.value().block == id_of(data.old),
              "matching_halves_publish_exact_head_in_either_order");
    }
  });

  add("applied_bytes_and_state_must_bind_exact_block", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    auto wrong_id = feed->note_applied(
        id_of(data.predecessor), data.old_block, data.old_state);
    require(!wrong_id.ok() &&
                wrong_id.error().code == "manager-finality-applied-binding",
            "applied_bytes_and_state_must_bind_exact_block");
    auto wrong_state = feed->note_applied(
        id_of(data.old), data.old_block, data.predecessor_state);
    require(!wrong_state.ok() &&
                wrong_state.error().code == "manager-finality-applied-binding",
            "applied_bytes_and_state_must_bind_exact_block");
  });

  add("a_later_complete_head_never_regresses", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    require(feed->note_verified(verification(data.predecessor)).ok(),
            "a_later_complete_head_never_regresses");
    auto first = feed->note_applied(
        id_of(data.predecessor), data.predecessor_block,
        data.predecessor_state);
    require(first.ok() && first.value(),
            "a_later_complete_head_never_regresses");
    require(feed->note_verified(verification(data.old)).ok(),
            "a_later_complete_head_never_regresses");
    auto second =
        feed->note_applied(id_of(data.old), data.old_block, data.old_state);
    require(second.ok() && second.value() &&
                feed->latest_complete() == id_of(data.old),
            "a_later_complete_head_never_regresses");
    auto old_again = feed->note_verified(verification(data.predecessor));
    require(old_again.ok() && !old_again.value() &&
                feed->latest_complete() == id_of(data.old),
            "a_later_complete_head_never_regresses");
  });

  add("receipt_lookup_is_exact_block_only", [=] {
    auto data = fixture::make_fixture(owner, committee);
    auto feed = source(data);
    require(feed->note_verified(verification(data.old)).ok(),
            "receipt_lookup_is_exact_block_only");
    auto absent = feed->verify_signatures(id_of(data.predecessor));
    require(!absent.ok() &&
                absent.error().code ==
                    "manager-finality-verification-missing",
            "receipt_lookup_is_exact_block_only");
  });

  return out;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr << "USAGE: test-p0-manager-finalized-head OWNER COMMITTEE "
                 "[case|--list|--exclude=case]\n";
    return 2;
  }
  auto all = cases(argv[1], argv[2]);
  if (argc == 4 && std::string_view(argv[3]) == "--list") {
    for (const auto& item : all)
      std::cout << item.first << '\n';
    return 0;
  }
  std::string selected, excluded;
  if (argc == 4) {
    std::string arg = argv[3];
    if (arg.starts_with("--exclude="))
      excluded = arg.substr(10);
    else
      selected = arg;
  }
  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (!selected.empty() && selected != name)
      continue;
    if (!excluded.empty() && excluded == name)
      continue;
    std::cout << "SETUP_OK " << name << '\n';
    try {
      fn();
    } catch (const Failure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": " << error.what()
                << '\n';
      return 2;
    }
    std::cout << "CASE_PASS " << name << '\n';
    ++ran;
  }
  if (!ran)
    return 2;
  std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
  return 0;
}
