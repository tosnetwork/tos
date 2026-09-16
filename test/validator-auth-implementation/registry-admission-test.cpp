// Whether a block admits a registry update.
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "validator/auth/cells.h"
#include "validator/auth/native-config-message.h"
#include "validator/auth/native-evidence.h"
#include "validator/auth/native-registry-admission.h"
#include "vm/boc.h"
#include "vm/excno.hpp"

#include "native-config-context-fixture.h"
#include "owner-history-fixture.h"

using namespace owner_fixture;
using namespace owner_history_fixture;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
void admits(const Result<T>& result, const char* name) {
  if (!result.ok()) {
    std::cerr << "DETAIL " << name << " expected=assembled actual=" << result.error().code << '\n';
    throw AssertionFailure(name);
  }
}

template <class T>
void refuses(const Result<T>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "assembled" : result.error().code) << '\n';
    throw AssertionFailure(name);
  }
}

Hash account(unsigned n) {
  return h(500 + n);
}

td::Ref<vm::Cell> external(const Hash& destination, td::Ref<vm::Cell> body, std::int32_t workchain = -1) {
  vm::CellBuilder b;
  b.store_long(2, 2).store_long(0, 2).store_long(2, 2).store_long(0, 1).store_long(workchain, 8);
  b.store_bytes(td::Slice(reinterpret_cast<const char*>(destination.data()), destination.size()));
  b.store_long(0, 4).store_long(0, 1).store_ref(body);
  return b.finalize();
}

td::Ref<vm::Cell> registry_body(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence,
                                std::uint32_t action = native_registry_action) {
  vm::CellBuilder b;
  b.store_zeroes(512).store_long(action, 32).store_long(1, 32).store_long(2, 32);
  b.store_ref(std::move(update)).store_ref(std::move(evidence));
  return b.finalize();
}

td::Ref<vm::Cell> evidence_without_owner() {
  Authorizations none;
  auto encoded = value(encode(none), "evidence-authorizations");
  auto packed = value(pack_bytes(encoded), "evidence-packed");
  vm::CellBuilder b;
  b.store_long(native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
  b.store_ref(std::move(packed)).store_ref(vm::CellBuilder().finalize());
  return b.finalize();
}

using Test = std::pair<std::string, std::function<void()>>;
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 3 || argc > 4) {
      std::cerr << "USAGE: test-p0-registry-admission FIXTURES OWNER-INPUTS [case-name|--list|--exclude=case]\n";
      return 2;
    }
    std::filesystem::path fixtures(argv[1]), owner_inputs(argv[2]);

    std::uint32_t case_wc = 0, case_cc = 0;
    std::uint64_t case_shard = 0;
    std::string label;
    bool accepted = false;
    std::filesystem::path selected_fixture;
    for (unsigned n = 0; n < 64 && selected_fixture.empty(); ++n) {
      auto candidate = fixtures / std::to_string(n);
      if (!std::filesystem::exists(candidate.string() + ".case"))
        continue;
      std::ifstream(candidate.string() + ".case") >> case_wc >> case_shard >> case_cc >> accepted >> label;
      if (accepted)
        selected_fixture = candidate;
    }
    check(!selected_fixture.empty(), "no-accepted-committee-case");

    auto raw_state = read(selected_fixture.string() + ".boc");
    auto parsed = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(raw_state.data()), raw_state.size()));
    check(parsed.is_ok(), "state-boc");
    auto history = make_with_owner_history(parsed.move_as_ok(), owner_inputs);
    const auto configuration = history.address;
    const tos::BlockIdExt parent_block{{tos::masterchainId, tos::shardIdAll, history.head.seqno_},
                                       td::Bits256(td::ConstBitPtr(history.head.root_.data())),
                                       td::Bits256(td::ConstBitPtr(history.head.file_.data()))};

    RegistryAdmissionInputs inputs;
    inputs.configuration_account = configuration;
    inputs.message =
        external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
    inputs.parent_block = parent_block;
    inputs.catchain_source = case_cc;
    inputs.transaction.masterchain_state = history.root;
    inputs.transaction.parent = history.head;
    inputs.transaction.chain = history.chain;
    inputs.transaction.shard = {static_cast<tos::WorkchainId>(case_wc), case_shard};
    // The block's prefix, opened once from the same parent every case admits
    // against. Admission does not derive one: what a message is admitted onto
    // is what the transactions before it in this block committed.
    const auto sequence = config_context_fixture::sequence_for(history.root, history.head, history.chain,
                                                                  history.head.seqno_ + 1);
    inputs.transaction.catchain = case_cc;
    inputs.transaction.inclusion = history.head.seqno_ + 1;

    // An update approved by an owner, carrying the anchor it declares and the
    // witness offered for it. Neither is invented here: both are produced from
    // a block the parent state's index actually holds, so a case that changes
    // one of them changes exactly one thing.
    auto approved_by_owners = [&](const std::vector<Anchor>& declared, td::Ref<vm::Cell> witness) {
      Authorizations owned;
      for (const auto& anchor : declared) {
        OwnerAuth owner;
        owner.proof_.anchor_ = anchor;
        owner.proof_.kind_ = 1;
        owner.proof_.proof_ = value(object_value(5, Bytes{1, 2, 3, 4}), "owner-proof-object");
        owned.owner_.push_back(owner);
      }
      auto encoded = value(encode(owned), "owner-authorizations");
      auto packed = value(pack_bytes(encoded), "owner-packed");
      vm::CellBuilder b;
      b.store_long(native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
      b.store_ref(std::move(packed)).store_ref(std::move(witness));
      auto result = inputs;
      result.message =
          external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), b.finalize()));
      return result;
    };
    auto approved_by_owner = [&](const Anchor& declared, td::Ref<vm::Cell> witness) {
      return approved_by_owners({declared}, std::move(witness));
    };

    std::vector<Test> tests;
    auto add = [&](std::string name, std::function<void()> fn) { tests.emplace_back(std::move(name), std::move(fn)); };

    add("complete-input-produces-an-authority", [&] {
      auto assembled = admit_registry_message(inputs, sequence);
      require(assembled.ok() && assembled.value() != nullptr, "complete-input-produces-an-authority");
      assembled.value()->host().checkpoints();
    });
    add("collator-gathering-produces-an-authority", [&] {
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, history.root, parent_block, parent_block, history.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, history.head.seqno_ + 1);
      require(gathered.ok(), "collator-gathering-produces-an-authority");
      auto assembled = admit_registry_message(gathered.value(), sequence);
      require(assembled.ok() && assembled.value() != nullptr, "collator-gathering-produces-an-authority");
      assembled.value()->host().checkpoints();
    });
    // What comparing two sources does not cover, recorded so the pair of checks
    // above is not read as more than it is.
    //
    // The parent identity and the catchain each arrive twice, from places that
    // do not depend on each other, and a mistake in one of them is refused. A
    // mistake they share is not: both copies are then wrong and agree, and
    // nothing here can tell that from the truth. That is the boundary of
    // cross-source verification, not a defect in it -- catching it would take a
    // third source that does not depend on the first two, and there is none at
    // this boundary.
    //
    // No mutation names this case. Nothing in this file can be removed to make
    // it fail, which is exactly what it is here to say. If a third source is
    // ever introduced, this case starts failing, and that is the signal to
    // replace it with a guard.
    add("sources-that-are-wrong-together-are-not-caught", [&] {
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, history.root, parent_block, parent_block, history.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc ^ 1u, case_cc ^ 1u, history.head.seqno_ + 1);
      require(gathered.ok(), "sources-that-are-wrong-together-are-not-caught");
      auto assembled = admit_registry_message(gathered.value(), sequence);
      require(assembled.ok() && assembled.value() != nullptr, "sources-that-are-wrong-together-are-not-caught");
    });
    add("wrong-catchain-source-is-refused", [&] {
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, history.root, parent_block, parent_block, history.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc ^ 1u, history.head.seqno_ + 1);
      refuses(gathered, "registry-admission-catchain-source", "wrong-catchain-source-is-refused");
    });
    add("wrong-parent-root-source-is-refused", [&] {
      auto wrong_parent = parent_block;
      const auto other_root = h(773);
      wrong_parent.root_hash = td::Bits256(td::ConstBitPtr(other_root.data()));
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, history.root, parent_block, wrong_parent, history.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, history.head.seqno_ + 1);
      refuses(gathered, "registry-admission-parent-source", "wrong-parent-root-source-is-refused");
    });
    add("wrong-parent-file-source-is-refused", [&] {
      auto wrong_parent = parent_block;
      const auto other_file = h(774);
      wrong_parent.file_hash = td::Bits256(td::ConstBitPtr(other_file.data()));
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, history.root, parent_block, wrong_parent, history.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, history.head.seqno_ + 1);
      refuses(gathered, "registry-admission-parent-source", "wrong-parent-file-source-is-refused");
    });
    add("gathered-catchain-must-match-source", [&] {
      auto wrong = inputs;
      wrong.catchain_source ^= 1u;
      refuses(admit_registry_message(wrong, sequence), "registry-admission-catchain-input",
              "gathered-catchain-must-match-source");
    });
    add("gathered-parent-root-must-match-source", [&] {
      auto wrong = inputs;
      const auto other_root = h(771);
      wrong.parent_block.root_hash = td::Bits256(td::ConstBitPtr(other_root.data()));
      refuses(admit_registry_message(wrong, sequence), "registry-admission-parent-input",
              "gathered-parent-root-must-match-source");
    });
    add("gathered-parent-file-must-match-source", [&] {
      auto wrong = inputs;
      const auto other_file = h(772);
      wrong.parent_block.file_hash = td::Bits256(td::ConstBitPtr(other_file.data()));
      refuses(admit_registry_message(wrong, sequence), "registry-admission-parent-input",
              "gathered-parent-file-must-match-source");
    });
    // A producer and a validator must reach the same answer from the same
    // block. This one admits with an owner approval while the only archive
    // reader admission can construct is one that refuses every read: if any
    // part of the path consulted an archive rather than the witness, this case
    // would come back "registry-admission-archive-read" instead of an
    // authority. That refusal is the read counter -- there is deliberately no
    // reader in the signature for a test to count calls on.
    add("an-authenticated-witness-needs-no-archive", [&] {
      auto approved = approved_by_owner(history.owner.anchor, history.owner.witness);
      auto admitted = admit_registry_message(approved, sequence);
      admits(admitted, "an-authenticated-witness-needs-no-archive");
      require(admitted.value() != nullptr, "an-authenticated-witness-needs-no-archive");
      auto served = admitted.value()->history().finalized_anchor(history.owner.at);
      require(served.ok() && served.value() == history.owner.anchor, "an-authenticated-witness-needs-no-archive");
    });
    // A witness is evidence for one coordinate, not for finality in general.
    // This offers a structurally perfect witness for a real, indexed block
    // while declaring the anchor of the block beside it.
    add("a-witness-for-another-block-is-refused", [&] {
      auto approved = approved_by_owner(history.other.anchor, history.owner.witness);
      refuses(admit_registry_message(approved, sequence), "header-root", "a-witness-for-another-block-is-refused");
    });
    add("a-malformed-witness-is-refused", [&] {
      auto approved = approved_by_owner(history.owner.anchor, history.owner.block);
      refuses(admit_registry_message(approved, sequence), "header-surface", "a-malformed-witness-is-refused");
    });
    // The declared anchor is compared whole. Its resulting state is the field
    // nothing else in the path would notice: the index binds root and file
    // hashes, and a wrong state hash would otherwise travel into execution as
    // the anchor an approval is measured against.
    add("an-anchor-differing-only-in-state-is-refused", [&] {
      auto declared = history.owner.anchor;
      declared.state_ = h(999);
      auto approved = approved_by_owner(declared, history.owner.witness);
      refuses(admit_registry_message(approved, sequence), "evidence-owner-anchor",
              "an-anchor-differing-only-in-state-is-refused");
    });
    // No block may authorise itself with state it is in the middle of
    // producing, so an approval naming the block being built is refused before
    // any witness is examined.
    add("an-approval-cannot-name-the-block-being-built", [&] {
      auto declared = history.owner.anchor;
      declared.seqno_ = inputs.transaction.inclusion;
      auto approved = approved_by_owner(declared, history.owner.witness);
      refuses(admit_registry_message(approved, sequence), "owner-finality-coordinate",
              "an-approval-cannot-name-the-block-being-built");
    });
    // Execution may reach exactly the history this message witnessed. The
    // parent is the tempting extra: admission holds its anchor already and
    // serving it would cost nothing, which is why the absence has to be a case.
    add("only-the-witnessed-coordinate-is-served", [&] {
      auto approved = approved_by_owner(history.owner.anchor, history.owner.witness);
      auto admitted = admit_registry_message(approved, sequence);
      admits(admitted, "only-the-witnessed-coordinate-is-served");
      require(admitted.value() != nullptr, "only-the-witnessed-coordinate-is-served");
      for (std::uint32_t at : {history.other.at, history.head.seqno_})
        refuses(admitted.value()->history().finalized_anchor(at), "finalized-anchor-unavailable",
                "only-the-witnessed-coordinate-is-served");
    });
    // One witness, one approval. The evidence container carries a single
    // mc_header, so a second approval could only be authenticated by reading
    // that one witness twice and calling it proof of two different
    // coordinates. Admission is built on that cardinality, but does not
    // enforce it: the wire format does, in one bit of list length, and a second
    // approval cannot even be written. Pinned from here so that widening it is
    // not a one-line change -- whoever does has to answer how the format
    // carries a second witness, whether authenticate_owner becomes plural, and
    // how admission comes to own both authenticated anchors. Behind this, and
    // unreachable while it holds, authenticate_owner refuses any count but one.
    add("a-second-owner-approval-cannot-be-encoded", [&] {
      Authorizations two;
      for (const auto& anchor : {history.owner.anchor, history.other.anchor}) {
        OwnerAuth owner;
        owner.proof_.anchor_ = anchor;
        owner.proof_.kind_ = 1;
        owner.proof_.proof_ = value(object_value(5, Bytes{1, 2, 3, 4}), "owner-proof-object");
        two.owner_.push_back(owner);
      }
      refuses(encode(two), "list-bound", "a-second-owner-approval-cannot-be-encoded");
    });
    // The privileged surface is one interface, but this transaction is a
    // registry update: the set an elector produces is bound by the host built
    // for that message, which implements nothing else. A contract reached
    // through this path asking to bind gets the answer it would get with no
    // authority at all.
    add("registry-update-host-refuses-bind", [&] {
      auto assembled = admit_registry_message(inputs, sequence);
      require(assembled.ok() && assembled.value() != nullptr, "registry-update-host-refuses-bind");
      auto empty = vm::CellBuilder().finalize();
      bool refused = false;
      try {
        // The update host refuses the instruction outright, so neither side of
        // the charge is reached.
        assembled.value()->host().bind(
            empty, empty,
            vm::ValidatorAuthHost::Charge{[](long long) { throw std::runtime_error("unexpected gas charge"); },
                                          [](std::uint16_t) {
                                            throw std::runtime_error("unexpected signature charge");
                                          }});
      } catch (const vm::VmError& error) {
        refused = error.get_errno() == static_cast<int>(vm::Excno::inv_opcode);
      }
      require(refused, "registry-update-host-refuses-bind");
    });
    add("history-outlives-the-call-that-assembled-it", [&] {
      // The witnessed history is built inside admission and the caller never
      // holds a reference to it. Owner verification reads it during VM
      // execution, after this call has returned, so the only question that
      // matters is whether it is still there -- and the only way to ask is to
      // read it here, where a reference to a destroyed local is a read of freed
      // memory rather than a wrong answer.
      auto approved = approved_by_owner(history.owner.anchor, history.owner.witness);
      std::unique_ptr<NativeConfigTransaction> authority;
      {
        auto admitted = admit_registry_message(approved, sequence);
        require(admitted.ok() && admitted.value() != nullptr, "history-outlives-the-call-that-assembled-it");
        authority = std::move(admitted.value());
      }
      auto served = authority->history().finalized_anchor(history.owner.at);
      require(served.ok() && served.value() == history.owner.anchor, "history-outlives-the-call-that-assembled-it");
    });
    add("gathered-account-must-match-parent-state", [&] {
      auto wrong = inputs;
      wrong.configuration_account = account(77);
      refuses(admit_registry_message(wrong, sequence), "registry-admission-configuration-input",
              "gathered-account-must-match-parent-state");
    });
    add("other-account-not-admitted", [&] {
      auto elsewhere = inputs;
      elsewhere.message =
          external(account(2), registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
      refuses(admit_registry_message(elsewhere, sequence), "registry-admission-not-configuration", "other-account-not-admitted");
    });
    add("non-masterchain-not-admitted", [&] {
      auto shard_chain = inputs;
      shard_chain.message = external(
          configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()), 0);
      refuses(admit_registry_message(shard_chain, sequence), "registry-admission-not-configuration",
              "non-masterchain-not-admitted");
    });
    add("other-action-not-admitted", [&] {
      auto other_action = inputs;
      other_action.message = external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(),
                                                                   evidence_without_owner(), 0x43665021));
      refuses(admit_registry_message(other_action, sequence), "registry-admission-not-registry", "other-action-not-admitted");
    });
    add("missing-account-is-an-input-error", [&] {
      auto unfilled = inputs;
      unfilled.configuration_account = Hash{};
      refuses(admit_registry_message(unfilled, sequence), "registry-admission-input", "missing-account-is-an-input-error");
    });

    if (argc == 4 && std::string_view(argv[3]) == "--list") {
      for (const auto& [name, _] : tests)
        std::cout << name << '\n';
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
    for (const auto& [name, fn] : tests) {
      if (!selected.empty() && name != selected)
        continue;
      if (!excluded.empty() && name == excluded)
        continue;
      // Flushed, because a case that aborts under the sanitizer never returns
      // to flush it, and a marker only this side can see is no marker at all.
      std::cout << "SETUP_OK " << name << std::endl;
      try {
        fn();
      } catch (const AssertionFailure&) {
        std::cerr << "ASSERTION_FAILED " << name << '\n';
        return 1;
      }
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    }
    if (ran == 0) {
      std::cerr << "UNKNOWN_CASE\n";
      return 2;
    }
    std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "UNEXPECTED_EXCEPTION " << error.what() << '\n';
    return 2;
  }
}
