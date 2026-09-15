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

#include "native-config-context-fixture.h"
#include "owner-fixture.h"

using namespace p0_owner_fixture;
namespace context_fixture = p0_config_context_fixture;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
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
    if (argc < 2 || argc > 3) {
      std::cerr << "USAGE: test-p0-registry-admission FIXTURES [case-name|--list|--exclude=case]\n";
      return 2;
    }
    std::filesystem::path fixtures(argv[1]);

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
    auto context = context_fixture::make(parsed.move_as_ok());
    const auto configuration = context.address;
    const tos::BlockIdExt parent_block{{tos::masterchainId, tos::shardIdAll, context.head.seqno_},
                                       td::Bits256(td::ConstBitPtr(context.head.root_.data())),
                                       td::Bits256(td::ConstBitPtr(context.head.file_.data()))};

    RegistryAdmissionInputs inputs;
    inputs.configuration_account = configuration;
    inputs.message =
        external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
    inputs.parent_block = parent_block;
    inputs.catchain_source = case_cc;
    inputs.transaction.masterchain_state = context.root;
    inputs.transaction.parent = context.head;
    inputs.transaction.chain = context.chain;
    inputs.transaction.shard = {static_cast<tos::WorkchainId>(case_wc), case_shard};
    inputs.transaction.catchain = case_cc;
    inputs.transaction.inclusion = context.head.seqno_ + 1;

    auto deferred_input = [&]() {
      Authorizations owned;
      OwnerAuth owner;
      const std::uint32_t owner_at = context.head.seqno_;
      owner.proof_.anchor_ = Anchor{owner_at, h(11), h(12), h(13)};
      owner.proof_.kind_ = 1;
      owner.proof_.proof_ = value(object_value(5, Bytes{1, 2, 3, 4}), "deferred-proof-object");
      owned.owner_.push_back(owner);
      auto encoded = value(encode(owned), "deferred-authorizations");
      auto packed = value(pack_bytes(encoded), "deferred-packed");
      vm::CellBuilder b;
      b.store_long(native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
      b.store_ref(std::move(packed)).store_ref(vm::CellBuilder().finalize());
      auto result = inputs;
      result.message =
          external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), b.finalize()));
      return result;
    };

    std::vector<Test> tests;
    auto add = [&](std::string name, std::function<void()> fn) { tests.emplace_back(std::move(name), std::move(fn)); };

    add("complete-input-produces-an-authority", [&] {
      NativeAnchorCache cache;
      auto assembled = admit_registry_message(inputs, cache);
      require(assembled.ok() && assembled.value() != nullptr, "complete-input-produces-an-authority");
      assembled.value()->host().checkpoints();
    });
    add("collator-gathering-produces-an-authority", [&] {
      NativeAnchorCache cache;
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, context.root, parent_block, parent_block, context.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, context.head.seqno_ + 1);
      require(gathered.ok(), "collator-gathering-produces-an-authority");
      auto assembled = admit_registry_message(gathered.value(), cache);
      require(assembled.ok() && assembled.value() != nullptr, "collator-gathering-produces-an-authority");
      assembled.value()->host().checkpoints();
    });
    add("wrong-catchain-source-is-refused", [&] {
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, context.root, parent_block, parent_block, context.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc ^ 1u, context.head.seqno_ + 1);
      refuses(gathered, "registry-admission-catchain-source", "wrong-catchain-source-is-refused");
    });
    add("wrong-parent-root-source-is-refused", [&] {
      auto wrong_parent = parent_block;
      const auto other_root = h(773);
      wrong_parent.root_hash = td::Bits256(td::ConstBitPtr(other_root.data()));
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, context.root, parent_block, wrong_parent, context.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, context.head.seqno_ + 1);
      refuses(gathered, "registry-admission-parent-source", "wrong-parent-root-source-is-refused");
    });
    add("wrong-parent-file-source-is-refused", [&] {
      auto wrong_parent = parent_block;
      const auto other_file = h(774);
      wrong_parent.file_hash = td::Bits256(td::ConstBitPtr(other_file.data()));
      auto gathered = gather_registry_admission_inputs(
          inputs.message, configuration, context.root, parent_block, wrong_parent, context.chain,
          {static_cast<tos::WorkchainId>(case_wc), case_shard}, case_cc, case_cc, context.head.seqno_ + 1);
      refuses(gathered, "registry-admission-parent-source", "wrong-parent-file-source-is-refused");
    });
    add("gathered-catchain-must-match-source", [&] {
      NativeAnchorCache cache;
      auto wrong = inputs;
      wrong.catchain_source ^= 1u;
      refuses(admit_registry_message(wrong, cache), "registry-admission-catchain-input",
              "gathered-catchain-must-match-source");
    });
    add("gathered-parent-root-must-match-source", [&] {
      NativeAnchorCache cache;
      auto wrong = inputs;
      const auto other_root = h(771);
      wrong.parent_block.root_hash = td::Bits256(td::ConstBitPtr(other_root.data()));
      refuses(admit_registry_message(wrong, cache), "registry-admission-parent-input",
              "gathered-parent-root-must-match-source");
    });
    add("gathered-parent-file-must-match-source", [&] {
      NativeAnchorCache cache;
      auto wrong = inputs;
      const auto other_file = h(772);
      wrong.parent_block.file_hash = td::Bits256(td::ConstBitPtr(other_file.data()));
      refuses(admit_registry_message(wrong, cache), "registry-admission-parent-input",
              "gathered-parent-file-must-match-source");
    });
    add("history-outlives-the-call-that-assembled-it", [&] {
      // The history is built inside admission and the caller never holds a
      // reference to it. Owner verification reads it during VM execution, after
      // this call has returned, so the only question that matters is whether it
      // is still there -- and the only way to ask is to read it here, where a
      // reference to a destroyed local is a read of freed memory rather than a
      // wrong answer.
      auto deferred = deferred_input();
      NativeAnchorCache resolved;
      const auto owner_at = context.head.seqno_;
      const Anchor expected{owner_at, h(11), h(12), h(13)};
      require(resolved.admit(owner_at, expected).ok(), "history-outlives-the-call-that-assembled-it");
      std::unique_ptr<NativeConfigTransaction> authority;
      {
        auto admitted = admit_registry_message(deferred, resolved);
        require(admitted.ok() && admitted.value() != nullptr, "history-outlives-the-call-that-assembled-it");
        authority = std::move(admitted.value());
      }
      auto served = authority->history().finalized_anchor(owner_at);
      require(served.ok() && served.value() == expected, "history-outlives-the-call-that-assembled-it");
    });
    add("gathered-account-must-match-parent-state", [&] {
      NativeAnchorCache cache;
      auto wrong = inputs;
      wrong.configuration_account = account(77);
      refuses(admit_registry_message(wrong, cache), "registry-admission-configuration-input",
              "gathered-account-must-match-parent-state");
    });
    add("other-account-not-admitted", [&] {
      NativeAnchorCache cache;
      auto elsewhere = inputs;
      elsewhere.message =
          external(account(2), registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
      refuses(admit_registry_message(elsewhere, cache), "registry-admission-not-configuration",
              "other-account-not-admitted");
    });
    add("non-masterchain-not-admitted", [&] {
      NativeAnchorCache cache;
      auto shard_chain = inputs;
      shard_chain.message = external(
          configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()), 0);
      refuses(admit_registry_message(shard_chain, cache), "registry-admission-not-configuration",
              "non-masterchain-not-admitted");
    });
    add("other-action-not-admitted", [&] {
      NativeAnchorCache cache;
      auto other_action = inputs;
      other_action.message = external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(),
                                                                   evidence_without_owner(), 0x43665021));
      refuses(admit_registry_message(other_action, cache), "registry-admission-not-registry",
              "other-action-not-admitted");
    });
    add("unresolved-history-defers", [&] {
      NativeAnchorCache cache;
      auto deferred = deferred_input();
      auto required = registry_message_requirements(deferred.message, deferred.transaction.inclusion);
      require(required.ok() && required.value().size() == 1, "unresolved-history-defers");
      refuses(admit_registry_message(deferred, cache), "registry-admission-deferred", "unresolved-history-defers");
    });
    add("resolved-history-admits", [&] {
      auto deferred = deferred_input();
      NativeAnchorCache resolved;
      const auto owner_at = context.head.seqno_;
      require(resolved.admit(owner_at, Anchor{owner_at, h(11), h(12), h(13)}).ok(), "resolved-history-admits");
      auto admitted = admit_registry_message(deferred, resolved);
      require(admitted.ok() && admitted.value() != nullptr, "resolved-history-admits");
    });
    add("missing-account-is-an-input-error", [&] {
      NativeAnchorCache cache;
      auto unfilled = inputs;
      unfilled.configuration_account = Hash{};
      refuses(admit_registry_message(unfilled, cache), "registry-admission-input", "missing-account-is-an-input-error");
    });
    add("requirements-are-reportable", [&] {
      auto required = registry_message_requirements(inputs.message, inputs.transaction.inclusion);
      require(required.ok() && required.value().empty(), "requirements-are-reportable");
    });

    if (argc == 3 && std::string_view(argv[2]) == "--list") {
      for (const auto& [name, _] : tests)
        std::cout << name << '\n';
      return 0;
    }
    std::string selected;
    std::string excluded;
    if (argc == 3) {
      std::string argument(argv[2]);
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
