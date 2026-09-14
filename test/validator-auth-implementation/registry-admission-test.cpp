// Whether a block admits a registry update.
//
// This exists because the first attempt at the collation side of this was
// written, compiled, and was dead: it set the account but never built the
// authority, so the gate that needs both was never satisfied and the
// instruction stayed unreachable. Nothing failed. A node that never admits an
// update is indistinguishable from a node on a chain that has none.
//
// So the case that matters most here is not any refusal. It is that a complete
// input actually produces an authority.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "validator/auth/cells.h"
#include "validator/auth/native-config-message.h"
#include "validator/auth/native-evidence.h"
#include "validator/auth/native-registry-admission.h"
#include "vm/boc.h"

#include "owner-fixture.h"

using namespace p0_owner_fixture;

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

void refuses(const Result<std::unique_ptr<NativeConfigTransaction>>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "assembled" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}

Hash account(unsigned n) {
  return h(500 + n);
}

// An external message addressed to one account, carrying one body.
td::Ref<vm::Cell> external(const Hash& destination, td::Ref<vm::Cell> body, std::int32_t workchain = -1) {
  vm::CellBuilder b;
  b.store_long(2, 2);  // ext_in_msg_info$10
  b.store_long(0, 2);  // src: addr_none$00
  b.store_long(2, 2);  // dest: addr_std$10
  b.store_long(0, 1);  // no anycast
  b.store_long(workchain, 8);
  b.store_bytes(td::Slice(reinterpret_cast<const char*>(destination.data()), destination.size()));
  b.store_long(0, 4);  // import_fee
  b.store_long(0, 1);  // body in reference
  b.store_ref(body);
  return b.finalize();
}

// A registry message body in exactly the shape the contract parses.
td::Ref<vm::Cell> registry_body(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence,
                                std::uint32_t action = native_registry_action) {
  vm::CellBuilder b;
  b.store_zeroes(512);
  b.store_long(action, 32);
  b.store_long(1, 32);
  b.store_long(2, 32);
  b.store_ref(std::move(update));
  b.store_ref(std::move(evidence));
  return b.finalize();
}

// Built through the real encoder and to the exact shape the parser requires:
// tag, version, an absent-optional flag, then the encoded authorizations and an
// empty header. A stand-in cell with only the tag is refused for its shape, and
// a case built on one proves nothing about admission.
td::Ref<vm::Cell> evidence_without_owner() {
  Authorizations none;
  auto encoded = value(encode(none), "evidence-authorizations");
  auto packed = value(pack_bytes(encoded), "evidence-packed");
  vm::CellBuilder b;
  b.store_long(native_evidence_tag, 32);
  b.store_long(1, 16);
  b.store_long(0, 1);
  b.store_ref(std::move(packed));
  b.store_ref(vm::CellBuilder().finalize());
  return b.finalize();
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 2, "arguments");
    std::filesystem::path fixtures(argv[1]);

    // One accepted committee case supplies a state that really derives, with
    // the anchor and chain context it was derived against.
    std::uint32_t case_wc = 0, case_cc = 0;
    std::uint64_t case_shard = 0;
    std::string label;
    bool accepted = false;
    std::filesystem::path selected;
    for (unsigned n = 0; n < 64 && selected.empty(); ++n) {
      auto candidate = fixtures / std::to_string(n);
      if (!std::filesystem::exists(candidate.string() + ".case"))
        continue;
      std::ifstream(candidate.string() + ".case") >> case_wc >> case_shard >> case_cc >> accepted >> label;
      if (accepted)
        selected = candidate;
    }
    check(!selected.empty(), "no-accepted-committee-case");

    auto anchor = value(decode<Anchor>(read(selected.string() + ".anchor")), "anchor");
    auto chain_raw = read(selected.string() + ".chain");
    Reader reader(chain_raw);
    ChainContext chain;
    reader.integer(chain.network);
    reader.hash(chain.genesis_root);
    reader.hash(chain.genesis_file);
    reader.hash(chain.chain_domain);
    check(reader.ok(), "chain");
    auto raw_state = read(selected.string() + ".boc");
    auto parsed = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(raw_state.data()), raw_state.size()));
    check(parsed.is_ok(), "state-boc");
    auto state = parsed.move_as_ok();

    // Which account is the configuration account is a fact about the parent
    // state, and a caller reads it with declared_configuration_account(). These
    // fixtures carry no configuration parameter, so the case supplies one
    // directly; what is under test here is admission, not that extraction.
    const auto configuration = account(1);
    NativeAnchorCache cache;

    RegistryAdmissionInputs inputs;
    inputs.configuration_account = configuration;
    inputs.message =
        external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
    inputs.transaction.masterchain_state = state;
    inputs.transaction.parent = anchor;
    inputs.transaction.chain = chain;
    inputs.transaction.shard = {static_cast<tos::WorkchainId>(case_wc), case_shard};
    inputs.transaction.catchain = case_cc;
    inputs.transaction.inclusion = anchor.seqno_ + 1;

    // The case the dead first attempt would have failed: a complete input has
    // to produce an authority, not merely fail to refuse.
    auto assembled = admit_registry_message(inputs, cache);
    expect(assembled.ok(), "complete-input-produces-an-authority");
    expect(assembled.value() != nullptr, "complete-input-produces-an-authority");
    // And the authority has to be usable, which is what the gate downstream
    // actually requires.
    assembled.value()->host().checkpoints();
    ok("complete-input-produces-an-authority");

    // A message to another account is not this, and is not an error either.
    auto elsewhere = inputs;
    elsewhere.message =
        external(account(2), registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()));
    refuses(admit_registry_message(elsewhere, cache), "registry-admission-not-configuration",
            "other-account-not-admitted");

    auto shard_chain = inputs;
    shard_chain.message = external(
        configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), evidence_without_owner()), 0);
    refuses(admit_registry_message(shard_chain, cache), "registry-admission-not-configuration",
            "non-masterchain-not-admitted");

    auto other_action = inputs;
    other_action.message = external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(),
                                                                 evidence_without_owner(), 0x43665021));
    refuses(admit_registry_message(other_action, cache), "registry-admission-not-registry",
            "other-action-not-admitted");

    // The deferral this whole arrangement is built on: an update naming history
    // the node has not resolved is not admitted, and is not an error either.
    {
      Authorizations owned;
      OwnerAuth owner;
      const std::uint32_t owner_at = anchor.seqno_;  // strictly below inclusion, and never wraps
      owner.proof_.anchor_ = Anchor{owner_at, h(11), h(12), h(13)};
      owner.proof_.kind_ = 1;
      // The proof carries a real object, because the evidence parser validates
      // it before anything else is looked at; an empty one is refused for its
      // kind and the case would be about that instead of about deferral.
      owner.proof_.proof_ = value(object_value(5, Bytes{1, 2, 3, 4}), "deferred-proof-object");
      owned.owner_.push_back(owner);
      auto encoded = value(encode(owned), "deferred-authorizations");
      auto packed = value(pack_bytes(encoded), "deferred-packed");
      vm::CellBuilder b;
      b.store_long(native_evidence_tag, 32);
      b.store_long(1, 16);
      b.store_long(0, 1);
      b.store_ref(std::move(packed));
      b.store_ref(vm::CellBuilder().finalize());

      auto deferred = inputs;
      deferred.message =
          external(configuration, registry_body(vm::CellBuilder().store_long(1, 8).finalize(), b.finalize()));
      auto required_now = registry_message_requirements(deferred.message, deferred.transaction.inclusion);
      expect(required_now.ok() && required_now.value().size() == 1, "unresolved-history-defers");
      refuses(admit_registry_message(deferred, cache), "registry-admission-deferred", "unresolved-history-defers");

      // Once resolved, the same message is admitted; the deferral was about the
      // node's knowledge, not about the update.
      NativeAnchorCache resolved;
      expect(resolved.admit(owner_at, Anchor{owner_at, h(11), h(12), h(13)}).ok(), "resolved-history-admits");
      auto again = admit_registry_message(deferred, resolved);
      if (!again.ok()) {
        std::cerr << "DETAIL resolved-history-admits actual=" << again.error().code << '\n';
        throw std::runtime_error("resolved-history-admits");
      }
      expect(again.value() != nullptr, "resolved-history-admits");
      ok("resolved-history-admits");
    }

    // A caller that never filled in the account would otherwise be told its
    // message is for someone else, which is the same answer for a different
    // reason and reads as a chain with no update in flight.
    auto unfilled = inputs;
    unfilled.configuration_account = Hash{};
    refuses(admit_registry_message(unfilled, cache), "registry-admission-input", "missing-account-is-an-input-error");

    // Requirements are reportable without admitting anything, which is what a
    // caller needs after a deferral.
    auto required = registry_message_requirements(inputs.message, inputs.transaction.inclusion);
    expect(required.ok() && required.value().empty(), "requirements-are-reportable");
    ok("requirements-are-reportable");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
