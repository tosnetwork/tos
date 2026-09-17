// Bind the manager's session identity to the producer's, and prove the bind bites.
//
// The manager may not run a session under an identity the producer does not
// confirm. Two derivations of one fact, each passing its own tests, is the
// failure this repository keeps producing; the confirmation is what stops it.
//
// This exercises the decision the manager's insertion makes. It does not run the
// manager, an actor, or a chain: it establishes that the logic refuses what it
// must, not that the insertion executes.
#include <filesystem>
#include <fstream>
#include <iostream>

#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "block/mc-config.h"
#include "block/validator-set.h"
#include "tos/quorum.h"
#include "keys/keys.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator/auth/manager-session-binding.h"

#include "committee-fixture.h"

using namespace tos::auth;
using namespace auth_fixture;

namespace {
unsigned count = 0;

void ok(const char* label) {
  ++count;
  std::cout << "CASE_PASS " << label << '\n';
}

[[noreturn]] void bad(const char* label) {
  std::cerr << "ASSERTION: " << label << '\n';
  std::exit(1);
}

// The manager's own construction, transcribed. Keeping it separate from the
// producer is the point: if one changes and the other does not, the cases that
// require agreement fail here rather than in a running consensus session.
Hash manager_identity(tos::ShardIdFull shard, const std::vector<tos::ValidatorDescr>& members, std::uint32_t catchain,
                      td::Bits256 options, std::uint32_t vertical, std::uint32_t key_block, bool new_catchain_ids) {
  std::vector<tos::tl_object_ptr<tos::tos_api::validator_groupMember>> encoded;
  for (const auto& member : members) {
    auto key = tos::PublicKey{tos::pubkeys::Ed25519{member.key}};
    encoded.push_back(tos::create_tl_object<tos::tos_api::validator_groupMember>(
        key.compute_short_id().bits256_value(), member.addr, member.weight));
  }
  td::Bits256 value;
  if (!new_catchain_ids) {
    if (vertical == 0)
      value = tos::create_hash_tl_object<tos::tos_api::validator_group>(shard.workchain, shard.shard, catchain,
                                                                       options, std::move(encoded));
    else
      value = tos::create_hash_tl_object<tos::tos_api::validator_groupEx>(shard.workchain, shard.shard, vertical,
                                                                         catchain, options, std::move(encoded));
  } else {
    value = tos::create_hash_tl_object<tos::tos_api::validator_groupNew>(
        shard.workchain, shard.shard, vertical, key_block, catchain, options, std::move(encoded));
  }
  Hash out{};
  auto raw = value.as_slice();
  std::copy(raw.ubegin(), raw.uend(), out.begin());
  return out;
}

td::Bits256 bits(const Hash& value) {
  td::Bits256 out;
  out.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(value.data()), value.size()));
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    auto registry = state(4);
    // The shared fixture, not a second election built here. The local copy this
    // file used to carry named bindings no registry had ever issued, which is
    // why its accepted cases passed while the committee those very sets would
    // run under could not be derived at all.
    //
    // The selector shuffles, and that is load-bearing: without it the selection
    // does not depend on the catchain sequence, so a committee derived for
    // another session would seat the same members and nothing here could tell
    // the difference.
    auto root = chain_state(registry, 0, true);
    auto shard = tos::ShardIdFull(-1, tos::shardIdAll);
    // What the node establishes for itself: its own applied masterchain block
    // as the anchor, and the chain context it read from its own zero state.
    auto head = anchor(root, registry.coordinate());
    ChainContext chain{-239, h(6002), h(6003), registry.chain_domain()};

    // The gate is the same one native committee derivation uses, so a chain
    // cannot be refused here while native derivation would have admitted it.
    if (!native_session_binding_active(root))
      bad("active-chain-is-gated-on");
    ok("active-chain-is-gated-on");

    auto without_capability = masterchain(registry, registry.coordinate(), 0);
    if (native_session_binding_active(without_capability))
      bad("chain-without-capability-is-gated-off");
    ok("chain-without-capability-is-gated-off");

    if (native_session_binding_active({}))
      bad("unreadable-state-is-gated-off");
    ok("unreadable-state-is-gated-off");

    ManagerSessionInputs inputs;
    inputs.options_hash = h(4242);
    inputs.vertical_seqno = 0;
    inputs.key_block_seqno = 0;
    inputs.new_catchain_ids = false;

    // The same path the node takes: a shard validator set computed from the
    // elected set, so the catchain sequence and member order are the node's,
    // and the identity the manager would build from it. Every case below needs
    // both; three copies of this had already accumulated in this file.
    auto session_for = [&](const td::Ref<vm::Cell>& state_root, const ManagerSessionInputs& with) {
      auto config = block::ConfigInfo::extract_config(
          state_root,
          tos::BlockIdExt{tos::BlockId{tos::masterchainId, tos::shardIdAll, registry.coordinate()}},
          block::ConfigInfo::needValidatorSet | block::ConfigInfo::needCapabilities);
      check(config.is_ok(), "fixture-config");
      block::ValidatorSetCompute compute;
      check(compute.init(config.ok().get()).is_ok(), "fixture-compute");
      // A non-zero catchain sequence on purpose. With zero, a committee derived
      // for the wrong session would be indistinguishable from the right one,
      // because the wrong number and the fixture's number would be the same.
      auto set = compute.get_validator_set(shard, config.ok()->utime, 7);
      check(set.not_null(), "fixture-validator-set");
      check(!set->export_vector().empty(), "fixture-selected");
      auto identity =
          manager_identity(shard, set->export_vector(), set->get_catchain_seqno(), bits(with.options_hash),
                           with.vertical_seqno, with.key_block_seqno, with.new_catchain_ids);
      return std::pair<td::Ref<block::ValidatorSet>, Hash>{set, identity};
    };

    auto [validator_set, matching] = session_for(root, inputs);
    auto selected = validator_set->export_vector();
    auto catchain = validator_set->get_catchain_seqno();
    auto agreed = native_session_identity_confirms(root, head, chain, validator_set, shard, inputs, matching);
    if (!agreed.ok() || !agreed.value())
      bad("manager-identity-is-confirmed");
    ok("manager-identity-is-confirmed");

    // Every input the manager owns has to reach the confirmation. A field the
    // producer ignored would let a session run under a name the chain never
    // committed, and the confirmation would still say yes.
    for (const auto& [label, changed] : std::vector<std::pair<const char*, ManagerSessionInputs>>{
             {"different-options-hash-is-refused", [&] { auto c = inputs; c.options_hash = h(9999); return c; }()},
             {"different-vertical-seqno-is-refused", [&] { auto c = inputs; c.vertical_seqno = 3; return c; }()},
             {"different-catchain-form-is-refused",
              [&] { auto c = inputs; c.new_catchain_ids = true; c.key_block_seqno = 7; return c; }()}}) {
      auto refused = native_session_identity_confirms(root, head, chain, validator_set, shard, changed, matching);
      if (!refused.ok() || refused.value())
        bad(label);
      ok(label);
    }

    // A manager identity from a different session must not be confirmed by this
    // one: that is the disagreement the binding exists to catch.
    auto foreign = manager_identity(shard, selected, catchain + 1, bits(inputs.options_hash), inputs.vertical_seqno,
                                    inputs.key_block_seqno, inputs.new_catchain_ids);
    auto stale = native_session_identity_confirms(root, head, chain, validator_set, shard, inputs, foreign);
    if (!stale.ok() || stale.value())
      bad("foreign-identity-is-refused");
    ok("foreign-identity-is-refused");

    // A confirmation that cannot be established is an error, never a quiet yes.
    auto empty = native_session_identity_confirms(root, head, chain, validator_set, shard, inputs, Hash{});
    if (empty.ok())
      bad("zero-identity-is-an-error");
    ok("zero-identity-is-an-error");

    auto absent = native_session_identity_confirms(root, head, chain, {}, shard, inputs, matching);
    if (absent.ok())
      bad("absent-validator-set-is-an-error");
    ok("absent-validator-set-is-an-error");

    // A set whose members are not bound at all is refused before any identity
    // is derived.
    //
    // The identity is a hash of keys, addresses and weights, so it agrees
    // whether or not the members are bound. Without this, the manager could
    // create a validator group under a roster that committee derivation would
    // have refused with election-binding-required, and consensus receives
    // whatever the manager hands it. The confirmation has to mean the set was
    // admissible, not merely that two derivations of its identity agree.
    {
      auto unbound_root = chain_state(registry, 1, true);
      auto [unbound_set, unbound_identity] = session_for(unbound_root, inputs);
      auto refused = native_session_identity_confirms(unbound_root, anchor(unbound_root, registry.coordinate()),
                                                      chain, unbound_set, shard, inputs, unbound_identity);
      // Named, not merely refused. A negative case that accepts any error is
      // satisfied by a fixture that never reached the rule under test, which is
      // exactly what a refusal like this looks like from the outside.
      if (refused.ok() || refused.error().code != "election-binding-required")
        bad("an-unbound-election-is-refused");
      ok("an-unbound-election-is-refused");

      // The same roster, offered against a state that does admit. Every other
      // rule is about the state and reaches the roster only through it, so a
      // roster that did not come from this state has to be refused on its own
      // terms -- and it is, because it is not the roster derivation selects
      // from this state.
      auto foreign_roster =
          native_session_identity_confirms(root, head, chain, unbound_set, shard, inputs, unbound_identity);
      if (foreign_roster.ok() || foreign_roster.error().code != "manager-session-roster")
        bad("a-roster-from-another-state-is-refused");
      ok("a-roster-from-another-state-is-refused");
    }

    // Two members naming one identity is refused for the same reason: a
    // committee cannot say which member a duplicate is, so derivation refuses
    // it, and a roster consensus runs under must be one derivation admits.
    {
      auto shared_root = chain_state(registry, 12, true);
      auto [shared_set, shared_identity] = session_for(shared_root, inputs);
      auto duplicated = native_session_identity_confirms(shared_root, anchor(shared_root, registry.coordinate()),
                                                         chain, shared_set, shard, inputs, shared_identity);
      if (duplicated.ok() || duplicated.error().code != "election-duplicate")
        bad("a-duplicated-identity-is-refused");
      ok("a-duplicated-identity-is-refused");
    }

    // The rules this confirmation did not have at all until it derived the
    // committee instead of describing it: everything the registry decides.
    //
    // Each state below passes every rule the state settles on its own. The
    // bindings are present, distinct and well shaped, the counts and the
    // election window are in range, and the identity agrees -- it is a hash of
    // keys, addresses and weights, so it agrees whether or not the registry
    // ever issued what the set claims. The old confirmation said yes to all of
    // them, and the committee those sessions would have run under could not be
    // derived at all: the chain would not have continued unauthenticated, it
    // would have stalled, with the manager seating a group and derivation
    // refusing the same set.
    {
      // A member whose identity the registry knows, carrying a stake the
      // registry never issued for it.
      auto substituted = chain_state(registry, 10, true);
      auto [substituted_set, substituted_identity] = session_for(substituted, inputs);
      auto refused = native_session_identity_confirms(substituted, anchor(substituted, registry.coordinate()),
                                                      chain, substituted_set, shard, inputs, substituted_identity);
      if (refused.ok() || refused.error().code != "election-registry-binding")
        bad("a-binding-the-registry-never-issued-is-refused");
      ok("a-binding-the-registry-never-issued-is-refused");

      // And the plainest form: a registry that has never heard of any of them.
      auto strangers = state(3);
      auto swapped = replace_config(root, 46, value(strangers.encode_cell(), "fixture-other-registry"));
      auto unknown = native_session_identity_confirms(swapped, anchor(swapped, registry.coordinate()), chain,
                                                      validator_set, shard, inputs, matching);
      if (unknown.ok() || unknown.error().code != "election-registry-binding")
        bad("a-registry-that-knows-no-member-is-refused");
      ok("a-registry-that-knows-no-member-is-refused");
    }

    // The anchor and the context are inputs to that derivation, so both have to
    // be ones the caller established rather than ones it accepted. An anchor
    // naming a different state would file the registry read under a coordinate
    // this state never had; a context from another chain would let the domain
    // check pass against a name this node does not believe.
    {
      auto elsewhere = head;
      elsewhere.state_[0] ^= 1;
      auto refused =
          native_session_identity_confirms(root, elsewhere, chain, validator_set, shard, inputs, matching);
      if (refused.ok() || refused.error().code != "committee-anchor")
        bad("an-anchor-naming-another-state-is-refused");
      ok("an-anchor-naming-another-state-is-refused");

      auto alien = chain;
      alien.chain_domain = h(31337);
      auto refused_domain =
          native_session_identity_confirms(root, head, alien, validator_set, shard, inputs, matching);
      if (refused_domain.ok() || refused_domain.error().code != "chain-domain")
        bad("a-context-from-another-chain-is-refused");
      ok("a-context-from-another-chain-is-refused");
    }

    // A rule the confirmation did not have until it took derivation's own. The
    // ceiling on how many validators may be elected is decided from the state
    // and not from the roster, so the identity -- a hash of keys, addresses and
    // weights -- agrees exactly as it does for the accepted case above. Without
    // the shared admission the manager would confirm a session on a chain
    // derivation refuses outright, and consensus would receive the group.
    {
      vm::CellBuilder beyond;
      beyond.store_long(401, 16).store_long(100, 16).store_long(1, 16);
      auto beyond_root = replace_config(root, 16, beyond.finalize());
      auto refused = native_session_identity_confirms(beyond_root, anchor(beyond_root, registry.coordinate()), chain,
                                                      validator_set, shard, inputs, matching);
      if (refused.ok() || refused.error().code != "validator-count")
        bad("a-state-beyond-the-validator-ceiling-is-refused");
      ok("a-state-beyond-the-validator-ceiling-is-refused");
    }

    // And the same state with the ceiling it actually has is confirmed, so the
    // case above is about the ceiling rather than about replacing a parameter.
    {
      vm::CellBuilder within;
      within.store_long(400, 16).store_long(100, 16).store_long(1, 16);
      auto within_root = replace_config(root, 16, within.finalize());
      auto agreed = native_session_identity_confirms(within_root, anchor(within_root, registry.coordinate()), chain,
                                                    validator_set, shard, inputs, matching);
      if (!agreed.ok() || !agreed.value())
        bad("a-state-within-the-validator-ceiling-is-confirmed");
      ok("a-state-within-the-validator-ceiling-is-confirmed");
    }

    if (argc == 2) {
      std::filesystem::path out(argv[1]);
      std::filesystem::create_directories(out);
      std::ofstream(out / "complete") << count << '\n';
    }
    std::cout << "SUMMARY cases=" << count << " passed=" << count << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
