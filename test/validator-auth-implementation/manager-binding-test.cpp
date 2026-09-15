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
using namespace p0_fixture;

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

// A minimal election cell: ordinary descriptors, no binding variants. The
// committee cases cover descriptor shapes; this file only needs a validator set
// the production unpacker accepts.
td::Ref<vm::Cell> election(unsigned count = 4) {
  vm::Dictionary list(16);
  std::uint64_t weight = 0;
  for (unsigned i = 1; i <= count; ++i) {
    vm::CellBuilder pub;
    auto key = h(10000 + i);
    pub.store_long(0x8e81278a, 32).store_bytes(td::Slice(reinterpret_cast<const char*>(key.data()), 32));
    vm::CellBuilder cell;
    cell.store_long(0x73, 8)
        .append_cellslice(vm::CellSlice(vm::NoVm{}, pub.finalize()))
        .store_long(i * 3, 64)
        .store_bytes(td::Slice(reinterpret_cast<const char*>(h(20000 + i).data()), 32));
    td::BitArray<16> index(i - 1);
    check(list.set(index.bits(), 16, td::make_ref<vm::CellSlice>(vm::NoVm{}, cell.finalize())), "list-add");
    check(tos::checked_add_validator_weight(weight, i * 3), "fixture-weight");
  }
  vm::CellBuilder root;
  root.store_long(0x12, 8)
      .store_long(0, 32)
      .store_long(10000, 32)
      .store_long(count, 16)
      .store_long(std::min(count, 3u), 16)
      .store_long(weight, 64);
  check(list.append_dict_to_bool(root), "election-list");
  return root.finalize();
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
    auto root = replace_config(replace_config(masterchain(registry, 0), 34, election()), 28,
                               catchain_selector());
    auto shard = tos::ShardIdFull(-1, tos::shardIdAll);

    // The gate is the same one native committee derivation uses, so a chain
    // cannot be refused here while native derivation would have admitted it.
    if (!native_session_binding_active(root))
      bad("active-chain-is-gated-on");
    ok("active-chain-is-gated-on");

    auto without_capability = masterchain(registry, 0, 0);
    if (native_session_binding_active(without_capability))
      bad("chain-without-capability-is-gated-off");
    ok("chain-without-capability-is-gated-off");

    if (native_session_binding_active({}))
      bad("unreadable-state-is-gated-off");
    ok("unreadable-state-is-gated-off");

    // The same path the node takes: a shard validator set computed from the
    // elected set, so the catchain sequence and member order are the node's.
    auto config = block::ConfigInfo::extract_config(
        root, tos::BlockIdExt{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0}},
        block::ConfigInfo::needValidatorSet | block::ConfigInfo::needCapabilities);
    check(config.is_ok(), "fixture-config");
    block::ValidatorSetCompute compute;
    check(compute.init(config.ok().get()).is_ok(), "fixture-compute");
    auto validator_set = compute.get_validator_set(shard, config.ok()->utime, 0);
    check(validator_set.not_null(), "fixture-validator-set");
    auto selected = validator_set->export_vector();
    check(!selected.empty(), "fixture-selected");
    auto catchain = validator_set->get_catchain_seqno();

    ManagerSessionInputs inputs;
    inputs.options_hash = h(4242);
    inputs.vertical_seqno = 0;
    inputs.key_block_seqno = 0;
    inputs.new_catchain_ids = false;

    auto matching = manager_identity(shard, selected, catchain, bits(inputs.options_hash), inputs.vertical_seqno,
                                     inputs.key_block_seqno, inputs.new_catchain_ids);
    auto agreed = native_session_identity_confirms(validator_set, shard, inputs, matching);
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
      auto refused = native_session_identity_confirms(validator_set, shard, changed, matching);
      if (!refused.ok() || refused.value())
        bad(label);
      ok(label);
    }

    // A manager identity from a different session must not be confirmed by this
    // one: that is the disagreement the binding exists to catch.
    auto foreign = manager_identity(shard, selected, catchain + 1, bits(inputs.options_hash), inputs.vertical_seqno,
                                    inputs.key_block_seqno, inputs.new_catchain_ids);
    auto stale = native_session_identity_confirms(validator_set, shard, inputs, foreign);
    if (!stale.ok() || stale.value())
      bad("foreign-identity-is-refused");
    ok("foreign-identity-is-refused");

    // A confirmation that cannot be established is an error, never a quiet yes.
    auto empty = native_session_identity_confirms(validator_set, shard, inputs, Hash{});
    if (empty.ok())
      bad("zero-identity-is-an-error");
    ok("zero-identity-is-an-error");

    auto absent = native_session_identity_confirms({}, shard, inputs, matching);
    if (absent.ok())
      bad("absent-validator-set-is-an-error");
    ok("absent-validator-set-is-an-error");

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
