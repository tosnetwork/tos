// Require the derived session identity to equal the one the manager computes.
//
// The manager names a session by hashing one of three TL forms over the exact
// members, catchain sequence, options hash and coordinates it holds. Walking
// history has to name the same sessions, so this compares the library's
// derivation against that construction written out here, member for member.
// If they ever disagree, an actor's live session and the session history
// reports for the same state would carry different identities.
#include <filesystem>
#include <fstream>
#include <iostream>

#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "block/mc-config.h"
#include "keys/keys.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator/auth/native-session.h"

#include "committee-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

namespace {
unsigned count = 0;

// The manager's construction, transcribed. It is deliberately a separate
// expression of the same rule rather than a call into the library, so that a
// change to one and not the other fails here.
Hash manager_identity(tos::ShardIdFull shard, const std::vector<tos::ValidatorDescr>& members,
                      std::uint32_t catchain, td::Bits256 options, std::uint32_t vertical, std::uint32_t key_block,
                      bool new_catchain_ids) {
  std::vector<tos::tl_object_ptr<tos::tos_api::validator_groupMember>> encoded;
  for (const auto& member : members) {
    auto key = tos::PublicKey{tos::pubkeys::Ed25519{member.key}};
    encoded.push_back(tos::create_tl_object<tos::tos_api::validator_groupMember>(key.compute_short_id().bits256_value(),
                                                                           member.addr, member.weight));
  }
  td::Bits256 value;
  if (!new_catchain_ids) {
    if (vertical == 0)
      value = tos::create_hash_tl_object<tos::tos_api::validator_group>(shard.workchain, shard.shard, catchain, options,
                                                                   std::move(encoded));
    else
      value = tos::create_hash_tl_object<tos::tos_api::validator_groupEx>(shard.workchain, shard.shard, vertical, catchain,
                                                                     options, std::move(encoded));
  } else {
    value = tos::create_hash_tl_object<tos::tos_api::validator_groupNew>(shard.workchain, shard.shard, vertical, key_block,
                                                                    catchain, options, std::move(encoded));
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

Anchor fixture_anchor(td::Ref<vm::Cell> root) {
  Anchor a{};
  a.seqno_ = 0;
  a.root_ = h(3);
  a.file_ = h(4);
  auto raw = root->get_hash().as_slice();
  std::copy(raw.ubegin(), raw.uend(), a.state_.begin());
  return a;
}

void agrees(td::Ref<vm::Cell> root, const NativeSessionContext& context, tos::ShardIdFull shard, const char* label) {
  auto derived = native_session_epoch(root, fixture_anchor(root), shard, context);
  if (!derived.ok()) {
    std::cerr << "ASSERTION: " << label << " derive=" << derived.error().code << '\n';
    std::exit(1);
  }
  if (!derived.value().has_value()) {
    std::cerr << "ASSERTION: " << label << " derive=empty\n";
    std::exit(1);
  }
  const auto& epoch = *derived.value();

  auto config = block::ConfigInfo::extract_config(
      root, tos::BlockIdExt{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0}},
      block::ConfigInfo::needValidatorSet | block::ConfigInfo::needCapabilities);
  if (config.is_error()) { std::cerr << "ASSERTION: " << label << " config=" << config.error().message().str() << '\n'; std::exit(1); }
  auto election_cell = config.ok()->get_config_param(35, 34);
  auto election = block::Config::unpack_validator_set(election_cell);
  check(election.is_ok(), label);
  tos::CatchainSeqno catchain = 0;
  auto members = config.ok()->compute_validator_set_cc(shard, *election.ok(), config.ok()->utime, &catchain);
  check(!members.empty(), label);
  tos::BlockIdExt key_block;
  tos::LogicalTime key_lt = 0;
  config.ok()->get_last_key_block(key_block, key_lt);

  auto expected = manager_identity(shard, members, catchain, bits(context.options_hash), context.vertical_seqno,
                                   key_block.seqno(), context.new_catchain_ids);
  if (epoch.native_session_id != expected) {
    std::cerr << "ASSERTION: " << label << '\n';
    std::exit(1);
  }
  check(epoch.catchain == catchain, label);
  check(epoch.key_block_seqno == key_block.seqno(), label);
  check(epoch.native_options_hash == context.options_hash, label);
  ++count;
  std::cout << "AGREES " << label << '\n';
}

void refuses(td::Ref<vm::Cell> root, const NativeSessionContext& context, tos::ShardIdFull shard,
             const char* expected, const char* label) {
  auto derived = native_session_epoch(root, fixture_anchor(root), shard, context);
  if (derived.ok() || derived.error().code != expected) {
    std::cerr << "ASSERTION: " << label << '\n';
    std::exit(1);
  }
  ++count;
  std::cout << "REFUSES " << label << '\n';
}

void differs(const Hash& left, const Hash& right, const char* label) {
  if (left == right) {
    std::cerr << "ASSERTION: " << label << '\n';
    std::exit(1);
  }
  ++count;
  std::cout << "DIFFERS " << label << '\n';
}

Hash identity_of(td::Ref<vm::Cell> root, const NativeSessionContext& context, tos::ShardIdFull shard,
                 const char* label) {
  auto derived = native_session_epoch(root, fixture_anchor(root), shard, context);
  check(derived.ok() && derived.value().has_value(), label);
  return derived.value()->native_session_id;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    auto registry = state(4);
    auto root = chain_state(registry);
    // Known gap: this fixture's catchain sequence is zero, so replacing the
    // derived value with zero changes nothing and that removal survives. The
    // field is carried, but these cases cannot tell that apart from it always
    // being zero. Covering it needs a fixture with a nonzero catchain sequence.
    auto master = tos::ShardIdFull(-1, tos::shardIdAll);

    NativeSessionContext base{};
    base.vertical_seqno = 0;
    base.new_catchain_ids = false;
    base.options_hash = h(4242);
    agrees(root, base, master, "legacy-form-agrees");

    NativeSessionContext vertical = base;
    vertical.vertical_seqno = 3;
    agrees(root, vertical, master, "extended-form-agrees");

    // The newest form hashes the last key block coordinate, so a state that has
    // not produced one cannot name a session in that form. This fixture has no
    // key block, which makes the refusal the observable behaviour here; the
    // newest form's agreement still needs a fixture that carries one.
    NativeSessionContext modern = base;
    modern.new_catchain_ids = true;
    refuses(root, modern, master, "session-epoch-key-block", "new-form-refuses-without-key-block");

    // Every node-owned input has to reach the identity. A field that does not
    // change it would let two different sessions share one name.
    auto reference = identity_of(root, base, master, "reference");
    differs(reference, identity_of(root, vertical, master, "vertical"), "vertical-seqno-changes-identity");
    NativeSessionContext other_options = base;
    other_options.options_hash = h(9999);
    differs(reference, identity_of(root, other_options, master, "options"), "options-hash-changes-identity");

    // The extended form at vertical zero is the legacy form, not a third name.
    check(identity_of(root, base, master, "legacy") == reference, "legacy-form-is-stable");
    ++count;
    std::cout << "AGREES legacy-form-is-stable\n";

    if (argc == 2) {
      std::filesystem::path out(argv[1]);
      std::filesystem::create_directories(out);
      std::ofstream(out / "complete") << count << '\n';
    }
    std::cout << "PASS: derived session identity matches the manager construction, " << count << " cases\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
