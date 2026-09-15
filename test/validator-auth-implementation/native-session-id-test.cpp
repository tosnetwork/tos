#include "auto/tl/tos_api.h"
#include "keys/keys.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/auth/native-session-id.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace tos;
using namespace tos::auth;

namespace {
Hash h(std::uint8_t byte) {
  Hash result{};
  result.fill(byte);
  return result;
}
td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}
Hash hash(td::Slice value) {
  Hash result{};
  if (value.size() == result.size())
    std::copy(value.ubegin(), value.uend(), result.begin());
  return result;
}
void check(bool condition, const char* label) {
  if (!condition)
    throw std::runtime_error(label);
}
td::Ref<block::ValidatorSet> validator_set() {
  std::vector<ValidatorDescr> nodes;
  nodes.emplace_back(Ed25519_PublicKey{bits(h(11))}, 5, bits(h(21)));
  nodes.emplace_back(Ed25519_PublicKey{bits(h(12))}, 7, bits(h(22)));
  nodes.emplace_back(Ed25519_PublicKey{bits(h(13))}, 9, td::Bits256::zero());
  return td::make_ref<block::ValidatorSet>(19, ShardIdFull{masterchainId, shardIdAll}, std::move(nodes));
}
NativeSessionIdInput input(NativeSessionIdForm form) {
  return {h(31), masterchainId, shardIdAll,
          form == NativeSessionIdForm::group ? 0u : 17u, 41u, form};
}
const char* form_label(NativeSessionIdForm form) {
  switch (form) {
    case NativeSessionIdForm::group:
      return "native-session-group";
    case NativeSessionIdForm::group_ex:
      return "native-session-group-ex";
    case NativeSessionIdForm::group_new:
      return "native-session-group-new";
  }
  return "native-session-form";
}
Hash manager_oracle(td::Ref<block::ValidatorSet> set,
                    const NativeSessionIdInput& source) {
  std::vector<tl_object_ptr<tos_api::validator_groupMember>> members;
  for (const auto& validator : set->export_vector()) {
    auto public_key = PublicKey{pubkeys::Ed25519{validator.key}};
    members.push_back(create_tl_object<tos_api::validator_groupMember>(
        public_key.compute_short_id().bits256_value(), validator.addr,
        validator.weight));
  }
  auto options = bits(source.native_options_hash);
  switch (source.form) {
    case NativeSessionIdForm::group:
      return hash(create_hash_tl_object<tos_api::validator_group>(
                      source.workchain, source.shard,
                      set->get_catchain_seqno(), options, std::move(members))
                      .as_slice());
    case NativeSessionIdForm::group_ex:
      return hash(create_hash_tl_object<tos_api::validator_groupEx>(
                      source.workchain, source.shard,
                      source.maximal_vertical_seqno,
                      set->get_catchain_seqno(), options, std::move(members))
                      .as_slice());
    case NativeSessionIdForm::group_new:
      return hash(create_hash_tl_object<tos_api::validator_groupNew>(
                      source.workchain, source.shard,
                      source.maximal_vertical_seqno,
                      source.last_key_block_seqno,
                      set->get_catchain_seqno(), options, std::move(members))
                      .as_slice());
  }
  return {};
}
NativeSessionIdentity manager_identity_oracle(
    td::Ref<block::ValidatorSet> set, const NativeSessionIdInput& source) {
  std::uint32_t vertical = source.maximal_vertical_seqno;
  std::uint32_t key_block =
      source.form == NativeSessionIdForm::group_new ? source.last_key_block_seqno : 0;
  if (source.form == NativeSessionIdForm::group)
    vertical = 0;
  return {manager_oracle(set, source), source.native_options_hash,
          source.workchain, source.shard, set->get_catchain_seqno(), vertical,
          key_block, source.form};
}
}  // namespace

int main() {
  try {
    auto set = validator_set();
    unsigned count = 0;

    auto new_source = input(NativeSessionIdForm::group_new);
    auto new_identity = derive_native_session_identity(set, new_source);
    check(new_identity.ok() && new_identity.value().catchain == 19,
          "native-session-catchain");
    ++count;

    for (auto form : {NativeSessionIdForm::group,
                      NativeSessionIdForm::group_ex,
                      NativeSessionIdForm::group_new}) {
      auto source = input(form);
      auto actual = derive_native_session_identity(set, source);
      check(actual.ok(), "native-session-derive");
      check(actual.value() == manager_identity_oracle(set, source),
            form_label(form));
      ++count;
    }

    auto legacy_a = input(NativeSessionIdForm::group_ex);
    auto legacy_b = legacy_a;
    legacy_b.last_key_block_seqno = 99;
    auto legacy_left = derive_native_session_identity(set, legacy_a);
    auto legacy_right = derive_native_session_identity(set, legacy_b);
    check(legacy_left.ok() && legacy_right.ok() &&
              legacy_left.value().key_block_seqno == 0 &&
              legacy_left.value().native_session_id ==
                  legacy_right.value().native_session_id,
          "native-session-legacy-key-normalization");
    ++count;

    auto changed_options = new_source;
    changed_options.native_options_hash = h(32);
    auto changed = derive_native_session_identity(set, changed_options);
    check(changed.ok() &&
              changed.value().native_session_id !=
                  new_identity.value().native_session_id,
          "native-session-options");
    ++count;

    auto changed_vertical = new_source;
    changed_vertical.maximal_vertical_seqno = 18;
    changed = derive_native_session_identity(set, changed_vertical);
    check(changed.ok() &&
              changed.value().native_session_id !=
                  new_identity.value().native_session_id,
          "native-session-vertical");
    ++count;

    auto changed_key = new_source;
    changed_key.last_key_block_seqno = 42;
    changed = derive_native_session_identity(set, changed_key);
    check(changed.ok() &&
              changed.value().native_session_id !=
                  new_identity.value().native_session_id,
          "native-session-key-block");
    ++count;

    auto wrong_shard = new_source;
    wrong_shard.shard ^= std::uint64_t{1} << 62;
    auto mismatch = derive_native_session_identity(set, wrong_shard);
    check(!mismatch.ok() && mismatch.error().code == "native-session-shard-binding",
          "native-session-shard-binding");
    ++count;

    std::cout << "PASS: native session identity " << count << " cases\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
