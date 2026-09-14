#include <algorithm>

#include "auto/tl/tos_api.h"
#include "keys/keys.hpp"
#include "tos/tos-tl.hpp"

#include "native-session-id.h"

namespace tos::auth {
namespace {
Hash hash(td::Slice raw) {
  Hash result{};
  if (raw.size() == result.size())
    std::copy(raw.ubegin(), raw.uend(), result.begin());
  return result;
}
td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}
}  // namespace

Result<NativeSessionIdentity> derive_native_session_identity(
    td::Ref<block::ValidatorSet> validator_set,
    const NativeSessionIdInput& input) {
  if (validator_set.is_null())
    return Error{"native-session-validator-set"};
  auto selected_shard = validator_set->get_shard();
  if (selected_shard.workchain != input.workchain || selected_shard.shard != input.shard)
    return Error{"native-session-shard-binding"};

  std::vector<NativeSessionIdMember> members;
  auto validators = validator_set->export_vector();
  members.reserve(validators.size());
  for (const auto& validator : validators) {
    auto public_key = PublicKey{pubkeys::Ed25519{validator.key}};
    members.push_back({hash(public_key.compute_short_id().bits256_value().as_slice()),
                       hash(validator.addr.as_slice()), validator.weight});
  }

  NativeSessionIdEncoder encoder = [](
      NativeSessionIdForm form, std::int32_t workchain, std::uint64_t shard,
      std::uint32_t vertical, std::uint32_t key_block,
      std::uint32_t catchain, const Hash& options,
      std::span<const NativeSessionIdMember> source) -> Result<Hash> {
    std::vector<tl_object_ptr<tos_api::validator_groupMember>> encoded;
    encoded.reserve(source.size());
    for (const auto& member : source) {
      encoded.push_back(create_tl_object<tos_api::validator_groupMember>(
          bits(member.short_id), bits(member.adnl_id), member.weight));
    }
    switch (form) {
      case NativeSessionIdForm::group:
        return hash(create_hash_tl_object<tos_api::validator_group>(
                        workchain, shard, catchain, bits(options),
                        std::move(encoded))
                        .as_slice());
      case NativeSessionIdForm::group_ex:
        return hash(create_hash_tl_object<tos_api::validator_groupEx>(
                        workchain, shard, vertical, catchain, bits(options),
                        std::move(encoded))
                        .as_slice());
      case NativeSessionIdForm::group_new:
        return hash(create_hash_tl_object<tos_api::validator_groupNew>(
                        workchain, shard, vertical, key_block, catchain,
                        bits(options), std::move(encoded))
                        .as_slice());
    }
    return Error{"native-session-form"};
  };

  return derive_native_session_identity_core(
      input, validator_set->get_catchain_seqno(), members, encoder);
}

}  // namespace tos::auth
