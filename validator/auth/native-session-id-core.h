#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <utility>
#include <vector>

#include "codec.h"

namespace tos::auth {

enum class NativeSessionIdForm : std::uint8_t {
  group = 0,
  group_ex = 1,
  group_new = 2,
};

struct NativeSessionIdMember {
  Hash short_id{};
  Hash adnl_id{};
  std::uint64_t weight{};
  bool operator==(const NativeSessionIdMember&) const = default;
};

struct NativeSessionIdInput {
  Hash native_options_hash{};
  std::int32_t workchain{};
  std::uint64_t shard{};
  std::uint32_t maximal_vertical_seqno{};
  std::uint32_t last_key_block_seqno{};
  NativeSessionIdForm form{NativeSessionIdForm::group};
};

// This is the one owned description of the values actually committed by the
// selected native constructor. Fields omitted by that constructor are zero.
struct NativeSessionIdentity {
  Hash native_session_id{};
  Hash native_options_hash{};
  std::int32_t workchain{};
  std::uint64_t shard{};
  std::uint32_t catchain{};
  std::uint32_t vertical_seqno{};
  std::uint32_t key_block_seqno{};
  NativeSessionIdForm form{NativeSessionIdForm::group};
  bool operator==(const NativeSessionIdentity&) const = default;
};

using NativeSessionIdEncoder = std::function<Result<Hash>(
    NativeSessionIdForm, std::int32_t, std::uint64_t, std::uint32_t,
    std::uint32_t, std::uint32_t, const Hash&,
    std::span<const NativeSessionIdMember>)>;

// The caller owns the constructor form, options hash and vertical coordinate.
// The validator set owns member order and catchain. This helper only validates
// their agreement and normalizes coordinates the selected form does not encode.
inline Result<NativeSessionIdentity> derive_native_session_identity_core(
    const NativeSessionIdInput& input, std::uint32_t catchain,
    std::span<const NativeSessionIdMember> members,
    const NativeSessionIdEncoder& encode) {
  if (!encode)
    return Error{"native-session-encoder"};
  if (input.native_options_hash == Hash{})
    return Error{"native-session-options"};
  if (input.workchain < -1 || input.shard == 0)
    return Error{"native-session-coordinate"};
  if (members.empty())
    return Error{"native-session-members"};
  for (const auto& member : members) {
    if (member.short_id == Hash{} || member.weight == 0)
      return Error{"native-session-member"};
  }

  std::uint32_t vertical = input.maximal_vertical_seqno;
  std::uint32_t key_block = 0;
  switch (input.form) {
    case NativeSessionIdForm::group:
      if (vertical != 0)
        return Error{"native-session-form"};
      break;
    case NativeSessionIdForm::group_ex:
      if (vertical == 0)
        return Error{"native-session-form"};
      break;
    case NativeSessionIdForm::group_new:
      key_block = input.last_key_block_seqno;
      break;
    default:
      return Error{"native-session-form"};
  }

  auto encoded = encode(input.form, input.workchain, input.shard, vertical,
                        key_block, catchain, input.native_options_hash, members);
  if (!encoded.ok())
    return encoded.error();
  if (encoded.value() == Hash{})
    return Error{"native-session-id"};
  return NativeSessionIdentity{encoded.value(), input.native_options_hash,
                               input.workchain, input.shard, catchain, vertical,
                               key_block, input.form};
}

}  // namespace tos::auth
