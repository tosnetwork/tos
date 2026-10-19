/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstring>

#include "auto/tl/tos_api.hpp"
#include "block/validator-session-id.h"
#include "block/validator-session-members.h"
#include "common/checksum.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"

namespace block {

td::Bits256 validator_session_options_hash(const tos::ValidatorSessionConfig& config) {
  const auto& catchain = config.catchain_opts;
  if (config.proto_version == 0) {
    if (!config.new_catchain_ids) {
      return tos::create_hash_tl_object<tos::tos_api::validatorSession_config>(
          catchain.idle_timeout, catchain.max_deps, config.round_candidates, config.next_candidate_delay,
          config.round_attempt_duration, config.max_round_attempts, config.max_block_size,
          config.max_collated_data_size);
    }
    return tos::create_hash_tl_object<tos::tos_api::validatorSession_configNew>(
        catchain.idle_timeout, catchain.max_deps, config.round_candidates, config.next_candidate_delay,
        config.round_attempt_duration, config.max_round_attempts, config.max_block_size, config.max_collated_data_size,
        config.new_catchain_ids);
  }
  if (config.proto_version == 1) {
    return tos::create_hash_tl_object<tos::tos_api::validatorSession_configVersioned>(
        catchain.idle_timeout, catchain.max_deps, config.round_candidates, config.next_candidate_delay,
        config.round_attempt_duration, config.max_round_attempts, config.max_block_size, config.max_collated_data_size,
        config.proto_version);
  }
  return tos::create_hash_tl_object<tos::tos_api::validatorSession_configVersionedV2>(
      tos::create_tl_object<tos::tos_api::validatorSession_catchainOptions>(
          catchain.idle_timeout, catchain.max_deps, static_cast<td::uint32>(catchain.max_serialized_block_size),
          catchain.block_hash_covers_data, static_cast<td::uint32>(catchain.max_block_height_coeff),
          catchain.debug_disable_db),
      config.round_candidates, config.next_candidate_delay, config.round_attempt_duration, config.max_round_attempts,
      config.max_block_size, config.max_collated_data_size, config.proto_version);
}

td::Bits256 validator_session_config_hash(td::int32 global_id, const td::Bits256& validator_options_hash,
                                          const td::Bits256& simplex_config_cell_hash) {
  static constexpr char domain[] = "TOS-VALIDATOR-SESSION-CONFIG-v1";
  static_assert(sizeof(domain) - 1 == 31);
  std::array<td::uint8, 31 + 4 + 32 + 32> bytes{};
  std::memcpy(bytes.data(), domain, 31);
  const auto id = static_cast<td::uint32>(global_id);
  bytes[31] = static_cast<td::uint8>(id);
  bytes[32] = static_cast<td::uint8>(id >> 8);
  bytes[33] = static_cast<td::uint8>(id >> 16);
  bytes[34] = static_cast<td::uint8>(id >> 24);
  std::memcpy(bytes.data() + 35, validator_options_hash.data(), 32);
  std::memcpy(bytes.data() + 67, simplex_config_cell_hash.data(), 32);
  return td::sha256_bits256(td::Slice{reinterpret_cast<const char*>(bytes.data()), bytes.size()});
}

namespace {

tos::ValidatorSessionId session_id_from_config_hash(tos::ShardIdFull shard, tos::CatchainSeqno catchain_seqno,
                                                    const std::vector<tos::ValidatorDescr>& validators,
                                                    const td::Bits256& session_config_hash, td::uint32 vertical_seqno,
                                                    tos::BlockSeqno last_key_block_seqno, bool new_catchain_ids) {
  auto members = validator_session_members(validators);
  if (!new_catchain_ids) {
    if (vertical_seqno == 0) {
      return create_hash_tl_object<tos::tos_api::validator_group>(shard.workchain, shard.shard, catchain_seqno,
                                                                  session_config_hash, std::move(members));
    }
    return create_hash_tl_object<tos::tos_api::validator_groupEx>(
        shard.workchain, shard.shard, vertical_seqno, catchain_seqno, session_config_hash, std::move(members));
  }
  return create_hash_tl_object<tos::tos_api::validator_groupNew>(shard.workchain, shard.shard, vertical_seqno,
                                                                 last_key_block_seqno, catchain_seqno,
                                                                 session_config_hash, std::move(members));
}

}  // namespace

ValidatorSessionIdentity derive_validator_session_identity(
    td::int32 global_id, const td::Bits256& validator_options_hash, const td::Bits256& simplex_config_cell_hash,
    tos::ShardIdFull shard, tos::CatchainSeqno catchain_seqno, const std::vector<tos::ValidatorDescr>& validators,
    td::uint32 vertical_seqno, tos::BlockSeqno last_key_block_seqno, bool new_catchain_ids) {
  auto config_hash = validator_session_config_hash(global_id, validator_options_hash, simplex_config_cell_hash);
  auto session_id = session_id_from_config_hash(shard, catchain_seqno, validators, config_hash, vertical_seqno,
                                                last_key_block_seqno, new_catchain_ids);
  return {.session_config_hash = config_hash, .session_id = session_id};
}

ValidatorSessionIdentity derive_validator_session_identity(const ValidatorSessionIdentityInput& input) {
  return derive_validator_session_identity(
      input.global_id, input.validator_options_hash, input.simplex_config_cell_hash, input.shard, input.catchain_seqno,
      input.validators, input.vertical_seqno, input.last_key_block_seqno, input.new_catchain_ids);
}

}  // namespace block
