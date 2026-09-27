/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "validator/interfaces/config.h"
#include "validator/interfaces/shard.h"

namespace tos::validator {

namespace detail {

inline td::Status check_governing_global_id(td::int32 header_global_id, const ConfigHolder& governing_config) {
  TRY_RESULT(config_global_id, governing_config.get_config_global_id());
  if (header_global_id != config_global_id) {
    return td::Status::Error(ErrorCode::protoviolation,
                             PSTRING() << "pq finality context: governing state global_id " << header_global_id
                                       << " disagrees with ConfigParam 19 global_id " << config_global_id);
  }
  return td::Status::OK();
}

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    td::int32 global_id, const ValidatorSessionConfig& session_config,
    const td::optional<SelectedNewConsensusConfig>& selected_config, td::Ref<block::ValidatorSet> validator_set,
    BlockIdExt block_id, td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  if (validator_set.is_null()) {
    return td::Status::Error("pq finality context: trusted validator set is missing");
  }
  if (!selected_config) {
    return td::Status::Error("pq finality context: selected ConfigParam 30 is missing or malformed");
  }
  if (!selected_config.value().config.protocol_version_supported()) {
    return td::Status::Error("pq finality context: selected ConfigParam 30 protocol version is unsupported");
  }
  auto identity = block::derive_validator_session_identity(
      global_id, block::validator_session_options_hash(session_config), selected_config.value().cell_hash,
      block_id.shard_full(), validator_set->get_catchain_seqno(), validator_set->export_vector(), vertical_seqno,
      previous_key_block_seqno, session_config.new_catchain_ids);
  return block::PQFinalityVerificationContext{std::move(validator_set), block_id, identity.session_id};
}

}  // namespace detail

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    const MasterchainState& governing_state, td::Ref<block::ValidatorSet> validator_set, BlockIdExt block_id,
    td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  try {
    TRY_RESULT(governing_config, governing_state.get_config_holder());
    TRY_STATUS(detail::check_governing_global_id(governing_state.get_global_id(), *governing_config));
    return detail::derive_pq_finality_context(governing_state.get_global_id(), governing_state.get_consensus_config(),
                                              governing_state.get_selected_new_consensus_config(block_id.id.workchain),
                                              std::move(validator_set), block_id, vertical_seqno,
                                              previous_key_block_seqno);
  } catch (vm::VmVirtError& error) {
    return error.as_status("pq finality context is unavailable in the governing state proof: ");
  }
}

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    const ConfigHolder& governing_config, td::Ref<block::ValidatorSet> validator_set, BlockIdExt block_id,
    td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  try {
    TRY_STATUS(detail::check_governing_global_id(governing_config.get_global_id(), governing_config));
    return detail::derive_pq_finality_context(governing_config.get_global_id(), governing_config.get_consensus_config(),
                                              governing_config.get_selected_new_consensus_config(block_id.id.workchain),
                                              std::move(validator_set), block_id, vertical_seqno,
                                              previous_key_block_seqno);
  } catch (vm::VmVirtError& error) {
    return error.as_status("pq finality context is unavailable in the governing key-block proof: ");
  }
}

inline td::Result<ValidatorWeight> verify_pq_proof_signatures(const block::PQFinalityVerificationContext& context,
                                                              const block::BlockSignatureSet& signatures,
                                                              ValidatorWeight claimed_weight) {
  TRY_RESULT(verified_weight, block::verify_pq_finality(context, signatures, block::FinalityRole::Final));
  if (verified_weight != claimed_weight) {
    return td::Status::Error(ErrorCode::protoviolation, PSTRING() << "bad signature set weight: expected "
                                                                  << verified_weight << ", found " << claimed_weight);
  }
  return verified_weight;
}

}  // namespace tos::validator
