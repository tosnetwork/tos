/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"

namespace pq_block_signature_test {

[[noreturn]] inline void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

inline td::Bits256 hash_of(std::string_view text) {
  td::Bits256 result;
  td::sha256(td::Slice(text.data(), text.size()), result.as_slice());
  return result;
}

inline std::string_view view(td::Slice value) {
  return {value.data(), value.size()};
}

inline tos::ConsensusKeyId key_id_of(const tos::pq::ConsensusPQKey& key) {
  td::Bits256 bits;
  std::memcpy(bits.data(), key.key_id.data(), key.key_id.size());
  return tos::ConsensusKeyId{bits};
}

inline tos::BlockIdExt block_id(std::string_view label = "pq-finality") {
  return {-1, 0x8000000000000000ULL, 42, hash_of(std::string(label) + "-root"), hash_of(std::string(label) + "-file")};
}

inline tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate(
    const tos::BlockIdExt& id, std::string_view parent_label = "pq-finality-parent") {
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(id.id.workchain, static_cast<td::int64>(id.id.shard),
                                                              id.id.seqno, id.root_hash, id.file_hash),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(2718280, hash_of(parent_label)));
}

inline std::vector<block::PQBlockSignature> clone_pairs(const std::vector<block::PQBlockSignature>& signatures) {
  std::vector<block::PQBlockSignature> result;
  result.reserve(signatures.size());
  for (const auto& signature : signatures) {
    result.push_back({signature.validator_id, signature.algorithm_id, signature.signature.clone()});
  }
  return result;
}

struct Fixture {
  static constexpr tos::CatchainSeqno catchain_seqno = 1789434;
  static constexpr td::uint32 slot = 2718281;

  std::vector<tos::pq::ValidatorPQKeyStore> stores;
  std::vector<tos::ValidatorId> validator_ids;
  std::vector<tos::ValidatorWeight> weights{4, 3, 2, 1};
  td::Ref<block::ValidatorSet> validator_set;
  tos::BlockIdExt id{block_id()};
  td::Bits256 session{hash_of("pq-finality-session")};

  Fixture() {
    std::vector<tos::ValidatorDescr> descriptors;
    for (std::size_t i = 0; i < weights.size(); ++i) {
      std::array<char, 32> seed{};
      seed.fill(static_cast<char>(0x31 + i));
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store.has_value()) {
        fail("PQ_BLOCK_SIGNATURE_FIXTURE_KEY_DERIVATION_FAILED");
      }
      const auto validator_id = tos::ValidatorId{hash_of("pq-finality-validator-" + std::to_string(i))};
      const auto& key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key), key.public_key,
                               weights[i], hash_of("pq-finality-adnl-" + std::to_string(i)));
      validator_ids.push_back(validator_id);
      stores.push_back(std::move(*store));
    }
    validator_set = td::Ref<block::ValidatorSet>{true, catchain_seqno, tos::ShardIdFull{tos::masterchainId},
                                                 std::move(descriptors)};
  }

  tos::ValidatorDescr descriptor(std::size_t index) const {
    const auto& key = stores.at(index).consensus_key();
    return {validator_ids.at(index), static_cast<td::uint16>(key.algorithm_id),
            key_id_of(key),          key.public_key,
            weights.at(index),       hash_of("pq-finality-adnl-" + std::to_string(index))};
  }

  td::Ref<block::ValidatorSet> make_validator_set(std::vector<tos::ValidatorDescr> descriptors,
                                                  tos::CatchainSeqno cc = catchain_seqno) const {
    return td::Ref<block::ValidatorSet>{true, cc, tos::ShardIdFull{tos::masterchainId}, std::move(descriptors)};
  }

  std::vector<block::PQBlockSignature> sign(const std::vector<std::size_t>& signers, td::Bits256 signed_session,
                                            td::uint32 signed_slot,
                                            const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& data,
                                            bool final, const tos::BlockIdExt& signed_block_id) {
    auto message =
        block::BlockSignatureSet::build_simplex_data_to_sign(signed_session, signed_slot, data, final, signed_block_id);
    if (message.is_error()) {
      fail("PQ_BLOCK_SIGNATURE_FIXTURE_PREIMAGE_FAILED: " + message.error().message().str());
    }
    auto bytes = message.move_as_ok();
    std::vector<block::PQBlockSignature> result;
    result.reserve(signers.size());
    for (const auto signer : signers) {
      auto signature = stores.at(signer).sign_consensus(view(bytes.as_slice()));
      if (!signature.has_value()) {
        fail("PQ_BLOCK_SIGNATURE_FIXTURE_SIGNING_FAILED");
      }
      result.push_back({validator_ids.at(signer), signature->algorithm_id, td::BufferSlice(signature->signature)});
    }
    return result;
  }

  tos::ValidatorWeight weight_of(const std::vector<std::size_t>& signers) const {
    tos::ValidatorWeight result = 0;
    for (const auto signer : signers) {
      if (!tos::checked_add_validator_weight(result, weights.at(signer))) {
        fail("PQ_BLOCK_SIGNATURE_FIXTURE_WEIGHT_FAILED");
      }
    }
    return result;
  }

  td::Result<td::Ref<block::BlockSignatureSet>> persisted_final(
      const std::vector<block::PQBlockSignature>& signatures, td::Bits256 carried_session, td::uint32 carried_slot,
      const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& data, tos::ValidatorWeight claimed_weight,
      td::uint32 validator_hash, tos::CatchainSeqno cc_seqno, td::Ref<block::ValidatorSet> trusted_set) const {
    TRY_RESULT(cell, block::BlockSignatureSet::serialize_simplex_pq(
                         signatures, cc_seqno, validator_hash, claimed_weight, carried_session, carried_slot, data));
    return block::BlockSignatureSet::fetch(std::move(cell), std::move(trusted_set));
  }
};

template <class T>
inline void expect_error(td::Result<T> result, std::string_view expected, std::string_view name) {
  if (result.is_ok()) {
    fail("PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=" + std::string(name) + " expected=" + std::string(expected));
  }
  const auto actual = result.error().message().str();
  if (actual.find(expected) == std::string::npos) {
    fail("PQ_BLOCK_SIGNATURE_REASON_MISMATCH case=" + std::string(name) + " expected=" + std::string(expected) +
         " actual=" + actual);
  }
}

template <class T>
inline T require_ok(td::Result<T> result, std::string_view name) {
  if (result.is_error()) {
    fail("PQ_BLOCK_SIGNATURE_UNEXPECTED_REJECT case=" + std::string(name) +
         " actual=" + result.error().message().str());
  }
  return result.move_as_ok();
}

}  // namespace pq_block_signature_test
