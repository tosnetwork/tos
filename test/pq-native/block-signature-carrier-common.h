/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-sign-under.h"
#include "td/utils/crypto.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellString.h"
#include "vm/dict.h"

namespace block_signature_carrier_test {

inline constexpr std::size_t measured_signer_ceiling = 400;
inline constexpr std::uint32_t validator_set_hash = 0x31415926;
inline constexpr std::uint32_t catchain_seqno = 1789434;
inline constexpr std::uint32_t slot = 2718281;
inline constexpr std::uint64_t signature_weight = 1;
inline constexpr auto algorithm_id =
    static_cast<std::underlying_type_t<tos::pq::PQAlgorithmId>>(tos::pq::PQAlgorithmId::mldsa44);

inline td::Bits256 hash_of(const std::string& text) {
  td::Bits256 out;
  td::sha256(td::Slice(text), out.as_slice());
  return out;
}

inline tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate() {
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(-1, static_cast<td::int64>(0x8000000000000000ULL), 42,
                                                              hash_of("carrier-root"), hash_of("carrier-file")),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("carrier-parent")));
}

inline tos::BlockIdExt block_id() {
  return {-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
}

inline tos::tl_object_ptr<tos::tos_api::tosNode_blockIdExt> node_block_id() {
  return tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
      block_id().id.workchain, static_cast<td::int64>(block_id().id.shard), block_id().id.seqno, block_id().root_hash,
      block_id().file_hash);
}

inline tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> lite_block_id() {
  return tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
      block_id().id.workchain, static_cast<td::int64>(block_id().id.shard), block_id().id.seqno, block_id().root_hash,
      block_id().file_hash);
}

inline td::Bits256 session_id() {
  return hash_of("persisted-pq-block-signature-session");
}

inline td::BufferSlice signed_message() {
  auto candidate_value = candidate();
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate_value).raw});
  auto vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id));
  return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session_id(), std::move(vote));
}

struct SignatureInput {
  td::Bits256 validator_id;
  td::BufferSlice signature;
};

inline td::BufferSlice patterned_signature(std::size_t signer) {
  td::BufferSlice out(tos::pq::mldsa44_signature_bytes);
  std::size_t offset = 0;
  std::string seed = "persisted-pq-signature-" + std::to_string(signer);
  while (offset < out.size()) {
    auto block = hash_of(seed);
    const auto take = std::min<std::size_t>(32, out.size() - offset);
    std::memcpy(out.data() + offset, block.data(), take);
    offset += take;
    seed.assign(reinterpret_cast<const char*>(block.data()), 32);
  }
  return out;
}

inline std::vector<SignatureInput> make_signatures(std::size_t count, bool cryptographically_valid) {
  std::vector<SignatureInput> result;
  result.reserve(count);
  auto message = signed_message();
  std::vector<std::uint8_t> prefix{0, static_cast<std::uint8_t>(tos::pq::simplex_sign_context.size())};
  prefix.insert(prefix.end(), tos::pq::simplex_sign_context.begin(), tos::pq::simplex_sign_context.end());
  for (std::size_t i = 0; i < count; ++i) {
    td::BufferSlice signature;
    if (cryptographically_valid) {
      tos::pq::ConsensusPQKey key;
      std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> secret{};
      const auto seed = hash_of("persisted-signature-key-" + std::to_string(i));
      if (!tos::pq::detail::derive_from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), 32), key,
                                             secret.data())) {
        std::fprintf(stderr, "deterministic key derivation failed for signer %zu\n", i);
        std::abort();
      }
      std::array<std::uint8_t, MLDSA_RNDBYTES> randomness{};
      const auto randomness_bits = hash_of("persisted-signature-randomness-" + std::to_string(i));
      std::memcpy(randomness.data(), randomness_bits.data(), randomness.size());
      signature = td::BufferSlice(tos::pq::mldsa44_signature_bytes);
      if (tos_pq_cs_native_signature_internal(reinterpret_cast<std::uint8_t*>(signature.data()),
                                              reinterpret_cast<const std::uint8_t*>(message.data()), message.size(),
                                              prefix.data(), prefix.size(), randomness.data(), secret.data(), 0) != 0) {
        std::fprintf(stderr, "deterministic signing failed for signer %zu\n", i);
        std::abort();
      }
      if (tos::pq::verify_mldsa44(std::string_view(message.data(), message.size()), tos::pq::simplex_sign_context,
                                  std::string_view(signature.data(), signature.size()),
                                  key.public_key) != tos::pq::VerifyResult::valid) {
        std::fprintf(stderr, "deterministic signature verification failed for signer %zu\n", i);
        std::abort();
      }
      OPENSSL_cleanse(secret.data(), secret.size());
    } else {
      signature = patterned_signature(i);
    }
    result.push_back(SignatureInput{hash_of("persisted-validator-" + std::to_string(i)), std::move(signature)});
  }
  return result;
}

inline td::Result<td::Ref<vm::Cell>> try_signature_set_cell(const std::vector<SignatureInput>& signatures) {
  std::vector<block::PQBlockSignature> pairs;
  pairs.reserve(signatures.size());
  tos::ValidatorWeight weight = 0;
  for (const auto& signature : signatures) {
    if (!tos::checked_add_validator_weight(weight, signature_weight)) {
      return td::Status::Error("measurement signature weight overflow");
    }
    pairs.push_back(block::PQBlockSignature{tos::ValidatorId{signature.validator_id},
                                            static_cast<tos::pq::PQAlgorithmId>(algorithm_id),
                                            signature.signature.clone()});
  }
  return block::BlockSignatureSet::serialize_simplex_pq(pairs, catchain_seqno, validator_set_hash, weight, session_id(),
                                                        slot, candidate());
}

inline td::Ref<vm::Cell> signature_set_cell(const std::vector<SignatureInput>& signatures) {
  auto serialized = try_signature_set_cell(signatures);
  if (serialized.is_error()) {
    std::fprintf(stderr, "production signature-set serializer failed: %s\n",
                 serialized.error().message().str().c_str());
    std::abort();
  }
  return serialized.move_as_ok();
}

inline td::BufferSlice boc(const td::Ref<vm::Cell>& root) {
  auto result = vm::std_boc_serialize(root, 0);
  if (result.is_error()) {
    std::abort();
  }
  return result.move_as_ok();
}

inline td::Ref<vm::Cell> block_proof_cell(const td::Ref<vm::Cell>& signatures) {
  tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  vm::CellBuilder proof_payload;
  proof_payload.store_long(0x51, 8);
  vm::CellBuilder root;
  if (!(root.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(root, id) &&
        root.store_ref_bool(proof_payload.finalize()) && root.store_bool_bool(true) &&
        root.store_ref_bool(signatures))) {
    std::abort();
  }
  return root.finalize_novm();
}

inline tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> node_signature_set(
    const std::vector<SignatureInput>& signatures) {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_pqBlockSignature>> pairs;
  pairs.reserve(signatures.size());
  for (const auto& signature : signatures) {
    pairs.push_back(tos::create_tl_object<tos::tos_api::tosNode_pqBlockSignature>(signature.validator_id, algorithm_id,
                                                                                  signature.signature.clone()));
  }
  return tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplexPq>(
      true, catchain_seqno, validator_set_hash, std::move(pairs), session_id(), slot, candidate());
}

inline td::BufferSlice node_tl(const std::vector<SignatureInput>& signatures) {
  return tos::serialize_tl_object(node_signature_set(signatures), true);
}

inline tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> lite_signature_set(
    const std::vector<SignatureInput>& signatures) {
  auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
  std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_pqSignature>> pairs;
  pairs.reserve(signatures.size());
  for (const auto& signature : signatures) {
    pairs.push_back(tos::create_tl_object<tos::lite_api::liteServer_pqSignature>(signature.validator_id, algorithm_id,
                                                                                 signature.signature.clone()));
  }
  return tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplexPq>(
      catchain_seqno, validator_set_hash, std::move(pairs), session_id(), slot, std::move(candidate_bytes));
}

inline td::BufferSlice lite_tl(const std::vector<SignatureInput>& signatures) {
  return tos::serialize_tl_object(lite_signature_set(signatures), true);
}

inline td::BufferSlice finality_broadcast_tl(const std::vector<SignatureInput>& signatures) {
  return tos::create_serialize_tl_object<tos::tos_api::tosNode_blockFinalityBroadcast>(node_block_id(),
                                                                                       node_signature_set(signatures));
}

inline td::BufferSlice lite_forward_proof_tl(const std::vector<SignatureInput>& signatures) {
  vm::CellBuilder proof;
  proof.store_long(0x51, 8);
  auto proof_boc = boc(proof.finalize_novm());
  std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_BlockLink>> links;
  links.push_back(tos::create_tl_object<tos::lite_api::liteServer_blockLinkForward>(
      true, lite_block_id(), lite_block_id(), td::BufferSlice{}, std::move(proof_boc), lite_signature_set(signatures)));
  return tos::create_serialize_tl_object<tos::lite_api::liteServer_partialBlockProof>(
      true, lite_block_id(), lite_block_id(), std::move(links));
}

inline td::BufferSlice lite_answer_tl(const std::vector<SignatureInput>& signatures) {
  return tos::create_serialize_tl_object<tos::tos_api::adnl_message_answer>(hash_of("pq-carrier-lite-query"),
                                                                            lite_forward_proof_tl(signatures));
}

inline std::size_t certificate_tl_bytes(const std::vector<SignatureInput>& signatures) {
  std::vector<tos::tl_object_ptr<tos::tos_api::consensus_simplex_voteSignature>> votes;
  votes.reserve(signatures.size());
  for (std::size_t i = 0; i < signatures.size(); ++i) {
    votes.push_back(tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignature>(
        static_cast<std::int32_t>(i), signatures[i].signature.clone()));
  }
  auto candidate_value = candidate();
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate_value).raw});
  auto cert = tos::create_tl_object<tos::tos_api::consensus_simplex_certificate>(
      tos::create_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id)),
      tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignatureSet>(std::move(votes)));
  return tos::serialize_tl_object(cert, true).size();
}

struct Measurement {
  std::size_t signers;
  std::size_t cells;
  std::size_t depth;
  std::size_t signatures_boc_bytes;
  std::string signatures_boc_sha256;
  std::size_t block_proof_boc_bytes;
  std::size_t node_tl_bytes;
  std::size_t lite_tl_bytes;
  std::size_t certificate_tl_bytes;
  std::int64_t boc_minus_certificate;
};

inline Measurement measure(std::size_t count, bool valid) {
  auto signatures = make_signatures(count, valid);
  auto root = signature_set_cell(signatures);
  vm::CellStorageStat stat;
  if (stat.add_used_storage(root).is_error()) {
    std::abort();
  }
  const auto signature_boc = boc(root);
  td::Bits256 signature_boc_hash;
  td::sha256(signature_boc.as_slice(), signature_boc_hash.as_slice());
  const auto proof_boc = boc(block_proof_cell(root));
  const auto cert_size = certificate_tl_bytes(signatures);
  return Measurement{count,
                     static_cast<std::size_t>(stat.cells),
                     root->get_depth(),
                     signature_boc.size(),
                     signature_boc_hash.to_hex(),
                     proof_boc.size(),
                     node_tl(signatures).size(),
                     lite_tl(signatures).size(),
                     cert_size,
                     static_cast<std::int64_t>(signature_boc.size()) - static_cast<std::int64_t>(cert_size)};
}

}  // namespace block_signature_carrier_test
