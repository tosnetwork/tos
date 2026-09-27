/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstdio>
#include <string_view>
#include <vector>

#include "block/validator-session-id.h"

#include "pq-block-signature-test-common.h"

namespace {

using namespace pq_block_signature_test;

td::Result<td::Ref<block::BlockSignatureSet>> persisted(
    const Fixture& fixture, const std::vector<block::PQBlockSignature>& signatures, td::Bits256 session,
    td::uint32 slot, const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate,
    tos::ValidatorWeight weight, td::Ref<block::ValidatorSet> trusted_set) {
  return fixture.persisted_final(signatures, session, slot, candidate, weight, trusted_set->get_validator_set_hash(),
                                 trusted_set->get_catchain_seqno(), trusted_set);
}

td::Result<tos::ValidatorWeight> verify_final(
    const Fixture& fixture, const std::vector<block::PQBlockSignature>& signatures, td::Bits256 session,
    td::uint32 slot, const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate,
    tos::ValidatorWeight weight, const tos::BlockIdExt& block_id, td::Ref<block::ValidatorSet> trusted_set) {
  TRY_RESULT(signature_set, persisted(fixture, signatures, session, slot, candidate, weight, trusted_set));
  return signature_set->check_pq_signatures_under_carried_session_for_test(std::move(trusted_set), block_id,
                                                                           block::FinalityRole::Final);
}

td::BufferSlice independent_preimage(
    td::Bits256 session, td::uint32 slot,
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate_data, bool final) {
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate_data).raw});
  td::BufferSlice vote;
  if (final) {
    vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id));
  } else {
    vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_notarizeVote>(std::move(candidate_id));
  }
  return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session, std::move(vote));
}

}  // namespace

int main() {
  Fixture fixture;
  const td::int32 global_id = -239;
  const auto opts_hash = hash_of("trusted-param29-options");
  const auto param30_hash = hash_of("trusted-selected-param30-cell");
  const tos::ShardIdFull shard{tos::masterchainId};
  const td::uint32 vertical_seqno = 17;
  const tos::BlockSeqno previous_key_block_seqno = 9001;
  const bool new_catchain_ids = true;
  const auto derive_session = [&](td::int32 id, td::Bits256 options, td::Bits256 config, tos::ShardIdFull for_shard,
                                  td::uint32 vertical, tos::BlockSeqno previous_key) {
    return block::derive_validator_session_identity(id, options, config, for_shard, Fixture::catchain_seqno,
                                                    fixture.validator_set->export_vector(), vertical, previous_key,
                                                    new_catchain_ids)
        .session_id;
  };
  fixture.session = derive_session(global_id, opts_hash, param30_hash, shard, vertical_seqno, previous_key_block_seqno);
  auto base_candidate = candidate(fixture.id);
  auto shared_preimage = require_ok(block::BlockSignatureSet::build_simplex_data_to_sign(
                                        fixture.session, Fixture::slot, base_candidate, true, fixture.id),
                                    "shared-simplex-preimage");
  const auto expected_preimage = independent_preimage(fixture.session, Fixture::slot, base_candidate, true);
  if (shared_preimage.as_slice() != expected_preimage.as_slice()) {
    fail("PQ_BLOCK_SIGNATURE_PREIMAGE_MISMATCH case=shared-simplex-preimage");
  }
  const std::vector<std::size_t> quorum_signers{0, 1};
  auto quorum = fixture.sign(quorum_signers, fixture.session, Fixture::slot, base_candidate, true, fixture.id);
  const auto quorum_weight = fixture.weight_of(quorum_signers);

  const block::PQFinalityVerificationContext trusted_context{fixture.validator_set, fixture.id, fixture.session};
  auto persisted_valid = require_ok(
      persisted(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight, fixture.validator_set),
      "trusted-session-boundary-construction");
  expect_error(persisted_valid->check_signatures(fixture.validator_set, fixture.id),
               "trusted expected session context is required", "pq-low-level-production-refusal");
  if (require_ok(block::verify_pq_finality(trusted_context, *persisted_valid, block::FinalityRole::Final),
                 "trusted-session-boundary") != quorum_weight) {
    fail("PQ_BLOCK_SIGNATURE_WEIGHT_MISMATCH case=trusted-session-boundary");
  }

  const auto expect_alternate_session_rejected = [&](std::string_view name, td::Bits256 alternate_session) {
    if (alternate_session == fixture.session) {
      fail("PQ_BLOCK_SIGNATURE_ALTERNATE_SESSION_COLLISION case=" + std::string(name));
    }
    auto alternate_pairs =
        fixture.sign(quorum_signers, alternate_session, Fixture::slot, base_candidate, true, fixture.id);
    auto alternate = require_ok(persisted(fixture, alternate_pairs, alternate_session, Fixture::slot, base_candidate,
                                          quorum_weight, fixture.validator_set),
                                std::string(name) + "-construction");
    require_ok(alternate->check_pq_signatures_under_carried_session_for_test(fixture.validator_set, fixture.id,
                                                                             block::FinalityRole::Final),
               std::string(name) + "-raw-positive-control");
    expect_error(block::verify_pq_finality(trusted_context, *alternate, block::FinalityRole::Final),
                 "carried session_id does not match trusted expected session_id", name);
  };

  expect_alternate_session_rejected(
      "wrong-workchain-shard-session",
      derive_session(global_id, opts_hash, param30_hash, tos::ShardIdFull{0, 0x8000000000000000ULL}, vertical_seqno,
                     previous_key_block_seqno));
  expect_alternate_session_rejected("different-global-id", derive_session(global_id + 1, opts_hash, param30_hash, shard,
                                                                          vertical_seqno, previous_key_block_seqno));
  expect_alternate_session_rejected("wrong-param29-options-hash",
                                    derive_session(global_id, hash_of("other-param29-options"), param30_hash, shard,
                                                   vertical_seqno, previous_key_block_seqno));
  expect_alternate_session_rejected("different-trusted-param30",
                                    derive_session(global_id, opts_hash, hash_of("other-selected-param30-cell"), shard,
                                                   vertical_seqno, previous_key_block_seqno));
  expect_alternate_session_rejected(
      "wrong-vertical-seqno",
      derive_session(global_id, opts_hash, param30_hash, shard, vertical_seqno + 1, previous_key_block_seqno));
  expect_alternate_session_rejected(
      "wrong-previous-key-block-coordinate",
      derive_session(global_id, opts_hash, param30_hash, shard, vertical_seqno, previous_key_block_seqno + 1));
  expect_alternate_session_rejected("pre-rotation-session-after-rotation",
                                    derive_session(global_id, opts_hash, hash_of("pre-rotation-param30-cell"), shard,
                                                   vertical_seqno, previous_key_block_seqno));

  auto valid = verify_final(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight, fixture.id,
                            fixture.validator_set);
  if (require_ok(std::move(valid), "valid-quorum") != quorum_weight) {
    fail("PQ_BLOCK_SIGNATURE_WEIGHT_MISMATCH case=valid-quorum");
  }

  auto tampered = clone_pairs(quorum);
  tampered[0].signature.data()[0] ^= 1;
  expect_error(verify_final(fixture, tampered, fixture.session, Fixture::slot, base_candidate, quorum_weight,
                            fixture.id, fixture.validator_set),
               "pq signatures: invalid signature", "tampered-signature");

  auto unknown = clone_pairs(quorum);
  unknown[0].validator_id = tos::ValidatorId{hash_of("unknown-pq-finality-validator")};
  expect_error(
      persisted(fixture, unknown, fixture.session, Fixture::slot, base_candidate, quorum_weight, fixture.validator_set),
      "pq signatures: unknown validator_id", "wrong-validator-id");

  auto relabelled = clone_pairs(quorum);
  relabelled.resize(1);
  relabelled[0].validator_id = fixture.validator_ids[1];
  expect_error(verify_final(fixture, relabelled, fixture.session, Fixture::slot, base_candidate, fixture.weights[1],
                            fixture.id, fixture.validator_set),
               "pq signatures: invalid signature", "signature-a-labelled-b");

  auto wrong_algorithm = clone_pairs(quorum);
  wrong_algorithm[0].algorithm_id = static_cast<tos::pq::PQAlgorithmId>(2);
  expect_error(block::BlockSignatureSet::create_simplex_pq_final(std::move(wrong_algorithm), Fixture::catchain_seqno,
                                                                 fixture.validator_set->get_validator_set_hash(),
                                                                 fixture.session, Fixture::slot, candidate(fixture.id)),
               "pq signatures: unsupported algorithm", "wrong-algorithm-id");

  std::vector<tos::ValidatorDescr> mismatched_algorithm_descriptors;
  auto mismatched_algorithm = fixture.descriptor(0);
  mismatched_algorithm.algorithm_id = 2;
  mismatched_algorithm_descriptors.push_back(std::move(mismatched_algorithm));
  for (std::size_t i = 1; i < fixture.weights.size(); ++i) {
    mismatched_algorithm_descriptors.push_back(fixture.descriptor(i));
  }
  auto mismatched_algorithm_set = fixture.make_validator_set(std::move(mismatched_algorithm_descriptors));
  expect_error(persisted(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight,
                         mismatched_algorithm_set),
               "pq signatures: validator algorithm mismatch", "descriptor-algorithm-mismatch");

  std::vector<tos::ValidatorDescr> classical_descriptor_set;
  auto classical_descriptor = tos::ValidatorDescr{tos::Ed25519_PublicKey{hash_of("classical-consensus-key")},
                                                  fixture.weights[0], hash_of("classical-adnl")};
  classical_descriptor.validator_id = fixture.validator_ids[0];
  classical_descriptor_set.push_back(std::move(classical_descriptor));
  for (std::size_t i = 1; i < fixture.weights.size(); ++i) {
    classical_descriptor_set.push_back(fixture.descriptor(i));
  }
  auto mixed_set = fixture.make_validator_set(std::move(classical_descriptor_set));
  auto pq_with_mixed_hash =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(clone_pairs(quorum), Fixture::catchain_seqno,
                                                                   mixed_set->get_validator_set_hash(), fixture.session,
                                                                   Fixture::slot, candidate(fixture.id)),
                 "pq-with-mixed-set-construction");
  expect_error(pq_with_mixed_hash->get_weight(mixed_set), "pq signatures: validator is not post-quantum",
               "classical-descriptor-for-pq-pair");

  std::array<char, 32> outsider_seed{};
  outsider_seed.fill(0x66);
  auto outsider = tos::pq::ValidatorPQKeyStore::from_seed(std::string_view(outsider_seed.data(), outsider_seed.size()));
  if (!outsider.has_value()) {
    fail("PQ_BLOCK_SIGNATURE_FIXTURE_KEY_DERIVATION_FAILED case=wrong-public-key");
  }
  std::vector<tos::ValidatorDescr> wrong_key_descriptors;
  const auto& outsider_key = outsider->consensus_key();
  wrong_key_descriptors.emplace_back(fixture.validator_ids[0], static_cast<td::uint16>(outsider_key.algorithm_id),
                                     key_id_of(outsider_key), outsider_key.public_key, fixture.weights[0],
                                     hash_of("wrong-key-adnl"));
  for (std::size_t i = 1; i < fixture.weights.size(); ++i) {
    wrong_key_descriptors.push_back(fixture.descriptor(i));
  }
  auto wrong_key_set = fixture.make_validator_set(std::move(wrong_key_descriptors));
  expect_error(verify_final(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight, fixture.id,
                            wrong_key_set),
               "pq signatures: invalid signature", "wrong-public-key");

  auto flipped_session = fixture.session;
  flipped_session.data()[0] ^= 1;
  expect_error(verify_final(fixture, quorum, flipped_session, Fixture::slot, base_candidate, quorum_weight, fixture.id,
                            fixture.validator_set),
               "pq signatures: invalid signature", "bit-flipped-session-id");

  expect_error(verify_final(fixture, quorum, fixture.session, Fixture::slot + 1, base_candidate, quorum_weight,
                            fixture.id, fixture.validator_set),
               "pq signatures: invalid signature", "wrong-slot");

  auto wrong_candidate = candidate(fixture.id, "different-parent");
  expect_error(verify_final(fixture, quorum, fixture.session, Fixture::slot, wrong_candidate, quorum_weight, fixture.id,
                            fixture.validator_set),
               "pq signatures: invalid signature", "wrong-candidate-data");

  auto other_block_id = block_id("different-block");
  auto other_block_candidate = candidate(other_block_id);
  expect_error(verify_final(fixture, quorum, fixture.session, Fixture::slot, other_block_candidate, quorum_weight,
                            other_block_id, fixture.validator_set),
               "pq signatures: invalid signature", "different-block-id");

  auto approve_pairs = fixture.sign(quorum_signers, fixture.session, Fixture::slot, base_candidate, false, fixture.id);
  auto approve = require_ok(
      block::BlockSignatureSet::create_simplex_pq_approve(clone_pairs(approve_pairs), Fixture::catchain_seqno,
                                                          fixture.validator_set->get_validator_set_hash(),
                                                          fixture.session, Fixture::slot, candidate(fixture.id)),
      "valid-approve-construction");
  if (require_ok(block::verify_pq_finality(trusted_context, *approve, block::FinalityRole::Approve), "valid-approve") !=
      quorum_weight) {
    fail("PQ_BLOCK_SIGNATURE_WEIGHT_MISMATCH case=valid-approve");
  }
  expect_error(block::verify_pq_finality(trusted_context, *approve, block::FinalityRole::Final), "not final signatures",
               "notarize-presented-as-final");

  auto final_in_memory =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                     clone_pairs(quorum), Fixture::catchain_seqno, fixture.validator_set->get_validator_set_hash(),
                     fixture.session, Fixture::slot, candidate(fixture.id)),
                 "valid-final-construction");
  expect_error(block::verify_pq_finality(trusted_context, *final_in_memory, block::FinalityRole::Approve),
               "not approve signatures", "finalize-presented-as-approve");

  auto duplicate = clone_pairs(quorum);
  duplicate[1].validator_id = duplicate[0].validator_id;
  expect_error(block::BlockSignatureSet::create_simplex_pq_final(std::move(duplicate), Fixture::catchain_seqno,
                                                                 fixture.validator_set->get_validator_set_hash(),
                                                                 fixture.session, Fixture::slot, candidate(fixture.id)),
               "pq signatures: duplicate validator_id", "duplicate-validator-id");

  const std::vector<std::size_t> one_signer{0};
  auto sub_quorum = fixture.sign(one_signer, fixture.session, Fixture::slot, base_candidate, true, fixture.id);
  expect_error(verify_final(fixture, sub_quorum, fixture.session, Fixture::slot, base_candidate,
                            fixture.weight_of(one_signer), fixture.id, fixture.validator_set),
               "pq signatures: insufficient verified weight", "sub-quorum-weight");

  const std::vector<std::size_t> surplus_signers{0, 1, 2};
  auto surplus = fixture.sign(surplus_signers, fixture.session, Fixture::slot, base_candidate, true, fixture.id);
  surplus[2].signature.data()[0] ^= 1;
  expect_error(verify_final(fixture, surplus, fixture.session, Fixture::slot, base_candidate,
                            fixture.weight_of(surplus_signers), fixture.id, fixture.validator_set),
               "pq signatures: invalid signature", "invalid-surplus-signature");

  expect_error(persisted(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight - 1,
                         fixture.validator_set),
               "signature weight mismatch", "claimed-weight-too-small");
  expect_error(persisted(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight + 1,
                         fixture.validator_set),
               "signature weight mismatch", "claimed-weight-too-large");

  expect_error(fixture.persisted_final(quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight,
                                       fixture.validator_set->get_validator_set_hash() ^ 1, Fixture::catchain_seqno,
                                       fixture.validator_set),
               "validator set hash mismatch", "validator-set-hash-mismatch");
  expect_error(fixture.persisted_final(quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight,
                                       fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno + 1,
                                       fixture.validator_set),
               "catchain seqno mismatch", "catchain-seqno-mismatch");

  std::vector<tos::ValidatorDescr> wrong_key_id_descriptors;
  auto wrong_key_id = fixture.descriptor(0);
  wrong_key_id.key_id = tos::ConsensusKeyId{hash_of("wrong-key-id")};
  wrong_key_id_descriptors.push_back(std::move(wrong_key_id));
  for (std::size_t i = 1; i < fixture.weights.size(); ++i) {
    wrong_key_id_descriptors.push_back(fixture.descriptor(i));
  }
  auto wrong_key_id_set = fixture.make_validator_set(std::move(wrong_key_id_descriptors));
  expect_error(
      persisted(fixture, quorum, fixture.session, Fixture::slot, base_candidate, quorum_weight, wrong_key_id_set),
      "pq signatures: validator key_id mismatch", "descriptor-key-id-mismatch");

  std::printf("PQ_BLOCK_SIGNATURE_CONFORMANCE_OK positive_cases=3 negative_cases=29\n");
  return 0;
}
