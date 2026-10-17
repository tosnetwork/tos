/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstdio>
#include <string_view>
#include <utility>
#include <vector>

#include "block/validator-session-id.h"
#include "td/utils/bits.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellString.h"
#include "vm/dict.h"

#include "pq-block-signature-test-common.h"

namespace {

using namespace pq_block_signature_test;

// Dictionary edge label encodings: hml_short, hml_long and hml_same spell the same
// key bits in different cells; the serializer writes the shortest one.
enum class LabelForm { Short, Long, Same };

td::Ref<vm::Cell> relabel_node(td::Ref<vm::Cell> node, int max_len, LabelForm form, std::string_view name) {
  vm::dict::LabelParser label{std::move(node), max_len, vm::dict::LabelParser::chk_all};
  td::BitArray<16> bits;
  const int len = label.extract_label_to(bits.bits());
  const int len_bits = 32 - td::count_leading_zeroes32(static_cast<td::uint32>(max_len));
  vm::CellBuilder builder;
  bool ok = true;
  switch (form) {
    case LabelForm::Short:
      // hml_short$0 len:(Unary ~n) s:(n * Bit)
      ok = builder.store_long_bool(0, 1);
      for (int i = 0; ok && i < len; ++i) {
        ok = builder.store_long_bool(1, 1);
      }
      ok = ok && builder.store_long_bool(0, 1) && builder.store_bits_bool(bits.cbits(), len);
      break;
    case LabelForm::Long:
      // hml_long$10 n:(#<= m) s:(n * Bit)
      ok = builder.store_long_bool(2, 2) && builder.store_long_bool(len, len_bits) &&
           builder.store_bits_bool(bits.cbits(), len);
      break;
    case LabelForm::Same: {
      // hml_same$11 v:Bit n:(#<= m)
      const bool value = len > 0 && bits[0];
      for (int i = 0; i < len; ++i) {
        if (bits[i] != value) {
          fail("PQ_BLOCK_SIGNATURE_RELABEL_NOT_UNIFORM case=" + std::string(name));
        }
      }
      ok = builder.store_long_bool(3, 2) && builder.store_long_bool(value ? 1 : 0, 1) &&
           builder.store_long_bool(len, len_bits);
      break;
    }
  }
  if (!(ok && builder.append_cellslice_bool(*label.remainder))) {
    fail("PQ_BLOCK_SIGNATURE_RELABEL_FAILED case=" + std::string(name));
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> replace_ref(const td::Ref<vm::Cell>& cell, unsigned index, td::Ref<vm::Cell> replacement) {
  vm::CellSlice slice{vm::NoVm(), cell};
  vm::CellBuilder builder;
  builder.store_bits(slice.data_bits(), slice.size());
  for (unsigned i = 0; i < slice.size_refs(); ++i) {
    builder.store_ref(i == index ? replacement : slice.prefetch_ref(i));
  }
  return builder.finalize_novm();
}

int root_label_bits(const td::Ref<vm::Cell>& dict_root) {
  vm::dict::LabelParser label{dict_root, 16, vm::dict::LabelParser::chk_all};
  return label.l_bits;
}

// Re-encodes one edge label of the signatures dictionary held in ref 0 of a
// signature set root. The two-signer dictionary is a root fork with two leaves.
td::Ref<vm::Cell> relabel_signature_set(const td::Ref<vm::Cell>& set_root, int leaf, LabelForm form,
                                        std::string_view name) {
  const auto dict_root = vm::CellSlice{vm::NoVm(), set_root}.prefetch_ref(0);
  td::Ref<vm::Cell> new_dict;
  if (leaf < 0) {
    new_dict = relabel_node(dict_root, 16, form, name);
  } else {
    const int leaf_max_len = 16 - root_label_bits(dict_root) - 1;
    const auto leaf_node = vm::CellSlice{vm::NoVm(), dict_root}.prefetch_ref(leaf);
    new_dict = replace_ref(dict_root, leaf, relabel_node(leaf_node, leaf_max_len, form, name));
  }
  return replace_ref(set_root, 0, std::move(new_dict));
}

// The entries a dictionary holds, independent of how its nodes are encoded.
std::vector<std::pair<unsigned, td::Bits256>> dictionary_entries(const td::Ref<vm::Cell>& set_root,
                                                                 std::string_view name) {
  std::vector<std::pair<unsigned, td::Bits256>> entries;
  vm::Dictionary dict{vm::CellSlice{vm::NoVm(), set_root}.prefetch_ref(0), 16};
  const bool ok = dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_bits) {
    vm::CellBuilder builder;
    if (!builder.append_cellslice_bool(*value)) {
      return false;
    }
    entries.emplace_back(static_cast<unsigned>(key.get_uint(key_bits)),
                         td::Bits256{builder.finalize_novm()->get_hash().bits()});
    return true;
  });
  if (!ok || entries.empty()) {
    fail("PQ_BLOCK_SIGNATURE_DICTIONARY_ENUMERATION_FAILED case=" + std::string(name));
  }
  return entries;
}

struct LabelVariant {
  std::string_view name;
  int leaf;  // -1 is the root edge
  LabelForm form;
};

constexpr std::array<LabelVariant, 4> noncanonical_label_variants{{
    {"leaf-label-long", 0, LabelForm::Long},
    {"leaf-label-same", 1, LabelForm::Same},
    {"root-label-short", -1, LabelForm::Short},
    {"root-label-long", -1, LabelForm::Long},
}};

// A set whose signature dictionary is not in the serializer's form is the same
// signatures under a second cell hash, and is refused before any signature is
// verified. Returns the number of refused encodings.
std::size_t check_noncanonical_dictionary(const td::Ref<vm::Cell>& canonical, std::string_view prefix,
                                          std::string_view expected, td::Ref<block::ValidatorSet> trusted_set) {
  // Positive control for the re-encoder: writing each canonical label in its
  // own form reproduces the canonical cell bit for bit.
  if (relabel_signature_set(canonical, -1, LabelForm::Same, prefix)->get_hash() != canonical->get_hash() ||
      relabel_signature_set(canonical, 0, LabelForm::Short, prefix)->get_hash() != canonical->get_hash() ||
      relabel_signature_set(canonical, 1, LabelForm::Short, prefix)->get_hash() != canonical->get_hash()) {
    fail("PQ_BLOCK_SIGNATURE_RELABEL_CONTROL_FAILED case=" + std::string(prefix));
  }
  const auto canonical_entries = dictionary_entries(canonical, prefix);
  std::size_t refused = 0;
  for (const auto& variant : noncanonical_label_variants) {
    const auto name = std::string(prefix) + "-" + std::string(variant.name);
    auto encoded = relabel_signature_set(canonical, variant.leaf, variant.form, name);
    if (encoded->get_hash() == canonical->get_hash()) {
      fail("PQ_BLOCK_SIGNATURE_RELABEL_NO_CHANGE case=" + name);
    }
    // Same keys and values: only the encoding differs.
    if (dictionary_entries(encoded, name) != canonical_entries) {
      fail("PQ_BLOCK_SIGNATURE_RELABEL_CHANGED_ENTRIES case=" + name);
    }
    tos::ValidatorWeight ignored_weight = 0;
    expect_error(block::BlockSignatureSet::fetch(encoded, ignored_weight), expected, name + "-untrusted");
    if (trusted_set.not_null()) {
      expect_error(block::BlockSignatureSet::fetch(encoded, trusted_set), expected, name + "-trusted");
    }
    ++refused;
  }
  return refused;
}

td::Ref<vm::Cell> classical_signature_set(unsigned tag) {
  vm::Dictionary dict{16};
  for (unsigned i = 0; i < 2; ++i) {
    vm::CellBuilder pair;
    std::array<unsigned char, 64> signature{};
    signature.fill(static_cast<unsigned char>(0x41 + i));
    if (!(pair.store_bits_bool(hash_of("classical-node-" + std::to_string(i)).cbits(), 256) &&
          pair.store_long_bool(5, 4) && pair.store_bytes_bool(signature.data(), signature.size()) &&
          dict.set_builder(td::BitArray<16>{i}, pair, vm::Dictionary::SetMode::Add))) {
      fail("PQ_BLOCK_SIGNATURE_CLASSICAL_DICTIONARY_FAILED");
    }
  }
  vm::CellBuilder root;
  bool ok = root.store_long_bool(tag, 8) && root.store_long_bool(0x31415926, 32) &&
            root.store_long_bool(Fixture::catchain_seqno, 32) && root.store_long_bool(2, 32) &&
            root.store_long_bool(2, 64) && root.store_maybe_ref(std::move(dict).extract_root_cell());
  if (ok && tag == 0x12) {
    const auto id = block_id("classical");
    auto candidate_cell = vm::CellString::create(tos::serialize_tl_object(candidate(id), true));
    ok = candidate_cell.is_ok() && root.store_bits_bool(hash_of("classical-session").cbits(), 256) &&
         root.store_long_bool(Fixture::slot, 32) && root.store_ref_bool(candidate_cell.move_as_ok());
  }
  if (!ok) {
    fail("PQ_BLOCK_SIGNATURE_CLASSICAL_ROOT_FAILED");
  }
  return root.finalize_novm();
}

// The finality signature set dictionary must have exactly one encoding. The
// committed reproducer is a genuinely valid set whose leaf label was changed from
// hml_short to hml_long; it verified as final before the parser compared the
// dictionary with the canonical rebuild.
std::size_t check_canonical_signature_dictionaries() {
  Fixture fixture;
  const std::vector<std::size_t> signers{0, 1};
  auto data = candidate(fixture.id);
  auto signatures = fixture.sign(signers, fixture.session, Fixture::slot, data, true, fixture.id);
  const auto weight = fixture.weight_of(signers);
  auto canonical = require_ok(block::BlockSignatureSet::serialize_simplex_pq(
                                  signatures, Fixture::catchain_seqno, fixture.validator_set->get_validator_set_hash(),
                                  weight, fixture.session, Fixture::slot, data),
                              "canonical-dictionary-serialize");
  if (root_label_bits(vm::CellSlice{vm::NoVm(), canonical}.prefetch_ref(0)) != 15) {
    fail("PQ_BLOCK_SIGNATURE_UNEXPECTED_DICTIONARY_SHAPE case=canonical-dictionary");
  }

  // The honest encoding parses, verifies and serializes back to the same cell.
  const block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};
  const auto expect_final = [&](const td::Ref<vm::Cell>& cell, const std::string& name) {
    auto parsed = require_ok(block::BlockSignatureSet::fetch(cell, fixture.validator_set), name);
    if (require_ok(block::verify_pq_finality(context, *parsed, block::FinalityRole::Final), name + "-final") !=
        weight) {
      fail("PQ_BLOCK_SIGNATURE_WEIGHT_MISMATCH case=" + name + "-final");
    }
    auto reserialized =
        require_ok(block::BlockSignatureSet::serialize_simplex_pq(
                       require_ok(parsed->export_pq_signatures(), name + "-export"), parsed->get_catchain_seqno(),
                       parsed->get_validator_set_hash(), weight, fixture.session, Fixture::slot, data),
                   name + "-reserialize");
    if (reserialized->get_hash() != cell->get_hash()) {
      fail("PQ_BLOCK_SIGNATURE_ROUNDTRIP_DRIFT case=" + name);
    }
  };
  expect_final(canonical, "canonical-dictionary");

  std::size_t refused = check_noncanonical_dictionary(canonical, "pq-dictionary",
                                                      "pq signatures: noncanonical dictionary", fixture.validator_set);

  // The committed reproducer: a set signed by validators 0 and 1 of this fixture
  // (the signer randomizes, so it is read from disk rather than re-signed) whose
  // leaf 0 label is hml_long. Writing that label back in its short form gives a set
  // that is accepted and verifies as final; the reproducer itself is refused.
  auto bytes = require_ok(td::read_file(NONCANONICAL_LABEL_BOC), "reproducer-read");
  auto reproducer = require_ok(vm::std_boc_deserialize(bytes.as_slice()), "reproducer-boc");
  auto repaired = relabel_signature_set(reproducer, 0, LabelForm::Short, "reproducer");
  if (repaired->get_hash() == reproducer->get_hash() ||
      dictionary_entries(reproducer, "reproducer") != dictionary_entries(repaired, "reproducer-repaired")) {
    fail("PQ_BLOCK_SIGNATURE_REPRODUCER_NOT_A_REENCODING");
  }
  expect_final(repaired, "reproducer-repaired");
  tos::ValidatorWeight ignored_weight = 0;
  expect_error(block::BlockSignatureSet::fetch(reproducer, ignored_weight), "pq signatures: noncanonical dictionary",
               "reproducer-untrusted");
  expect_error(block::BlockSignatureSet::fetch(reproducer, fixture.validator_set),
               "pq signatures: noncanonical dictionary", "reproducer-trusted");
  ++refused;

  // The classical carriers read their dictionary through the other parser.
  for (const unsigned tag : {0x11u, 0x12u}) {
    const auto prefix = std::string(tag == 0x11 ? "ordinary" : "simplex") + "-dictionary";
    const auto classical = classical_signature_set(tag);
    tos::ValidatorWeight classical_weight = 0;
    auto classical_parsed = require_ok(block::BlockSignatureSet::fetch(classical, classical_weight), prefix);
    if (classical_parsed->get_size() != 2) {
      fail("PQ_BLOCK_SIGNATURE_CLASSICAL_SIZE case=" + prefix);
    }
    refused += check_noncanonical_dictionary(classical, prefix, "noncanonical signatures dict", {});
  }
  return refused;
}

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

  const auto noncanonical_refused = check_canonical_signature_dictionaries();
  std::printf("PQ_BLOCK_SIGNATURE_CONFORMANCE_OK positive_cases=7 negative_cases=%zu\n", 29 + noncanonical_refused);
  return 0;
}
