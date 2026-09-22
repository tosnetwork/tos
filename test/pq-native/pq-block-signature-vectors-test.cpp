/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "common/checksum.h"
#include "crypto/block/mc-config.h"
#include "crypto/block/pq-signature-limits.h"
#include "crypto/block/signature-set.h"
#include "crypto/block/validator-set.h"
#include "crypto/pq/pq-bytes.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include "block-signature-carrier-common.h"

namespace {

using block_signature_carrier_test::algorithm_id;
using block_signature_carrier_test::candidate;
using block_signature_carrier_test::catchain_seqno;
using block_signature_carrier_test::hash_of;
using block_signature_carrier_test::make_signatures;
using block_signature_carrier_test::session_id;
using block_signature_carrier_test::slot;
using block_signature_carrier_test::validator_set_hash;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

struct RawPair {
  td::Bits256 validator_id;
  td::uint16 algorithm;
  td::Ref<vm::Cell> signature;
};

struct VectorCase {
  std::string name;
  bool accept;
  std::string reason;
  td::Ref<vm::Cell> root;
  std::string constructor;
  td::uint32 validator_hash;
  td::uint32 cc_seqno;
  std::size_t sig_count;
  std::vector<td::Bits256> validator_ids;
  std::vector<td::uint16> algorithms;
  td::Bits256 session;
  td::uint32 candidate_slot;
  std::string candidate_hash;
  bool parse_with_validator_set{false};
};

std::string reason_code(const std::string& reason) {
  if (reason == "-")
    return "-";
  if (reason == "pq signatures: duplicate validator_id")
    return "duplicate_validator_id";
  if (reason == "pq signatures: unsupported algorithm")
    return "unsupported_algorithm";
  if (reason.find("pq signatures: signature length") == 0)
    return "signature_length";
  if (reason.find("pq signatures: noncanonical PQBytes") == 0)
    return "noncanonical_pqbytes";
  if (reason == "pq signatures: dictionary index")
    return "dictionary_index";
  if (reason == "pq signatures: dictionary missing entry")
    return "dictionary_missing_entry";
  if (reason == "pq signatures: dictionary extra entry")
    return "dictionary_extra_entry";
  if (reason == "pq candidate data: oversize")
    return "candidate_oversize";
  if (reason == "pq candidate data: noncanonical chunk size")
    return "candidate_noncanonical_chunk";
  if (reason == "pq candidate data: non-byte-aligned cell")
    return "candidate_non_byte_aligned";
  if (reason == "pq candidate data: multiple continuation refs")
    return "candidate_multiple_refs";
  if (reason == "pq candidate data: chain too long")
    return "candidate_chain_length";
  if (reason == "pq candidate data: trailing empty cell")
    return "candidate_trailing_ref";
  if (reason.find("pq candidate data: invalid TL") == 0)
    return "candidate_tl";
  if (reason == "pq signatures: signer count exceeds maximum")
    return "signer_count";
  if (reason == "pq signatures: unknown validator_id")
    return "unknown_validator_id";
  if (reason == "pq signatures: validator algorithm mismatch")
    return "validator_algorithm_mismatch";
  if (reason == "signature weight mismatch")
    return "weight_mismatch";
  if (reason == "unsupported carrier for post-quantum validator set")
    return "unsupported_carrier";
  fail("VECTOR_UNKNOWN_REASON reason=" + reason);
}

std::vector<std::string> split(const std::string& line, char delimiter) {
  std::vector<std::string> out;
  std::istringstream input(line);
  std::string field;
  while (std::getline(input, field, delimiter)) {
    out.push_back(std::move(field));
  }
  if (!line.empty() && line.back() == delimiter) {
    out.emplace_back();
  }
  return out;
}

std::size_t number(const std::string& text, const std::string& context) {
  std::size_t end = 0;
  const auto value = std::stoull(text, &end);
  if (end != text.size()) {
    fail("VECTOR_BAD_NUMBER case=" + context + " value=" + text);
  }
  return value;
}

td::Ref<vm::Cell> byte_chain(td::Slice bytes, const std::vector<std::size_t>& chunks) {
  std::size_t total = 0;
  for (const auto chunk : chunks) {
    total += chunk;
  }
  if (total != bytes.size()) {
    fail("VECTOR_BUILDER_BAD_CHUNKS");
  }
  td::Ref<vm::Cell> next;
  std::size_t end = bytes.size();
  for (std::size_t i = chunks.size(); i-- > 0;) {
    const auto chunk = chunks[i];
    end -= chunk;
    vm::CellBuilder builder;
    if (!builder.store_bytes_bool(bytes.substr(end, chunk)) ||
        (next.not_null() && !builder.store_ref_bool(std::move(next)))) {
      fail("VECTOR_BUILDER_BYTE_CHAIN");
    }
    next = builder.finalize_novm();
  }
  return next;
}

std::vector<std::size_t> greedy_chunks(std::size_t bytes) {
  std::vector<std::size_t> chunks;
  while (bytes != 0) {
    const auto chunk = std::min<std::size_t>(tos::pq::pq_bytes_chunk, bytes);
    chunks.push_back(chunk);
    bytes -= chunk;
  }
  return chunks;
}

td::Ref<vm::Cell> pq_bytes_with_trailing_ref(td::Slice bytes) {
  auto chunks = greedy_chunks(bytes.size());
  td::Ref<vm::Cell> next = vm::CellBuilder{}.finalize_novm();
  std::size_t end = bytes.size();
  for (std::size_t i = chunks.size(); i-- > 0;) {
    const auto chunk = chunks[i];
    end -= chunk;
    vm::CellBuilder builder;
    if (!builder.store_bytes_bool(bytes.substr(end, chunk)) || !builder.store_ref_bool(std::move(next))) {
      fail("VECTOR_BUILDER_TRAILING_REF");
    }
    next = builder.finalize_novm();
  }
  vm::CellBuilder root;
  if (!(root.store_long_bool(bytes.size(), 32) && root.store_ref_bool(std::move(next)))) {
    fail("VECTOR_BUILDER_PQ_BYTES");
  }
  return root.finalize_novm();
}

td::Ref<vm::Cell> candidate_cell(td::Slice bytes) {
  auto chunks = greedy_chunks(bytes.size());
  return byte_chain(bytes, chunks);
}

td::Ref<vm::Cell> empty_chain(std::size_t cells) {
  td::Ref<vm::Cell> next;
  while (cells-- != 0) {
    vm::CellBuilder builder;
    if (next.not_null() && !builder.store_ref_bool(std::move(next))) {
      fail("VECTOR_BUILDER_EMPTY_CHAIN");
    }
    next = builder.finalize_novm();
  }
  return next;
}

td::Ref<vm::Cell> candidate_with_trailing_ref(td::Slice candidate_bytes) {
  if (candidate_bytes.size() > tos::pq::pq_bytes_chunk) {
    fail("VECTOR_BUILDER_CANDIDATE_TOO_LARGE");
  }
  td::BufferSlice full_chunk(tos::pq::pq_bytes_chunk);
  std::memcpy(full_chunk.data(), candidate_bytes.data(), candidate_bytes.size());
  std::memset(full_chunk.data() + candidate_bytes.size(), 0, full_chunk.size() - candidate_bytes.size());
  vm::CellBuilder builder;
  if (!(builder.store_bytes_bool(full_chunk.as_slice()) && builder.store_ref_bool(vm::CellBuilder{}.finalize_novm()))) {
    fail("VECTOR_BUILDER_CANDIDATE_TRAILING_REF");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> raw_signature_set(const std::vector<std::pair<unsigned, RawPair>>& entries,
                                    std::size_t declared_count, tos::ValidatorWeight claimed_weight,
                                    td::Ref<vm::Cell> candidate_data, td::uint32 vset_hash = validator_set_hash,
                                    td::uint32 cc_seqno = catchain_seqno, unsigned tag = 0x13) {
  vm::Dictionary dict{16};
  for (const auto& [index, entry] : entries) {
    vm::CellBuilder value;
    if (!(value.store_bits_bool(entry.validator_id.cbits(), 256) && value.store_long_bool(entry.algorithm, 16) &&
          value.store_ref_bool(entry.signature) &&
          dict.set_builder(td::BitArray<16>{index}, value, vm::Dictionary::SetMode::Add))) {
      fail("VECTOR_BUILDER_DICTIONARY");
    }
  }
  vm::CellBuilder root;
  if (!(root.store_long_bool(tag, 8) && root.store_long_bool(vset_hash, 32) && root.store_long_bool(cc_seqno, 32) &&
        root.store_long_bool(declared_count, 32) && root.store_long_bool(claimed_weight, 64) &&
        root.store_maybe_ref(std::move(dict).extract_root_cell()) && root.store_bits_bool(session_id().cbits(), 256) &&
        root.store_long_bool(slot, 32) && root.store_ref_bool(std::move(candidate_data)))) {
    fail("VECTOR_BUILDER_ROOT");
  }
  return root.finalize_novm();
}

td::Ref<vm::Cell> old_signature_set(unsigned tag) {
  vm::CellBuilder root;
  if (!(root.store_long_bool(tag, 8) && root.store_long_bool(validator_set_hash, 32) &&
        root.store_long_bool(catchain_seqno, 32) && root.store_long_bool(0, 32) && root.store_long_bool(0, 64) &&
        root.store_bool_bool(false))) {
    fail("VECTOR_BUILDER_OLD_ROOT");
  }
  if (tag == 0x12) {
    const auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
    root.store_bits(session_id().cbits(), 256);
    root.store_long(slot, 32);
    root.store_ref(candidate_cell(candidate_bytes.as_slice()));
  }
  return root.finalize_novm();
}

std::vector<block::PQBlockSignature> pq_pairs(std::size_t count) {
  const auto signatures = make_signatures(count, false);
  std::vector<block::PQBlockSignature> result;
  result.reserve(count);
  for (const auto& signature : signatures) {
    result.push_back(block::PQBlockSignature{tos::ValidatorId{signature.validator_id}, tos::pq::PQAlgorithmId::mldsa44,
                                             signature.signature.clone()});
  }
  return result;
}

td::Ref<block::ValidatorSet> validator_set(const std::vector<td::Bits256>& validator_ids,
                                           const std::vector<td::uint16>& algorithms) {
  std::vector<tos::ValidatorDescr> validators;
  validators.reserve(validator_ids.size());
  for (std::size_t i = 0; i < validator_ids.size(); ++i) {
    const auto key_id = tos::ConsensusKeyId{hash_of("fixture-key-" + std::to_string(i))};
    validators.emplace_back(tos::ValidatorId{validator_ids[i]}, algorithms[i], key_id,
                            std::string(tos::pq::mldsa44_public_key_bytes, static_cast<char>(i + 1)), 1,
                            hash_of("fixture-adnl-" + std::to_string(i)));
  }
  return td::Ref<block::ValidatorSet>{true, catchain_seqno, tos::ShardIdFull{tos::masterchainId},
                                      std::move(validators)};
}

td::Ref<block::ValidatorSet> trusted_validator_set(const std::vector<td::Bits256>& validator_ids,
                                                   const std::vector<td::uint16>& algorithms) {
  std::vector<tos::ValidatorDescr> validators;
  validators.reserve(validator_ids.size());
  for (std::size_t i = 0; i < validator_ids.size(); ++i) {
    const auto public_key = std::string(tos::pq::mldsa44_public_key_bytes, static_cast<char>(i + 1));
    const auto derived = tos::pq::derive_key_id(static_cast<tos::pq::PQAlgorithmId>(algorithms[i]), public_key);
    if (!derived.has_value()) {
      fail("VECTOR_VALIDATOR_KEY_ID_DERIVATION_FAILED");
    }
    td::Bits256 key_id_bits;
    std::memcpy(key_id_bits.data(), derived->data(), derived->size());
    validators.emplace_back(tos::ValidatorId{validator_ids[i]}, algorithms[i], tos::ConsensusKeyId{key_id_bits},
                            public_key, 1, hash_of("fixture-adnl-" + std::to_string(i)));
  }
  return td::Ref<block::ValidatorSet>{true, catchain_seqno, tos::ShardIdFull{tos::masterchainId},
                                      std::move(validators)};
}

std::vector<td::Bits256> ids_of(const std::vector<block::PQBlockSignature>& signatures) {
  std::vector<td::Bits256> result;
  for (const auto& signature : signatures) {
    result.push_back(signature.validator_id.value);
  }
  return result;
}

std::vector<td::uint16> algorithms_of(const std::vector<block::PQBlockSignature>& signatures) {
  std::vector<td::uint16> result;
  for (const auto& signature : signatures) {
    result.push_back(static_cast<td::uint16>(signature.algorithm_id));
  }
  return result;
}

std::string candidate_hash() {
  const auto bytes = tos::serialize_tl_object(candidate(), true);
  return td::sha256_bits256(bytes.as_slice()).to_hex();
}

VectorCase valid_case(const std::string& name, std::size_t count) {
  auto signatures = pq_pairs(count);
  const auto ids = ids_of(signatures);
  const auto algorithms = algorithms_of(signatures);
  auto vset = validator_set(ids, algorithms);
  auto root = block::BlockSignatureSet::serialize_simplex_pq(signatures, catchain_seqno, vset->get_validator_set_hash(),
                                                             count, session_id(), slot, candidate());
  if (root.is_error()) {
    fail("VECTOR_VALID_SERIALIZATION_FAILED case=" + name + " reason=" + root.error().message().str());
  }
  return VectorCase{name,
                    true,
                    "-",
                    root.move_as_ok(),
                    "#13",
                    vset->get_validator_set_hash(),
                    catchain_seqno,
                    count,
                    ids,
                    algorithms,
                    session_id(),
                    slot,
                    candidate_hash(),
                    false};
}

RawPair raw_pair(std::size_t signer, std::size_t signature_bytes = tos::pq::mldsa44_signature_bytes,
                 td::uint16 pair_algorithm = algorithm_id) {
  auto bytes = block_signature_carrier_test::patterned_signature(signer);
  if (signature_bytes != bytes.size()) {
    td::BufferSlice resized(signature_bytes);
    const auto copied = std::min(signature_bytes, bytes.size());
    std::memcpy(resized.data(), bytes.data(), copied);
    if (signature_bytes > copied) {
      std::memset(resized.data() + copied, 0x5a, signature_bytes - copied);
    }
    bytes = std::move(resized);
  }
  auto packed = tos::pq::pack_pq_bytes(bytes.as_slice(), tos::pq::pq_bytes_hard_max);
  if (packed.is_error()) {
    fail("VECTOR_SIGNATURE_PACK_FAILED");
  }
  return RawPair{hash_of("persisted-validator-" + std::to_string(signer)), pair_algorithm, packed.move_as_ok()};
}

VectorCase rejected_case(std::string name, std::string reason, td::Ref<vm::Cell> root, std::size_t count,
                         std::vector<td::Bits256> ids, std::vector<td::uint16> algorithms, bool parse_with_vset = false,
                         td::uint32 vset_hash = validator_set_hash, std::string constructor = "#13") {
  return VectorCase{
      std::move(name),  false,          std::move(reason), std::move(root),       std::move(constructor), vset_hash,
      catchain_seqno,   count,          std::move(ids),    std::move(algorithms), session_id(),           slot,
      candidate_hash(), parse_with_vset};
}

std::vector<VectorCase> make_cases() {
  std::vector<VectorCase> cases;
  cases.push_back(valid_case("valid-1", 1));
  cases.push_back(valid_case("valid-21", 21));
  const auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
  const auto canonical_candidate = [&] { return candidate_cell(candidate_bytes.as_slice()); };

  auto first = raw_pair(0);
  auto duplicate = raw_pair(0);
  cases.push_back(rejected_case("duplicate-validator-id", "pq signatures: duplicate validator_id",
                                raw_signature_set({{0, first}, {1, duplicate}}, 2, 2, canonical_candidate()), 2,
                                {first.validator_id, duplicate.validator_id}, {first.algorithm, duplicate.algorithm}));

  auto unknown = raw_pair(0, tos::pq::mldsa44_signature_bytes, 2);
  cases.push_back(rejected_case("unknown-algorithm", "pq signatures: unsupported algorithm",
                                raw_signature_set({{0, unknown}}, 1, 1, canonical_candidate()), 1,
                                {unknown.validator_id}, {unknown.algorithm}));

  auto short_signature = raw_pair(0, tos::pq::mldsa44_signature_bytes - 1);
  cases.push_back(rejected_case("wrong-signature-length-short", "pq signatures: signature length 2419, expected 2420",
                                raw_signature_set({{0, short_signature}}, 1, 1, canonical_candidate()), 1,
                                {short_signature.validator_id}, {short_signature.algorithm}));

  auto long_signature = raw_pair(0, tos::pq::mldsa44_signature_bytes + 1);
  cases.push_back(rejected_case("wrong-signature-length-long", "pq signatures: signature length exceeds 2420",
                                raw_signature_set({{0, long_signature}}, 1, 1, canonical_candidate()), 1,
                                {long_signature.validator_id}, {long_signature.algorithm}));

  auto noncanonical_bytes = block_signature_carrier_test::patterned_signature(0);
  RawPair noncanonical{hash_of("persisted-validator-0"), algorithm_id,
                       pq_bytes_with_trailing_ref(noncanonical_bytes.as_slice())};
  cases.push_back(rejected_case("noncanonical-pqbytes", "pq signatures: noncanonical PQBytes: pq-bytes: trailing ref",
                                raw_signature_set({{0, noncanonical}}, 1, 1, canonical_candidate()), 1,
                                {noncanonical.validator_id}, {noncanonical.algorithm}));

  auto count_pair = raw_pair(0);
  cases.push_back(rejected_case("sig-count-mismatch", "pq signatures: dictionary missing entry",
                                raw_signature_set({{0, count_pair}}, 2, 1, canonical_candidate()), 2,
                                {count_pair.validator_id}, {count_pair.algorithm}));

  auto gap0 = raw_pair(0);
  auto gap2 = raw_pair(2);
  cases.push_back(rejected_case("dictionary-gap", "pq signatures: dictionary index",
                                raw_signature_set({{0, gap0}, {2, gap2}}, 2, 2, canonical_candidate()), 2,
                                {gap0.validator_id, gap2.validator_id}, {gap0.algorithm, gap2.algorithm}));

  auto extra0 = raw_pair(0);
  auto extra1 = raw_pair(1);
  cases.push_back(rejected_case("dictionary-extra-entry", "pq signatures: dictionary extra entry",
                                raw_signature_set({{0, extra0}, {1, extra1}}, 1, 2, canonical_candidate()), 1,
                                {extra0.validator_id, extra1.validator_id}, {extra0.algorithm, extra1.algorithm}));

  td::BufferSlice oversize_candidate(block::pq::pq_candidate_data_max_bytes + 1);
  std::memcpy(oversize_candidate.data(), candidate_bytes.data(), candidate_bytes.size());
  std::memset(oversize_candidate.data() + candidate_bytes.size(), 0,
              oversize_candidate.size() - candidate_bytes.size());
  auto oversize_pair = raw_pair(0);
  cases.push_back(
      rejected_case("candidate-data-oversize", "pq candidate data: oversize",
                    raw_signature_set({{0, oversize_pair}}, 1, 1, candidate_cell(oversize_candidate.as_slice())), 1,
                    {oversize_pair.validator_id}, {oversize_pair.algorithm}));

  auto candidate_chunks = std::vector<std::size_t>{1, candidate_bytes.size() - 1};
  auto candidate_noncanonical_pair = raw_pair(0);
  cases.push_back(rejected_case("candidate-data-noncanonical-chunk", "pq candidate data: noncanonical chunk size",
                                raw_signature_set({{0, candidate_noncanonical_pair}}, 1, 1,
                                                  byte_chain(candidate_bytes.as_slice(), candidate_chunks)),
                                1, {candidate_noncanonical_pair.validator_id},
                                {candidate_noncanonical_pair.algorithm}));

  vm::CellBuilder nonaligned_builder;
  nonaligned_builder.store_bytes(candidate_bytes.as_slice());
  nonaligned_builder.store_bool_bool(true);
  auto nonaligned_pair = raw_pair(0);
  cases.push_back(rejected_case("candidate-data-non-byte-aligned", "pq candidate data: non-byte-aligned cell",
                                raw_signature_set({{0, nonaligned_pair}}, 1, 1, nonaligned_builder.finalize_novm()), 1,
                                {nonaligned_pair.validator_id}, {nonaligned_pair.algorithm}));

  vm::CellBuilder multi_ref_builder;
  multi_ref_builder.store_bytes(candidate_bytes.as_slice());
  multi_ref_builder.store_ref(vm::CellBuilder{}.finalize_novm());
  multi_ref_builder.store_ref(vm::CellBuilder{}.finalize_novm());
  auto multi_ref_pair = raw_pair(0);
  cases.push_back(rejected_case("candidate-data-multiple-refs", "pq candidate data: multiple continuation refs",
                                raw_signature_set({{0, multi_ref_pair}}, 1, 1, multi_ref_builder.finalize_novm()), 1,
                                {multi_ref_pair.validator_id}, {multi_ref_pair.algorithm}));

  auto overlong_pair = raw_pair(0);
  cases.push_back(
      rejected_case("candidate-data-overlong-chain", "pq candidate data: chain too long",
                    raw_signature_set({{0, overlong_pair}}, 1, 1, empty_chain(vm::CellString::max_chain_length + 1)), 1,
                    {overlong_pair.validator_id}, {overlong_pair.algorithm}));

  auto trailing_ref_pair = raw_pair(0);
  cases.push_back(rejected_case(
      "candidate-data-trailing-ref", "pq candidate data: trailing empty cell",
      raw_signature_set({{0, trailing_ref_pair}}, 1, 1, candidate_with_trailing_ref(candidate_bytes.as_slice())), 1,
      {trailing_ref_pair.validator_id}, {trailing_ref_pair.algorithm}));

  td::BufferSlice trailing_candidate(candidate_bytes.size() + 4);
  std::memcpy(trailing_candidate.data(), candidate_bytes.data(), candidate_bytes.size());
  std::memset(trailing_candidate.data() + candidate_bytes.size(), 0, 4);
  auto trailing_pair = raw_pair(0);
  cases.push_back(
      rejected_case("candidate-data-trailing-tl", "pq candidate data: invalid TL: Too much data to fetch at 120",
                    raw_signature_set({{0, trailing_pair}}, 1, 1, candidate_cell(trailing_candidate.as_slice())), 1,
                    {trailing_pair.validator_id}, {trailing_pair.algorithm}));

  std::vector<std::pair<unsigned, RawPair>> too_many_entries;
  std::vector<td::Bits256> too_many_ids;
  std::vector<td::uint16> too_many_algorithms;
  too_many_entries.reserve(401);
  for (unsigned i = 0; i < 401; ++i) {
    auto entry = raw_pair(i);
    too_many_ids.push_back(entry.validator_id);
    too_many_algorithms.push_back(entry.algorithm);
    too_many_entries.emplace_back(i, std::move(entry));
  }
  cases.push_back(rejected_case("401-signers", "pq signatures: signer count exceeds maximum",
                                raw_signature_set(too_many_entries, 401, 401, canonical_candidate()), 401,
                                std::move(too_many_ids), std::move(too_many_algorithms)));

  auto weight_signatures = pq_pairs(1);
  auto weight_ids = ids_of(weight_signatures);
  auto weight_algorithms = algorithms_of(weight_signatures);
  auto weight_vset = trusted_validator_set(weight_ids, weight_algorithms);
  auto weight_pair = raw_pair(0);
  cases.push_back(rejected_case(
      "claimed-weight-mismatch", "signature weight mismatch",
      raw_signature_set({{0, weight_pair}}, 1, 2, canonical_candidate(), weight_vset->get_validator_set_hash()), 1,
      weight_ids, weight_algorithms, true, weight_vset->get_validator_set_hash()));

  auto known_signer = raw_pair(0);
  auto absent_signer = raw_pair(1);
  auto known_vset = trusted_validator_set({known_signer.validator_id}, {known_signer.algorithm});
  cases.push_back(rejected_case("unknown-validator-id", "pq signatures: unknown validator_id",
                                raw_signature_set({{0, known_signer}, {1, absent_signer}}, 2, 1, canonical_candidate(),
                                                  known_vset->get_validator_set_hash()),
                                2, {known_signer.validator_id}, {known_signer.algorithm}, true,
                                known_vset->get_validator_set_hash()));

  auto algorithm_mismatch_pair = raw_pair(0);
  auto algorithm_mismatch_vset = validator_set({algorithm_mismatch_pair.validator_id}, {2});
  cases.push_back(rejected_case("validator-algorithm-mismatch", "pq signatures: validator algorithm mismatch",
                                raw_signature_set({{0, algorithm_mismatch_pair}}, 1, 1, canonical_candidate(),
                                                  algorithm_mismatch_vset->get_validator_set_hash()),
                                1, {algorithm_mismatch_pair.validator_id}, {2}, true,
                                algorithm_mismatch_vset->get_validator_set_hash()));

  auto old_id = hash_of("persisted-validator-0");
  cases.push_back(rejected_case("old-11-under-pq-vset", "unsupported carrier for post-quantum validator set",
                                old_signature_set(0x11), 0, {old_id}, {algorithm_id}, true, validator_set_hash, "#11"));
  cases.push_back(rejected_case("old-12-under-pq-vset", "unsupported carrier for post-quantum validator set",
                                old_signature_set(0x12), 0, {old_id}, {algorithm_id}, true, validator_set_hash, "#12"));
  return cases;
}

std::string join_bits(const std::vector<td::Bits256>& values) {
  std::string result;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      result += ',';
    }
    result += values[i].to_hex();
  }
  return result.empty() ? "-" : result;
}

std::string join_algorithms(const std::vector<td::uint16>& values) {
  std::string result;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      result += ',';
    }
    result += std::to_string(values[i]);
  }
  return result.empty() ? "-" : result;
}

std::vector<td::Bits256> parse_bits(const std::string& text) {
  std::vector<td::Bits256> result;
  if (text == "-") {
    return result;
  }
  for (const auto& item : split(text, ',')) {
    td::Bits256 value;
    if (!value.from_hex(item)) {
      fail("VECTOR_BAD_BITS256 value=" + item);
    }
    result.push_back(value);
  }
  return result;
}

std::vector<td::uint16> parse_algorithms(const std::string& text) {
  std::vector<td::uint16> result;
  if (text == "-") {
    return result;
  }
  for (const auto& item : split(text, ',')) {
    const auto value = number(item, "algorithm");
    if (value > std::numeric_limits<td::uint16>::max()) {
      fail("VECTOR_BAD_ALGORITHM value=" + item);
    }
    result.push_back(static_cast<td::uint16>(value));
  }
  return result;
}

void write_fixture(const std::vector<VectorCase>& cases) {
  std::ofstream output(VECTORS_FILE, std::ios::trunc);
  if (!output) {
    fail("VECTOR_FIXTURE_WRITE_FAILED");
  }
  output << "# Shared canonical post-quantum BlockSignatures vectors. Fields are tab-separated.\n";
  output << "# validator_ids and algorithm_ids describe the trusted set for vset-dependent rejects; otherwise they "
            "describe the pairs.\n";
  output << "# case outcome reason_code reason boc_hex constructor validator_set_hash catchain_seqno sig_count "
            "validator_ids "
            "algorithm_ids session_id slot candidate_sha256\n";
  for (const auto& item : cases) {
    auto boc = vm::std_boc_serialize(item.root, 0);
    if (boc.is_error()) {
      fail("VECTOR_BOC_SERIALIZATION_FAILED case=" + item.name);
    }
    output << item.name << '\t' << (item.accept ? "accept" : "reject") << '\t' << reason_code(item.reason) << '\t'
           << item.reason << '\t' << td::hex_encode(boc.ok().as_slice()) << '\t' << item.constructor << '\t'
           << item.validator_hash << '\t' << item.cc_seqno << '\t' << item.sig_count << '\t'
           << join_bits(item.validator_ids) << '\t' << join_algorithms(item.algorithms) << '\t' << item.session.to_hex()
           << '\t' << item.candidate_slot << '\t' << item.candidate_hash << '\n';
  }
}

void verify_fixture(const std::vector<VectorCase>& definitions) {
  std::map<std::string, const VectorCase*> expected;
  for (const auto& item : definitions) {
    expected.emplace(item.name, &item);
  }
  std::set<std::string> seen;
  std::ifstream input(VECTORS_FILE);
  if (!input) {
    fail("VECTOR_FIXTURE_MISSING");
  }
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto row = split(line, '\t');
    if (row.size() != 14) {
      fail("VECTOR_BAD_ROW fields=" + std::to_string(row.size()));
    }
    const auto definition = expected.find(row[0]);
    if (definition == expected.end()) {
      fail("VECTOR_UNCLAIMED_ROW case=" + row[0]);
    }
    if (!seen.insert(row[0]).second) {
      fail("VECTOR_DUPLICATE_ROW case=" + row[0]);
    }
    const auto* item = definition->second;
    if (row[1] != (item->accept ? "accept" : "reject") || row[2] != reason_code(item->reason) ||
        row[3] != item->reason || row[5] != item->constructor || number(row[6], row[0]) != item->validator_hash ||
        number(row[7], row[0]) != item->cc_seqno || number(row[8], row[0]) != item->sig_count ||
        row[9] != join_bits(item->validator_ids) || row[10] != join_algorithms(item->algorithms) ||
        row[11] != item->session.to_hex() || number(row[12], row[0]) != item->candidate_slot ||
        row[13] != item->candidate_hash) {
      fail("VECTOR_METADATA_MISMATCH case=" + row[0]);
    }
    auto generated_boc = vm::std_boc_serialize(item->root, 0);
    if (generated_boc.is_error() || td::hex_encode(generated_boc.ok().as_slice()) != row[4]) {
      fail("VECTOR_BOC_DRIFT case=" + row[0]);
    }
    auto bytes = td::hex_decode(row[4]);
    if (bytes.is_error()) {
      fail("VECTOR_BAD_BOC_HEX case=" + row[0]);
    }
    auto root = vm::std_boc_deserialize(bytes.move_as_ok());
    if (root.is_error()) {
      fail("VECTOR_BAD_BOC case=" + row[0] + " reason=" + root.error().message().str());
    }
    td::Result<td::Ref<block::BlockSignatureSet>> parsed;
    // The shared accept vectors are codec fixtures: their signatures and descriptor
    // metadata are patterned bytes, not cryptographic authority. Only cases whose
    // refusal itself needs a trusted set take the authoritative fetch path here.
    if (item->parse_with_validator_set) {
      auto ids = parse_bits(row[9]);
      auto algorithms = parse_algorithms(row[10]);
      if (ids.empty() && !item->accept) {
        ids.push_back(hash_of("persisted-validator-0"));
        algorithms.push_back(algorithm_id);
      }
      const auto authoritative_weights = row[0] == "claimed-weight-mismatch" || row[0] == "unknown-validator-id";
      auto vset = authoritative_weights ? trusted_validator_set(ids, algorithms) : validator_set(ids, algorithms);
      parsed = block::BlockSignatureSet::fetch(root.move_as_ok(), std::move(vset));
    } else {
      tos::ValidatorWeight claimed_weight = 0;
      parsed = block::BlockSignatureSet::fetch(root.move_as_ok(), claimed_weight);
    }
    if (!item->accept) {
      if (parsed.is_ok()) {
        fail("VECTOR_UNEXPECTED_ACCEPT case=" + row[0] + " expected=" + row[2]);
      }
      const auto actual = parsed.error().message().str();
      if (actual != row[3]) {
        fail("VECTOR_REASON_MISMATCH case=" + row[0] + " expected=" + row[3] + " actual=" + actual);
      }
      if (reason_code(actual) != row[2]) {
        fail("VECTOR_REASON_CODE_MISMATCH case=" + row[0] + " expected=" + row[2] + " actual=" + reason_code(actual));
      }
      continue;
    }
    if (parsed.is_error()) {
      fail("VECTOR_UNEXPECTED_REJECT case=" + row[0] + " actual=" + parsed.error().message().str());
    }
    const auto signature_set = parsed.move_as_ok();
    if (!signature_set->is_pq() || !signature_set->is_final() || signature_set->get_size() != item->sig_count ||
        signature_set->get_validator_set_hash() != item->validator_hash ||
        signature_set->get_catchain_seqno() != item->cc_seqno) {
      fail("VECTOR_PARSED_METADATA_MISMATCH case=" + row[0]);
    }
    auto parsed_signatures = signature_set->export_pq_signatures();
    auto parsed_session = signature_set->pq_session_id();
    auto parsed_slot = signature_set->pq_slot();
    auto parsed_candidate = signature_set->pq_candidate_data();
    if (parsed_signatures.is_error() || parsed_session.is_error() || parsed_slot.is_error() ||
        parsed_candidate.is_error()) {
      fail("VECTOR_PARSED_EXPORT_FAILED case=" + row[0]);
    }
    const auto ids = ids_of(parsed_signatures.ok());
    const auto algorithms = algorithms_of(parsed_signatures.ok());
    if (join_bits(ids) != row[9] || join_algorithms(algorithms) != row[10] || parsed_session.ok().to_hex() != row[11] ||
        parsed_slot.ok() != number(row[12], row[0]) ||
        td::sha256_bits256(parsed_candidate.ok().as_slice()).to_hex() != row[13]) {
      fail("VECTOR_PARSED_CONTENT_MISMATCH case=" + row[0]);
    }
    auto candidate_object =
        tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(parsed_candidate.ok().as_slice(), true);
    if (candidate_object.is_error()) {
      fail("VECTOR_CANDIDATE_REPARSE_FAILED case=" + row[0] + " actual=" + candidate_object.error().message().str());
    }
    auto reserialized = block::BlockSignatureSet::serialize_simplex_pq(
        parsed_signatures.ok(), item->cc_seqno, item->validator_hash, item->sig_count, parsed_session.ok(),
        parsed_slot.ok(), candidate_object.ok());
    if (reserialized.is_error()) {
      fail("VECTOR_RESERIALIZATION_FAILED case=" + row[0] + " actual=" + reserialized.error().message().str());
    }
    auto reserialized_boc = vm::std_boc_serialize(reserialized.move_as_ok(), 0);
    if (reserialized_boc.is_error() || td::hex_encode(reserialized_boc.ok().as_slice()) != row[4]) {
      fail("VECTOR_RESERIALIZATION_DRIFT case=" + row[0]);
    }
  }
  for (const auto& [name, item] : expected) {
    if (!seen.contains(name)) {
      fail("VECTOR_MISSING_ROW case=" + name);
    }
  }
  std::printf("PQ_BLOCK_SIGNATURE_VECTORS_OK rows=%zu\n", seen.size());
}

}  // namespace

int main(int argc, char** argv) {
  const auto cases = make_cases();
  if (argc == 2 && std::string(argv[1]) == "--write-fixture") {
    write_fixture(cases);
    return 0;
  }
  if (argc != 1) {
    fail("usage: test-pq-block-signature-vectors [--write-fixture]");
  }
  verify_fixture(cases);
  return 0;
}
