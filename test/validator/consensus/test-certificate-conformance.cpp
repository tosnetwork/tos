/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The structural and cryptographic guards on the live Simplex entrypoints, exercised
// with real post-quantum consensus keys.
//
// This runs the production parsers themselves: Signed<Vote>::from_tl, Certificate<T>::from_tl
// and Candidate::deserialize. Nothing here re-implements quorum arithmetic or signature
// checking, and no verification result is supplied by the test; every acceptance below is a
// real ML-DSA-44 verification against the key the validator set records, and every refusal is
// the production code's own.
//
// The guards covered are the ones a Simplex certificate rests on:
//   * a vote signature belongs to the signer, the session and that exact vote role;
//   * a certificate refuses an out-of-range index, a repeated signer, a sub-quorum weight and
//     an invalid signature, including one that arrives after the quorum is already met;
//   * weight, not signer count, decides the quorum;
//   * a candidate's leader comes from the collator schedule and its producer identity comes
//     from the validator set, never from the wire or from the signing key.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "crypto/pq/consensus-pq-signer.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "validator/consensus/simplex/votes.h"
#include "vm/boc.h"
#include "vm/vm.h"

namespace c = tos::validator::consensus;
namespace sx = tos::validator::consensus::simplex;

namespace {

unsigned checks = 0;

void expect(bool condition, const char* label) {
  if (!condition) {
    std::fprintf(stderr, "FAIL %s\n", label);
    std::abort();
  }
  ++checks;
}

// A refusal is only evidence when it is the refusal we meant. Matching the reason keeps a
// test from passing because the fixture broke somewhere earlier.
template <class T>
void reject(td::Result<T> result, const char* label, const char* reason) {
  expect(result.is_error(), label);
  if (result.error().message().str().find(reason) == std::string::npos) {
    std::fprintf(stderr, "FAIL %s: expected reason '%s', got '%s'\n", label, reason, result.error().message().c_str());
    std::abort();
  }
  ++checks;
}

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

std::string_view sv(td::Slice slice) {
  return std::string_view(slice.data(), slice.size());
}

std::string hex(td::Slice data) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (std::size_t i = 0; i < data.size(); ++i) {
    auto byte = static_cast<unsigned char>(data[i]);
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}

// One transcript line per signing domain: the exact bytes this build signs, the key they
// verify under, and the signature. check-simplex-preimages.py rebuilds the preimage from
// the TL constructor schemas and compares, so a change to what consensus signs cannot pass
// unnoticed just because the same serializer produced both sides.
void transcript(const char* label, const tos::pq::ConsensusPQKey& key, td::Slice message, td::Slice signature) {
  std::printf("VECTOR\t%s\t%s\t%s\t%s\n", label, hex(td::Slice(key.public_key)).c_str(), hex(message).c_str(),
              hex(signature).c_str());
}

struct Schedule final : c::CollatorSchedule {
  c::PeerValidatorId expected_collator_for(td::uint32) const override {
    return c::PeerValidatorId{0};
  }
};

struct Fixture {
  c::Bus bus;
  std::vector<tos::pq::ValidatorPQKeyStore> stores;
  tos::BlockIdExt block_id{tos::BlockId{tos::masterchainId, tos::shardIdAll, 7}, fill(0x31), fill(0x32)};
  c::CandidateHashData candidate_data = c::CandidateHashData::create_empty(block_id, c::CandidateId{6, fill(0x33)});
  c::CandidateId candidate_id = candidate_data.build_id_with(7);

  explicit Fixture(const std::vector<tos::ValidatorWeight>& weights = {1, 1, 1}, unsigned char seed_base = 0x40) {
    bus.session_id = fill(0x42);
    bus.shard = tos::ShardIdFull{tos::masterchainId};
    bus.cc_seqno = 11;
    bus.total_weight = 0;
    bus.collator_schedule = td::make_ref<Schedule>();
    for (std::size_t i = 0; i < weights.size(); ++i) {
      // Deliberately public fixture seeds, never operational key material.
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(seed_base + i)));
      expect(store.has_value(), "fixture-key-store");
      stores.push_back(std::move(*store));
      // The identity is the descriptor's own, unrelated to the consensus key, so anything
      // that reconstructs it from a key produces different bytes and is caught here.
      auto adnl = tos::adnl::AdnlNodeIdShort{fill(static_cast<unsigned char>(0x90 + i))};
      bus.validator_set.push_back(c::PeerValidator{
          .validator_id = tos::ValidatorId{fill(static_cast<unsigned char>(0x70 + i))},
          .idx = c::PeerValidatorId{i},
          .consensus_key = stores.back().consensus_key(),
          .transport_key_id = adnl.pubkey_hash(),
          .adnl_id = adnl,
          .weight = weights[i],
      });
      expect(tos::checked_add_validator_weight(bus.total_weight, weights[i]), "fixture-weight");
    }
  }

  // The exact bytes consensus signs: the session-bound envelope around the serialized
  // unsigned object. check_signature rebuilds this same envelope on the verifying side.
  td::BufferSlice envelope(td::Slice inner) const {
    return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(bus.session_id, td::BufferSlice(inner));
  }

  td::BufferSlice sign(std::size_t i, td::Slice inner) const {
    auto signed_bytes = envelope(inner);
    auto signature = stores.at(i).sign_consensus(sv(signed_bytes.as_slice()));
    expect(signature.has_value(), "fixture-sign");
    return td::BufferSlice(signature->signature);
  }

  // `who` may name an index outside the set on purpose; those entries are signed by
  // validator 0 so the refusal under test is the index check, not a missing signature.
  template <typename Vote>
  sx::tl::VoteSignatureSetRef signatures(const Vote& vote, const std::vector<int>& who,
                                         bool corrupt_last = false) const {
    auto inner = tos::serialize_tl_object(vote.to_tl(), true);
    std::vector<sx::tl::VoteSignatureRef> result;
    for (int i : who) {
      const bool in_range = i >= 0 && i < static_cast<int>(stores.size());
      auto signature = sign(in_range ? static_cast<std::size_t>(i) : 0, inner.as_slice());
      result.push_back(tos::create_tl_object<sx::tl::voteSignature>(i, std::move(signature)));
    }
    if (corrupt_last) {
      result.back()->signature_.as_slice()[0] ^= 1;
    }
    return tos::create_tl_object<sx::tl::voteSignatureSet>(std::move(result));
  }
};

// A vote signature authenticates one signer, one session and one vote role. The role check
// is the one that is easy to lose: the three vote kinds carry the same candidate id, so a
// notarize signature replayed as a finalize vote would be a finality forgery.
void votes(Fixture& f) {
  const std::vector<sx::Vote> all = {sx::Vote{sx::NotarizeVote{f.candidate_id}},
                                     sx::Vote{sx::FinalizeVote{f.candidate_id}}, sx::Vote{sx::SkipVote{7}}};
  const char* labels[] = {"notarize", "finalize", "skip"};
  for (std::size_t i = 0; i < all.size(); ++i) {
    auto inner = tos::serialize_tl_object(all[i].to_tl(), true);
    auto signature = f.sign(0, inner.as_slice());
    transcript(labels[i], f.bus.validator_set[0].consensus_key, f.envelope(inner.as_slice()).as_slice(),
               signature.as_slice());

    auto good = tos::create_tl_object<sx::tl::vote>(all[i].to_tl(), signature.clone());
    expect(
        sx::Signed<sx::Vote>::deserialize(tos::serialize_tl_object(good, true), c::PeerValidatorId{0}, f.bus).is_ok(),
        "vote-accepted");

    for (std::size_t j = 0; j < all.size(); ++j) {
      auto item = tos::create_tl_object<sx::tl::vote>(all[j].to_tl(), signature.clone());
      expect(sx::Signed<sx::Vote>::from_tl(std::move(*item), c::PeerValidatorId{0}, f.bus).is_ok() == (i == j),
             "vote-role-binding");
    }

    // 2420 is ML-DSA-44's own length; every other width, including the classical 64, must be
    // refused by the verifier rather than reinterpreted.
    for (std::size_t size : {std::size_t{0}, std::size_t{64}, std::size_t{2419}, std::size_t{2421}}) {
      auto item = tos::create_tl_object<sx::tl::vote>(all[i].to_tl(), td::BufferSlice(std::string(size, 'x')));
      reject(sx::Signed<sx::Vote>::from_tl(std::move(*item), c::PeerValidatorId{0}, f.bus), "vote-signature-width",
             "Invalid vote signature");
    }

    auto wrong_signer = tos::create_tl_object<sx::tl::vote>(all[i].to_tl(), signature.clone());
    reject(sx::Signed<sx::Vote>::from_tl(std::move(*wrong_signer), c::PeerValidatorId{1}, f.bus), "vote-wrong-signer",
           "Invalid vote signature");

    auto other_session = f.bus.session_id;
    f.bus.session_id = fill(0x43);
    expect(!f.bus.validator_set[0].check_signature(f.bus.session_id, inner.as_slice(), signature.as_slice()),
           "vote-wrong-session");
    f.bus.session_id = other_session;
  }
}

void certificates(Fixture& f) {
  const std::vector<sx::Vote> all = {sx::Vote{sx::NotarizeVote{f.candidate_id}},
                                     sx::Vote{sx::FinalizeVote{f.candidate_id}}, sx::Vote{sx::SkipVote{7}}};
  for (const auto& vote : all) {
    auto evaluate = [&](const std::vector<int>& who, bool corrupt = false) {
      return sx::Certificate<sx::Vote>::from_tl(std::move(*f.signatures(vote, who, corrupt)), vote, f.bus);
    };
    expect(evaluate({0, 1}).is_ok(), "certificate-quorum");
    reject(evaluate({0}), "certificate-below-quorum", "Not enough");
    reject(evaluate({0, 0}), "certificate-duplicate-signer", "Duplicate");
    reject(evaluate({0, -1}), "certificate-negative-index", "Invalid validator");
    reject(evaluate({0, 3}), "certificate-unknown-index", "Invalid validator");
    reject(evaluate({0, 1}, true), "certificate-invalid-signature", "Invalid vote signature");
    // Reaching the quorum must not stop the verification: the third signature is checked
    // even though the first two already carry the weight.
    reject(evaluate({0, 1, 2}, true), "certificate-invalid-after-quorum", "Invalid vote signature");

    auto cert = evaluate({0, 1}).move_as_ok();
    auto wire = tos::fetch_tl_object<sx::tl::certificate>(cert->serialize(), true).move_as_ok();
    expect(sx::Certificate<sx::Vote>::from_tl(std::move(*wire), f.bus).is_ok(), "certificate-wire-roundtrip");
  }

  // Weight decides, not the number of signers: one validator holding 7 of 10 is a quorum,
  // and two holding 3 of 10 between them is not.
  Fixture weighted({7, 2, 1}, 0x50);
  sx::NotarizeVote vote{weighted.candidate_id};
  expect(sx::NotarCert::from_tl(std::move(*weighted.signatures(vote, {0})), vote, weighted.bus).is_ok(),
         "certificate-weight-single-signer-quorum");
  reject(sx::NotarCert::from_tl(std::move(*weighted.signatures(vote, {1, 2})), vote, weighted.bus),
         "certificate-weight-two-signers-below-quorum", "Not enough");
}

// Conversion preserves the exact certificate bytes and takes authority metadata from the
// trusted descriptor, in canonical signer-index order. It also rechecks every structural
// premise needed to make a persisted carrier safe to construct.
void carrier_conversion(Fixture& f) {
  auto candidate = td::make_ref<c::Candidate>(f.candidate_id, f.candidate_data.parent, c::PeerValidatorId{0},
                                              f.block_id, td::BufferSlice());
  sx::FinalizeVote final_vote{f.candidate_id};
  auto final_cert =
      sx::FinalCert::from_tl(std::move(*f.signatures(final_vote, {1, 0})), final_vote, f.bus).move_as_ok();
  auto final_set = final_cert->to_signature_set(candidate, f.bus).move_as_ok();
  expect(final_set->is_pq() && final_set->is_final(), "final-cert-converted-to-pq-final");
  auto final_pairs = final_set->export_pq_signatures().move_as_ok();
  expect(final_pairs.size() == final_cert->signatures.size(), "final-cert-conversion-count");
  for (std::size_t i = 0; i < final_pairs.size(); ++i) {
    const auto& descriptor = f.bus.validator_set[i];
    expect(final_pairs[i].validator_id == descriptor.validator_id, "conversion-validator-id-from-descriptor");
    expect(final_pairs[i].algorithm_id == descriptor.consensus_key.algorithm_id,
           "conversion-algorithm-from-descriptor");
    auto source = std::find_if(final_cert->signatures.begin(), final_cert->signatures.end(),
                               [i](const auto& item) { return item.validator.value() == i; });
    expect(source != final_cert->signatures.end(), "conversion-source-signature-present");
    expect(final_pairs[i].signature.as_slice() == source->signature.as_slice(), "conversion-preserves-signature-bytes");
  }

  sx::NotarizeVote notar_vote{f.candidate_id};
  auto notar = sx::NotarCert::from_tl(std::move(*f.signatures(notar_vote, {0, 1})), notar_vote, f.bus).move_as_ok();
  auto approve_set = notar->to_signature_set(candidate, f.bus).move_as_ok();
  expect(approve_set->is_pq() && !approve_set->is_final(), "notar-cert-converted-to-pq-approve");

  auto wrong_candidate = td::make_ref<c::Candidate>(c::CandidateId{8, fill(0x91)}, f.candidate_data.parent,
                                                    c::PeerValidatorId{0}, f.block_id, td::BufferSlice());
  reject(final_cert->to_signature_set(wrong_candidate, f.bus), "conversion-vote-candidate-mismatch",
         "vote id does not match candidate id");

  std::vector<sx::FinalCert::VoteSignature> short_signatures;
  for (const auto& item : final_cert->signatures) {
    short_signatures.push_back({item.validator, item.signature.clone()});
  }
  short_signatures[0].signature = td::BufferSlice(std::string(2419, 's'));
  auto short_cert = td::make_ref<sx::FinalCert>(final_vote, std::move(short_signatures));
  reject(short_cert->to_signature_set(candidate, f.bus), "conversion-signature-length", "wrong length");

  auto below = sx::FinalCert::from_tl(std::move(*f.signatures(final_vote, {0})), final_vote, f.bus);
  expect(below.is_error(), "fixture-below-quorum-refused-before-conversion");
  std::vector<sx::FinalCert::VoteSignature> one;
  one.push_back({c::PeerValidatorId{0}, f.sign(0, tos::serialize_tl_object(final_vote.to_tl(), true).as_slice())});
  auto below_direct = td::make_ref<sx::FinalCert>(final_vote, std::move(one));
  reject(below_direct->to_signature_set(candidate, f.bus), "conversion-weighted-quorum", "below weighted quorum");
}

void empty_candidate(Fixture& f) {
  auto inner = tos::serialize_tl_object(f.candidate_id.to_tl(), true);
  auto proposal_signature = f.sign(0, inner.as_slice());
  transcript("proposal", f.bus.validator_set[0].consensus_key, f.envelope(inner.as_slice()).as_slice(),
             proposal_signature.as_slice());
  auto proposal = td::make_ref<c::Candidate>(f.candidate_id, f.candidate_data.parent, c::PeerValidatorId{0}, f.block_id,
                                             std::move(proposal_signature));
  expect(c::Candidate::deserialize(proposal->serialize(), f.bus, c::PeerValidatorId{0}, 7).is_ok(),
         "candidate-accepted");
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus, c::PeerValidatorId{1}), "candidate-wrong-leader",
         "source");
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus, std::nullopt, 8), "candidate-wrong-slot", "slot");
  proposal.write().signature.as_slice()[0] ^= 1;
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus), "candidate-bad-signature", "signature");
}

// The producer written into an accepted candidate must be the identity the validator set
// holds for its leader. The fixture gives the leader an identity that is neither its
// consensus key nor anything derived from it, and the wire claims a different one again, so
// putting either back would be caught here rather than by blocks failing on a network.
void candidate_producer_identity(Fixture& f) {
  auto cell_of = [](unsigned char byte) {
    vm::CellBuilder cb;
    cb.store_long(byte, 8);
    return vm::std_boc_serialize(cb.finalize(), 31).move_as_ok();
  };
  auto data = cell_of(0xb1);
  td::BufferSlice collated;  // empty: the payload pipeline re-serializes collated cells
  tos::BlockIdExt full_id{tos::BlockId{f.bus.shard.workchain, f.bus.shard.shard, 7}, fill(0x55),
                          td::sha256_bits256(data.as_slice())};
  tos::BlockCandidate block{tos::ValidatorId{fill(0x99)}, full_id, td::sha256_bits256(collated.as_slice()),
                            data.clone(), collated.clone()};
  auto hash_data = c::CandidateHashData::create_full(block, std::nullopt);
  auto id = hash_data.build_id_with(7);
  auto signature = f.sign(0, tos::serialize_tl_object(id.to_tl(), true).as_slice());
  auto candidate =
      td::make_ref<c::Candidate>(id, std::nullopt, c::PeerValidatorId{0}, std::move(block), std::move(signature));

  auto restored = c::Candidate::deserialize(candidate->serialize(), f.bus, c::PeerValidatorId{0}, 7);
  expect(restored.is_ok(), "full-candidate-accepted");
  // The accepted candidate has to outlive the reference taken into it: lifetime extension
  // does not reach through a reference-counted pointer.
  auto accepted = restored.move_as_ok();
  const auto& produced = std::get<tos::BlockCandidate>(accepted->block);
  expect(produced.producer == f.bus.validator_set[0].validator_id, "full-candidate-producer-from-set");
  expect(produced.producer.value != fill(0x99), "full-candidate-producer-not-from-wire");
  expect(produced.producer.value != f.bus.validator_set[0].adnl_id.bits256_value(),
         "full-candidate-producer-not-transport-identity");
}

}  // namespace

int main() {
  vm::init_vm().ensure();
  Fixture f;
  votes(f);
  certificates(f);
  carrier_conversion(f);
  empty_candidate(f);
  candidate_producer_identity(f);
  std::printf("CERTIFICATE_CONFORMANCE_OK %u checks over the live post-quantum Simplex entrypoints\n", checks);
  return 0;
}
