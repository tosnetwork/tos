/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Execute the live parsers and quorum verifier with public deterministic test keys.
// No supplied verification booleans and no replacement certificate implementation.
#include "auto/tl/tos_api.hpp"
#include "crypto/Ed25519.h"
#include "crypto/block/signature-set.h"
#include "crypto/block/validator-set.h"
#include "keys/keys.hpp"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "validator/consensus/simplex/votes.h"
#include "vm/boc.h"
#include "vm/dict.h"
#include "vm/vm.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace c = tos::validator::consensus;
namespace sx = tos::validator::consensus::simplex;

namespace {
unsigned checks = 0;
void expect(bool condition, const std::string& label) {
  if (!condition) throw std::runtime_error(label);
  ++checks;
  std::cout << "PASS\t" << label << '\n';
}
template <class T> void reject(td::Result<T> result, const std::string& label, td::Slice text) {
  expect(result.is_error(), label);
  expect(result.error().message().str().find(text.str()) != std::string::npos, label + "-reason");
}
std::string hex(td::Slice data) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (unsigned char ch : data) { out += digits[ch >> 4]; out += digits[ch & 15]; }
  return out;
}
td::Bits256 bits(unsigned char byte) {
  td::Bits256 value;
  value.as_slice().fill(static_cast<char>(byte));
  return value;
}
struct Schedule final : c::CollatorSchedule {
  c::PeerValidatorId expected_collator_for(td::uint32) const override { return c::PeerValidatorId{0}; }
};
struct Fixture {
  c::Bus bus;
  std::vector<td::Ed25519::PrivateKey> secret;
  td::Ref<block::ValidatorSet> vset;
  tos::BlockIdExt block_id{tos::BlockId{tos::masterchainId, tos::shardIdAll, 7}, bits(0x31), bits(0x32)};
  c::CandidateHashData candidate_data = c::CandidateHashData::create_empty(block_id, c::CandidateId{6, bits(0x33)});
  c::CandidateId candidate_id = candidate_data.build_id_with(7);

  explicit Fixture(const std::vector<tos::ValidatorWeight>& weights = {1, 1, 1}) {
    bus.session_id = bits(0x42);
    bus.shard = tos::ShardIdFull{tos::masterchainId};
    bus.cc_seqno = 11;
    bus.total_weight = 0;
    bus.collator_schedule = td::make_ref<Schedule>();
    std::vector<tos::ValidatorDescr> nodes;
    for (std::size_t i = 0; i < weights.size(); ++i) {
      // These seeds are deliberately public fixtures, never operational keys.
      secret.emplace_back(td::SecureString(std::string(32, static_cast<char>(i + 1))));
      auto pk = secret.back().get_public_key().move_as_ok();
      tos::PublicKey key{tos::pubkeys::Ed25519{std::move(pk)}};
      nodes.emplace_back(tos::Ed25519_PublicKey{key.ed25519_value().raw()}, weights[i]);
      // A classical validator's membership identity is the one derived from its key,
      // which is what the validator set settles on too.
      bus.validator_set.push_back({tos::ValidatorId{key.compute_short_id().bits256_value()}, c::PeerValidatorId{i}, key,
                                   key.compute_short_id(), tos::adnl::AdnlNodeIdShort{key.compute_short_id()},
                                   weights[i]});
      expect(tos::checked_add_validator_weight(bus.total_weight, weights[i]), "fixture-weight-" + std::to_string(i));
    }
    vset = td::make_ref<block::ValidatorSet>(bus.cc_seqno, bus.shard, std::move(nodes));
    bus.validator_set_hash = vset->get_validator_set_hash();
  }
  td::BufferSlice sign(std::size_t i, td::Slice bytes) const {
    return td::BufferSlice(secret.at(i).sign(bytes).move_as_ok());
  }
  td::BufferSlice wrapped(td::Slice bytes) const {
    return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(bus.session_id, td::BufferSlice(bytes));
  }
  template <typename Vote> sx::tl::VoteSignatureSetRef signatures(const Vote& vote, const std::vector<int>& who,
                                                                bool corrupt_last = false) const {
    auto data = wrapped(tos::serialize_tl_object(vote.to_tl(), true));
    std::vector<sx::tl::VoteSignatureRef> result;
    for (int i : who) {
      auto signature = sign(static_cast<std::size_t>(i >= 0 && i < static_cast<int>(secret.size()) ? i : 0), data);
      result.push_back(tos::create_tl_object<sx::tl::voteSignature>(i, std::move(signature)));
    }
    if (corrupt_last) result.back()->signature_.as_slice()[0] ^= 1;
    return tos::create_tl_object<sx::tl::voteSignatureSet>(std::move(result));
  }
  std::vector<tos::BlockSignature> block_signatures(td::Slice bytes, const std::vector<int>& who) const {
    std::vector<tos::BlockSignature> result;
    for (int i : who) result.emplace_back(bus.validator_set.at(i).short_id.bits256_value(), sign(i, bytes));
    return result;
  }
};

void transcript(const Fixture& f, const std::string& label, td::Slice bytes) {
  auto key = f.secret[0].get_public_key().move_as_ok();
  auto signature = f.sign(0, bytes);
  std::cout << "VECTOR\t" << label << '\t' << hex(key.as_octet_string()) << '\t' << hex(bytes)
            << '\t' << hex(signature) << '\n';
}

void votes_and_candidates(Fixture& f) {
  const std::vector<sx::Vote> votes = {sx::NotarizeVote{f.candidate_id}, sx::FinalizeVote{f.candidate_id}, sx::SkipVote{7}};
  const std::vector<std::string> labels = {"notarize", "finalize", "skip"};
  for (std::size_t i = 0; i < votes.size(); ++i) {
    auto raw = tos::serialize_tl_object(votes[i].to_tl(), true);
    auto signature = f.sign(0, f.wrapped(raw));
    transcript(f, labels[i], f.wrapped(raw));
    auto good = tos::create_tl_object<sx::tl::vote>(votes[i].to_tl(), signature.clone());
    expect(sx::Signed<sx::Vote>::deserialize(tos::serialize_tl_object(good, true), c::PeerValidatorId{0}, f.bus).is_ok(),
           labels[i] + "-real-vote");
    for (std::size_t j = 0; j < votes.size(); ++j) {
      auto item = tos::create_tl_object<sx::tl::vote>(votes[j].to_tl(), signature.clone());
      expect(sx::Signed<sx::Vote>::from_tl(std::move(*item), c::PeerValidatorId{0}, f.bus).is_ok() == (i == j),
             labels[i] + "-role-" + labels[j]);
    }
    for (std::size_t size : {std::size_t(0), std::size_t(63), std::size_t(65), std::size_t(2420)}) {
      auto item = tos::create_tl_object<sx::tl::vote>(votes[i].to_tl(), td::BufferSlice(std::string(size, 'x')));
      reject(sx::Signed<sx::Vote>::from_tl(std::move(*item), c::PeerValidatorId{0}, f.bus),
             labels[i] + "-signature-length-" + std::to_string(size), "Invalid vote signature");
    }
    auto wrong_key = tos::create_tl_object<sx::tl::vote>(votes[i].to_tl(), signature.clone());
    reject(sx::Signed<sx::Vote>::from_tl(std::move(*wrong_key), c::PeerValidatorId{1}, f.bus),
           labels[i] + "-wrong-key", "Invalid vote signature");
    auto old_session = f.bus.session_id;
    f.bus.session_id = bits(0x43);
    expect(!f.bus.validator_set[0].check_signature(f.bus.session_id, raw, signature), labels[i] + "-wrong-session");
    f.bus.session_id = old_session;
    auto altered = raw.clone(); altered.as_slice()[altered.size() - 1] ^= 1;
    expect(!f.bus.validator_set[0].check_signature(f.bus.session_id, altered, signature), labels[i] + "-tamper");
  }
  auto data = tos::serialize_tl_object(f.candidate_id.to_tl(), true);
  transcript(f, "proposal", f.wrapped(data));
  auto proposal = td::make_ref<c::Candidate>(f.candidate_id, f.candidate_data.parent, c::PeerValidatorId{0},
                                          f.block_id, f.sign(0, f.wrapped(data)));
  expect(c::Candidate::deserialize(proposal->serialize(), f.bus, c::PeerValidatorId{0}, 7).is_ok(), "proposal-accepted");
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus, c::PeerValidatorId{1}), "proposal-wrong-leader", "source");
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus, std::nullopt, 8), "proposal-wrong-slot", "slot");
  proposal.write().signature.as_slice()[0] ^= 1;
  reject(c::Candidate::deserialize(proposal->serialize(), f.bus), "proposal-bad-signature", "signature");
}

// A candidate's producer must be the identity the validator set holds for its leader,
// not anything reconstructed from the leader's key. The fixture gives the leader an
// identity that is neither its key nor the identity derived from it, so putting either
// of those back would be caught here rather than by blocks being refused on a network.
void candidate_producer_identity(Fixture& f) {
  const auto set_identity = tos::ValidatorId{bits(0x77)};
  f.bus.validator_set[0].validator_id = set_identity;

  // Real cells: the candidate payload is parsed as a bag of cells downstream.
  auto cell_of = [](unsigned char byte) {
    vm::CellBuilder cb;
    cb.store_long(byte, 8);
    return vm::std_boc_serialize(cb.finalize(), 31).move_as_ok();
  };
  auto data = cell_of(0xb1);
  td::BufferSlice collated;  // empty: the payload pipeline re-serialises collated cells
  tos::BlockIdExt full_id{tos::BlockId{f.bus.shard.workchain, f.bus.shard.shard, 7}, bits(0x55),
                          td::sha256_bits256(data.as_slice())};
  // What the wire claims about the producer is deliberately wrong: it must be ignored.
  tos::BlockCandidate block{tos::ValidatorId{bits(0x99)}, full_id, td::sha256_bits256(collated.as_slice()),
                            data.clone(), collated.clone()};
  auto hash_data = c::CandidateHashData::create_full(block, std::nullopt);
  auto id = hash_data.build_id_with(7);
  auto signature = f.sign(0, f.wrapped(tos::serialize_tl_object(id.to_tl(), true)));
  auto candidate =
      td::make_ref<c::Candidate>(id, std::nullopt, c::PeerValidatorId{0}, std::move(block), std::move(signature));

  auto restored = c::Candidate::deserialize(candidate->serialize(), f.bus, c::PeerValidatorId{0}, 7);
  expect(restored.is_ok(), "full-candidate-accepted");
  // The candidate has to outlive the reference taken into it: lifetime extension does not
  // reach through a reference-counted pointer, so binding to a temporary's pointee leaves
  // `produced` dangling for every check below.
  auto accepted = restored.move_as_ok();
  const auto& produced = std::get<tos::BlockCandidate>(accepted->block);
  expect(produced.producer == set_identity, "full-candidate-producer-from-set");
  expect(produced.producer.value != f.bus.validator_set[0].key.ed25519_value().raw(),
         "full-candidate-producer-not-raw-key");
  expect(produced.producer.value != f.bus.validator_set[0].short_id.bits256_value(),
         "full-candidate-producer-not-key-short-id");
}

void certificates(Fixture& f) {
  const std::vector<sx::Vote> votes = {sx::NotarizeVote{f.candidate_id}, sx::FinalizeVote{f.candidate_id}, sx::SkipVote{7}};
  for (std::size_t i = 0; i < votes.size(); ++i) {
    std::string label = "certificate-" + std::to_string(i);
    auto evaluate = [&](const std::vector<int>& who, bool corrupt = false) {
      return sx::Certificate<sx::Vote>::from_tl(std::move(*f.signatures(votes[i], who, corrupt)), votes[i], f.bus);
    };
    expect(evaluate({0, 1}).is_ok(), label + "-two-of-three");
    reject(evaluate({0}), label + "-below-quorum", "Not enough");
    reject(evaluate({0, 0}), label + "-duplicate", "Duplicate");
    reject(evaluate({0, -1}), label + "-negative-index", "Invalid validator");
    reject(evaluate({0, 3}), label + "-unknown-index", "Invalid validator");
    reject(evaluate({0, 1}, true), label + "-invalid-signer", "Invalid vote signature");
    reject(evaluate({0, 1, 2}, true), label + "-invalid-after-quorum", "Invalid vote signature");
    auto cert = evaluate({0, 1}).move_as_ok();
    auto wire = tos::fetch_tl_object<sx::tl::certificate>(cert->serialize(), true).move_as_ok();
    expect(sx::Certificate<sx::Vote>::from_tl(std::move(*wire), f.bus).is_ok(), label + "-wire-roundtrip");
  }
  Fixture weighted({7, 2, 1});
  sx::NotarizeVote vote{weighted.candidate_id};
  expect(sx::NotarCert::from_tl(std::move(*weighted.signatures(vote, {0})), vote, weighted.bus).is_ok(), "weighted-large-signer");
  reject(sx::NotarCert::from_tl(std::move(*weighted.signatures(vote, {1, 2})), vote, weighted.bus),
         "weighted-full-denominator", "Not enough");
}

void proofs(Fixture& f) {
  auto ordinary_bytes = tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(f.block_id.root_hash, f.block_id.file_hash);
  transcript(f, "ordinary-proof", ordinary_bytes);
  auto ordinary = [&](const std::vector<int>& who) {
    return block::BlockSignatureSet::create_ordinary(f.block_signatures(ordinary_bytes, who), f.bus.cc_seqno, f.bus.validator_set_hash);
  };
  auto proof = ordinary({0, 1});
  expect(proof->check_signatures(f.vset, f.block_id).is_ok(), "ordinary-proof-accepted");
  reject(ordinary({0})->check_signatures(f.vset, f.block_id), "ordinary-proof-quorum", "too small");
  reject(ordinary({0, 0})->check_signatures(f.vset, f.block_id), "ordinary-proof-duplicate", "duplicate");
  auto wrong_id = f.block_id; wrong_id.root_hash = bits(0x88);
  reject(proof->check_signatures(f.vset, wrong_id), "ordinary-proof-root", "signature");
  wrong_id = f.block_id; wrong_id.file_hash = bits(0x89);
  reject(proof->check_signatures(f.vset, wrong_id), "ordinary-proof-file", "signature");
  auto bad = f.block_signatures(ordinary_bytes, {0, 1, 2}); bad.back().signature.as_slice()[0] ^= 1;
  reject(block::BlockSignatureSet::create_ordinary(std::move(bad), f.bus.cc_seqno, f.bus.validator_set_hash)
             ->check_signatures(f.vset, f.block_id), "ordinary-proof-invalid-after-quorum", "signature");
  auto unknown = f.block_signatures(ordinary_bytes, {0, 1}); unknown.back().node = bits(0xee);
  reject(block::BlockSignatureSet::create_ordinary(std::move(unknown), f.bus.cc_seqno, f.bus.validator_set_hash)
             ->check_signatures(f.vset, f.block_id), "ordinary-proof-unknown", "unknown node");
  reject(block::BlockSignatureSet::create_ordinary(f.block_signatures(ordinary_bytes, {0, 1}), f.bus.cc_seqno + 1,
                f.bus.validator_set_hash)->check_signatures(f.vset, f.block_id), "ordinary-proof-cc-seqno", "catchain");
  reject(block::BlockSignatureSet::create_ordinary(f.block_signatures(ordinary_bytes, {0, 1}), f.bus.cc_seqno,
                f.bus.validator_set_hash ^ 1)->check_signatures(f.vset, f.block_id), "ordinary-proof-vset", "validator set");
  reject(proof->check_approve_signatures(f.vset, f.block_id), "ordinary-proof-not-approval", "not approve");
  for (std::size_t size : {std::size_t(0), std::size_t(63), std::size_t(65), std::size_t(2420)}) {
    auto sigs = f.block_signatures(ordinary_bytes, {0, 1}); sigs[0].signature = td::BufferSlice(std::string(size, 'x'));
    auto item = block::BlockSignatureSet::create_ordinary(std::move(sigs), f.bus.cc_seqno, f.bus.validator_set_hash);
    expect(item->serialize(f.vset).is_error(), "proof-codec-fixed-width-" + std::to_string(size));
    expect(item->check_signatures(f.vset, f.block_id).is_error(), "proof-verifier-fixed-width-" + std::to_string(size));
  }
  auto roundtrip = [&](td::Ref<block::BlockSignatureSet> item, const std::string& label) {
    auto wire = item->serialize(f.vset).move_as_ok();
    auto encoded = vm::std_boc_serialize(wire).move_as_ok();
    auto decoded = vm::std_boc_deserialize(encoded).move_as_ok();
    auto from_boc = block::BlockSignatureSet::fetch(decoded, f.vset).move_as_ok();
    expect(from_boc->check_signatures(f.vset, f.block_id).is_ok(), label + "-boc-roundtrip");
    auto from_tl = block::BlockSignatureSet::fetch(item->tl());
    expect(from_tl->check_signatures(f.vset, f.block_id).is_ok(), label + "-tl-roundtrip");
    auto lite = block::BlockSignatureSet::fetch(item->tl_lite()).move_as_ok();
    expect(lite->check_signatures(f.vset, f.block_id).is_ok(), label + "-lite-roundtrip");
    std::cout << "BOC\t" << label << '\t' << hex(encoded) << '\n';
  };
  roundtrip(proof, "ordinary");

  // Decoding a well-shaped certificate is not authentication. Corrupt proof
  // bytes can survive parsing, but must still fail the real signature check.
  auto corrupted_sigs=f.block_signatures(ordinary_bytes,{0,1});
  corrupted_sigs[0].signature.as_slice()[0]^=1;
  auto corrupt=block::BlockSignatureSet::create_ordinary(std::move(corrupted_sigs),f.bus.cc_seqno,f.bus.validator_set_hash);
  auto parsed_corrupt=block::BlockSignatureSet::fetch(corrupt->serialize(f.vset).move_as_ok(),f.vset).move_as_ok();
  expect(parsed_corrupt->check_signatures(f.vset,f.block_id).is_error(),"decoded-proof-is-not-authenticated");
  auto plain_sigs=f.block_signatures(ordinary_bytes,{0,1});
  auto wire_fixture=[&](unsigned tag,unsigned advertised_count,unsigned advertised_weight,
                        unsigned index_step,bool trailing_bit,bool trailing_ref,unsigned count=2) {
    vm::Dictionary dictionary{16};
    for(unsigned i=0;i<count;++i) {
      const auto& sig=plain_sigs[i%2];vm::CellBuilder leaf;
      if(!leaf.store_bits_bool(sig.node))throw std::runtime_error("invalid node-id fixture");
      leaf.store_long(tag,4);leaf.store_bytes(sig.signature);
      if(trailing_bit)leaf.store_long(0,1);
      if(trailing_ref)leaf.store_ref(vm::CellBuilder().finalize());
      if(!dictionary.set_builder(td::BitArray<16>{i*index_step},leaf,vm::Dictionary::SetMode::Add))
        throw std::runtime_error("invalid dictionary fixture");
    }
    vm::CellBuilder outer;
    outer.store_long(0x11,8);outer.store_long(f.bus.validator_set_hash,32);outer.store_long(f.bus.cc_seqno,32);
    outer.store_long(advertised_count,32);outer.store_long(advertised_weight,64);
    outer.store_maybe_ref(std::move(dictionary).extract_root_cell());return outer.finalize();
  };
  expect(block::BlockSignatureSet::fetch(wire_fixture(5,2,2,1,false,false),f.vset).is_ok(),"raw-codec-positive-control");
  for(const auto& item:std::vector<std::pair<std::string,td::Ref<vm::Cell>>>{
        {"wrong-tag",wire_fixture(6,2,2,1,false,false)},
        {"tail-bit",wire_fixture(5,2,2,1,true,false)},
        {"extra-ref",wire_fixture(5,2,2,1,false,true)},
        {"nonconsecutive-index",wire_fixture(5,2,2,2,false,false)},
        {"count-mismatch",wire_fixture(5,3,2,1,false,false)},
        {"weight-mismatch",wire_fixture(5,2,3,1,false,false)}}) {
    expect(block::BlockSignatureSet::fetch(item.second,f.vset).is_error(),"proof-codec-"+item.first);
  }
  tos::ValidatorWeight claimed_weight=0;
  expect(block::BlockSignatureSet::fetch(wire_fixture(5,1024,1024,1,false,false,1024),claimed_weight).is_ok(),
         "decoder-count-bound-positive-no-authentication");
  expect(block::BlockSignatureSet::fetch(wire_fixture(5,1025,1025,1,false,false,1025),claimed_weight).is_error(),
         "decoder-count-bound-negative");

  auto candidate = td::make_ref<c::Candidate>(f.candidate_id, f.candidate_data.parent, c::PeerValidatorId{0}, f.block_id, td::BufferSlice());
  sx::FinalizeVote final_vote{f.candidate_id};
  auto final_cert = sx::FinalCert::from_tl(std::move(*f.signatures(final_vote, {0, 1})), final_vote, f.bus).move_as_ok();
  auto simplex = final_cert->to_signature_set(candidate, f.bus);
  roundtrip(simplex, "simplex-final");
  reject(simplex->check_signatures(f.vset, wrong_id), "simplex-bound-block", "block id mismatch");
  sx::NotarizeVote notar_vote{f.candidate_id};
  auto notar = sx::NotarCert::from_tl(std::move(*f.signatures(notar_vote, {0, 1})), notar_vote, f.bus).move_as_ok();
  auto approve = notar->to_signature_set(candidate, f.bus);
  expect(approve->check_approve_signatures(f.vset, f.block_id).is_ok(), "simplex-approval");
  reject(approve->check_signatures(f.vset, f.block_id), "simplex-approval-not-final", "not final");
  expect(approve->serialize(f.vset).is_error(), "approval-cannot-be-persisted-as-final");
  auto approve_wire = block::BlockSignatureSet::fetch(approve->tl());
  expect(approve_wire->check_approve_signatures(f.vset, f.block_id).is_ok(), "approval-tl-roundtrip");
  auto role_confusion = block::BlockSignatureSet::create_simplex(f.block_signatures(f.wrapped(tos::serialize_tl_object(notar_vote.to_tl(), true)), {0, 1}),
      f.bus.cc_seqno, f.bus.validator_set_hash, f.bus.session_id, 7, f.candidate_data.to_tl());
  expect(role_confusion->check_signatures(f.vset, f.block_id).is_error(), "notarize-signature-not-finality");
  auto wrong_domain = block::BlockSignatureSet::create_simplex(f.block_signatures(ordinary_bytes, {0, 1}),
      f.bus.cc_seqno, f.bus.validator_set_hash, f.bus.session_id, 7, f.candidate_data.to_tl());
  expect(wrong_domain->check_signatures(f.vset, f.block_id).is_error(), "ordinary-signature-not-simplex");
  auto wrapped_ordinary = block::BlockSignatureSet::create_ordinary(f.block_signatures(f.wrapped(ordinary_bytes), {0, 1}), f.bus.cc_seqno, f.bus.validator_set_hash);
  expect(wrapped_ordinary->check_signatures(f.vset, f.block_id).is_error(), "ordinary-proof-does-not-use-session-wrapper");
}

void benchmark(Fixture& f) {
  const auto raw = tos::serialize_tl_object(sx::FinalizeVote{f.candidate_id}.to_tl(), true);
  const auto signature = f.sign(0, f.wrapped(raw));
  auto ordinary_bytes = tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(f.block_id.root_hash, f.block_id.file_hash);
  auto proof = block::BlockSignatureSet::create_ordinary(f.block_signatures(ordinary_bytes,{0,1}), f.bus.cc_seqno,
                                                       f.bus.validator_set_hash);
  auto measure=[&](const std::string& name, auto verify) {
    constexpr unsigned iterations=200, samples=7;
    std::vector<long long> timings;
    for(unsigned sample=0;sample<samples;++sample) {
      auto start=std::chrono::steady_clock::now();
      for(unsigned i=0;i<iterations;++i) if(!verify())throw std::runtime_error("benchmark failed its positive control");
      auto end=std::chrono::steady_clock::now();
      timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/iterations);
    }
    std::sort(timings.begin(),timings.end());
    std::cout<<"PERF\t"<<name<<"\t"<<iterations*samples<<"\t"<<timings.front()<<"\t"<<timings[samples/2]
             <<"\t"<<timings.back()<<"\tns-per-call; native entrypoint only, not validator TPS\n";
  };
  measure("peer-ed25519",[&]{return f.bus.validator_set[0].check_signature(f.bus.session_id,raw,signature);});
  measure("ordinary-two-signature-quorum",[&]{return proof->check_signatures(f.vset,f.block_id).is_ok();});
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const bool measure = argc == 2 && std::string(argv[1]) == "--benchmark";
    if (argc != 1 && !measure) throw std::runtime_error("usage: test-validator-auth-production [--benchmark]");
    vm::init_vm().ensure();
    Fixture f;
    if (measure) { benchmark(f); return 0; }
    votes_and_candidates(f);
    candidate_producer_identity(f);
    certificates(f);
    proofs(f);
    std::cout << "SUMMARY\t" << checks << "\tproduction-verification-checks\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
  }
}
