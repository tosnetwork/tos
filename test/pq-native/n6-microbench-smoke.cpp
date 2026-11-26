/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/utils/crypto.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/vm.h"

namespace {

namespace consensus = tos::validator::consensus;
namespace simplex = tos::validator::consensus::simplex;
using Clock = std::chrono::steady_clock;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "N6_MICROBENCH_SMOKE_FAILURE: " << message << '\n';
  std::exit(1);
}

template <class T>
T require_ok(td::Result<T> result, std::string_view operation) {
  if (result.is_error()) {
    fail(std::string(operation) + ": " + result.error().message().str());
  }
  return result.move_as_ok();
}

td::Bits256 hash_of(std::string_view value) {
  td::Bits256 result;
  td::sha256(td::Slice(value.data(), value.size()), result.as_slice());
  return result;
}

tos::ConsensusKeyId key_id_of(const tos::pq::ConsensusPQKey &key) {
  td::Bits256 bits;
  std::memcpy(bits.data(), key.key_id.data(), key.key_id.size());
  return tos::ConsensusKeyId{bits};
}

td::BufferSlice patterned_signature(std::size_t signer) {
  td::BufferSlice out(tos::pq::mldsa44_signature_bytes);
  std::size_t offset = 0;
  std::string seed = "persisted-pq-signature-" + std::to_string(signer);
  while (offset < out.size()) {
    const auto block = hash_of(seed);
    const auto take = std::min<std::size_t>(32, out.size() - offset);
    std::memcpy(out.data() + offset, block.data(), take);
    offset += take;
    seed.assign(reinterpret_cast<const char *>(block.data()), 32);
  }
  return out;
}

std::vector<block::PQBlockSignature> frozen_pairs(std::size_t count) {
  std::vector<block::PQBlockSignature> pairs;
  pairs.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    pairs.push_back({tos::ValidatorId{hash_of("persisted-validator-" + std::to_string(i))},
                     tos::pq::PQAlgorithmId::mldsa44, patterned_signature(i)});
  }
  return pairs;
}

tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> frozen_candidate() {
  constexpr td::uint32 slot = 2718281;
  const tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(id.id.workchain, static_cast<td::int64>(id.id.shard),
                                                              id.id.seqno, id.root_hash, id.file_hash),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("carrier-parent")));
}

td::Ref<vm::Cell> frozen_signature_set_cell(std::size_t count) {
  return require_ok(block::BlockSignatureSet::serialize_simplex_pq(frozen_pairs(count), 1789434, 0x31415926, count,
                                                                   hash_of("persisted-pq-block-signature-session"),
                                                                   2718281, frozen_candidate()),
                    "frozen #13 size fixture");
}

td::Ref<vm::Cell> frozen_block_proof_cell(td::Ref<vm::Cell> signatures) {
  const tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  vm::CellBuilder payload;
  payload.store_long(0x51, 8);
  vm::CellBuilder root;
  if (!(root.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(root, id) &&
        root.store_ref_bool(payload.finalize()) && root.store_bool_bool(true) &&
        root.store_ref_bool(std::move(signatures)))) {
    fail("frozen BlockProof fixture");
  }
  return root.finalize_novm();
}

struct Stats {
  std::size_t samples{};
  double p50_us{};
  double p95_us{};
  double max_us{};
};

Stats summarize(std::vector<double> elapsed) {
  std::sort(elapsed.begin(), elapsed.end());
  auto percentile = [&](double p) {
    const auto index = static_cast<std::size_t>(std::ceil(p * static_cast<double>(elapsed.size()))) - 1;
    return elapsed[std::min(index, elapsed.size() - 1)];
  };
  return {elapsed.size(), percentile(0.50), percentile(0.95), elapsed.back()};
}

struct CountedStats {
  Stats stats;
  std::uint64_t verify_calls{};
};

struct Operation {
  std::function<void()> run;
  std::vector<double> elapsed{};
  std::uint64_t verify_calls{};
};

// Times every operation once per round, so the samples of all operations are
// spread over the same wall-clock span. The large-regression bounds compare
// operations with one another; measured one after the other, each operation's
// samples came from its own short window, and a slower stretch of the host (a
// busy neighbour on a shared runner, a move to a slower core) inside one window
// moved that ratio with no change in the code. Interleaved, such a stretch
// reaches every operation alike. Each round runs the operations in a fresh
// random order (Fisher-Yates over a fixed-seed mt19937, whose output the
// standard fixes, so every platform runs the same orders), so no operation
// keeps one position or one predecessor whose cache or frequency state it
// inherits. The verification counter is read around each call, outside its
// timed span.
void measure_interleaved(std::vector<Operation *> operations, std::size_t warmup, std::size_t samples) {
  for (std::size_t i = 0; i < warmup; ++i) {
    for (auto *operation : operations) {
      operation->run();
    }
  }
  tos::pq::reset_mldsa44_verification_calls_for_test();
  for (auto *operation : operations) {
    operation->elapsed.reserve(samples);
  }
  std::mt19937 order_rng(0x4e36);
  auto order = operations;
  for (std::size_t round = 0; round < samples; ++round) {
    for (std::size_t i = order.size(); i > 1; --i) {
      std::swap(order[i - 1], order[order_rng() % i]);
    }
    for (auto *operation : order) {
      const auto calls_before = tos::pq::mldsa44_verification_calls_for_test();
      const auto begin = Clock::now();
      operation->run();
      const auto end = Clock::now();
      operation->verify_calls += tos::pq::mldsa44_verification_calls_for_test() - calls_before;
      operation->elapsed.push_back(std::chrono::duration<double, std::micro>(end - begin).count());
    }
  }
}

CountedStats counted(const Operation &operation) {
  return {summarize(operation.elapsed), operation.verify_calls};
}

struct Fixture {
  static constexpr tos::CatchainSeqno catchain_seqno = 1789434;
  static constexpr td::uint32 slot = 2718281;

  std::vector<tos::pq::ValidatorPQKeyStore> stores;
  std::vector<tos::ValidatorDescr> descriptors;
  std::vector<block::PQBlockSignature> signatures;
  tos::BlockIdExt block_id{-1, 0x8000000000000000ULL, 42, hash_of("n6-smoke-root"), hash_of("n6-smoke-file")};
  td::Bits256 session_id{hash_of("n6-smoke-session")};
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate;
  td::BufferSlice message;

  Fixture() {
    candidate = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
        tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
            block_id.id.workchain, static_cast<td::int64>(block_id.id.shard), block_id.id.seqno, block_id.root_hash,
            block_id.file_hash),
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("n6-smoke-parent")));
    message =
        require_ok(block::BlockSignatureSet::build_simplex_data_to_sign(session_id, slot, candidate, true, block_id),
                   "build smoke signed preimage");
    stores.reserve(100);
    descriptors.reserve(100);
    signatures.reserve(100);
    for (std::size_t i = 0; i < 100; ++i) {
      std::array<char, 32> seed{};
      const auto digest = hash_of("n6-smoke-key-" + std::to_string(i));
      std::memcpy(seed.data(), digest.data(), seed.size());
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store) {
        fail("smoke key derivation");
      }
      const auto validator_id = tos::ValidatorId{hash_of("n6-smoke-validator-" + std::to_string(i))};
      const auto &key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key), key.public_key,
                               1, hash_of("n6-smoke-adnl-" + std::to_string(i)));
      auto signature = store->sign_consensus(std::string_view(message.data(), message.size()));
      if (!signature) {
        fail("smoke fixture signing");
      }
      signatures.push_back({validator_id, signature->algorithm_id, td::BufferSlice(std::move(signature->signature))});
      stores.push_back(std::move(*store));
    }
  }

  std::vector<block::PQBlockSignature> pairs(std::size_t count) const {
    std::vector<block::PQBlockSignature> result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      result.push_back({signatures[i].validator_id, signatures[i].algorithm_id, signatures[i].signature.clone()});
    }
    return result;
  }

  td::Ref<block::ValidatorSet> validator_set(std::size_t count) const {
    std::vector<tos::ValidatorDescr> selected(descriptors.begin(), descriptors.begin() + count);
    return td::Ref<block::ValidatorSet>{true, catchain_seqno, tos::ShardIdFull{tos::masterchainId},
                                        std::move(selected)};
  }

  td::Ref<block::BlockSignatureSet> signature_set(std::size_t count, td::Ref<block::ValidatorSet> vset) const {
    auto candidate_copy = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
        tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
            block_id.id.workchain, static_cast<td::int64>(block_id.id.shard), block_id.id.seqno, block_id.root_hash,
            block_id.file_hash),
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("n6-smoke-parent")));
    return require_ok(
        block::BlockSignatureSet::create_simplex_pq_final(pairs(count), catchain_seqno, vset->get_validator_set_hash(),
                                                          session_id, slot, std::move(candidate_copy)),
        "create smoke #13 set");
  }
};

td::BufferSlice make_certificate(const Fixture &fixture, std::size_t count) {
  std::vector<tos::tl_object_ptr<tos::tos_api::consensus_simplex_voteSignature>> signatures;
  signatures.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    signatures.push_back(tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignature>(
        static_cast<td::int32>(i), fixture.signatures[i].signature.clone()));
  }
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      Fixture::slot, td::Bits256{tos::get_tl_object_sha256(fixture.candidate).raw});
  return tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_certificate>(
      tos::create_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id)),
      tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignatureSet>(std::move(signatures)));
}

std::unique_ptr<consensus::Bus> make_bus(const Fixture &fixture, std::size_t count) {
  auto bus = std::make_unique<consensus::Bus>();
  bus->session_id = fixture.session_id;
  bus->shard = tos::ShardIdFull{tos::masterchainId};
  bus->cc_seqno = Fixture::catchain_seqno;
  bus->validator_set.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto adnl = tos::adnl::AdnlNodeIdShort{fixture.descriptors[i].addr};
    bus->validator_set.push_back(consensus::PeerValidator{
        .validator_id = fixture.descriptors[i].validator_id,
        .idx = consensus::PeerValidatorId{i},
        .consensus_key = fixture.stores[i].consensus_key(),
        .transport_key_id = adnl.pubkey_hash(),
        .adnl_id = adnl,
        .weight = fixture.descriptors[i].weight,
    });
    if (!tos::checked_add_validator_weight(bus->total_weight, fixture.descriptors[i].weight)) {
      fail("smoke validator weight overflow");
    }
  }
  return bus;
}

void verify_raw(const Fixture &fixture) {
  const auto &signature = fixture.signatures.front();
  if (tos::pq::verify_mldsa44(std::string_view(fixture.message.data(), fixture.message.size()),
                              tos::pq::simplex_sign_context,
                              std::string_view(signature.signature.data(), signature.signature.size()),
                              fixture.descriptors.front().pq_public_key) != tos::pq::VerifyResult::valid) {
    fail("single verification");
  }
}

struct CertificateFixture {
  td::BufferSlice certificate;
  std::unique_ptr<consensus::Bus> bus;
  std::size_t count;

  CertificateFixture(const Fixture &fixture, std::size_t count)
      : certificate(make_certificate(fixture, count)), bus(make_bus(fixture, count)), count(count) {
  }

  void verify() const {
    auto parsed = tos::fetch_tl_object<tos::tos_api::consensus_simplex_certificate>(certificate.clone(), true);
    if (parsed.is_error() ||
        simplex::Certificate<simplex::Vote>::from_tl(std::move(*parsed.move_as_ok()), *bus).is_error()) {
      fail(std::to_string(count) + "-signer certificate verification");
    }
  }
};

void write_stats(std::ostream &out, const Stats &stats) {
  out << "{\"samples\":" << stats.samples << ",\"p50_us\":" << stats.p50_us << ",\"p95_us\":" << stats.p95_us
      << ",\"max_us\":" << stats.max_us << '}';
}

void write_counted(std::ostream &out, const CountedStats &stats) {
  out << "{\"timing\":";
  write_stats(out, stats.stats);
  out << ",\"verify_calls\":" << stats.verify_calls << '}';
}

}  // namespace

int main(int argc, char **argv) {
  std::string output_path;
  std::size_t samples = 100;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--output" && ++i < argc) {
      output_path = argv[i];
    } else if (arg == "--samples" && ++i < argc) {
      samples = std::stoull(argv[i]);
    } else {
      fail("unknown or incomplete argument " + arg);
    }
  }
  if (output_path.empty() || samples < 100) {
    fail("--output is required and --samples must be at least 100");
  }

  vm::init_vm().ensure();
  Fixture fixture;
  const CertificateFixture certificate_fixture_21(fixture, 21);
  const CertificateFixture certificate_fixture_100(fixture, 100);
  auto vset_21 = fixture.validator_set(21);
  auto signatures_21 = fixture.signature_set(21, vset_21);
  block::PQFinalityVerificationContext context_21{vset_21, fixture.block_id, fixture.session_id};

  Operation sign_operation{[&] {
    if (!fixture.stores.front().sign_consensus(std::string_view(fixture.message.data(), fixture.message.size()))) {
      fail("single signing");
    }
  }};
  Operation verify_operation{[&] { verify_raw(fixture); }};
  Operation certificate_21_operation{[&] { certificate_fixture_21.verify(); }};
  Operation certificate_100_operation{[&] { certificate_fixture_100.verify(); }};
  Operation proof_21_operation{[&] {
    if (block::verify_pq_finality(context_21, *signatures_21, block::FinalityRole::Final).is_error()) {
      fail("21-signer #13 verification");
    }
  }};
  Operation lite_21_operation{[&] {
    auto serialized = tos::serialize_tl_object(signatures_21->tl_lite(), true);
    auto object = tos::fetch_tl_object<tos::lite_api::liteServer_SignatureSet>(std::move(serialized), true);
    if (object.is_error()) {
      fail("21-signer lite parse");
    }
    auto parsed = block::BlockSignatureSet::fetch_lite_checked(object.ok());
    if (parsed.is_error() ||
        block::verify_pq_finality(context_21, *parsed.ok(), block::FinalityRole::Final).is_error()) {
      fail("21-signer lite verification");
    }
  }};
  measure_interleaved({&sign_operation, &verify_operation, &certificate_21_operation, &certificate_100_operation,
                       &proof_21_operation, &lite_21_operation},
                      10, samples);
  const auto sign = summarize(sign_operation.elapsed);
  const auto verify = counted(verify_operation);
  const auto certificate_21 = counted(certificate_21_operation);
  const auto certificate_100 = counted(certificate_100_operation);
  const auto proof_21 = counted(proof_21_operation);
  const auto lite_21 = counted(lite_21_operation);

  const auto frozen_21 = frozen_signature_set_cell(21);
  const auto frozen_100 = frozen_signature_set_cell(100);
  const auto boc_21 = require_ok(vm::std_boc_serialize(frozen_21, 0), "21-signer #13 BOC");
  const auto boc_100 = require_ok(vm::std_boc_serialize(frozen_100, 0), "100-signer #13 BOC");
  const auto block_proof_21 =
      require_ok(vm::std_boc_serialize(frozen_block_proof_cell(frozen_21), 0), "21-signer BlockProof BOC");
  const auto block_proof_100 =
      require_ok(vm::std_boc_serialize(frozen_block_proof_cell(frozen_100), 0), "100-signer BlockProof BOC");

  auto over_limit = block::BlockSignatureSet::create_simplex_pq_final(frozen_pairs(401), Fixture::catchain_seqno,
                                                                      0x31415926, hash_of("n6-smoke-cap-session"),
                                                                      Fixture::slot, frozen_candidate());
  const bool cap_refused = over_limit.is_error() &&
                           over_limit.error().message().str().find("signer count exceeds maximum") != std::string::npos;

  std::ofstream out(output_path);
  if (!out) {
    fail("open output");
  }
  out << std::fixed << std::setprecision(3);
  out << "{\"schema_version\":1,\"samples\":" << samples << ",\"operations\":{";
  out << "\"single_sign\":{" << "\"timing\":";
  write_stats(out, sign);
  out << ",\"iterations\":" << samples << "},\"single_verify\":";
  write_counted(out, verify);
  out << ",\"certificate_verify_21\":";
  write_counted(out, certificate_21);
  out << ",\"certificate_verify_100\":";
  write_counted(out, certificate_100);
  out << ",\"proof_verify_21\":";
  write_counted(out, proof_21);
  out << ",\"lite_verify_21\":";
  write_counted(out, lite_21);
  out << "},\"exact_sizes\":{\"n5_13_boc_21\":" << boc_21.size() << ",\"n5_13_boc_100\":" << boc_100.size()
      << ",\"block_proof_boc_21\":" << block_proof_21.size() << ",\"block_proof_boc_100\":" << block_proof_100.size()
      << "},\"structural_cap\":{\"maximum\":400,"
         "\"tested\":401,\"refused\":"
      << (cap_refused ? "true" : "false") << "}}\n";
  out.close();
  std::cout << "N6_MICROBENCH_SMOKE_DONE output=" << output_path << " samples=" << samples << '\n';
  return 0;
}
