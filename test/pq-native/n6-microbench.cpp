/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <optional>
#include <sched.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/pq-bytes.h"
#include "td/actor/actor.h"
#include "td/utils/crypto.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "validator/finality-cache-policy.h"
#include "validator/pending-finality-ingress.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/vm.h"

namespace {

namespace consensus = tos::validator::consensus;
namespace simplex = tos::validator::consensus::simplex;

using Clock = std::chrono::steady_clock;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "N6_MICROBENCH_FAILURE: " << message << '\n';
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

td::BufferSlice frozen_patterned_signature(std::size_t signer) {
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

td::Ref<vm::Cell> frozen_signature_set_cell(std::size_t count) {
  constexpr td::uint32 validator_set_hash = 0x31415926;
  constexpr td::uint32 catchain_seqno = 1789434;
  constexpr td::uint32 slot = 2718281;
  const tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  auto candidate = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(id.id.workchain, static_cast<td::int64>(id.id.shard),
                                                              id.id.seqno, id.root_hash, id.file_hash),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("carrier-parent")));
  std::vector<block::PQBlockSignature> pairs;
  pairs.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    pairs.push_back({tos::ValidatorId{hash_of("persisted-validator-" + std::to_string(i))},
                     tos::pq::PQAlgorithmId::mldsa44, frozen_patterned_signature(i)});
  }
  return require_ok(block::BlockSignatureSet::serialize_simplex_pq(pairs, catchain_seqno, validator_set_hash, count,
                                                                   hash_of("persisted-pq-block-signature-session"),
                                                                   slot, std::move(candidate)),
                    "frozen #13 size fixture");
}

td::Ref<vm::Cell> frozen_block_proof_cell(td::Ref<vm::Cell> signatures) {
  const tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  vm::CellBuilder proof_payload;
  proof_payload.store_long(0x51, 8);
  vm::CellBuilder root;
  if (!(root.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(root, id) &&
        root.store_ref_bool(proof_payload.finalize()) && root.store_bool_bool(true) &&
        root.store_ref_bool(std::move(signatures)))) {
    fail("frozen BlockProof size fixture");
  }
  return root.finalize_novm();
}

tos::ConsensusKeyId key_id_of(const tos::pq::ConsensusPQKey &key) {
  td::Bits256 bits;
  std::memcpy(bits.data(), key.key_id.data(), key.key_id.size());
  return tos::ConsensusKeyId{bits};
}

std::string json_string(std::string_view value) {
  std::string out{"\""};
  for (char c : value) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      default:
        out += c;
    }
  }
  out += '"';
  return out;
}

struct Stats {
  std::size_t samples{};
  double p50_us{};
  double p95_us{};
  std::optional<double> p99_us;
  double max_us{};
};

Stats summarize(std::vector<double> values) {
  if (values.empty()) {
    fail("cannot summarize zero samples");
  }
  std::sort(values.begin(), values.end());
  auto percentile = [&](double p) {
    auto index = static_cast<std::size_t>(std::ceil(p * static_cast<double>(values.size()))) - 1;
    return values[std::min(index, values.size() - 1)];
  };
  return {values.size(), percentile(0.50), percentile(0.95),
          values.size() >= 100 ? std::optional<double>{percentile(0.99)} : std::nullopt, values.back()};
}

template <class Function>
Stats measure(std::size_t warmup, std::size_t samples, Function &&function) {
  for (std::size_t i = 0; i < warmup; ++i) {
    function();
  }
  std::vector<double> elapsed;
  elapsed.reserve(samples);
  for (std::size_t i = 0; i < samples; ++i) {
    const auto begin = Clock::now();
    function();
    const auto end = Clock::now();
    elapsed.push_back(std::chrono::duration<double, std::micro>(end - begin).count());
  }
  return summarize(std::move(elapsed));
}

void write_stats(std::ostream &out, const Stats &stats) {
  out << "{\"samples\":" << stats.samples << ",\"p50_us\":" << stats.p50_us << ",\"p95_us\":" << stats.p95_us
      << ",\"p99_us\":";
  if (stats.p99_us) {
    out << *stats.p99_us;
  } else {
    out << "null";
  }
  out << ",\"max_us\":" << stats.max_us << '}';
}

struct Fixture {
  static constexpr tos::CatchainSeqno catchain_seqno = 1789434;
  static constexpr td::uint32 slot = 2718281;

  std::vector<tos::pq::ValidatorPQKeyStore> stores;
  std::vector<tos::ValidatorDescr> descriptors;
  std::vector<block::PQBlockSignature> signatures;
  tos::BlockIdExt block_id{-1, 0x8000000000000000ULL, 42, hash_of("n6-root"), hash_of("n6-file")};
  td::Bits256 session_id{hash_of("n6-session")};
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate;
  td::BufferSlice message;

  Fixture() {
    candidate = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
        tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
            block_id.id.workchain, static_cast<td::int64>(block_id.id.shard), block_id.id.seqno, block_id.root_hash,
            block_id.file_hash),
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("n6-parent")));
    message =
        require_ok(block::BlockSignatureSet::build_simplex_data_to_sign(session_id, slot, candidate, true, block_id),
                   "build signed preimage");
    stores.reserve(400);
    descriptors.reserve(400);
    signatures.reserve(400);
    for (std::size_t i = 0; i < 400; ++i) {
      std::array<char, 32> seed{};
      auto digest = hash_of("n6-key-" + std::to_string(i));
      std::memcpy(seed.data(), digest.data(), seed.size());
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store) {
        fail("deterministic key derivation");
      }
      auto validator_id = tos::ValidatorId{hash_of("n6-validator-" + std::to_string(i))};
      const auto &key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key), key.public_key,
                               1, hash_of("n6-adnl-" + std::to_string(i)));
      auto signature = store->sign_consensus(std::string_view(message.data(), message.size()));
      if (!signature) {
        fail("deterministic fixture signing");
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
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("n6-parent")));
    return require_ok(
        block::BlockSignatureSet::create_simplex_pq_final(pairs(count), catchain_seqno, vset->get_validator_set_hash(),
                                                          session_id, slot, std::move(candidate_copy)),
        "create #13 signature set");
  }
};

struct MatrixRow {
  std::size_t signers{};
  std::size_t samples{};
  std::size_t n4_bytes{};
  std::size_t n5_boc_bytes{};
  std::size_t block_proof_boc_bytes{};
  std::size_t lite_tl_bytes{};
  Stats n4_parse;
  Stats n4_verify;
  Stats n5_serialize;
  Stats n5_parse;
  Stats n5_verify;
  Stats block_proof_roundtrip_verify;
  Stats lite_roundtrip_verify;
};

struct AuthorityRow {
  std::size_t validators{};
  Stats miss;
  Stats hit;
};

td::BufferSlice make_n4_certificate(const Fixture &fixture, std::size_t count) {
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

std::unique_ptr<consensus::Bus> make_consensus_bus(const Fixture &fixture, std::size_t count) {
  auto bus = std::make_unique<consensus::Bus>();
  bus->session_id = fixture.session_id;
  bus->shard = tos::ShardIdFull{tos::masterchainId};
  bus->cc_seqno = Fixture::catchain_seqno;
  bus->total_weight = 0;
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
      fail("N4 fixture validator weight overflow");
    }
  }
  return bus;
}

void verify_raw(const Fixture &fixture, std::size_t count, bool invalid_first = false) {
  for (std::size_t i = 0; i < count; ++i) {
    auto signature = fixture.signatures[i].signature.as_slice();
    std::string changed;
    if (invalid_first && i == 0) {
      changed.assign(signature.data(), signature.size());
      changed[100] ^= 1;
      signature = td::Slice(changed);
    }
    const auto result = tos::pq::verify_mldsa44(
        std::string_view(fixture.message.data(), fixture.message.size()), tos::pq::simplex_sign_context,
        std::string_view(signature.data(), signature.size()), fixture.descriptors[i].pq_public_key);
    const auto expected = invalid_first && i == 0 ? tos::pq::VerifyResult::invalid : tos::pq::VerifyResult::valid;
    if (result != expected) {
      fail("raw ML-DSA verification result signer=" + std::to_string(i) + " actual=" +
           std::to_string(static_cast<int>(result)) + " expected=" + std::to_string(static_cast<int>(expected)));
    }
  }
}

td::Ref<vm::Cell> make_block_proof(const Fixture &fixture, td::Ref<vm::Cell> signatures) {
  vm::CellBuilder proof_payload;
  proof_payload.store_long(0x51, 8);
  vm::CellBuilder root;
  if (!(root.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(root, fixture.block_id) &&
        root.store_ref_bool(proof_payload.finalize()) && root.store_bool_bool(true) &&
        root.store_ref_bool(std::move(signatures)))) {
    fail("build block proof");
  }
  return root.finalize_novm();
}

td::Ref<block::BlockSignatureSet> parse_block_proof(td::Slice boc, td::Ref<block::ValidatorSet> vset) {
  auto root = require_ok(vm::std_boc_deserialize(boc), "block proof BOC parse");
  block::gen::BlockProof::Record record;
  if (!block::gen::t_BlockProof.cell_unpack(root, record) || record.signatures.is_null()) {
    fail("block proof signature reference parse");
  }
  return require_ok(block::BlockSignatureSet::fetch(record.signatures->prefetch_ref(), std::move(vset)),
                    "block proof #13 parse");
}

MatrixRow measure_matrix_row(const Fixture &fixture, std::size_t count, std::size_t samples) {
  const auto warmup = std::min<std::size_t>(10, samples);
  auto vset = fixture.validator_set(count);
  auto signature_set = fixture.signature_set(count, vset);
  auto n4 = make_n4_certificate(fixture, count);
  auto consensus_bus = make_consensus_bus(fixture, count);
  auto n5_cell = require_ok(signature_set->serialize(vset), "#13 serialize fixture");
  // Size claims reuse the N5 frozen fixture. Dictionary layout depends on validator-id
  // bit patterns, so sizing a second valid fixture is not evidence for the frozen worst-case
  // envelope even though it exercises the same codec and signer count.
  const auto frozen_n5_cell = frozen_signature_set_cell(count);
  const auto n5_boc = require_ok(vm::std_boc_serialize(frozen_n5_cell, 0), "frozen #13 BOC size");
  const auto proof_boc =
      require_ok(vm::std_boc_serialize(frozen_block_proof_cell(frozen_n5_cell), 0), "frozen BlockProof BOC size");
  auto lite_bytes = tos::serialize_tl_object(signature_set->tl_lite(), true);
  block::PQFinalityVerificationContext context{vset, fixture.block_id, fixture.session_id};

  auto n4_parse = measure(warmup, samples, [&] {
    auto parsed = tos::fetch_tl_object<tos::tos_api::consensus_simplex_certificate>(n4.clone(), true);
    if (parsed.is_error()) {
      fail("N4 certificate parse");
    }
  });
  auto n4_verify = measure(warmup, samples, [&] {
    auto parsed = tos::fetch_tl_object<tos::tos_api::consensus_simplex_certificate>(n4.clone(), true);
    if (parsed.is_error()) {
      fail("N4 certificate verify parse");
    }
    auto verified = simplex::Certificate<simplex::Vote>::from_tl(std::move(*parsed.move_as_ok()), *consensus_bus);
    if (verified.is_error()) {
      fail("N4 production certificate verify: " + verified.error().message().str());
    }
  });
  auto n5_serialize = measure(warmup, samples, [&] {
    auto cell = signature_set->serialize(vset);
    if (cell.is_error()) {
      fail("#13 serialize");
    }
  });
  auto n5_parse = measure(warmup, samples, [&] {
    auto parsed = block::BlockSignatureSet::fetch(n5_cell, vset);
    if (parsed.is_error()) {
      fail("#13 parse");
    }
  });
  auto n5_verify = measure(warmup, samples, [&] {
    auto verified = block::verify_pq_finality(context, *signature_set, block::FinalityRole::Final);
    if (verified.is_error()) {
      fail("#13 verify");
    }
  });
  auto block_proof = measure(warmup, samples, [&] {
    auto proof_cell = make_block_proof(fixture, n5_cell);
    auto serialized = require_ok(vm::std_boc_serialize(proof_cell, 0), "BlockProof serialize");
    auto parsed = parse_block_proof(serialized.as_slice(), vset);
    auto verified = block::verify_pq_finality(context, *parsed, block::FinalityRole::Final);
    if (verified.is_error()) {
      fail("BlockProof signature-reference verify");
    }
  });
  auto lite = measure(warmup, samples, [&] {
    auto serialized = tos::serialize_tl_object(signature_set->tl_lite(), true);
    auto object = tos::fetch_tl_object<tos::lite_api::liteServer_SignatureSet>(std::move(serialized), true);
    if (object.is_error()) {
      fail("lite SignatureSet TL parse");
    }
    auto parsed = block::BlockSignatureSet::fetch_lite_checked(object.ok());
    if (parsed.is_error()) {
      fail("lite SignatureSet checked parse");
    }
    auto verified = block::verify_pq_finality(context, *parsed.ok(), block::FinalityRole::Final);
    if (verified.is_error()) {
      fail("lite SignatureSet verify");
    }
  });
  return {count,    samples,   n4.size(),    n5_boc.size(), proof_boc.size(), lite_bytes.size(),
          n4_parse, n4_verify, n5_serialize, n5_parse,      n5_verify,        block_proof,
          lite};
}

struct StallActor final : td::actor::Actor {
  StallActor(block::PQFinalityVerificationContext context, td::Ref<block::BlockSignatureSet> signatures,
             double &elapsed_us)
      : context_(std::move(context)), signatures_(std::move(signatures)), elapsed_us_(elapsed_us) {
  }
  void start_up() override {
    const auto begin = Clock::now();
    auto result = block::verify_pq_finality(context_, *signatures_, block::FinalityRole::Final);
    elapsed_us_ = std::chrono::duration<double, std::micro>(Clock::now() - begin).count();
    if (result.is_error()) {
      fail("actor callback verification");
    }
    stop();
  }
  void tear_down() override {
    td::actor::SchedulerContext::get().stop();
  }
  block::PQFinalityVerificationContext context_;
  td::Ref<block::BlockSignatureSet> signatures_;
  double &elapsed_us_;
};

double actor_stall(const Fixture &fixture, std::size_t count) {
  auto vset = fixture.validator_set(count);
  auto signatures = fixture.signature_set(count, vset);
  double elapsed_us = 0;
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<StallActor> actor;
  scheduler.run_in_context([&] {
    actor = td::actor::create_actor<StallActor>(
        "n6-stall", block::PQFinalityVerificationContext{vset, fixture.block_id, fixture.session_id}, signatures,
        elapsed_us);
  });
  while (scheduler.run(1)) {
  }
  actor.reset();
  scheduler.stop();
  return elapsed_us;
}

std::string read_first_line(const std::string &path) {
  std::ifstream input(path);
  std::string line;
  if (input) {
    std::getline(input, line);
  }
  return line.empty() ? "unavailable" : line;
}

std::vector<int> affinity_cpus() {
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) != 0) {
    fail("sched_getaffinity");
  }
  std::vector<int> result;
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &set)) {
      result.push_back(cpu);
    }
  }
  if (result.empty()) {
    fail("empty CPU affinity");
  }
  return result;
}

}  // namespace

int main(int argc, char **argv) {
  std::string output_path;
  std::string git_commit;
  std::string criteria_sha256;
  std::size_t single_samples = 10000;
  std::size_t small_batch_samples = 100;
  std::size_t large_batch_samples = 30;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto value = [&]() -> std::string {
      if (++i >= argc) {
        fail("missing value for " + arg);
      }
      return argv[i];
    };
    if (arg == "--output") {
      output_path = value();
    } else if (arg == "--git-commit") {
      git_commit = value();
    } else if (arg == "--criteria-sha256") {
      criteria_sha256 = value();
    } else if (arg == "--single-samples") {
      single_samples = std::stoull(value());
    } else if (arg == "--small-batch-samples") {
      small_batch_samples = std::stoull(value());
    } else if (arg == "--large-batch-samples") {
      large_batch_samples = std::stoull(value());
    } else {
      fail("unknown argument " + arg);
    }
  }
  if (output_path.empty() || git_commit.empty() || criteria_sha256.size() != 64) {
    fail("--output, --git-commit and a 64-hex --criteria-sha256 are required");
  }

  vm::init_vm().ensure();
  const auto cpus = affinity_cpus();
  Fixture fixture;
  const auto single_warmup = std::min<std::size_t>(1000, single_samples);
  auto sign = measure(single_warmup, single_samples, [&] {
    if (!fixture.stores[0].sign_consensus(std::string_view(fixture.message.data(), fixture.message.size()))) {
      fail("single sign");
    }
  });
  auto verify_valid = measure(single_warmup, single_samples, [&] { verify_raw(fixture, 1); });
  auto verify_invalid = measure(single_warmup, single_samples, [&] { verify_raw(fixture, 1, true); });
  auto key_id = measure(single_warmup, single_samples, [&] {
    if (!tos::pq::derive_key_id(fixture.signatures[0].algorithm_id, fixture.descriptors[0].pq_public_key)) {
      fail("key-id derivation");
    }
  });
  td::BufferSlice key_bytes(tos::pq::mldsa44_public_key_bytes);
  td::BufferSlice signature_bytes(tos::pq::mldsa44_signature_bytes);
  auto pqbytes_1312 = measure(single_warmup, single_samples, [&] {
    auto cell = require_ok(tos::pq::pack_pq_bytes(key_bytes.as_slice(), key_bytes.size()), "PQBytes 1312 pack");
    require_ok(tos::pq::unpack_pq_bytes(std::move(cell), key_bytes.size()), "PQBytes 1312 unpack");
  });
  auto pqbytes_2420 = measure(single_warmup, single_samples, [&] {
    auto cell =
        require_ok(tos::pq::pack_pq_bytes(signature_bytes.as_slice(), signature_bytes.size()), "PQBytes 2420 pack");
    require_ok(tos::pq::unpack_pq_bytes(std::move(cell), signature_bytes.size()), "PQBytes 2420 unpack");
  });

  std::vector<MatrixRow> matrix;
  for (std::size_t count : {1U, 4U, 21U, 32U, 64U, 100U, 200U, 300U, 400U}) {
    matrix.push_back(measure_matrix_row(fixture, count, count <= 100 ? small_batch_samples : large_batch_samples));
  }
  auto over_limit = fixture.pairs(400);
  over_limit.push_back({fixture.signatures[0].validator_id, fixture.signatures[0].algorithm_id,
                        fixture.signatures[0].signature.clone()});
  auto rejected_401 = block::BlockSignatureSet::create_simplex_pq_final(
      std::move(over_limit), Fixture::catchain_seqno, fixture.validator_set(400)->get_validator_set_hash(),
      fixture.session_id, Fixture::slot,
      tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
          tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
              fixture.block_id.id.workchain, static_cast<td::int64>(fixture.block_id.id.shard),
              fixture.block_id.id.seqno, fixture.block_id.root_hash, fixture.block_id.file_hash),
          tos::create_tl_object<tos::tos_api::consensus_candidateId>(Fixture::slot - 1, hash_of("n6-parent"))));
  if (rejected_401.is_ok() ||
      rejected_401.error().message().str().find("signer count exceeds maximum") == std::string::npos) {
    fail("401-signer structural negative");
  }

  std::vector<AuthorityRow> authority;
  for (std::size_t count : {21U, 100U, 400U}) {
    tos::validator::PendingFinalityAuthorityMemo memo;
    const auto validator_count = static_cast<int>(count);
    block::TotalValidatorSet total(0, 1, validator_count, validator_count);
    total.list.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      const auto &descriptor = fixture.descriptors[i];
      total.list.emplace_back(descriptor.validator_id, descriptor.algorithm_id, descriptor.key_id,
                              descriptor.pq_public_key, descriptor.weight, i, descriptor.addr);
    }
    total.total_weight = count;
    block::CatchainValidatorsConfig config(0, 0, 0, static_cast<td::uint32>(count));
    const tos::ShardIdFull shard{tos::basechainId, tos::shardIdAll};
    auto make_set = [&](tos::CatchainSeqno seqno) {
      auto descriptors = block::Config::do_compute_validator_set(config, shard, total, seqno);
      std::vector<tos::PublicKeyHash> roots;
      roots.reserve(descriptors.size());
      for (const auto &descriptor : descriptors) {
        roots.push_back(tos::PublicKeyHash{block::validator_adnl_identity(descriptor)});
      }
      auto set = td::Ref<block::ValidatorSet>{true, seqno, shard, std::move(descriptors)};
      return tos::validator::PendingFinalityAuthoritySet{set->get_validator_set_hash(), std::move(roots), set};
    };
    const auto expected = make_set(Fixture::catchain_seqno);
    auto loader = [&] {
      std::vector<tos::validator::PendingFinalityAuthoritySet> result;
      result.push_back(make_set(Fixture::catchain_seqno));
      result.push_back(make_set(Fixture::catchain_seqno + 1));
      return result;
    };
    auto miss = measure(10, small_batch_samples, [&] {
      memo.clear();
      if (!memo.contains({shard, Fixture::catchain_seqno}, expected.validator_set_hash, expected.roots.back(),
                         loader)) {
        fail("authority memo miss classification");
      }
    });
    memo.clear();
    if (!memo.contains({shard, Fixture::catchain_seqno}, expected.validator_set_hash, expected.roots.back(), loader)) {
      fail("authority memo hit setup");
    }
    auto hit = measure(10, small_batch_samples, [&] {
      if (!memo.contains({shard, Fixture::catchain_seqno}, expected.validator_set_hash, expected.roots.back(),
                         loader)) {
        fail("authority memo hit classification");
      }
    });
    authority.push_back({count, miss, hit});
  }

  auto pending_primitives = measure(100, single_samples, [&] {
    const auto decision = tos::validator::pending_finality_failure_action(
        tos::ErrorCode::notready, 1.0, tos::validator::pending_finality_retention_seconds);
    if (decision != tos::validator::PendingFinalityFailureAction::Retry ||
        tos::validator::pending_finality_exceeds_budget(4096, 0, 4096, 16384)) {
      fail("pending-finality primitive");
    }
  });

  std::vector<std::pair<std::size_t, Stats>> concurrency;
  for (std::size_t workers : {1U, 2U, 4U, 8U, 16U}) {
    if (workers > cpus.size()) {
      continue;
    }
    concurrency.emplace_back(
        workers, measure(2, 20, [&] {
          std::vector<std::thread> threads;
          for (std::size_t worker = 0; worker < workers; ++worker) {
            threads.emplace_back([&, worker] {
              for (std::size_t i = worker; i < 100; i += workers) {
                const auto &signature = fixture.signatures[i];
                if (tos::pq::verify_mldsa44(std::string_view(fixture.message.data(), fixture.message.size()),
                                            tos::pq::simplex_sign_context,
                                            std::string_view(signature.signature.data(), signature.signature.size()),
                                            fixture.descriptors[i].pq_public_key) != tos::pq::VerifyResult::valid) {
                  fail("bounded concurrency verification");
                }
              }
            });
          }
          for (auto &thread : threads) {
            thread.join();
          }
        }));
  }

  const double stall_us = actor_stall(fixture, 100);
  const auto &launch_row =
      *std::find_if(matrix.begin(), matrix.end(), [](const auto &row) { return row.signers == 100; });
  const auto cpu = cpus.front();
  const auto governor =
      read_first_line("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/scaling_governor");
  const auto frequency =
      read_first_line("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/scaling_cur_freq");
  std::string cpu_model = "unavailable";
  std::ifstream cpuinfo("/proc/cpuinfo");
  for (std::string line; std::getline(cpuinfo, line);) {
    if (line.rfind("model name", 0) == 0) {
      const auto separator = line.find(':');
      if (separator != std::string::npos) {
        cpu_model = line.substr(separator + 1);
        while (!cpu_model.empty() && cpu_model.front() == ' ')
          cpu_model.erase(cpu_model.begin());
      }
      break;
    }
  }

  std::ofstream out(output_path);
  if (!out) {
    fail("open output");
  }
  out << std::fixed << std::setprecision(3);
  out << "{\n  \"schema_version\":1,\n  \"evidence_class\":\"DIAGNOSTIC_FEASIBILITY_ONLY\",\n";
  out << "  \"release_evidence_eligible\":false,\n  \"git_commit\":" << json_string(git_commit) << ",\n";
  out << "  \"acceptance_criteria_sha256\":" << json_string(criteria_sha256) << ",\n";
  out << "  \"build\":{\"type\":" << json_string(N6_BUILD_TYPE) << ",\"compiler\":" << json_string(N6_COMPILER)
      << ",\"allocator\":\"system\",\"pq_backend\":\"native-ml-dsa-44\"},\n";
  out << "  \"host\":{\"cpu_model\":" << json_string(cpu_model) << ",\"affinity_cpus\":[";
  for (std::size_t i = 0; i < cpus.size(); ++i) {
    if (i)
      out << ',';
    out << cpus[i];
  }
  out << "],\"frequency_khz_observed\":" << json_string(frequency) << ",\"governor_observed\":" << json_string(governor)
      << ",\"frequency_or_governor_changed_by_runner\":false},\n";
  out << "  \"sample_policy\":{\"single_warmup\":" << single_warmup << ",\"single_measured\":" << single_samples
      << ",\"small_batch_measured\":" << small_batch_samples << ",\"large_batch_measured\":" << large_batch_samples
      << ",\"shortened_batches_are_diagnostic\":true},\n";
  out << "  \"single_operations\":{\n";
  for (const auto &[name, stats] :
       std::vector<std::pair<std::string, Stats>>{{"mldsa44_sign", sign},
                                                  {"mldsa44_verify_valid", verify_valid},
                                                  {"mldsa44_verify_invalid", verify_invalid},
                                                  {"key_id_derivation", key_id},
                                                  {"pqbytes_1312_pack_unpack", pqbytes_1312},
                                                  {"pqbytes_2420_pack_unpack", pqbytes_2420},
                                                  {"pending_finality_primitives", pending_primitives}}) {
    out << "    " << json_string(name) << ':';
    write_stats(out, stats);
    out << (name == "pending_finality_primitives" ? "\n" : ",\n");
  }
  out << "  },\n  \"authority_classification\":[\n";
  for (std::size_t i = 0; i < authority.size(); ++i) {
    out << "    {\"validators\":" << authority[i].validators << ",\"memo_miss_current_and_next\":";
    write_stats(out, authority[i].miss);
    out << ",\"memo_hit\":";
    write_stats(out, authority[i].hit);
    out << '}' << (i + 1 == authority.size() ? "\n" : ",\n");
  }
  out << "  ],\n  \"certificate_proof_matrix\":[\n";
  for (std::size_t i = 0; i < matrix.size(); ++i) {
    const auto &row = matrix[i];
    out << "    {\"signers\":" << row.signers << ",\"samples\":" << row.samples
        << ",\"sizes\":{\"n4_certificate_tl_bytes\":" << row.n4_bytes << ",\"n5_13_boc_bytes\":" << row.n5_boc_bytes
        << ",\"block_proof_boc_bytes\":" << row.block_proof_boc_bytes
        << ",\"lite_signature_set_tl_bytes\":" << row.lite_tl_bytes << "},\"timings\":{";
    const std::array<std::pair<std::string_view, const Stats *>, 7> timings{
        {{"n4_certificate_parse", &row.n4_parse},
         {"n4_certificate_verify", &row.n4_verify},
         {"n5_13_serialize", &row.n5_serialize},
         {"n5_13_parse", &row.n5_parse},
         {"n5_13_verify", &row.n5_verify},
         {"block_proof_signature_reference_roundtrip_verify", &row.block_proof_roundtrip_verify},
         {"lite_signature_set_roundtrip_verify", &row.lite_roundtrip_verify}}};
    for (std::size_t j = 0; j < timings.size(); ++j) {
      out << json_string(timings[j].first) << ':';
      write_stats(out, *timings[j].second);
      if (j + 1 != timings.size())
        out << ',';
    }
    out << "}}" << (i + 1 == matrix.size() ? "\n" : ",\n");
  }
  out << "  ],\n  \"structural_401\":{\"accepted\":false,\"reason\":"
      << json_string(rejected_401.error().message().str()) << "},\n";
  out << "  \"concurrency_sweep_100_signers\":[";
  for (std::size_t i = 0; i < concurrency.size(); ++i) {
    out << "{\"workers\":" << concurrency[i].first << ",\"batch\":";
    write_stats(out, concurrency[i].second);
    out << '}' << (i + 1 == concurrency.size() ? "" : ",");
  }
  out << "],\n  \"actor_thread_decision\":{\"launch_proof_signers\":100,\"launch_block_proof_bytes\":"
      << launch_row.block_proof_boc_bytes << ",\"single_thread_actor_callback_stall_us\":" << stall_us
      << ",\"decision\":\"OPEN_UNTIL_OWNER_ACCEPTS_NONZERO_CRITERIA\",\"worker_pool_changed\":false},\n";
  out << "  \"scope\":{\"n4_certificate\":\"production TL parser, quorum and ML-DSA verifier\","
         "\"authority_classification\":\"production shard-set computation and memo lookup\","
         "\"n5_carrier_and_crypto\":\"production\",\"block_proof\":\"real serialized BlockProof signature "
         "reference; no CheckProof actor claim\",\"lite\":\"real checked SignatureSet parser; no transport or "
         "chain-advancement claim\"},\n";
  out << "  "
         "\"acceptance_evaluation\":{\"status\":\"NOT_EVALUATED_OWNER_CRITERIA_UNSET\",\"thresholds_moved_to_fit_"
         "results\":false}\n}\n";
  out.close();
  std::cout << "N6_MICROBENCH_DONE output=" << output_path << " evidence=DIAGNOSTIC_FEASIBILITY_ONLY\n";
  return 0;
}
