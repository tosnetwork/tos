/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/block/signature-set.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/mldsa44.h"
#include "overlay/broadcast-plumtree.hpp"
#include "td/utils/overloaded.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/full-node-serializer.hpp"
#include "validator/impl/accept-block.hpp"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

#include "block-signature-carrier-common.h"

namespace {

using namespace block_signature_carrier_test;
using tos::validator::BlockBroadcast;
using tos::validator::BlockFinalityBroadcast;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

template <class T>
T require_ok(td::Result<T> result, std::string_view where) {
  if (result.is_error()) {
    fail("PQ_BROADCAST_UNEXPECTED_ERROR where=" + std::string(where) + " reason=" + result.error().message().str());
  }
  return result.move_as_ok();
}

tos::ConsensusKeyId key_id_of(const tos::pq::ConsensusPQKey& key) {
  td::Bits256 bits;
  std::memcpy(bits.data(), key.key_id.data(), key.key_id.size());
  return tos::ConsensusKeyId{bits};
}

std::string_view view(td::Slice bytes) {
  return {bytes.data(), bytes.size()};
}

struct Fixture {
  std::vector<tos::pq::ValidatorPQKeyStore> stores;
  std::vector<tos::ValidatorId> validator_ids;
  td::Ref<block::ValidatorSet> validator_set;
  td::Ref<block::BlockSignatureSet> signature_set;

  explicit Fixture(std::size_t count) {
    std::vector<tos::ValidatorDescr> descriptors;
    descriptors.reserve(count);
    stores.reserve(count);
    validator_ids.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      const auto seed = hash_of("persisted-signature-key-" + std::to_string(i));
      auto store =
          tos::pq::ValidatorPQKeyStore::from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), 32));
      if (!store.has_value()) {
        fail("PQ_BROADCAST_KEY_DERIVATION signer=" + std::to_string(i));
      }
      auto validator_id = tos::ValidatorId{hash_of("persisted-validator-" + std::to_string(i))};
      const auto& key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key), key.public_key,
                               signature_weight, hash_of("persisted-validator-adnl-" + std::to_string(i)));
      validator_ids.push_back(validator_id);
      stores.push_back(std::move(*store));
    }
    validator_set = td::Ref<block::ValidatorSet>{true, catchain_seqno, tos::ShardIdFull{tos::masterchainId},
                                                 std::move(descriptors)};

    auto message = require_ok(
        block::BlockSignatureSet::build_simplex_data_to_sign(session_id(), slot, candidate(), true, block_id()),
        "build-preimage");
    std::vector<block::PQBlockSignature> signatures;
    signatures.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      auto signed_vote = stores[i].sign_consensus(view(message.as_slice()));
      if (!signed_vote.has_value()) {
        fail("PQ_BROADCAST_SIGN signer=" + std::to_string(i));
      }
      signatures.push_back({validator_ids[i], signed_vote->algorithm_id, td::BufferSlice(signed_vote->signature)});
    }
    signature_set = require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                                   std::move(signatures), catchain_seqno, validator_set->get_validator_set_hash(),
                                   session_id(), slot, candidate()),
                               "create-signature-set");
  }
};

td::BufferSlice tiny_boc(unsigned value) {
  vm::CellBuilder builder;
  if (!builder.store_long_bool(value, 8)) {
    fail("PQ_BROADCAST_TEST_CELL");
  }
  return require_ok(vm::std_boc_serialize(builder.finalize_novm(), 31), "serialize-test-cell");
}

std::size_t recorded_v2_size(std::size_t signers) {
  std::ifstream input(ROUTES_FILE);
  if (!input) {
    fail("PQ_BROADCAST_ROUTE_TABLE_MISSING");
  }
  const auto subject =
      "verdict\tcomplete-tosNode.blockBroadcastCompressedV2/" + std::to_string(signers) + "\tmeasured:";
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind(subject, 0) != 0) {
      continue;
    }
    const auto end = line.find('\t', subject.size());
    if (end == std::string::npos) {
      break;
    }
    return std::stoull(line.substr(subject.size(), end - subject.size()));
  }
  fail("PQ_BROADCAST_ROUTE_ROW_MISSING signers=" + std::to_string(signers));
}

void accept_received(const Fixture& fixture, const td::Ref<block::BlockSignatureSet>& signatures,
                     std::string_view route, std::size_t expected_calls) {
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto prepared =
      tos::validator::prepare_accepted_block_signatures(fixture.validator_set, signatures, block_id(), session_id());
  if (prepared.is_error()) {
    fail("PQ_BROADCAST_CONSUMER_REJECT route=" + std::string(route) + " reason=" + prepared.error().message().str());
  }
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (calls != expected_calls) {
    fail("PQ_BROADCAST_CRYPTO_CALLS route=" + std::string(route) + " expected=" + std::to_string(expected_calls) +
         " actual=" + std::to_string(calls));
  }
}

void run_semantic_round_trip(std::size_t count) {
  Fixture fixture(count);
  BlockBroadcast outgoing{block_id(), fixture.signature_set, tiny_boc(0x51), tiny_boc(0x52)};
  auto block_payload = require_ok(
      tos::validator::fullnode::serialize_block_broadcast(outgoing, "pq-broadcast-semantics"), "serialize-block");
  const auto recorded_block_bytes = recorded_v2_size(count);
  if (block_payload.size() != recorded_block_bytes) {
    fail("PQ_BROADCAST_RECORDED_SIZE signers=" + std::to_string(count) +
         " recorded=" + std::to_string(recorded_block_bytes) + " actual=" + std::to_string(block_payload.size()));
  }
  auto block_tl =
      require_ok(tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(block_payload.clone(), true), "parse-block-tl");
  if (block_tl->get_id() != tos::tos_api::tosNode_blockBroadcastCompressedV2::ID) {
    fail("PQ_BROADCAST_WRONG_BLOCK_VARIANT");
  }
  auto received = require_ok(tos::validator::fullnode::deserialize_block_broadcast(
                                 *block_tl, tos::overlay::Overlays::max_fec_broadcast_size(), "pq-broadcast-semantics"),
                             "deserialize-block");
  accept_received(fixture, received.sig_set, "compressed-v2", count);

  BlockFinalityBroadcast finality{block_id(), fixture.signature_set};
  auto finality_payload = tos::validator::fullnode::serialize_block_finality_broadcast(finality);
  auto admission = tos::overlay::check_plumtree_payload_size(finality_payload.size());
  if (admission.is_error()) {
    fail("PQ_BROADCAST_PLUMTREE_ADMISSION reason=" + admission.message().str());
  }
  auto finality_tl = require_ok(tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(finality_payload.clone(), true),
                                "parse-finality-tl");
  if (finality_tl->get_id() != tos::tos_api::tosNode_blockFinalityBroadcast::ID) {
    fail("PQ_BROADCAST_WRONG_FINALITY_VARIANT");
  }
  auto& finality_object = static_cast<tos::tos_api::tosNode_blockFinalityBroadcast&>(*finality_tl);
  auto received_finality = require_ok(tos::validator::fullnode::deserialize_block_finality_broadcast(finality_object),
                                      "deserialize-finality");
  accept_received(fixture, received_finality.sig_set, "plumtree-simple", count);

  std::printf(
      "PQ_BROADCAST_ROUND_TRIP signers=%zu block_variant=compressed-v2 block_bytes=%zu "
      "finality_route=plumtree-simple finality_bytes=%zu consumer=accept-block crypto_calls_per_route=%zu\n",
      count, block_payload.size(), finality_payload.size(), count);
}

void run_structural_v2_round_trip(std::size_t count) {
  auto signatures = make_signatures(count, false);
  auto parsed = require_ok(block::BlockSignatureSet::fetch_node_checked(node_signature_set(signatures)),
                           "structural-signature-set");
  BlockBroadcast outgoing{block_id(), std::move(parsed), tiny_boc(0x51), tiny_boc(0x52)};
  auto payload = require_ok(tos::validator::fullnode::serialize_block_broadcast(outgoing, "pq-broadcast-size"),
                            "serialize-size-block");
  const auto recorded = recorded_v2_size(count);
  if (payload.size() != recorded) {
    fail("PQ_BROADCAST_RECORDED_SIZE signers=" + std::to_string(count) + " recorded=" + std::to_string(recorded) +
         " actual=" + std::to_string(payload.size()));
  }
  auto object =
      require_ok(tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(payload.clone(), true), "parse-size-block");
  auto received = require_ok(tos::validator::fullnode::deserialize_block_broadcast(
                                 *object, tos::overlay::Overlays::max_fec_broadcast_size(), "pq-broadcast-size"),
                             "deserialize-size-block");
  auto actual = require_ok(received.sig_set->export_pq_signatures(), "export-size-signatures");
  if (actual.size() != count) {
    fail("PQ_BROADCAST_SIZE_SIGNER_COUNT expected=" + std::to_string(count) +
         " actual=" + std::to_string(actual.size()));
  }
  std::printf("PQ_BROADCAST_STRUCTURAL_ROUND_TRIP signers=%zu block_variant=compressed-v2 block_bytes=%zu\n", count,
              payload.size());
}

tos::tos_api::tosNode_signatureSet_simplexPq& pq_set(tos::tos_api::tosNode_blockFinalityBroadcast& finality) {
  if (finality.signature_set_->get_id() != tos::tos_api::tosNode_signatureSet_simplexPq::ID) {
    fail("PQ_BROADCAST_TAMPER_WRONG_VARIANT");
  }
  return static_cast<tos::tos_api::tosNode_signatureSet_simplexPq&>(*finality.signature_set_);
}

template <class Mutate>
void expect_tamper(const Fixture& fixture, std::string_view name, std::string_view reason, std::size_t expected_calls,
                   Mutate&& mutate) {
  auto bytes = tos::validator::fullnode::serialize_block_finality_broadcast({block_id(), fixture.signature_set});
  auto outer =
      require_ok(tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(std::move(bytes), true), "tamper-outer");
  auto& finality = static_cast<tos::tos_api::tosNode_blockFinalityBroadcast&>(*outer);
  mutate(pq_set(finality).signatures_[0]);
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto parsed = tos::validator::fullnode::deserialize_block_finality_broadcast(finality);
  td::Status error;
  if (parsed.is_error()) {
    error = parsed.move_as_error();
  } else {
    auto accepted = tos::validator::prepare_accepted_block_signatures(fixture.validator_set, parsed.ok().sig_set,
                                                                      block_id(), session_id());
    if (accepted.is_ok()) {
      fail("PQ_BROADCAST_TAMPER_UNEXPECTED_ACCEPT case=" + std::string(name));
    }
    error = accepted.move_as_error();
  }
  if (error.message().str() != reason) {
    fail("PQ_BROADCAST_TAMPER_REASON case=" + std::string(name) + " expected=" + std::string(reason) +
         " actual=" + error.message().str());
  }
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (calls != expected_calls) {
    fail("PQ_BROADCAST_TAMPER_CRYPTO_CALLS case=" + std::string(name) + " expected=" + std::to_string(expected_calls) +
         " actual=" + std::to_string(calls));
  }
  std::printf("PQ_BROADCAST_TAMPER case=%s reason=%s crypto_calls=%zu\n", std::string(name).c_str(),
              std::string(reason).c_str(), calls);
}

void run_tamper_matrix() {
  Fixture fixture(21);
  expect_tamper(fixture, "unknown-validator-id", "pq signatures: unknown validator_id", 0,
                [](auto& pair) { pair->validator_id_.as_slice()[0] ^= 1; });
  expect_tamper(fixture, "unsupported-algorithm", "pq tl: unsupported_algorithm", 0,
                [](auto& pair) { pair->algorithm_id_ = 2; });
  expect_tamper(fixture, "signature-length", "pq tl: signature_length", 0,
                [](auto& pair) { pair->signature_.truncate(pair->signature_.size() - 1); });
  expect_tamper(fixture, "invalid-signature", "pq signatures: invalid signature", 1,
                [](auto& pair) { pair->signature_.as_slice()[100] ^= 1; });
}

}  // namespace

int main() {
  run_structural_v2_round_trip(1);
  run_semantic_round_trip(21);
  run_semantic_round_trip(100);
  run_structural_v2_round_trip(400);
  run_tamper_matrix();
  std::printf(
      "PQ_BROADCAST_SCOPE deliverability_and_trusted_signature_consumer=1 live_overlay_peer_graph=0 "
      "block_acceptance_actor=0\n");
  return 0;
}
