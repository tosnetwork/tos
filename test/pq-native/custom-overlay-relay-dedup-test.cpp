/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Drives the relay decision FullNodeImpl uses for its custom overlays through a
// fake verifier and fake overlays. What is forwarded is remembered so it is sent
// once; an item that is not bound to its block id, or whose signatures did not
// verify, must never be remembered first, or it would keep the genuine item for
// that block from being forwarded.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "block/block-db.h"
#include "block/signature-set.h"
#include "validator/full-node-relay-dedup.h"

namespace {

using tos::validator::BlockBroadcast;
using tos::validator::BlockFinalityBroadcast;
using tos::validator::fullnode::CustomOverlayRelay;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "CUSTOM_OVERLAY_RELAY_DEDUP_FAILURE: " << message << '\n';
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

td::Bits256 fill(unsigned char value) {
  td::Bits256 result;
  std::memset(result.data(), value, result.as_slice().size());
  return result;
}

tos::BlockIdExt block_id(td::uint32 seqno, td::Bits256 file_hash) {
  return tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, seqno, fill(0x31), file_hash};
}

td::Ref<block::BlockSignatureSet> evidence(unsigned char marker) {
  std::vector<tos::BlockSignature> signatures;
  signatures.emplace_back(tos::NodeIdShort{fill(0x71)}, td::BufferSlice(std::string(64, static_cast<char>(marker))));
  return block::BlockSignatureSet::create_ordinary(std::move(signatures), 7, 0x1234);
}

struct ShardBlockInfo {
  tos::BlockIdExt block_id;
  tos::CatchainSeqno cc_seqno;
  std::string data;
};

struct Candidate {
  tos::BlockIdExt block_id;
  tos::CatchainSeqno cc_seqno;
  td::uint32 validator_set_hash;
  std::string data;
};

// A relay wired to a fake verifier, which only records what it was asked to
// verify, and fake overlays, which record what was sent.
struct Harness {
  explicit Harness(size_t capacity) : relay(capacity) {
    relay.set_hooks(CustomOverlayRelay::Hooks{
        .verify_block_signatures = [this](BlockBroadcast broadcast) { verifying.push_back(std::move(broadcast)); },
        .send_block = [this](const BlockBroadcast &broadcast) { blocks.push_back(broadcast.clone()); },
        .send_candidate =
            [this](const tos::BlockIdExt &id, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
                   const td::BufferSlice &data) {
              candidates.push_back(Candidate{id, cc_seqno, validator_set_hash, data.as_slice().str()});
            },
        .send_finality = [this](const BlockFinalityBroadcast &finality) { finality_sent.push_back(finality.clone()); },
        .send_shard_block_info =
            [this](const tos::BlockIdExt &id, tos::CatchainSeqno cc_seqno, const td::BufferSlice &data) {
              shard_block_infos.push_back(ShardBlockInfo{id, cc_seqno, data.as_slice().str()});
            },
    });
  }

  // The verifier accepts the most recent request.
  void verification_succeeds() {
    require(!verifying.empty(), "nothing was sent for verification");
    auto broadcast = std::move(verifying.back());
    verifying.pop_back();
    relay.block_signatures_verified(broadcast);
  }

  // The verifier rejects the most recent request; the owner does not call back.
  void verification_fails() {
    require(!verifying.empty(), "nothing was sent for verification");
    verifying.pop_back();
  }

  CustomOverlayRelay relay;
  std::vector<BlockBroadcast> verifying;
  std::vector<BlockBroadcast> blocks;
  std::vector<Candidate> candidates;
  std::vector<BlockFinalityBroadcast> finality_sent;
  std::vector<ShardBlockInfo> shard_block_infos;
};

BlockBroadcast broadcast(const tos::BlockIdExt &id, td::Slice data, unsigned char signatures) {
  return BlockBroadcast{id, evidence(signatures), td::BufferSlice(data), td::BufferSlice("proof")};
}

}  // namespace

int main() {
  const std::string genuine_data = "the genuine block data";
  const std::string corrupted_data = "corrupted data under a known block id";
  const auto genuine_hash = block::compute_file_hash(td::Slice(genuine_data));

  // Corrupted data arriving with signatures already checked (the compressed
  // paths check signatures before decompression) is never forwarded and never
  // remembered; the genuine broadcast that follows is forwarded.
  {
    Harness h(16);
    auto id = block_id(10, genuine_hash);
    h.relay.offer_block(broadcast(id, corrupted_data, 0x01), true);
    require(h.blocks.empty(), "corrupted data with checked signatures is not forwarded");
    require(h.verifying.empty(), "corrupted data is refused before verification");
    h.relay.offer_block(broadcast(id, genuine_data, 0x01), true);
    require(h.blocks.size() == 1 && h.blocks[0].data.as_slice() == genuine_data,
            "the genuine broadcast after corrupted data is forwarded");
    h.relay.offer_block(broadcast(id, genuine_data, 0x01), true);
    require(h.blocks.size() == 1, "a block is forwarded once");
  }

  // The same with signatures still to be checked: corrupted data never reaches
  // the verifier, and a verified broadcast whose data is not the block's is not
  // forwarded either.
  {
    Harness h(16);
    auto id = block_id(11, genuine_hash);
    h.relay.offer_block(broadcast(id, corrupted_data, 0x01), false);
    require(h.verifying.empty(), "corrupted data is refused before verification");
    h.relay.block_signatures_verified(broadcast(id, corrupted_data, 0x01));
    require(h.blocks.empty(), "verified signatures do not bind corrupted data");
    h.relay.offer_block(broadcast(id, genuine_data, 0x01), false);
    h.verification_succeeds();
    require(h.blocks.size() == 1 && h.blocks[0].data.as_slice() == genuine_data,
            "the genuine broadcast is forwarded after verification");
  }

  // A broadcast whose signatures fail verification is never forwarded and does
  // not keep the valid one that follows from being forwarded.
  {
    Harness h(16);
    auto id = block_id(12, genuine_hash);
    h.relay.offer_block(broadcast(id, genuine_data, 0x0b), false);
    require(h.blocks.empty(), "nothing is forwarded before verification");
    require(h.verifying.size() == 1, "an unchecked broadcast is sent for verification");
    h.verification_fails();
    require(h.blocks.empty(), "a broadcast that failed verification is not forwarded");
    auto valid = broadcast(id, genuine_data, 0x01);
    auto valid_signatures = valid.sig_set;
    h.relay.offer_block(std::move(valid), false);
    require(h.verifying.size() == 1, "the valid broadcast is sent for verification");
    h.verification_succeeds();
    require(h.blocks.size() == 1, "the valid broadcast after an invalid one is forwarded");
    require(h.blocks[0].sig_set.get() == valid_signatures.get(), "the forwarded broadcast is the verified one");
  }

  // Candidates: data that is not the block's is refused; candidate metadata
  // cannot be verified here, so a candidate with wrong metadata does not keep
  // the genuine one from being forwarded, and no candidate stands in for the
  // block broadcast.
  {
    Harness h(16);
    auto id = block_id(13, genuine_hash);
    h.relay.offer_candidate(id, 5, 0xabcd, td::BufferSlice(corrupted_data));
    require(h.candidates.empty(), "a candidate whose data does not hash to the id is refused");
    h.relay.offer_candidate(id, 999, 0xdead, td::BufferSlice(genuine_data));
    require(h.candidates.size() == 1, "a candidate with unverifiable metadata is forwarded");
    h.relay.offer_candidate(id, 5, 0xabcd, td::BufferSlice(genuine_data));
    require(h.candidates.size() == 2 && h.candidates[1].cc_seqno == 5 && h.candidates[1].validator_set_hash == 0xabcd,
            "wrong metadata first did not suppress the genuine candidate");
    h.relay.offer_candidate(id, 5, 0xabcd, td::BufferSlice(genuine_data));
    require(h.candidates.size() == 2, "a candidate is forwarded once");
    h.relay.offer_block(broadcast(id, genuine_data, 0x01), true);
    require(h.blocks.size() == 1, "candidates do not suppress the block broadcast");
  }
  require(CustomOverlayRelay::candidate_key(block_id(14, fill(1)), 1, 2) !=
              CustomOverlayRelay::candidate_key(block_id(14, fill(1)), 2, 1),
          "candidate metadata fields are not interchangeable");

  // Finality evidence is remembered by content: bad evidence forwarded first
  // cannot suppress different evidence for the same block.
  {
    Harness h(16);
    auto id = block_id(15, fill(0x43));
    h.relay.offer_finality(BlockFinalityBroadcast{id, {}, 0});
    require(h.finality_sent.empty(), "finality without signatures is not forwarded");
    h.relay.offer_finality(BlockFinalityBroadcast{id, evidence(0x0b), 0});
    h.relay.offer_finality(BlockFinalityBroadcast{id, evidence(0x02), 0});
    require(h.finality_sent.size() == 2, "bad evidence did not suppress the genuine evidence");
    h.relay.offer_finality(BlockFinalityBroadcast{id, evidence(0x02), 0});
    require(h.finality_sent.size() == 2, "the same evidence is forwarded once");
    h.relay.offer_finality(BlockFinalityBroadcast{block_id(16, fill(0x44)), evidence(0x02), 0});
    require(h.finality_sent.size() == 3, "the same signature set for another block is different evidence");
  }

  // Shard block info received from a peer is never forwarded: nothing reports
  // back whether its validation succeeded. An invalid description received
  // first under a block id leaves no record, so the genuine description this
  // node produces for that block is still forwarded; a valid description
  // received from a peer is not forwarded either.
  {
    using Origin = CustomOverlayRelay::ShardBlockInfoOrigin;
    Harness h(16);
    auto id = block_id(30, genuine_hash);
    h.relay.offer_shard_block_info(id, 7, td::BufferSlice("an invalid description"), Origin::Received);
    require(h.shard_block_infos.empty(), "received shard block info is not forwarded");
    h.relay.offer_shard_block_info(id, 7, td::BufferSlice("the valid description"), Origin::Received);
    require(h.shard_block_infos.empty(), "received shard block info is not forwarded even when valid");
    h.relay.offer_shard_block_info(id, 7, td::BufferSlice("the valid description"), Origin::ProducedLocally);
    require(h.shard_block_infos.size() == 1 && h.shard_block_infos[0].data == "the valid description" &&
                h.shard_block_infos[0].block_id == id && h.shard_block_infos[0].cc_seqno == 7,
            "an invalid description received first did not suppress the genuine one");
    h.relay.offer_shard_block_info(id, 7, td::BufferSlice("the valid description"), Origin::ProducedLocally);
    require(h.shard_block_infos.size() == 1, "shard block info is forwarded once");
    h.relay.offer_block(broadcast(id, genuine_data, 0x01), true);
    require(h.blocks.size() == 1, "shard block info does not suppress the block broadcast");
  }

  // Forwarding records are bounded: the oldest are forgotten.
  {
    Harness h(2);
    for (td::uint32 seqno : {20u, 21u, 22u, 20u}) {
      h.relay.offer_block(broadcast(block_id(seqno, genuine_hash), genuine_data, 0x01), true);
    }
    require(h.blocks.size() == 4, "the oldest record was forgotten");
  }

  std::cout << "CUSTOM_OVERLAY_RELAY_DEDUP_OK\n";
  return 0;
}
