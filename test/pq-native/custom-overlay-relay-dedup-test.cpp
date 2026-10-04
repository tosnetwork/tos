/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// What this node forwards to its custom overlays is remembered so it is sent
// once. An item that is not bound to its block id must never be remembered
// first, or it would keep the genuine item for that block from being forwarded.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "block/block-db.h"
#include "block/signature-set.h"
#include "validator/full-node-relay-dedup.h"

namespace {

using tos::validator::fullnode::CustomOverlayRelayDedup;

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

}  // namespace

int main() {
  // A block broadcast is claimed only after its signatures verified (the
  // caller's job); the first verified one per block wins.
  {
    CustomOverlayRelayDedup dedup(16);
    auto id = block_id(10, fill(0x41));
    require(dedup.claim_verified_block(id), "a verified block is forwarded");
    require(!dedup.claim_verified_block(id), "a block is forwarded once");
  }

  // A candidate whose data is not that block's is never remembered, so it cannot
  // keep the genuine block from being forwarded.
  {
    CustomOverlayRelayDedup dedup(16);
    td::BufferSlice genuine("the genuine block data");
    auto id = block_id(11, block::compute_file_hash(genuine.as_slice()));
    require(!dedup.claim_candidate(id, td::Slice("forged data under a known block id")),
            "a candidate whose data does not hash to the id is refused");
    require(dedup.claim_verified_block(id), "the forged candidate did not suppress the verified block");
  }
  {
    CustomOverlayRelayDedup dedup(16);
    td::BufferSlice genuine("the genuine block data");
    auto id = block_id(12, block::compute_file_hash(genuine.as_slice()));
    require(dedup.claim_candidate(id, genuine.as_slice()), "a genuine candidate is forwarded");
    require(!dedup.claim_candidate(id, genuine.as_slice()), "a candidate is forwarded once");
    require(!dedup.claim_verified_block(id), "the genuine candidate already carried the block");
  }

  // Finality evidence is remembered by content: bad evidence forwarded first
  // cannot suppress different evidence for the same block.
  {
    CustomOverlayRelayDedup dedup(16);
    auto id = block_id(13, fill(0x43));
    auto bad = evidence(0x01);
    auto genuine = evidence(0x02);
    require(CustomOverlayRelayDedup::finality_key(id, *bad) != CustomOverlayRelayDedup::finality_key(id, *genuine),
            "different evidence has different keys");
    require(dedup.claim_finality(id, *bad), "the first evidence is forwarded");
    require(dedup.claim_finality(id, *genuine), "bad evidence did not suppress the genuine evidence");
    require(!dedup.claim_finality(id, *genuine), "the same evidence is forwarded once");
    require(dedup.claim_finality(block_id(14, fill(0x44)), *genuine),
            "the same signature set for another block is different evidence");
  }

  // Forwarding records are bounded: the oldest are forgotten.
  {
    CustomOverlayRelayDedup dedup(2);
    require(dedup.claim_verified_block(block_id(20, fill(0x50))), "first");
    require(dedup.claim_verified_block(block_id(21, fill(0x51))), "second");
    require(dedup.claim_verified_block(block_id(22, fill(0x52))), "third");
    require(dedup.claim_verified_block(block_id(20, fill(0x50))), "the oldest record was forgotten");
  }

  std::cout << "CUSTOM_OVERLAY_RELAY_DEDUP_OK\n";
  return 0;
}
