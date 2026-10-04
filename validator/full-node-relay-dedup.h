/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
#pragma once

#include <functional>
#include <utility>

#include "block/block-db.h"
#include "block/signature-set.h"
#include "td/utils/LRUCache.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/types.h"

namespace tos::validator::fullnode {

// Decides which block, candidate and finality broadcasts this node forwards to
// its custom overlays, and forwards them through hooks bound to the node's
// validator manager and overlays.
//
// A forwarded item is remembered so it is sent once while the record is
// resident. The danger is remembering an unverified item under the key a
// genuine item would use: the genuine one would then never be forwarded. So:
// - a block broadcast is forwarded only if its data hashes to the block id's
//   file hash and its signatures verified (or were already checked), and only
//   then remembered under the block id;
// - a candidate is forwarded only if its data hashes to the file hash, and is
//   remembered under its id and metadata, which cannot be verified here, in a
//   domain of its own so it never stands in for a block broadcast;
// - finality evidence can often be verified only after its block arrives, so it
//   is forwarded unverified and remembered by its content (block id and
//   signature set): evidence that fails verification cannot suppress different
//   evidence for the same block. This deduplicates only while resident and does
//   not bound how many distinct pieces of evidence are forwarded; it relies on
//   the ingress (fast-sync members, allowlisted custom senders) being limited;
// - shard block info is forwarded only when this node produced it. Received
//   shard block info is validated asynchronously by the validator manager with
//   no completion signal back to the relay, so it is never forwarded and never
//   remembered: an unverified description cannot take the key its genuine
//   counterpart would use.
class CustomOverlayRelay {
 public:
  struct Hooks {
    // Starts signature verification of a block broadcast; on success the owner
    // calls block_signatures_verified with the same broadcast.
    std::function<void(BlockBroadcast)> verify_block_signatures;
    std::function<void(const BlockBroadcast &)> send_block;
    std::function<void(const BlockIdExt &, CatchainSeqno, td::uint32, const td::BufferSlice &)> send_candidate;
    std::function<void(const BlockFinalityBroadcast &)> send_finality;
    std::function<void(const BlockIdExt &, CatchainSeqno, const td::BufferSlice &)> send_shard_block_info;
  };

  enum class ShardBlockInfoOrigin { ProducedLocally, Received };

  explicit CustomOverlayRelay(size_t capacity)
      : blocks_(capacity), candidates_(capacity), finality_(capacity), shard_block_infos_(capacity) {
  }

  void set_hooks(Hooks hooks) {
    hooks_ = std::move(hooks);
  }

  // A block broadcast received from a peer, or made by this node.
  void offer_block(BlockBroadcast broadcast, bool signatures_checked) {
    if (!data_is_block(broadcast.block_id, broadcast.data.as_slice())) {
      return;
    }
    if (signatures_checked) {
      forward_block(broadcast);
      return;
    }
    hooks_.verify_block_signatures(std::move(broadcast));
  }

  // Called by the owner once a broadcast passed to verify_block_signatures verified.
  void block_signatures_verified(const BlockBroadcast &broadcast) {
    if (data_is_block(broadcast.block_id, broadcast.data.as_slice())) {
      forward_block(broadcast);
    }
  }

  void offer_candidate(const BlockIdExt &block_id, CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
                       const td::BufferSlice &data) {
    if (!data_is_block(block_id, data.as_slice())) {
      return;
    }
    if (claim(candidates_, candidate_key(block_id, cc_seqno, validator_set_hash))) {
      hooks_.send_candidate(block_id, cc_seqno, validator_set_hash, data);
    }
  }

  void offer_finality(const BlockFinalityBroadcast &finality) {
    if (finality.sig_set.is_null()) {
      return;
    }
    if (claim(finality_, finality_key(finality.block_id, *finality.sig_set))) {
      hooks_.send_finality(finality);
    }
  }

  // Shard block info: forwarded once, and only if this node produced it. A
  // received description is processed locally by the caller but takes no part
  // in relaying until a validation result can be fed back here.
  void offer_shard_block_info(const BlockIdExt &block_id, CatchainSeqno cc_seqno, const td::BufferSlice &data,
                              ShardBlockInfoOrigin origin) {
    if (origin != ShardBlockInfoOrigin::ProducedLocally) {
      return;
    }
    if (claim(shard_block_infos_, block_id)) {
      hooks_.send_shard_block_info(block_id, cc_seqno, data);
    }
  }

  static td::Bits256 finality_key(const BlockIdExt &block_id, const block::BlockSignatureSet &sig_set) {
    td::BufferSlice id = serialize_tl_object(create_tl_block_id(block_id), true);
    td::BufferSlice evidence = serialize_tl_object(sig_set.tl(), true);
    return digest({id.as_slice(), evidence.as_slice()});
  }

  static td::Bits256 candidate_key(const BlockIdExt &block_id, CatchainSeqno cc_seqno, td::uint32 validator_set_hash) {
    td::BufferSlice id = serialize_tl_object(create_tl_block_id(block_id), true);
    unsigned char metadata[8];
    for (int i = 0; i < 4; i++) {
      metadata[i] = static_cast<unsigned char>(cc_seqno >> (24 - 8 * i));
      metadata[4 + i] = static_cast<unsigned char>(validator_set_hash >> (24 - 8 * i));
    }
    return digest({id.as_slice(), td::Slice(metadata, sizeof(metadata))});
  }

 private:
  static bool data_is_block(const BlockIdExt &block_id, td::Slice data) {
    return block::compute_file_hash(data) == block_id.file_hash;
  }

  void forward_block(const BlockBroadcast &broadcast) {
    if (claim(blocks_, broadcast.block_id)) {
      hooks_.send_block(broadcast);
    }
  }

  static td::Bits256 digest(std::initializer_list<td::Slice> parts) {
    td::Sha256State state;
    state.init();
    for (auto part : parts) {
      state.feed(part);
    }
    td::Bits256 result;
    state.extract(result.as_slice());
    return result;
  }

  template <typename K>
  static bool claim(td::LRUCache<K, td::Unit> &cache, const K &key) {
    if (cache.contains(key)) {
      return false;
    }
    cache.put(key, {});
    return true;
  }

  Hooks hooks_;
  td::LRUCache<BlockIdExt, td::Unit> blocks_;
  td::LRUCache<td::Bits256, td::Unit> candidates_;
  td::LRUCache<td::Bits256, td::Unit> finality_;
  td::LRUCache<BlockIdExt, td::Unit> shard_block_infos_;
};

}  // namespace tos::validator::fullnode
