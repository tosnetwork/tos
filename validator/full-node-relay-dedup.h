/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
#pragma once

#include "block/block-db.h"
#include "block/signature-set.h"
#include "td/utils/LRUCache.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"

namespace tos::validator::fullnode {

// Decides which block, candidate and finality broadcasts this node forwards to
// its custom overlays. A forwarded item is remembered so it is sent once; the
// danger is remembering something unverified under a block id, after which the
// genuine item for that id would never be forwarded. So nothing is remembered
// under a block id unless it is bound to that id: a block broadcast once its
// signatures verified, a candidate once its data hashes to the id's file hash.
// Finality evidence can often be verified only after its block arrives, so it
// is forwarded unverified and remembered by its content: evidence that fails
// verification cannot suppress different evidence for the same block.
class CustomOverlayRelayDedup {
 public:
  explicit CustomOverlayRelayDedup(size_t capacity) : blocks_(capacity), finality_(capacity) {
  }

  // Call only for a block broadcast whose signatures verified. True the first
  // time a block id (or a candidate for it) is claimed.
  bool claim_verified_block(const BlockIdExt &block_id) {
    return claim(blocks_, block_id);
  }

  // True the first time a candidate for block_id is claimed, and only if its
  // data is that block's: the file hash in the id commits to the data.
  bool claim_candidate(const BlockIdExt &block_id, td::Slice data) {
    if (block::compute_file_hash(data) != block_id.file_hash) {
      return false;
    }
    return claim(blocks_, block_id);
  }

  // True the first time this exact evidence (block id and signature set) is claimed.
  bool claim_finality(const BlockIdExt &block_id, const block::BlockSignatureSet &sig_set) {
    return claim(finality_, finality_key(block_id, sig_set));
  }

  static td::Bits256 finality_key(const BlockIdExt &block_id, const block::BlockSignatureSet &sig_set) {
    td::BufferSlice id = serialize_tl_object(create_tl_block_id(block_id), true);
    td::BufferSlice evidence = serialize_tl_object(sig_set.tl(), true);
    td::Sha256State state;
    state.init();
    state.feed(id.as_slice());
    state.feed(evidence.as_slice());
    td::Bits256 key;
    state.extract(key.as_slice());
    return key;
  }

 private:
  template <typename K>
  static bool claim(td::LRUCache<K, td::Unit> &cache, const K &key) {
    if (cache.contains(key)) {
      return false;
    }
    cache.put(key, {});
    return true;
  }

  td::LRUCache<BlockIdExt, td::Unit> blocks_;
  td::LRUCache<td::Bits256, td::Unit> finality_;
};

}  // namespace tos::validator::fullnode
