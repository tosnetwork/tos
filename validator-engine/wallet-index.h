/*
    TOS wc=0 in-process wallet index — side-channel RocksDB.

    Serves wallet "aggregate" queries (jetton list, NFT list, account events)
    directly from the node, with no external indexer. Modeled on the EVM
    workchain's EvmRpcCacheDb (evm/rpc/cache-db.{h,cpp}): a standalone, per-
    validator RocksDB at `${db_root}/wc0-index`, parallel to celldb/statedb and
    completely outside the consensus state cell tree. It never contributes to any
    state hash; operators can prune/rebuild independently without a hardfork.

    Writes happen best-effort on block apply (off the consensus path): a failed
    write only degrades RPC for that block, it never blocks consensus.

    See doc/tos-wc0-wallet-index.md.
*/
#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/bits.h"
#include "vm/cells.h"

namespace td {
class RocksDb;
}

namespace tos_wallet_index {

using HashKey = td::Bits256;  // owner / master / nft / account / tx hash

class WalletIndexDb {
 public:
  // Open (or create) the index DB at `path`. The directory is created if needed.
  static td::Result<std::unique_ptr<WalletIndexDb>> open(std::string path);

  WalletIndexDb(const WalletIndexDb&) = delete;
  WalletIndexDb& operator=(const WalletIndexDb&) = delete;
  ~WalletIndexDb();

  // --- Jetton ownership: 0x10 + owner(32) + master(32) -> value cell ---
  td::Status put_jetton(const HashKey& owner, const HashKey& master, td::Ref<vm::Cell> value);
  td::Status erase_jetton(const HashKey& owner, const HashKey& master);
  // Walk at most `limit` jetton masters held by `owner`. Callback receives
  // (master, value cell).
  td::Status for_each_jetton(
      const HashKey& owner, size_t limit,
      std::function<td::Status(const HashKey& master, td::Ref<vm::Cell>)> cb);

  // --- NFT ownership: 0x11 + owner(32) + nft(32) -> value cell ---
  td::Status put_nft(const HashKey& owner, const HashKey& nft, td::Ref<vm::Cell> value);
  td::Status erase_nft(const HashKey& owner, const HashKey& nft);
  td::Status for_each_nft(
      const HashKey& owner, size_t limit,
      std::function<td::Status(const HashKey& nft, td::Ref<vm::Cell>)> cb);

  // --- Account event feed: 0x12 + account(32) + ~lt_be(8) -> value cell ---
  // Keys store the bitwise complement of lt so RocksDB's ascending iteration
  // yields newest events first and `limit` bounds the scan to the most recent.
  td::Status put_event(const HashKey& account, uint64_t lt, td::Ref<vm::Cell> value);
  // Walk at most `limit` events for `account`, newest first.
  td::Status for_each_event(
      const HashKey& account, size_t limit,
      std::function<td::Status(uint64_t lt, td::Ref<vm::Cell>)> cb);

  // --- NFT current-owner reverse map: 0x13 + nft(32) -> owner(32) ---
  // Tracks the last verified owner of each indexed NFT so the writer can erase
  // the previous owner's 0x11 entry when ownership changes (no stale entries).
  td::Status put_nft_owner(const HashKey& nft, const HashKey& owner);
  // Returns true and fills `owner` if a previous owner is recorded. Reads
  // committed state only — an open write batch is not visible — which is what
  // the writer wants: the pre-block owner.
  td::Result<bool> get_nft_owner(const HashKey& nft, HashKey& owner);

  // --- Crash-recovery marker: 0x1E + block_seqno_be(8) ---
  // put_incomplete_block is durable on return (flushed); delete_incomplete_block
  // joins the open write batch when one is active.
  td::Status put_incomplete_block(uint64_t seqno);
  td::Status delete_incomplete_block(uint64_t seqno);
  td::Result<bool> has_incomplete_block(uint64_t seqno);

  // --- Per-block batched writes ---
  // Writers must hold write_mutex() across begin_batch()..commit_batch()/abort_batch():
  // the underlying td::RocksDb write batch is a single unsynchronized member, and
  // block-apply actors can run concurrently. Readers (for_each_*) need no lock —
  // they iterate committed state only.
  std::mutex& write_mutex() { return write_mutex_; }
  // Route subsequent put_/erase_ calls into an atomic batch.
  td::Status begin_batch();
  // Atomically commit the batch and flush the WAL (single fsync per block).
  td::Status commit_batch();
  // Drop the batch (e.g. after a parse error) so no partial block is written.
  void abort_batch();

 private:
  explicit WalletIndexDb(std::unique_ptr<td::RocksDb> db);
  td::Status put_cell(td::Slice key, td::Ref<vm::Cell> value);
  // Iterate keys in [prefix, next(prefix)) — a bounded range scan, never a full
  // table walk. Visits at most `limit` keys.
  td::Status for_each_with_prefix(
      td::Slice prefix, size_t limit,
      std::function<td::Status(td::Slice key, td::Ref<vm::Cell>)> cb);

  std::unique_ptr<td::RocksDb> db_;
  std::mutex write_mutex_;
  bool batch_open_ = false;
};

// Module-scope singleton (mirrors evm_rpc_cache_db()). Returns nullptr until the
// validator opens the index at startup.
WalletIndexDb* wallet_index_db();
void set_wallet_index_db(std::unique_ptr<WalletIndexDb> db);

// Open the index at `${db_root}/wc0-index` and install it as the singleton.
// Best-effort: logs and leaves the singleton null on failure.
void open_wallet_index_db(const std::string& db_root);

}  // namespace tos_wallet_index
