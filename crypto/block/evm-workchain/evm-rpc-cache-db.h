/*
    EVM Workchain — RPC cache DB (Phase F.3 / F.4 — Pure B side-channel).

    A standalone, per-validator RocksDB instance that persists receipts
    (and later transactions / blocks / logs) so they survive validator
    restart. Lives in `${db_root}/evm-rpc-cache`, parallel to the
    existing celldb/statedb/archive instances — completely outside the
    consensus state cell tree.

    Atomicity: receipts are written eagerly per-tx during compute-phase,
    NOT in the same WriteBatch as ShardAccounts. The trade-off is that
    a crash between state commit and receipt write could leave one
    receipt missing on restart. The state still progresses correctly;
    only RPC for that one tx returns null. In exchange, we get zero
    coupling with the consensus layer and per-validator retention
    flexibility (each operator can prune independently without a
    hardfork).

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <memory>
#include <string>
#include <functional>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace td {
class RocksDb;
}

namespace evm_workchain {

class EvmRpcCacheDb {
  public:
    /// Open (or create) a cache DB at `path`. The directory is created
    /// if it doesn't exist. Returns a moveable handle.
    static td::Result<std::unique_ptr<EvmRpcCacheDb>> open(std::string path);

    /// Persist a receipt cell keyed by tx_hash. Best-effort durability.
    td::Status put_receipt(const td::Bits256& tx_hash, td::Ref<vm::Cell> cell);

    /// Look up a receipt by tx_hash. Returns null cell if not found.
    td::Result<td::Ref<vm::Cell>> get_receipt(const td::Bits256& tx_hash);

    /// Walk every persisted receipt. Used by F.4 hydration on restart.
    /// Callback receives (tx_hash, cell). Stops if callback returns
    /// non-OK status.
    td::Status for_each_receipt(
        std::function<td::Status(const td::Bits256&, td::Ref<vm::Cell>)> cb);

    /// Number of persisted receipts (best-effort, may be expensive).
    td::Result<size_t> count_receipts();

    EvmRpcCacheDb(EvmRpcCacheDb&&);
    ~EvmRpcCacheDb();

  private:
    explicit EvmRpcCacheDb(std::unique_ptr<td::RocksDb> db);
    std::unique_ptr<td::RocksDb> db_;
};

/// Process-global handle. Set by init_evm_workchain when a db_root is
/// provided. Returns nullptr on the test harness path (no db_root).
EvmRpcCacheDb* evm_rpc_cache_db();
void set_evm_rpc_cache_db(std::unique_ptr<EvmRpcCacheDb> db);

}  // namespace evm_workchain
