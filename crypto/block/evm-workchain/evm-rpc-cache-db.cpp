/*
    EVM Workchain — RPC cache DB implementation.
    See evm-rpc-cache-db.h for design notes.
*/
#include "evm-rpc-cache-db.h"

#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"

#include <memory>

namespace evm_workchain {

namespace {

// Key format: a single byte tag + payload. Tag namespace:
//   0x01 + bits256 tx_hash    → receipt cell           (Phase F.3)
//   0x02 + bits256 tx_hash    → transaction cell       (Phase F.6)
//   0x03 + uint64-be          → block-by-number cell   (Phase F.6)
//   0x04 + bits256 block_hash → block-by-hash cell     (Phase F.6, dup payload)
//   0x05 + uint64-be          → per-block logs cell    (Phase F.6)
//
// Block-by-number uses big-endian uint64 so RocksDB lexicographic iteration
// returns blocks in chain order — handy for hydration replay.
constexpr uint8_t kReceiptTag = 0x01;
constexpr uint8_t kTransactionTag = 0x02;
constexpr uint8_t kBlockByNumberTag = 0x03;
constexpr uint8_t kBlockByHashTag = 0x04;
constexpr uint8_t kLogsByBlockTag = 0x05;
constexpr size_t kReceiptKeyLen = 1 + 32;
constexpr size_t kTransactionKeyLen = 1 + 32;
constexpr size_t kBlockByNumberKeyLen = 1 + 8;
constexpr size_t kBlockByHashKeyLen = 1 + 32;
constexpr size_t kLogsByBlockKeyLen = 1 + 8;

void make_receipt_key(const td::Bits256& tx_hash, char out[kReceiptKeyLen]) {
    out[0] = static_cast<char>(kReceiptTag);
    std::memcpy(out + 1, tx_hash.data(), 32);
}

void make_transaction_key(const td::Bits256& tx_hash, char out[kTransactionKeyLen]) {
    out[0] = static_cast<char>(kTransactionTag);
    std::memcpy(out + 1, tx_hash.data(), 32);
}

void make_block_by_hash_key(const td::Bits256& block_hash, char out[kBlockByHashKeyLen]) {
    out[0] = static_cast<char>(kBlockByHashTag);
    std::memcpy(out + 1, block_hash.data(), 32);
}

void store_be_u64(uint64_t v, char out[8]) {
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<char>(v & 0xff);
        v >>= 8;
    }
}

uint64_t load_be_u64(const char in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint8_t>(in[i]);
    }
    return v;
}

void make_block_by_number_key(uint64_t block_number, char out[kBlockByNumberKeyLen]) {
    out[0] = static_cast<char>(kBlockByNumberTag);
    store_be_u64(block_number, out + 1);
}

void make_logs_by_block_key(uint64_t block_number, char out[kLogsByBlockKeyLen]) {
    out[0] = static_cast<char>(kLogsByBlockTag);
    store_be_u64(block_number, out + 1);
}

// Generic put: serialize cell, set under the given key, flush.
td::Status put_cell_with_key(td::RocksDb& db, td::Slice key, td::Ref<vm::Cell> cell,
                              const char* what) {
    if (cell.is_null()) {
        return td::Status::Error(PSLICE() << "evm-rpc-cache: null " << what << " cell");
    }
    auto serialized_r = vm::std_boc_serialize(cell);
    if (serialized_r.is_error()) return serialized_r.move_as_error();
    auto serialized = serialized_r.move_as_ok();
    auto set_status = db.set(key, td::Slice{serialized.as_slice()});
    if (set_status.is_error()) return set_status;
    return db.flush();
}

td::Result<td::Ref<vm::Cell>> get_cell_with_key(td::RocksDb& db, td::Slice key) {
    std::string value;
    auto status = db.get(key, value);
    if (status.is_error()) return status.move_as_error();
    auto get_status = status.move_as_ok();
    if (get_status == td::KeyValue::GetStatus::NotFound) {
        return td::Ref<vm::Cell>{};
    }
    auto cell_r = vm::std_boc_deserialize(td::Slice{value});
    if (cell_r.is_error()) return cell_r.move_as_error();
    return cell_r.move_as_ok();
}

// Singleton storage. Owned at module scope; lifetime managed by
// set_evm_rpc_cache_db. Validator process holds it for the duration of
// its run.
std::unique_ptr<EvmRpcCacheDb> g_db;

}  // namespace

td::Result<std::unique_ptr<EvmRpcCacheDb>> EvmRpcCacheDb::open(std::string path) {
    // Create parent directory if needed (RocksDb::open creates the leaf
    // dir but not parents).
    auto mkdir_status = td::mkdir(path);
    if (mkdir_status.is_error()) {
        // EEXIST is fine — the directory already exists from a prior boot.
        // Other errors are fatal.
        if (mkdir_status.message() != td::Slice{"File exists"}) {
            // Best-effort: log and try to open anyway. RocksDB will fail
            // with a clearer error if the dir really doesn't exist.
            LOG(WARNING) << "evm-rpc-cache: mkdir " << path << " returned: "
                         << mkdir_status.message();
        }
    }
    auto db_r = td::RocksDb::open(path);
    if (db_r.is_error()) {
        return td::Status::Error(PSTRING()
            << "evm-rpc-cache: cannot open RocksDB at " << path
            << ": " << db_r.error().message());
    }
    auto db = std::make_unique<td::RocksDb>(db_r.move_as_ok());
    return std::unique_ptr<EvmRpcCacheDb>(new EvmRpcCacheDb(std::move(db)));
}

EvmRpcCacheDb::EvmRpcCacheDb(std::unique_ptr<td::RocksDb> db) : db_(std::move(db)) {}
EvmRpcCacheDb::EvmRpcCacheDb(EvmRpcCacheDb&&) = default;
EvmRpcCacheDb::~EvmRpcCacheDb() = default;

td::Status EvmRpcCacheDb::put_receipt(const td::Bits256& tx_hash, td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return td::Status::Error("evm-rpc-cache: null receipt cell");
    }
    auto serialized_r = vm::std_boc_serialize(cell);
    if (serialized_r.is_error()) {
        return serialized_r.move_as_error();
    }
    auto serialized = serialized_r.move_as_ok();
    char key[kReceiptKeyLen];
    make_receipt_key(tx_hash, key);
    auto set_status = db_->set(td::Slice{key, kReceiptKeyLen},
                               td::Slice{serialized.as_slice()});
    if (set_status.is_error()) return set_status;

    // td::RocksDb opens with manual_wal_flush=true and its destructor does
    // NOT flush, so without an explicit flush() each put dies in the
    // memtable on a SIGTERM restart. flush() is heavyweight (memtable →
    // SST) but guarantees durability across restart, which is the entire
    // point of Phase F. Receipts are produced ~1/s under normal load so
    // the cost is fine; if it ever shows up as a hot path we can switch
    // to a periodic flush or expose FlushWAL via the td wrapper.
    return db_->flush();
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_receipt(const td::Bits256& tx_hash) {
    char key[kReceiptKeyLen];
    make_receipt_key(tx_hash, key);
    std::string value;
    auto status = db_->get(td::Slice{key, kReceiptKeyLen}, value);
    if (status.is_error()) return status.move_as_error();
    auto get_status = status.move_as_ok();
    if (get_status == td::KeyValue::GetStatus::NotFound) {
        return td::Ref<vm::Cell>{};
    }
    auto cell_r = vm::std_boc_deserialize(td::Slice{value});
    if (cell_r.is_error()) return cell_r.move_as_error();
    return cell_r.move_as_ok();
}

td::Status EvmRpcCacheDb::for_each_receipt(
    std::function<td::Status(const td::Bits256&, td::Ref<vm::Cell>)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kReceiptKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kReceiptTag) return td::Status::OK();
        td::Bits256 tx_hash;
        std::memcpy(tx_hash.data(), key.data() + 1, 32);
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
            // Skip corrupt entries — better than crashing the whole walk.
            LOG(WARNING) << "evm-rpc-cache: skipping corrupt receipt for tx "
                         << tx_hash.to_hex() << ": " << cell_r.error().message();
            return td::Status::OK();
        }
        return cb(tx_hash, cell_r.move_as_ok());
    });
}

td::Result<size_t> EvmRpcCacheDb::count_receipts() {
    char prefix = static_cast<char>(kReceiptTag);
    return db_->count(td::Slice{&prefix, 1});
}

// ---------------------------------------------------------------------------
// Phase F.6 — transactions / blocks / logs.
// ---------------------------------------------------------------------------

td::Status EvmRpcCacheDb::put_transaction(const td::Bits256& tx_hash, td::Ref<vm::Cell> cell) {
    char key[kTransactionKeyLen];
    make_transaction_key(tx_hash, key);
    return put_cell_with_key(*db_, td::Slice{key, kTransactionKeyLen}, std::move(cell),
                             "transaction");
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_transaction(const td::Bits256& tx_hash) {
    char key[kTransactionKeyLen];
    make_transaction_key(tx_hash, key);
    return get_cell_with_key(*db_, td::Slice{key, kTransactionKeyLen});
}

td::Status EvmRpcCacheDb::for_each_transaction(
    std::function<td::Status(const td::Bits256&, td::Ref<vm::Cell>)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kTransactionKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kTransactionTag) return td::Status::OK();
        td::Bits256 tx_hash;
        std::memcpy(tx_hash.data(), key.data() + 1, 32);
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: skipping corrupt transaction for tx "
                         << tx_hash.to_hex() << ": " << cell_r.error().message();
            return td::Status::OK();
        }
        return cb(tx_hash, cell_r.move_as_ok());
    });
}

td::Status EvmRpcCacheDb::put_block_by_number(uint64_t block_number, td::Ref<vm::Cell> cell) {
    char key[kBlockByNumberKeyLen];
    make_block_by_number_key(block_number, key);
    return put_cell_with_key(*db_, td::Slice{key, kBlockByNumberKeyLen}, std::move(cell),
                             "block-by-number");
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_block_by_number(uint64_t block_number) {
    char key[kBlockByNumberKeyLen];
    make_block_by_number_key(block_number, key);
    return get_cell_with_key(*db_, td::Slice{key, kBlockByNumberKeyLen});
}

td::Status EvmRpcCacheDb::for_each_block_by_number(
    std::function<td::Status(uint64_t, td::Ref<vm::Cell>)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kBlockByNumberKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kBlockByNumberTag) return td::Status::OK();
        uint64_t block_number = load_be_u64(key.data() + 1);
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: skipping corrupt block-by-number for #"
                         << block_number << ": " << cell_r.error().message();
            return td::Status::OK();
        }
        return cb(block_number, cell_r.move_as_ok());
    });
}

td::Status EvmRpcCacheDb::put_block_by_hash(const td::Bits256& block_hash,
                                             td::Ref<vm::Cell> cell) {
    char key[kBlockByHashKeyLen];
    make_block_by_hash_key(block_hash, key);
    return put_cell_with_key(*db_, td::Slice{key, kBlockByHashKeyLen}, std::move(cell),
                             "block-by-hash");
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_block_by_hash(const td::Bits256& block_hash) {
    char key[kBlockByHashKeyLen];
    make_block_by_hash_key(block_hash, key);
    return get_cell_with_key(*db_, td::Slice{key, kBlockByHashKeyLen});
}

td::Status EvmRpcCacheDb::for_each_block_by_hash(
    std::function<td::Status(const td::Bits256&, td::Ref<vm::Cell>)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kBlockByHashKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kBlockByHashTag) return td::Status::OK();
        td::Bits256 block_hash;
        std::memcpy(block_hash.data(), key.data() + 1, 32);
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: skipping corrupt block-by-hash for "
                         << block_hash.to_hex() << ": " << cell_r.error().message();
            return td::Status::OK();
        }
        return cb(block_hash, cell_r.move_as_ok());
    });
}

td::Status EvmRpcCacheDb::put_logs_for_block(uint64_t block_number, td::Ref<vm::Cell> cell) {
    char key[kLogsByBlockKeyLen];
    make_logs_by_block_key(block_number, key);
    return put_cell_with_key(*db_, td::Slice{key, kLogsByBlockKeyLen}, std::move(cell),
                             "logs-for-block");
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_logs_for_block(uint64_t block_number) {
    char key[kLogsByBlockKeyLen];
    make_logs_by_block_key(block_number, key);
    return get_cell_with_key(*db_, td::Slice{key, kLogsByBlockKeyLen});
}

td::Status EvmRpcCacheDb::for_each_block_logs(
    std::function<td::Status(uint64_t, td::Ref<vm::Cell>)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kLogsByBlockKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kLogsByBlockTag) return td::Status::OK();
        uint64_t block_number = load_be_u64(key.data() + 1);
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: skipping corrupt logs-for-block for #"
                         << block_number << ": " << cell_r.error().message();
            return td::Status::OK();
        }
        return cb(block_number, cell_r.move_as_ok());
    });
}

EvmRpcCacheDb* evm_rpc_cache_db() {
    return g_db.get();
}

void set_evm_rpc_cache_db(std::unique_ptr<EvmRpcCacheDb> db) {
    g_db = std::move(db);
}

}  // namespace evm_workchain
