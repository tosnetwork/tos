/*
    EVM Workchain — RPC cache DB implementation.
    See evm-rpc-cache-db.h for design notes.
*/
#include "evm/rpc/cache-db.h"

#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

namespace evm_workchain {

namespace {

// Key format: a single byte tag + payload. Tag namespace:
//   0x01 + bits256 tx_hash    → receipt cell           (Phase F.3)
//   0x02 + bits256 tx_hash    → transaction cell       (Phase F.6)
//   0x03 + uint64-be          → block-by-number cell   (Phase F.6)
//   0x04 + bits256 block_hash → block-by-hash cell     (Phase F.6, dup payload)
//   0x05 + uint64-be          → per-block logs cell    (Phase F.6)
//   0x06 + candidate context  → pending post-accept side effects
//   0x07 + bits256 tx_hash    → durable tx indexing-incomplete marker
//   0x08 + uint64-be          → durable block indexing-incomplete marker
//
// Block-by-number uses big-endian uint64 so RocksDB lexicographic iteration
// returns blocks in chain order — handy for hydration replay.
constexpr uint8_t kReceiptTag = 0x01;
constexpr uint8_t kTransactionTag = 0x02;
constexpr uint8_t kBlockByNumberTag = 0x03;
constexpr uint8_t kBlockByHashTag = 0x04;
constexpr uint8_t kLogsByBlockTag = 0x05;
constexpr uint8_t kPendingSideEffectsTag = 0x06;
constexpr uint8_t kIncompleteTxTag = 0x07;
constexpr uint8_t kIncompleteBlockTag = 0x08;
constexpr size_t kReceiptKeyLen = 1 + 32;
constexpr size_t kTransactionKeyLen = 1 + 32;
constexpr size_t kBlockByNumberKeyLen = 1 + 8;
constexpr size_t kBlockByHashKeyLen = 1 + 32;
constexpr size_t kLogsByBlockKeyLen = 1 + 8;
constexpr size_t kPendingSideEffectsKeyLen = 1 + 8 + 8 + 32 + 32 + 32;
constexpr size_t kIncompleteTxKeyLen = 1 + 32;
constexpr size_t kIncompleteBlockKeyLen = 1 + 8;

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

void make_pending_side_effects_key(uint64_t block_seqno,
                                   uint64_t timestamp,
                                   const td::Bits256& rand_seed,
                                   const td::Bits256& parent_hash,
                                   const td::Bits256& tx_hash,
                                   char out[kPendingSideEffectsKeyLen]) {
    out[0] = static_cast<char>(kPendingSideEffectsTag);
    store_be_u64(block_seqno, out + 1);
    store_be_u64(timestamp, out + 1 + 8);
    std::memcpy(out + 1 + 8 + 8, rand_seed.data(), 32);
    std::memcpy(out + 1 + 8 + 8 + 32, parent_hash.data(), 32);
    std::memcpy(out + 1 + 8 + 8 + 32 + 32, tx_hash.data(), 32);
}

void make_pending_side_effects_upper_bound(uint64_t block_seqno, char out[1 + 8]) {
    out[0] = static_cast<char>(kPendingSideEffectsTag);
    store_be_u64(block_seqno, out + 1);
}

void make_incomplete_tx_key(const td::Bits256& tx_hash, char out[kIncompleteTxKeyLen]) {
    out[0] = static_cast<char>(kIncompleteTxTag);
    std::memcpy(out + 1, tx_hash.data(), 32);
}

void make_incomplete_block_key(uint64_t block_number, char out[kIncompleteBlockKeyLen]) {
    out[0] = static_cast<char>(kIncompleteBlockTag);
    store_be_u64(block_number, out + 1);
}

uint64_t current_unix_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string make_incomplete_marker_value(uint64_t timestamp) {
    char out[8];
    store_be_u64(timestamp, out);
    return std::string(out, sizeof(out));
}

uint64_t load_incomplete_marker_timestamp(td::Slice value) {
    if (value.size() != 8) {
        return 0;
    }
    return load_be_u64(value.data());
}

// Generic put: serialize cell, set under the given key, optionally flush.
td::Status put_cell_with_key(td::RocksDb& db, td::Slice key, td::Ref<vm::Cell> cell,
                             const char* what, bool flush_after = true,
                             size_t max_serialized_bytes = 0) {
    if (cell.is_null()) {
        return td::Status::Error(PSLICE() << "evm-rpc-cache: null " << what << " cell");
    }
    auto serialized_r = vm::std_boc_serialize(cell);
    if (serialized_r.is_error()) return serialized_r.move_as_error();
    auto serialized = serialized_r.move_as_ok();
    if (max_serialized_bytes != 0 && serialized.size() > max_serialized_bytes) {
        return td::Status::Error(PSLICE()
            << "evm-rpc-cache: " << what << " cell too large: "
            << serialized.size() << " > " << max_serialized_bytes);
    }
    auto set_status = db.set(key, td::Slice{serialized.as_slice()});
    if (set_status.is_error()) return set_status;
    if (!flush_after) return td::Status::OK();
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

td::Result<size_t> EvmRpcCacheDb::count_transactions() {
    char prefix = static_cast<char>(kTransactionTag);
    return db_->count(td::Slice{&prefix, 1});
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

td::Result<size_t> EvmRpcCacheDb::count_blocks_by_number() {
    char prefix = static_cast<char>(kBlockByNumberTag);
    return db_->count(td::Slice{&prefix, 1});
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

td::Result<size_t> EvmRpcCacheDb::count_log_blocks() {
    char prefix = static_cast<char>(kLogsByBlockTag);
    return db_->count(td::Slice{&prefix, 1});
}

td::Status EvmRpcCacheDb::put_pending_side_effects(uint64_t block_seqno,
                                                    uint64_t timestamp,
                                                    const td::Bits256& rand_seed,
                                                    const td::Bits256& parent_hash,
                                                    const td::Bits256& tx_hash,
                                                    td::Ref<vm::Cell> cell) {
    constexpr size_t kMaxPendingSideEffectBytes = 1 << 20;  // side-channel recovery cap
    char key[kPendingSideEffectsKeyLen];
    make_pending_side_effects_key(block_seqno, timestamp, rand_seed, parent_hash,
                                  tx_hash, key);
    return put_cell_with_key(*db_, td::Slice{key, kPendingSideEffectsKeyLen},
                             std::move(cell), "pending-side-effects",
                             /*flush_after=*/false,
                             kMaxPendingSideEffectBytes);
}

td::Result<td::Ref<vm::Cell>> EvmRpcCacheDb::get_pending_side_effects(
    uint64_t block_seqno,
    uint64_t timestamp,
    const td::Bits256& rand_seed,
    const td::Bits256& parent_hash,
    const td::Bits256& tx_hash) {
    char key[kPendingSideEffectsKeyLen];
    make_pending_side_effects_key(block_seqno, timestamp, rand_seed, parent_hash,
                                  tx_hash, key);
    return get_cell_with_key(*db_, td::Slice{key, kPendingSideEffectsKeyLen});
}

td::Status EvmRpcCacheDb::delete_pending_side_effects(uint64_t block_seqno,
                                                       uint64_t timestamp,
                                                       const td::Bits256& rand_seed,
                                                       const td::Bits256& parent_hash,
                                                       const td::Bits256& tx_hash) {
    char key[kPendingSideEffectsKeyLen];
    make_pending_side_effects_key(block_seqno, timestamp, rand_seed, parent_hash,
                                  tx_hash, key);
    auto erase_status = db_->erase(td::Slice{key, kPendingSideEffectsKeyLen});
    return erase_status;
}

td::Status EvmRpcCacheDb::prune_pending_side_effects(uint64_t keep_from_block_seqno,
                                                      size_t max_records) {
    std::vector<std::string> keys_to_delete;
    char begin[1] = {static_cast<char>(kPendingSideEffectsTag)};
    char end[1 + 8];
    make_pending_side_effects_upper_bound(keep_from_block_seqno, end);

    auto old_walk = db_->for_each_in_range(
        td::Slice{begin, 1}, td::Slice{end, sizeof(end)},
        [&keys_to_delete](td::Slice key, td::Slice) -> td::Status {
            if (key.size() == kPendingSideEffectsKeyLen &&
                static_cast<uint8_t>(key[0]) == kPendingSideEffectsTag) {
                keys_to_delete.push_back(key.str());
            }
            return td::Status::OK();
        });
    if (old_walk.is_error()) return old_walk;

    if (max_records != 0) {
        char prefix = static_cast<char>(kPendingSideEffectsTag);
        auto count_r = db_->count(td::Slice{&prefix, 1});
        if (count_r.is_error()) return count_r.move_as_error();
        size_t total = count_r.move_as_ok();
        if (total > max_records) {
            size_t extra = total - max_records;
            auto cap_walk = db_->for_each(
                [&keys_to_delete, &extra](td::Slice key, td::Slice) -> td::Status {
                    if (extra == 0) return td::Status::OK();
                    if (key.size() == kPendingSideEffectsKeyLen &&
                        static_cast<uint8_t>(key[0]) == kPendingSideEffectsTag) {
                        keys_to_delete.push_back(key.str());
                        --extra;
                    }
                    return td::Status::OK();
                });
            if (cap_walk.is_error()) return cap_walk;
        }
    }

    if (keys_to_delete.empty()) return td::Status::OK();
    for (const auto& key : keys_to_delete) {
        auto erase_status = db_->erase(td::Slice{key});
        if (erase_status.is_error()) return erase_status;
    }
    return db_->flush();
}

td::Result<size_t> EvmRpcCacheDb::count_pending_side_effects() {
    char prefix = static_cast<char>(kPendingSideEffectsTag);
    return db_->count(td::Slice{&prefix, 1});
}

td::Status EvmRpcCacheDb::put_incomplete_transaction(const td::Bits256& tx_hash) {
    char key[kIncompleteTxKeyLen];
    make_incomplete_tx_key(tx_hash, key);
    auto value = make_incomplete_marker_value(current_unix_seconds());
    auto status = db_->set(td::Slice{key, kIncompleteTxKeyLen},
                           td::Slice{value.data(), value.size()});
    if (status.is_error()) return status;
    return db_->flush();
}

td::Status EvmRpcCacheDb::delete_incomplete_transaction(const td::Bits256& tx_hash) {
    char key[kIncompleteTxKeyLen];
    make_incomplete_tx_key(tx_hash, key);
    auto status = db_->erase(td::Slice{key, kIncompleteTxKeyLen});
    if (status.is_error()) return status;
    return db_->flush();
}

td::Result<bool> EvmRpcCacheDb::has_incomplete_transaction(const td::Bits256& tx_hash) {
    char key[kIncompleteTxKeyLen];
    make_incomplete_tx_key(tx_hash, key);
    std::string value;
    auto status = db_->get(td::Slice{key, kIncompleteTxKeyLen}, value);
    if (status.is_error()) return status.move_as_error();
    return status.move_as_ok() != td::KeyValue::GetStatus::NotFound;
}

td::Status EvmRpcCacheDb::for_each_incomplete_transaction(
    std::function<td::Status(const td::Bits256&)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice) -> td::Status {
        if (key.size() != kIncompleteTxKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kIncompleteTxTag) return td::Status::OK();
        td::Bits256 tx_hash;
        std::memcpy(tx_hash.data(), key.data() + 1, 32);
        return cb(tx_hash);
    });
}

td::Result<size_t> EvmRpcCacheDb::count_incomplete_transactions() {
    char prefix = static_cast<char>(kIncompleteTxTag);
    return db_->count(td::Slice{&prefix, 1});
}

td::Status EvmRpcCacheDb::put_incomplete_block(uint64_t block_number) {
    char key[kIncompleteBlockKeyLen];
    make_incomplete_block_key(block_number, key);
    auto value = make_incomplete_marker_value(current_unix_seconds());
    auto status = db_->set(td::Slice{key, kIncompleteBlockKeyLen},
                           td::Slice{value.data(), value.size()});
    if (status.is_error()) return status;
    return db_->flush();
}

td::Status EvmRpcCacheDb::delete_incomplete_block(uint64_t block_number) {
    char key[kIncompleteBlockKeyLen];
    make_incomplete_block_key(block_number, key);
    auto status = db_->erase(td::Slice{key, kIncompleteBlockKeyLen});
    if (status.is_error()) return status;
    return db_->flush();
}

td::Result<bool> EvmRpcCacheDb::has_incomplete_block(uint64_t block_number) {
    char key[kIncompleteBlockKeyLen];
    make_incomplete_block_key(block_number, key);
    std::string value;
    auto status = db_->get(td::Slice{key, kIncompleteBlockKeyLen}, value);
    if (status.is_error()) return status.move_as_error();
    return status.move_as_ok() != td::KeyValue::GetStatus::NotFound;
}

td::Status EvmRpcCacheDb::for_each_incomplete_block(
    std::function<td::Status(uint64_t)> cb) {
    return db_->for_each([&cb](td::Slice key, td::Slice) -> td::Status {
        if (key.size() != kIncompleteBlockKeyLen) return td::Status::OK();
        if (static_cast<uint8_t>(key[0]) != kIncompleteBlockTag) return td::Status::OK();
        return cb(load_be_u64(key.data() + 1));
    });
}

td::Result<size_t> EvmRpcCacheDb::count_incomplete_blocks() {
    char prefix = static_cast<char>(kIncompleteBlockTag);
    return db_->count(td::Slice{&prefix, 1});
}

td::Status EvmRpcCacheDb::prune_incomplete_markers(
    uint64_t now_unix_seconds,
    uint64_t max_age_seconds,
    size_t max_transactions,
    size_t max_blocks,
    IncompleteMarkerPruneStats* stats) {

    struct Marker {
        std::string key;
        uint64_t timestamp{0};
    };

    std::vector<Marker> tx_markers;
    std::vector<Marker> block_markers;
    auto collect_status = db_->for_each(
        [&](td::Slice key, td::Slice value) -> td::Status {
            if (key.size() == kIncompleteTxKeyLen &&
                static_cast<uint8_t>(key[0]) == kIncompleteTxTag) {
                tx_markers.push_back(Marker{
                    std::string(key.data(), key.size()),
                    load_incomplete_marker_timestamp(value)});
            } else if (key.size() == kIncompleteBlockKeyLen &&
                       static_cast<uint8_t>(key[0]) == kIncompleteBlockTag) {
                block_markers.push_back(Marker{
                    std::string(key.data(), key.size()),
                    load_incomplete_marker_timestamp(value)});
            }
            return td::Status::OK();
        });
    if (collect_status.is_error()) {
        return collect_status;
    }

    std::vector<std::string> keys_to_delete;
    auto prune = [&](std::vector<Marker>& markers,
                     size_t max_count,
                     size_t& expired,
                     size_t& overflow) {
        std::vector<Marker> retained;
        retained.reserve(markers.size());
        for (auto& marker : markers) {
            bool is_expired = marker.timestamp != 0 &&
                              max_age_seconds != 0 &&
                              now_unix_seconds > marker.timestamp &&
                              now_unix_seconds - marker.timestamp > max_age_seconds;
            if (is_expired) {
                keys_to_delete.push_back(std::move(marker.key));
                ++expired;
            } else {
                retained.push_back(std::move(marker));
            }
        }
        std::sort(retained.begin(), retained.end(),
                  [](const Marker& a, const Marker& b) {
                      if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
                      return a.key < b.key;
                  });
        while (retained.size() > max_count) {
            keys_to_delete.push_back(std::move(retained.front().key));
            retained.erase(retained.begin());
            ++overflow;
        }
    };

    IncompleteMarkerPruneStats local_stats;
    auto& out = stats ? *stats : local_stats;
    prune(tx_markers, max_transactions,
          out.expired_transactions, out.overflow_transactions);
    prune(block_markers, max_blocks,
          out.expired_blocks, out.overflow_blocks);

    for (const auto& key : keys_to_delete) {
        auto erase_status = db_->erase(td::Slice{key.data(), key.size()});
        if (erase_status.is_error()) {
            return erase_status;
        }
    }
    if (!keys_to_delete.empty()) {
        return db_->flush();
    }
    return td::Status::OK();
}

EvmRpcCacheDb* evm_rpc_cache_db() {
    return g_db.get();
}

void set_evm_rpc_cache_db(std::unique_ptr<EvmRpcCacheDb> db) {
    g_db = std::move(db);
}

}  // namespace evm_workchain
