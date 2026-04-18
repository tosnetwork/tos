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

// Key format: a single byte tag + payload. Reserves namespace for future
// addition of transactions / blocks / logs without colliding with receipts.
//   0x01 + bits256 tx_hash  → receipt cell
//   (0x02..0x05 reserved for future use)
constexpr uint8_t kReceiptTag = 0x01;
constexpr size_t kReceiptKeyLen = 1 + 32;

void make_receipt_key(const td::Bits256& tx_hash, char out[kReceiptKeyLen]) {
    out[0] = static_cast<char>(kReceiptTag);
    std::memcpy(out + 1, tx_hash.data(), 32);
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

EvmRpcCacheDb* evm_rpc_cache_db() {
    return g_db.get();
}

void set_evm_rpc_cache_db(std::unique_ptr<EvmRpcCacheDb> db) {
    g_db = std::move(db);
}

}  // namespace evm_workchain
