/*
    TOS wc=0 in-process wallet index — implementation.
    See wallet-index.h and doc/tos-wc0-wallet-index.md.
*/
#include "wallet-index.h"

#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"

#include <cstring>

namespace tos_wallet_index {

namespace {

// Key tags reserved for the wc=0 wallet index.
constexpr uint8_t kJettonTag = 0x10;        // 0x10 + owner(32) + master(32)
constexpr uint8_t kNftTag = 0x11;           // 0x11 + owner(32) + nft(32)
constexpr uint8_t kEventTag = 0x12;         // 0x12 + account(32) + ~lt_be(8)
constexpr uint8_t kNftOwnerTag = 0x13;      // 0x13 + nft(32) -> owner(32)
constexpr uint8_t kIncompleteBlockTag = 0x1E;  // 0x1E + seqno_be(8)

constexpr size_t kOwnerPairKeyLen = 1 + 32 + 32;
constexpr size_t kEventKeyLen = 1 + 32 + 8;
constexpr size_t kSingleHashKeyLen = 1 + 32;
constexpr size_t kIncompleteBlockKeyLen = 1 + 8;

void put_u64_be(char* out, uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<char>(v & 0xff);
    v >>= 8;
  }
}

void make_owner_pair_key(uint8_t tag, const HashKey& owner, const HashKey& other,
                         char out[kOwnerPairKeyLen]) {
  out[0] = static_cast<char>(tag);
  std::memcpy(out + 1, owner.data(), 32);
  std::memcpy(out + 1 + 32, other.data(), 32);
}

void make_owner_prefix(uint8_t tag, const HashKey& owner, char out[1 + 32]) {
  out[0] = static_cast<char>(tag);
  std::memcpy(out + 1, owner.data(), 32);
}

void make_event_key(const HashKey& account, uint64_t lt, char out[kEventKeyLen]) {
  out[0] = static_cast<char>(kEventTag);
  std::memcpy(out + 1, account.data(), 32);
  put_u64_be(out + 1 + 32, lt);
}

void make_incomplete_block_key(uint64_t seqno, char out[kIncompleteBlockKeyLen]) {
  out[0] = static_cast<char>(kIncompleteBlockTag);
  put_u64_be(out + 1, seqno);
}

// Module-scope singleton, owned here; lifetime managed by set_wallet_index_db.
std::unique_ptr<WalletIndexDb> g_db;

}  // namespace

td::Result<std::unique_ptr<WalletIndexDb>> WalletIndexDb::open(std::string path) {
  auto mkdir_status = td::mkdir(path);
  if (mkdir_status.is_error() && mkdir_status.message() != td::Slice{"File exists"}) {
    LOG(WARNING) << "wc0-index: mkdir " << path << " returned: " << mkdir_status.message();
  }
  auto db_r = td::RocksDb::open(path);
  if (db_r.is_error()) {
    return td::Status::Error(PSTRING() << "wc0-index: cannot open RocksDB at " << path << ": "
                                       << db_r.error().message());
  }
  auto db = std::make_unique<td::RocksDb>(db_r.move_as_ok());
  return std::unique_ptr<WalletIndexDb>(new WalletIndexDb(std::move(db)));
}

WalletIndexDb::WalletIndexDb(std::unique_ptr<td::RocksDb> db) : db_(std::move(db)) {}
WalletIndexDb::~WalletIndexDb() = default;

td::Status WalletIndexDb::put_cell(td::Slice key, td::Ref<vm::Cell> value) {
  if (value.is_null()) {
    return td::Status::Error("wc0-index: null value cell");
  }
  auto serialized_r = vm::std_boc_serialize(value);
  if (serialized_r.is_error()) {
    return serialized_r.move_as_error();
  }
  auto serialized = serialized_r.move_as_ok();
  // Durability comes from commit_batch()'s flush — per-entry flushing would
  // fsync once per transaction on the block-apply path.
  return db_->set(key, td::Slice{serialized.as_slice()});
}

td::Status WalletIndexDb::for_each_with_prefix(
    td::Slice prefix, size_t limit, std::function<td::Status(td::Slice, td::Ref<vm::Cell>)> cb) {
  // Range scan [prefix, next(prefix)): increment the last non-0xff byte of the
  // prefix to obtain the exclusive upper bound. Tags are 0x10..0x1E, so the
  // first byte can always absorb the carry.
  std::string end = prefix.str();
  size_t i = end.size();
  while (i > 0) {
    auto b = static_cast<uint8_t>(end[i - 1]);
    if (b != 0xff) {
      end[i - 1] = static_cast<char>(b + 1);
      end.resize(i);
      break;
    }
    --i;
  }
  if (i == 0) {
    return td::Status::Error("wc0-index: unbounded prefix");
  }
  size_t seen = 0;
  bool limit_hit = false;
  auto status = db_->for_each_in_range(prefix, td::Slice{end},
                                       [&](td::Slice key, td::Slice value) -> td::Status {
    if (seen >= limit) {
      limit_hit = true;
      return td::Status::Error("wc0-index: limit reached");
    }
    ++seen;
    auto cell_r = vm::std_boc_deserialize(value);
    if (cell_r.is_error()) {
      LOG(WARNING) << "wc0-index: skipping corrupt value: " << cell_r.error().message();
      return td::Status::OK();
    }
    return cb(key, cell_r.move_as_ok());
  });
  if (limit_hit) {
    return td::Status::OK();
  }
  return status;
}

// --- jettons ---

td::Status WalletIndexDb::put_jetton(const HashKey& owner, const HashKey& master,
                                     td::Ref<vm::Cell> value) {
  char key[kOwnerPairKeyLen];
  make_owner_pair_key(kJettonTag, owner, master, key);
  return put_cell(td::Slice{key, kOwnerPairKeyLen}, std::move(value));
}

td::Status WalletIndexDb::erase_jetton(const HashKey& owner, const HashKey& master) {
  char key[kOwnerPairKeyLen];
  make_owner_pair_key(kJettonTag, owner, master, key);
  return db_->erase(td::Slice{key, kOwnerPairKeyLen});
}

td::Status WalletIndexDb::for_each_jetton(
    const HashKey& owner, size_t limit,
    std::function<td::Status(const HashKey&, td::Ref<vm::Cell>)> cb) {
  char prefix[1 + 32];
  make_owner_prefix(kJettonTag, owner, prefix);
  return for_each_with_prefix(td::Slice{prefix, 1 + 32}, limit,
                              [&](td::Slice key, td::Ref<vm::Cell> cell) -> td::Status {
    if (key.size() != kOwnerPairKeyLen) return td::Status::OK();
    HashKey master;
    std::memcpy(master.data(), key.data() + 1 + 32, 32);
    return cb(master, std::move(cell));
  });
}

// --- nfts ---

td::Status WalletIndexDb::put_nft(const HashKey& owner, const HashKey& nft,
                                  td::Ref<vm::Cell> value) {
  char key[kOwnerPairKeyLen];
  make_owner_pair_key(kNftTag, owner, nft, key);
  return put_cell(td::Slice{key, kOwnerPairKeyLen}, std::move(value));
}

td::Status WalletIndexDb::erase_nft(const HashKey& owner, const HashKey& nft) {
  char key[kOwnerPairKeyLen];
  make_owner_pair_key(kNftTag, owner, nft, key);
  return db_->erase(td::Slice{key, kOwnerPairKeyLen});
}

td::Status WalletIndexDb::for_each_nft(
    const HashKey& owner, size_t limit,
    std::function<td::Status(const HashKey&, td::Ref<vm::Cell>)> cb) {
  char prefix[1 + 32];
  make_owner_prefix(kNftTag, owner, prefix);
  return for_each_with_prefix(td::Slice{prefix, 1 + 32}, limit,
                              [&](td::Slice key, td::Ref<vm::Cell> cell) -> td::Status {
    if (key.size() != kOwnerPairKeyLen) return td::Status::OK();
    HashKey nft;
    std::memcpy(nft.data(), key.data() + 1 + 32, 32);
    return cb(nft, std::move(cell));
  });
}

// --- events ---

td::Status WalletIndexDb::put_event(const HashKey& account, uint64_t lt,
                                    td::Ref<vm::Cell> value) {
  char key[kEventKeyLen];
  // Store ~lt so ascending key order is newest-first and `limit` caps the scan
  // to the most recent events instead of the oldest.
  make_event_key(account, ~lt, key);
  return put_cell(td::Slice{key, kEventKeyLen}, std::move(value));
}

td::Status WalletIndexDb::for_each_event(
    const HashKey& account, size_t limit,
    std::function<td::Status(uint64_t, td::Ref<vm::Cell>)> cb) {
  char prefix[1 + 32];
  make_owner_prefix(kEventTag, account, prefix);
  return for_each_with_prefix(td::Slice{prefix, 1 + 32}, limit,
                              [&](td::Slice key, td::Ref<vm::Cell> cell) -> td::Status {
    if (key.size() != kEventKeyLen) return td::Status::OK();
    uint64_t stored = 0;
    for (int i = 0; i < 8; ++i) {
      stored = (stored << 8) | static_cast<uint8_t>(key[1 + 32 + i]);
    }
    return cb(~stored, std::move(cell));
  });
}

// --- nft current-owner reverse map ---

td::Status WalletIndexDb::put_nft_owner(const HashKey& nft, const HashKey& owner) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  return db_->set(td::Slice{key, kSingleHashKeyLen}, owner.as_slice());
}

td::Result<bool> WalletIndexDb::get_nft_owner(const HashKey& nft, HashKey& owner) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  std::string value;
  auto status = db_->get(td::Slice{key, kSingleHashKeyLen}, value);
  if (status.is_error()) return status.move_as_error();
  if (status.ok() == td::KeyValue::GetStatus::NotFound || value.size() != 32) {
    return false;
  }
  owner.as_slice().copy_from(td::Slice{value});
  return true;
}

// --- crash-recovery markers ---

td::Status WalletIndexDb::put_incomplete_block(uint64_t seqno) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(seqno, key);
  char val[1] = {0};
  auto s = db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{val, 1});
  if (s.is_error()) return s;
  // The marker must be durable before the block's entries: a marker that survives
  // a crash flags a block whose indexing never committed.
  return db_->flush();
}

td::Status WalletIndexDb::delete_incomplete_block(uint64_t seqno) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(seqno, key);
  // Joins the open write batch (if any), so the marker disappears atomically
  // with the block's entries.
  return db_->erase(td::Slice{key, kIncompleteBlockKeyLen});
}

td::Result<bool> WalletIndexDb::has_incomplete_block(uint64_t seqno) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(seqno, key);
  std::string value;
  auto status = db_->get(td::Slice{key, kIncompleteBlockKeyLen}, value);
  if (status.is_error()) return status.move_as_error();
  return status.move_as_ok() != td::KeyValue::GetStatus::NotFound;
}

// --- per-block batched writes ---

td::Status WalletIndexDb::begin_batch() {
  if (batch_open_) {
    return td::Status::Error("wc0-index: batch already open");
  }
  auto s = db_->begin_write_batch();
  if (s.is_error()) return s;
  batch_open_ = true;
  return td::Status::OK();
}

td::Status WalletIndexDb::commit_batch() {
  if (!batch_open_) {
    return td::Status::Error("wc0-index: no batch open");
  }
  batch_open_ = false;
  auto s = db_->commit_write_batch();
  if (s.is_error()) return s;
  // td::RocksDb opens with manual WAL flush and its destructor does not flush, so
  // one explicit flush() per block is required for durability across restart
  // (see EvmRpcCacheDb).
  return db_->flush();
}

void WalletIndexDb::abort_batch() {
  if (!batch_open_) {
    return;
  }
  batch_open_ = false;
  db_->abort_write_batch().ignore();
}

// --- singleton ---

WalletIndexDb* wallet_index_db() { return g_db.get(); }

void set_wallet_index_db(std::unique_ptr<WalletIndexDb> db) { g_db = std::move(db); }

void open_wallet_index_db(const std::string& db_root) {
  if (db_root.empty()) {
    return;
  }
  auto db_r = WalletIndexDb::open(db_root + "/wc0-index");
  if (db_r.is_error()) {
    LOG(ERROR) << "wc0-index: failed to open: " << db_r.error().message();
    return;
  }
  set_wallet_index_db(db_r.move_as_ok());
  LOG(INFO) << "wc0-index: opened at " << db_root << "/wc0-index";
}

}  // namespace tos_wallet_index
