/*
    TOS wc=0 in-process wallet index — implementation.
    See wallet-index.h and https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md.
*/
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"

#include "wallet-index.h"

namespace tos_wallet_index {

namespace {

// Key tags reserved for the wc=0 wallet index.
constexpr uint8_t kJettonTag = 0x10;        // 0x10 + owner(32) + master(32)
constexpr uint8_t kNftTag = 0x11;           // 0x11 + owner(32) + nft(32)
constexpr uint8_t kEventTag = 0x12;         // 0x12 + account(32) + ~lt_be(8)
constexpr uint8_t kNftOwnerTag = 0x13;      // 0x13 + nft(32) -> owner(32)
constexpr uint8_t kEventAgeTag = 0x14;      // 0x14 + gen_utime_be(4) + account(32) + lt_be(8) -> sentinel(1)
constexpr uint8_t kTokenQueueTag = 0x15;    // 0x15 + bucket(1) + seq_be(8) -> kind(1) + address(32) + attempts(1)
constexpr uint8_t kTokenIndexTag = 0x16;    // 0x16 + kind(1) + address(32) -> bucket(1) + seq_be(8)
// Meta namespace, sorts before every data tag. 0x00 0x01 -> schema version
// (u32_be); 0x00 0x02 -> event-retention watermark (u32_be, max gen_utime seen).
constexpr uint8_t kMetaTag = 0x00;
constexpr uint8_t kMetaSchemaSub = 0x01;
constexpr uint8_t kMetaWatermarkSub = 0x02;
// Token backlog bookkeeping (u64_be each; absent means 0): 0x00 0x03 -> next
// queue sequence number, 0x00 0x04 -> entries, 0x00 0x05 -> candidates lost.
// 0x00 0x07 -> candidates that need another shard's state. 0x00 0x06 +
// shard_be(8) -> the queue (bucket) that shard serves next; 0x00 0x08 +
// shard_be(8) -> for a shard sharing its queue, the last queue key examined.
constexpr uint8_t kMetaTokenSeqSub = 0x03;
constexpr uint8_t kMetaTokenEntriesSub = 0x04;
constexpr uint8_t kMetaTokenLostSub = 0x05;
constexpr uint8_t kMetaTokenCursorSub = 0x06;
constexpr uint8_t kMetaTokenUnverifiableSub = 0x07;
constexpr uint8_t kMetaTokenPositionSub = 0x08;

// (kMaxEventsPerAccount / kMaxEventTrimPerPass are declared in the header
// so tests can reference the exact bound.)
// 0x1E + workchain_be(4) + shard_be(8) + seqno_be(4) + root_hash(32) + file_hash(32) -> sentinel(1)
// The full BlockIdExt is in the key, not split key/value: if a position could
// ever be re-applied with a different hash (e.g. some reorg/hardfork path),
// keying by position alone would let a new marker silently overwrite an old
// one's hash instead of being a distinct entry.
constexpr uint8_t kIncompleteBlockTag = 0x1E;
// Legacy key length: every binary before this change (including production
// binaries currently running, and this file's own first cut of the
// full-BlockIdExt redesign) used tag + seqno_be(8) only, no workchain/shard/
// hash. A node that ever had a real indexing failure under an older binary
// can have real markers in this format on disk. Recognized distinctly below
// so they surface loudly instead of being silently discarded as generic
// "malformed".
constexpr size_t kLegacySeqnoOnlyKeyLen = 1 + 8;

constexpr size_t kOwnerPairKeyLen = 1 + 32 + 32;
constexpr size_t kEventKeyLen = 1 + 32 + 8;
constexpr size_t kEventAgeKeyLen = 1 + 4 + 32 + 8;
constexpr size_t kMetaKeyLen = 2;
constexpr size_t kSingleHashKeyLen = 1 + 32;
constexpr size_t kIncompleteBlockKeyLen = 1 + 4 + 8 + 4 + 32 + 32;
constexpr size_t kIncompleteBlockValueLen = 1;
constexpr size_t kTokenQueueKeyLen = 1 + 1 + 8;
constexpr size_t kTokenQueueValueLen = 1 + 32 + 1;
constexpr size_t kTokenIndexKeyLen = 1 + 1 + 32;

void put_u32_be(char* out, uint32_t v) {
  for (int i = 3; i >= 0; --i) {
    out[i] = static_cast<char>(v & 0xff);
    v >>= 8;
  }
}

uint32_t get_u32_be(const char* p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    v = (v << 8) | static_cast<uint8_t>(p[i]);
  }
  return v;
}

void put_u64_be(char* out, uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<char>(v & 0xff);
    v >>= 8;
  }
}

uint64_t get_u64_be(const char* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | static_cast<uint8_t>(p[i]);
  }
  return v;
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

void make_event_age_key(uint32_t gen_utime, const HashKey& account, uint64_t lt, char out[kEventAgeKeyLen]) {
  out[0] = static_cast<char>(kEventAgeTag);
  put_u32_be(out + 1, gen_utime);
  std::memcpy(out + 1 + 4, account.data(), 32);
  put_u64_be(out + 1 + 4 + 32, lt);
}

void make_meta_key(uint8_t sub, char out[kMetaKeyLen]) {
  out[0] = static_cast<char>(kMetaTag);
  out[1] = static_cast<char>(sub);
}

void make_incomplete_block_key(const tos::BlockIdExt& block_id, char out[kIncompleteBlockKeyLen]) {
  out[0] = static_cast<char>(kIncompleteBlockTag);
  put_u32_be(out + 1, static_cast<uint32_t>(block_id.id.workchain));
  put_u64_be(out + 1 + 4, block_id.id.shard);
  put_u32_be(out + 1 + 4 + 8, block_id.id.seqno);
  std::memcpy(out + 1 + 4 + 8 + 4, block_id.root_hash.as_slice().data(), 32);
  std::memcpy(out + 1 + 4 + 8 + 4 + 32, block_id.file_hash.as_slice().data(), 32);
}

// Module-scope singleton, owned here; lifetime managed by set_wallet_index_db.
std::unique_ptr<WalletIndexDb> g_db;

}  // namespace

td::Result<std::unique_ptr<WalletIndexDb>> WalletIndexDb::open(std::string path) {
  auto mkdir_status = td::mkdir(path);
  if (mkdir_status.is_error() && mkdir_status.message() != td::Slice{"File exists"}) {
    LOG(WARNING) << "wc0-index: mkdir " << path << " returned: " << mkdir_status.message();
  }
  td::RocksDbOptions options;
  // WalletIndexDb uses one atomic WriteBatch per indexed block. It does not
  // use transactions and therefore does not need retained conflict history.
  options.no_transactions = true;
  auto db_r = td::RocksDb::open(path, std::move(options));
  if (db_r.is_error()) {
    return td::Status::Error(PSTRING() << "wc0-index: cannot open RocksDB at " << path << ": "
                                       << db_r.error().message());
  }
  auto db = std::make_unique<td::RocksDb>(db_r.move_as_ok());
  auto index = std::unique_ptr<WalletIndexDb>(new WalletIndexDb(std::move(db)));
  TRY_STATUS(index->migrate_schema());
  return index;
}

WalletIndexDb::WalletIndexDb(std::unique_ptr<td::RocksDb> db)
    : db_(std::move(db)), marker_db_(std::make_unique<td::RocksDb>(db_->clone())) {
}

td::Result<std::unique_ptr<WalletIndexDb>> WalletIndexDb::read_snapshot() {
  auto view = std::make_unique<td::RocksDb>(db_->clone());
  TRY_STATUS(view->begin_snapshot());
  return std::unique_ptr<WalletIndexDb>(new WalletIndexDb(std::move(view)));
}

td::Result<WalletIndexSnapshot> WalletIndexSnapshot::of(WalletIndexDb& db) {
  TRY_RESULT(view, db.read_snapshot());
  return WalletIndexSnapshot(std::move(view));
}
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

td::Status WalletIndexDb::for_each_key_with_prefix(
    td::Slice prefix, size_t limit, std::function<td::Status(td::Slice)> cb) {
  // As for_each_with_prefix, but hands over keys only: a row about to be
  // deleted does not need its cell deserialized first.
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
  return db_->for_each_in_range(prefix, td::Slice{end}, [&](td::Slice key, td::Slice) -> td::Status {
    if (seen >= limit) {
      return td::Status::Error("wc0-index: limit reached");
    }
    ++seen;
    return cb(key);
  });
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
  // Just write. Trimming is not done here: put_event runs once per
  // transaction on the block-apply path, and its committed-DB scan does
  // not see the batch's own writes, so trimming per put would re-scan the
  // account's whole history for every transaction in a block. The caller
  // trims each touched account once, after the block's events are in.
  return put_cell(td::Slice{key, kEventKeyLen}, std::move(value));
}

td::Status WalletIndexDb::trim_events(const HashKey& account, size_t added_this_block) {
  // Every workchain-zero transaction adds a row holding the whole
  // transaction, and until now nothing removed one: jetton and NFT rows have
  // erase paths, events did not, so this index grew for the life of the node
  // and outlived the archive retention that bounds everything else.
  //
  // The key orders an account's events newest-first, so a bound on how much
  // history is kept per account is just a matter of dropping the tail. That
  // also reaches rows written before this existed, which a separate
  // time-index would not: those rows have no companion entry to find them by.
  //
  // Two things make the bound actually hold on the production path:
  //
  //  * This runs inside the block's write batch, before commit, so the scan
  //    below sees only committed rows -- the `added_this_block` rows written
  //    for this account earlier in the batch are invisible to it. Keeping
  //    `kMaxEventsPerAccount - added_this_block` committed rows leaves room for
  //    them, so the post-commit total is at most kMaxEventsPerAccount, provided
  //    a single block adds fewer than kMaxEventsPerAccount events for one
  //    account (block transaction limits make this the case in practice). If a
  //    block ever added at least that many, `keep` clamps to 0 and those
  //    in-batch rows cannot be scanned to delete, so that one block would
  //    commit with `added_this_block` rows; the next block's trim then brings
  //    it back down -- growth still cannot run away, since a pass always
  //    deletes at least what the block added (see below).
  //
  //  * The delete budget is `added_this_block + kEventTrimDrainPerPass`. A pass
  //    therefore always removes at least as many rows as the block added, so an
  //    account gaining more rows per block than a fixed cap can no longer
  //    outrun trimming; the drain term additionally shrinks any pre-existing
  //    backlog block by block.
  char prefix[1 + 32];
  prefix[0] = static_cast<char>(kEventTag);
  std::memcpy(prefix + 1, account.data(), 32);

  size_t keep = added_this_block >= kMaxEventsPerAccount ? 0 : kMaxEventsPerAccount - added_this_block;
  size_t budget = added_this_block + kEventTrimDrainPerPass;

  std::vector<std::string> doomed;
  size_t seen = 0;
  auto status = for_each_key_with_prefix(td::Slice{prefix, sizeof(prefix)}, keep + budget + 1,
                                         [&](td::Slice key) -> td::Status {
    if (++seen > keep) {
      doomed.emplace_back(key.str());
      if (doomed.size() >= budget) {
        return td::Status::Error("wc0-index: trim batch full");
      }
    }
    return td::Status::OK();
  });
  // The iteration is stopped by returning an error once the batch is full;
  // a genuine read failure is reported, a full batch is not.
  if (status.is_error() && status.message() != "wc0-index: trim batch full") {
    return status;
  }
  for (const auto& key : doomed) {
    TRY_STATUS(db_->erase(td::Slice{key}));
  }
  return td::Status::OK();
}

td::Status WalletIndexDb::put_event_age(const HashKey& account, uint64_t lt, uint32_t gen_utime) {
  char key[kEventAgeKeyLen];
  make_event_age_key(gen_utime, account, lt, key);
  // Value is a one-byte sentinel; the key carries everything the pruner needs.
  const char sentinel = 0;
  return db_->set(td::Slice{key, kEventAgeKeyLen}, td::Slice{&sentinel, 1});
}

td::Status WalletIndexDb::prune_events_by_age(uint32_t cutoff_gen_utime, size_t budget) {
  // Delete event rows whose block gen_utime is strictly older than the cutoff,
  // reached through the age index rather than the per-account event prefix, so
  // whole dormant accounts are dropped. Scan [0x14, 0x14 | cutoff_be): the
  // exclusive upper bound retains events exactly at the cutoff. Bounded to
  // `budget` deletions so per-block work is bounded; a backlog drains over
  // successive blocks because the caller's budget always covers at least the
  // rows the block added.
  //
  // The range scan reads committed state only, not the current write batch, so
  // age rows written by *this* block are invisible here. An already-expired
  // event inserted by a late or recovery block is therefore not removed in its
  // own block; the next block's prune reclaims it (it is < cutoff and the budget
  // carries a drain). This is deliberately not strict same-block retention.
  if (budget == 0) {
    return td::Status::OK();
  }
  const char begin[1] = {static_cast<char>(kEventAgeTag)};
  char end[1 + 4];
  end[0] = static_cast<char>(kEventAgeTag);
  put_u32_be(end + 1, cutoff_gen_utime);

  std::vector<std::string> doomed_age;
  auto status = db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, sizeof(end)},
                                       [&](td::Slice key, td::Slice) -> td::Status {
    doomed_age.emplace_back(key.str());
    if (doomed_age.size() >= budget) {
      return td::Status::Error("wc0-index: prune batch full");
    }
    return td::Status::OK();
  });
  if (status.is_error() && status.message() != "wc0-index: prune batch full") {
    return status;
  }
  for (const auto& age_key : doomed_age) {
    if (age_key.size() != kEventAgeKeyLen) {
      continue;  // unexpected layout: skip rather than mis-parse the account/lt
    }
    const char* p = age_key.data();
    HashKey account;
    std::memcpy(account.data(), p + 1 + 4, 32);
    uint64_t lt = get_u64_be(p + 1 + 4 + 32);
    // Reconstruct the event key (0x12 | account | ~lt). Erasing an already-gone
    // event (e.g. one the per-account trim removed) is a harmless no-op.
    char event_key[kEventKeyLen];
    make_event_key(account, ~lt, event_key);
    TRY_STATUS(db_->erase(td::Slice{event_key, kEventKeyLen}));
    TRY_STATUS(db_->erase(td::Slice{age_key}));
  }
  return td::Status::OK();
}

td::Result<uint32_t> WalletIndexDb::get_event_watermark() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaWatermarkSub, key);
  std::string value;
  auto status = db_->get(td::Slice{key, kMetaKeyLen}, value);
  if (status.is_error()) {
    return status.move_as_error();
  }
  if (status.ok() == td::KeyValue::GetStatus::NotFound) {
    return 0u;
  }
  if (value.size() != 4) {
    return td::Status::Error("wc0-index: malformed event watermark");
  }
  return get_u32_be(value.data());
}

td::Status WalletIndexDb::put_event_watermark(uint32_t gen_utime) {
  char key[kMetaKeyLen];
  make_meta_key(kMetaWatermarkSub, key);
  char v[4];
  put_u32_be(v, gen_utime);
  return db_->set(td::Slice{key, kMetaKeyLen}, td::Slice{v, sizeof(v)});
}

td::Status WalletIndexDb::clear_namespace(uint8_t tag) {
  // A single range tombstone: O(1) work and memory regardless of how many keys
  // the namespace holds. Enumerating them here would defeat the purpose -- the
  // 0x12 event namespace this clears is exactly the one that could have grown
  // without bound, so loading all of it into memory to delete could OOM the very
  // node the migration exists to fix.
  const char begin[1] = {static_cast<char>(tag)};
  const char end[1] = {static_cast<char>(static_cast<uint8_t>(tag + 1))};
  return db_->erase_range(td::Slice{begin, 1}, td::Slice{end, 1});
}

td::Status WalletIndexDb::advance_retention(uint32_t gen_utime, size_t age_rows_added) {
  // The watermark, the age rows, and the prune together define the retention
  // invariant, so any error must propagate and let the caller abort the block
  // rather than commit a broken retention state. A watermark read error in
  // particular must NOT fall back to 0: that could regress the non-decreasing
  // watermark and let a late or recovery block retain expired rows.
  TRY_RESULT(stored_watermark, get_event_watermark());
  uint32_t watermark = stored_watermark > gen_utime ? stored_watermark : gen_utime;
  TRY_STATUS(put_event_watermark(watermark));
  uint32_t cutoff = watermark > kEventRetentionSeconds ? watermark - kEventRetentionSeconds : 0;
  return prune_events_by_age(cutoff, age_rows_added + kEventPruneDrainPerBlock);
}

td::Status WalletIndexDb::migrate_schema() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaSchemaSub, key);
  std::string value;
  auto gs = db_->get(td::Slice{key, kMetaKeyLen}, value);
  if (gs.is_error()) {
    return gs.move_as_error();
  }
  uint32_t version = 0;  // no key => predates versioning (version 0)
  if (gs.ok() != td::KeyValue::GetStatus::NotFound) {
    if (value.size() != 4) {
      return td::Status::Error("wc0-index: malformed schema version");
    }
    version = get_u32_be(value.data());
  }
  if (version == kWalletIndexSchemaVersion) {
    return td::Status::OK();
  }
  if (version > kWalletIndexSchemaVersion) {
    return td::Status::Error(PSTRING() << "wc0-index: on-disk schema version " << version
                                       << " is newer than supported " << kWalletIndexSchemaVersion
                                       << "; refusing to open");
  }
  // Upgrade path. The pre-version event index (0x12) had only per-account
  // retention, so it can carry unbounded one-transaction-account history; drop
  // it together with the (as-yet-empty) age index (0x14) and record the new
  // version, atomically and WAL-synced, before the DB is used. The index
  // rebuilds forward as new blocks are applied -- it does not replay archive
  // history (a derived, non-consensus RPC index), so pre-upgrade event history,
  // including recent history, is not available until re-indexed. Jetton/NFT/
  // nft-owner/incomplete-block namespaces are left intact.
  LOG(WARNING) << "wc0-index: migrating schema " << version << " -> " << kWalletIndexSchemaVersion
               << "; clearing event history (rebuilds forward from new blocks)";
  TRY_STATUS(db_->begin_write_batch());
  auto migrate = [&]() -> td::Status {
    TRY_STATUS(clear_namespace(kEventTag));
    TRY_STATUS(clear_namespace(kEventAgeTag));
    char v[4];
    put_u32_be(v, kWalletIndexSchemaVersion);
    return db_->set(td::Slice{key, kMetaKeyLen}, td::Slice{v, sizeof(v)});
  };
  auto status = migrate();
  if (status.is_error()) {
    db_->abort_write_batch();
    return status;
  }
  return db_->commit_write_batch();
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

td::Status WalletIndexDb::for_each_event_before(
    const HashKey& account, uint64_t before_lt, size_t limit,
    std::function<td::Status(uint64_t, td::Ref<vm::Cell>)> cb) {
  if (before_lt == 0) return td::Status::OK();
  char begin[kEventKeyLen];
  make_event_key(account, ~before_lt + 1, begin);
  char end[1 + 32];
  make_owner_prefix(kEventTag, account, end);
  size_t i = sizeof(end);
  while (i > 0 && static_cast<uint8_t>(end[i - 1]) == 0xff) --i;
  if (i == 0) return td::Status::Error("wc0-index: unbounded event prefix");
  end[i - 1] = static_cast<char>(static_cast<uint8_t>(end[i - 1]) + 1);

  size_t seen = 0;
  bool limit_hit = false;
  auto status = db_->for_each_in_range(
      td::Slice{begin, sizeof(begin)}, td::Slice{end, i},
      [&](td::Slice key, td::Slice value) -> td::Status {
        if (seen >= limit) {
          limit_hit = true;
          return td::Status::Error("wc0-index: limit reached");
        }
        if (key.size() != kEventKeyLen) return td::Status::OK();
        auto cell_r = vm::std_boc_deserialize(value);
        if (cell_r.is_error()) {
          LOG(WARNING) << "wc0-index: skipping corrupt event: " << cell_r.error().message();
          return td::Status::OK();
        }
        ++seen;
        return cb(~get_u64_be(key.data() + 1 + 32), cell_r.move_as_ok());
      });
  if (limit_hit) return td::Status::OK();
  return status;
}

td::Result<td::Ref<vm::Cell>> WalletIndexDb::get_event(const HashKey& account, uint64_t lt) {
  char key[kEventKeyLen];
  make_event_key(account, ~lt, key);
  std::string value;
  auto status = db_->get(td::Slice{key, sizeof(key)}, value);
  if (status.is_error()) return status.move_as_error();
  if (status.ok() == td::KeyValue::GetStatus::NotFound) {
    return td::Status::Error("account event not found");
  }
  return vm::std_boc_deserialize(td::Slice{value});
}

// --- nft current-owner reverse map ---

td::Status WalletIndexDb::put_nft_owner(const HashKey& nft, const HashKey& owner) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  return db_->set(td::Slice{key, kSingleHashKeyLen}, owner.as_slice());
}

td::Status WalletIndexDb::erase_nft_owner(const HashKey& nft) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  return db_->erase(td::Slice{key, kSingleHashKeyLen});
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

td::Status WalletIndexDb::put_incomplete_block(const tos::BlockIdExt& block_id) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(block_id, key);
  char val[kIncompleteBlockValueLen] = {0};
  auto s = db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{val, kIncompleteBlockValueLen});
  if (s.is_error()) return s;
  // The marker must be durable before the block's entries: a marker that survives
  // a crash flags a block whose indexing never committed. A WAL sync is enough
  // for that (manual_wal_flush=true means writes aren't synced by default) —
  // no need for a full memtable flush.
  return db_->flush_wal(true);
}

td::Status WalletIndexDb::mark_blocks_incomplete(const std::vector<tos::BlockIdExt>& block_ids) {
  if (block_ids.empty()) {
    return td::Status::OK();
  }
  char val[kIncompleteBlockValueLen] = {0};
  for (const auto& block_id : block_ids) {
    char key[kIncompleteBlockKeyLen];
    make_incomplete_block_key(block_id, key);
    TRY_STATUS(marker_db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{val, kIncompleteBlockValueLen}));
  }
  return marker_db_->flush_wal(true);
}

td::Status WalletIndexDb::delete_incomplete_block(const tos::BlockIdExt& block_id) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(block_id, key);
  // Joins the open write batch (if any), so the marker disappears atomically
  // with the block's entries.
  return db_->erase(td::Slice{key, kIncompleteBlockKeyLen});
}

td::Result<bool> WalletIndexDb::has_incomplete_block(const tos::BlockIdExt& block_id) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(block_id, key);
  std::string value;
  auto status = db_->get(td::Slice{key, kIncompleteBlockKeyLen}, value);
  if (status.is_error()) return status.move_as_error();
  return status.move_as_ok() != td::KeyValue::GetStatus::NotFound;
}

td::Status WalletIndexDb::for_each_incomplete_block(std::function<td::Status(const tos::BlockIdExt&)> cb) {
  // [0x1E, 0x1F) — the marker tag is a single byte, so the exclusive upper
  // bound is just tag+1; no carry-chain needed (unlike for_each_with_prefix,
  // which also handles multi-byte prefixes). Marker values are a sentinel
  // byte, not a BOC cell, so this deliberately doesn't route through
  // for_each_with_prefix (which BOC-deserializes every value).
  char begin[1] = {static_cast<char>(kIncompleteBlockTag)};
  char end[1] = {static_cast<char>(kIncompleteBlockTag + 1)};
  return db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1},
                                [&](td::Slice key, td::Slice value) -> td::Status {
    if (key.size() == kLegacySeqnoOnlyKeyLen) {
      // A pre-full-BlockIdExt marker: not enough information here (no
      // shard, no hash) to safely resolve to one specific block, so it
      // can't be auto-recovered. Surface it loudly rather than silently
      // dropping it — an operator needs to check whether this seqno's
      // block actually has incomplete jetton/NFT data.
      LOG(ERROR) << "wc0-index: found a legacy seqno-only incomplete-block marker (seqno="
                 << get_u64_be(key.data() + 1) << ") predating full-BlockIdExt markers; cannot"
                 << " auto-recover it — verify this block's index data manually, then delete the"
                 << " raw key if it's stale";
      return td::Status::OK();
    }
    if (key.size() != kIncompleteBlockKeyLen || value.size() != kIncompleteBlockValueLen) {
      LOG(WARNING) << "wc0-index: skipping malformed incomplete-block entry (key " << key.size()
                   << "B, value " << value.size() << "B)";
      return td::Status::OK();
    }
    tos::WorkchainId workchain = static_cast<tos::WorkchainId>(get_u32_be(key.data() + 1));
    tos::ShardId shard = get_u64_be(key.data() + 1 + 4);
    tos::BlockSeqno seqno = get_u32_be(key.data() + 1 + 4 + 8);
    tos::RootHash root_hash;
    tos::FileHash file_hash;
    root_hash.as_slice().copy_from(td::Slice{key.data() + 1 + 4 + 8 + 4, 32});
    file_hash.as_slice().copy_from(td::Slice{key.data() + 1 + 4 + 8 + 4 + 32, 32});
    return cb(tos::BlockIdExt{workchain, shard, seqno, root_hash, file_hash});
  });
}

// --- deferred token candidates ---

namespace {

struct QueueEntry {
  std::string key;
  ScheduledTokenCandidate scheduled;
};

std::string token_queue_bucket_prefix(size_t bucket) {
  std::string prefix(2, '\0');
  prefix[0] = static_cast<char>(kTokenQueueTag);
  prefix[1] = static_cast<char>(bucket);
  return prefix;
}

// Exclusive end of a queue's key range: the next queue's prefix, or the next
// tag after the last queue.
std::string token_queue_bucket_end(size_t bucket) {
  if (bucket + 1 < kTokenBacklogBuckets) {
    return token_queue_bucket_prefix(bucket + 1);
  }
  return std::string(1, static_cast<char>(kTokenQueueTag + 1));
}

size_t token_bucket(const HashKey& address) {
  return address.data()[0];
}

std::string token_index_key(const TokenCandidate& candidate) {
  std::string key(kTokenIndexKeyLen, '\0');
  key[0] = static_cast<char>(kTokenIndexTag);
  key[1] = static_cast<char>(candidate.kind);
  std::memcpy(&key[2], candidate.address.data(), 32);
  return key;
}

// The candidate a queue value names, if the value is intact enough to say.
td::Result<TokenCandidate> token_queue_identity(td::Slice key, td::Slice value) {
  if (key.size() != kTokenQueueKeyLen || value.size() != kTokenQueueValueLen) {
    return td::Status::Error("wc0-index: malformed token backlog entry");
  }
  auto kind = static_cast<uint8_t>(value[0]);
  if (kind != static_cast<uint8_t>(TokenKind::Jetton) && kind != static_cast<uint8_t>(TokenKind::Nft)) {
    return td::Status::Error("wc0-index: unknown token kind in backlog entry");
  }
  TokenCandidate candidate{static_cast<TokenKind>(kind), HashKey{}};
  std::memcpy(candidate.address.data(), value.data() + 1, 32);
  return candidate;
}

td::Result<ScheduledTokenCandidate> parse_token_queue_entry(td::Slice key, td::Slice value) {
  TRY_RESULT(candidate, token_queue_identity(key, value));
  auto attempts = static_cast<uint8_t>(value[1 + 32]);
  if (attempts >= kMaxTokenCandidateAttempts) {
    return td::Status::Error("wc0-index: backlog entry has no attempts left");
  }
  if (static_cast<uint8_t>(key[1]) != token_bucket(candidate.address)) {
    return td::Status::Error("wc0-index: backlog entry is in the wrong queue");
  }
  return ScheduledTokenCandidate{candidate, attempts};
}

// The queues a wc=0 shard reads: the top bytes its address range spans.
td::Result<std::pair<size_t, size_t>> token_shard_buckets(tos::ShardIdFull shard) {
  if (shard.workchain != 0 || shard.shard == 0) {
    return td::Status::Error("wc0-index: token scheduling needs a valid wc=0 shard");
  }
  uint64_t lowest = shard.shard & (~shard.shard + 1);
  uint64_t first = shard.shard - lowest;
  uint64_t last = shard.shard + (lowest - 1);
  return std::make_pair(static_cast<size_t>(first >> 56), static_cast<size_t>(last >> 56));
}

// A shard deeper than 8 levels owns only part of its one queue.
bool token_shard_shares_its_queue(tos::ShardIdFull shard) {
  uint64_t lowest = shard.shard & (~shard.shard + 1);
  return lowest < (1ULL << 55);
}

bool token_shard_contains(tos::ShardIdFull shard, const HashKey& address) {
  return tos::shard_contains(shard, tos::AccountIdPrefixFull{0, tos::extract_top64(address)});
}

std::string token_shard_meta_key(uint8_t sub, tos::ShardIdFull shard) {
  std::string key(kMetaKeyLen + 8, '\0');
  key[0] = static_cast<char>(kMetaTag);
  key[1] = static_cast<char>(sub);
  put_u64_be(&key[kMetaKeyLen], shard.shard);
  return key;
}

// The smallest key greater than `key`.
std::string key_after(const std::string& key) {
  return key + std::string(1, '\0');
}

}  // namespace

td::Result<uint64_t> WalletIndexDb::get_meta_u64(uint8_t sub) {
  char key[kMetaKeyLen];
  make_meta_key(sub, key);
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{key, kMetaKeyLen}, value));
  if (status == td::KeyValue::GetStatus::NotFound) {
    return static_cast<uint64_t>(0);
  }
  if (value.size() != 8) {
    return td::Status::Error("wc0-index: malformed token backlog counter");
  }
  return get_u64_be(value.data());
}

td::Status WalletIndexDb::put_meta_u64(uint8_t sub, uint64_t value) {
  char key[kMetaKeyLen];
  make_meta_key(sub, key);
  char v[8];
  put_u64_be(v, value);
  return db_->set(td::Slice{key, kMetaKeyLen}, td::Slice{v, sizeof(v)});
}

td::Result<std::string> WalletIndexDb::token_index_get(const std::string& index_key) {
  auto it = token_batch_.index_overlay.find(index_key);
  if (it != token_batch_.index_overlay.end()) {
    return it->second;
  }
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{index_key}, value));
  if (status == td::KeyValue::GetStatus::NotFound) {
    return std::string();
  }
  if (value.size() != kTokenQueueKeyLen - 1) {
    // Points nowhere usable; callers treat it as an orphan and replace it.
    return std::string(1, static_cast<char>(kTokenQueueTag));
  }
  return std::string(1, static_cast<char>(kTokenQueueTag)) + value;
}

td::Status WalletIndexDb::token_index_erase(const std::string& index_key) {
  TRY_STATUS(db_->erase(td::Slice{index_key}));
  token_batch_.index_overlay[index_key] = std::string();
  return td::Status::OK();
}

// Callers erase only rows token_queue_has still reports, so each row is
// erased, and counted out of `entries`, once per batch.
td::Status WalletIndexDb::token_queue_erase(const std::string& queue_key) {
  token_batch_.queue_erased.insert(queue_key);
  return db_->erase(td::Slice{queue_key});
}

td::Result<bool> WalletIndexDb::token_queue_has(const std::string& queue_key) {
  if (queue_key.size() != kTokenQueueKeyLen || token_batch_.queue_erased.count(queue_key) != 0) {
    return false;
  }
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{queue_key}, value));
  return status == td::KeyValue::GetStatus::Ok;
}

td::Result<uint8_t> WalletIndexDb::token_claim(const TokenCandidate& candidate) {
  auto index_key = token_index_key(candidate);
  TRY_RESULT(queue_key, token_index_get(index_key));
  if (queue_key.empty()) {
    return static_cast<uint8_t>(0);
  }
  // Waiting already: take its queue entry and keep the attempts it has used.
  uint8_t attempts = 0;
  std::string value;
  TRY_RESULT(queued, token_queue_has(queue_key));
  if (queued) {
    TRY_RESULT(status, db_->get(td::Slice{queue_key}, value));
    if (status == td::KeyValue::GetStatus::Ok) {
      auto parsed = parse_token_queue_entry(queue_key, value);
      if (parsed.is_ok() && parsed.ok().candidate == candidate) {
        attempts = parsed.ok().attempts;
      }
      TRY_STATUS(token_queue_erase(queue_key));
      if (token_batch_.entries > 0) {
        --token_batch_.entries;
      }
    }
  }
  TRY_STATUS(token_index_erase(index_key));
  return attempts;
}

td::Status WalletIndexDb::token_note_lost(const TokenCandidate& candidate, td::Slice reason) {
  if (token_batch_.lost < std::numeric_limits<uint64_t>::max()) {
    ++token_batch_.lost;
  }
  LOG(ERROR) << "wc0-index: token candidate " << candidate.address.to_hex() << " lost (" << reason
             << "); the token index is incomplete until rebuilt, lost=" << token_batch_.lost;
  return td::Status::OK();
}

td::Status WalletIndexDb::token_enqueue(const TokenCandidate& candidate, uint8_t attempts) {
  auto index_key = token_index_key(candidate);
  TRY_RESULT(queue_key, token_index_get(index_key));
  if (!queue_key.empty()) {
    bool added_in_batch = token_batch_.index_overlay.count(index_key) != 0;
    TRY_RESULT(queued, token_queue_has(queue_key));
    if (added_in_batch || queued) {
      // Already waiting; it keeps its place in the queue.
      return td::Status::OK();
    }
    // An index entry whose queue entry is gone would refuse this candidate
    // for good; replace it.
    TRY_STATUS(token_index_erase(index_key));
  }
  if (token_batch_.entries >= token_backlog_limit_) {
    return token_note_lost(candidate, "token backlog full");
  }
  if (token_batch_.next_seq == std::numeric_limits<uint64_t>::max()) {
    return td::Status::Error("wc0-index: token backlog sequence exhausted");
  }
  char key[kTokenQueueKeyLen];
  key[0] = static_cast<char>(kTokenQueueTag);
  key[1] = static_cast<char>(token_bucket(candidate.address));
  put_u64_be(key + 2, token_batch_.next_seq);
  char value[kTokenQueueValueLen];
  value[0] = static_cast<char>(candidate.kind);
  std::memcpy(value + 1, candidate.address.data(), 32);
  value[1 + 32] = static_cast<char>(attempts);
  TRY_STATUS(db_->set(td::Slice{key, kTokenQueueKeyLen}, td::Slice{value, kTokenQueueValueLen}));
  TRY_STATUS(db_->set(td::Slice{index_key}, td::Slice{key + 1, kTokenQueueKeyLen - 1}));
  token_batch_.index_overlay[index_key] = std::string(key, kTokenQueueKeyLen);
  ++token_batch_.next_seq;
  ++token_batch_.entries;
  return td::Status::OK();
}

td::Status WalletIndexDb::token_write_counters() {
  TRY_STATUS(put_meta_u64(kMetaTokenSeqSub, token_batch_.next_seq));
  TRY_STATUS(put_meta_u64(kMetaTokenEntriesSub, token_batch_.entries));
  TRY_STATUS(put_meta_u64(kMetaTokenUnverifiableSub, token_batch_.unverifiable));
  return put_meta_u64(kMetaTokenLostSub, token_batch_.lost);
}

td::Result<std::vector<ScheduledTokenCandidate>> WalletIndexDb::schedule_token_candidates(
    const std::vector<TokenCandidate>& block_candidates, tos::ShardIdFull shard, size_t capacity) {
  if (!batch_open_) {
    return td::Status::Error("wc0-index: token scheduling needs an open batch");
  }
  if (token_batch_.scheduled) {
    // The counters are loaded from committed state; a second pass would start
    // again from values the first one has already moved on from.
    return td::Status::Error("wc0-index: token candidates already scheduled in this batch");
  }
  if (capacity > kMaxTokenCandidatesPerBlock) {
    return td::Status::Error("wc0-index: token capacity exceeds the per-block bound");
  }
  TRY_RESULT(buckets, token_shard_buckets(shard));
  TRY_RESULT(next_seq, get_meta_u64(kMetaTokenSeqSub));
  TRY_RESULT(entries, get_meta_u64(kMetaTokenEntriesSub));
  TRY_RESULT(lost, get_meta_u64(kMetaTokenLostSub));
  TRY_RESULT(unverifiable, get_meta_u64(kMetaTokenUnverifiableSub));
  token_batch_.next_seq = next_seq;
  token_batch_.entries = entries;
  token_batch_.lost = lost;
  token_batch_.unverifiable = unverifiable;

  std::vector<QueueEntry> backlog;
  std::vector<size_t> backlog_bucket;
  std::set<std::string> collected;
  std::vector<std::string> malformed;
  const bool shares_queue = token_shard_shares_its_queue(shard);
  const size_t first_bucket = buckets.first;
  const size_t bucket_count = buckets.second - buckets.first + 1;
  auto bucket_cursor_key = token_shard_meta_key(kMetaTokenCursorSub, shard);
  auto position_key = token_shard_meta_key(kMetaTokenPositionSub, shard);
  std::string last_scanned;

  // Scan one key range of a queue, collecting this shard's entries until
  // `quota` are taken or `budget` keys are examined.
  auto scan_range = [&](size_t bucket, const std::string& begin, const std::string& end, size_t quota,
                        size_t& budget) -> td::Status {
    size_t taken = 0;
    bool stopped = false;
    auto status =
        db_->for_each_in_range(td::Slice{begin}, td::Slice{end}, [&](td::Slice key, td::Slice value) -> td::Status {
          if (taken >= quota || backlog.size() >= capacity || budget == 0) {
            stopped = true;
            return td::Status::Error("wc0-index: queue pass complete");
          }
          --budget;
          auto key_str = key.str();
          last_scanned = key_str;
          if (collected.count(key_str) != 0) {
            return td::Status::OK();
          }
          auto parsed = parse_token_queue_entry(key, value);
          if (parsed.is_error()) {
            collected.insert(key_str);
            malformed.push_back(std::move(key_str));
            return td::Status::OK();
          }
          auto scheduled = parsed.move_as_ok();
          if (!token_shard_contains(shard, scheduled.candidate.address)) {
            return td::Status::OK();
          }
          collected.insert(key_str);
          backlog.push_back(QueueEntry{std::move(key_str), scheduled});
          backlog_bucket.push_back(bucket);
          ++taken;
          return td::Status::OK();
        });
    if (!stopped) {
      return status;
    }
    return td::Status::OK();
  };

  if (capacity > 0 && token_batch_.entries > 0) {
    if (shares_queue) {
      // The queue is shared with sibling shards, whose entries this shard
      // must skip. Resume after the last key examined and wrap around, so a
      // run of a sibling's entries delays this shard but cannot hide its own.
      std::string position;
      TRY_RESULT(status, db_->get(td::Slice{position_key}, position));
      auto begin = token_queue_bucket_prefix(first_bucket);
      auto end = token_queue_bucket_end(first_bucket);
      if (status != td::KeyValue::GetStatus::Ok || position < begin || position >= end) {
        position = begin;
      }
      size_t budget = kTokenBacklogScanPerBucket;
      TRY_STATUS(scan_range(first_bucket, key_after(position), end, capacity, budget));
      TRY_STATUS(scan_range(first_bucket, begin, key_after(position), capacity, budget));
    } else {
      // Every entry of these queues is this shard's. Round robin over them
      // from the cursor: first an equal share from each, then whatever is
      // left from each in turn. Oldest first within a queue.
      size_t cursor = first_bucket;
      std::string value;
      TRY_RESULT(status, db_->get(td::Slice{bucket_cursor_key}, value));
      if (status == td::KeyValue::GetStatus::Ok && value.size() == 1) {
        size_t stored = static_cast<uint8_t>(value[0]);
        if (stored >= first_bucket && stored <= buckets.second) {
          cursor = stored;
        }
      }
      const size_t share = (capacity + bucket_count - 1) / bucket_count;
      for (size_t quota : {share, capacity}) {
        for (size_t i = 0; i < bucket_count && backlog.size() < capacity; ++i) {
          size_t bucket = first_bucket + (cursor - first_bucket + i) % bucket_count;
          size_t budget = kTokenBacklogScanPerBucket;
          TRY_STATUS(
              scan_range(bucket, token_queue_bucket_prefix(bucket), token_queue_bucket_end(bucket), quota, budget));
        }
      }
    }
  }

  // A malformed entry cannot be verified or put right; dropping it, and
  // saying so, keeps it from failing every later block of this shard. When
  // the entry still names its candidate, its index entry goes too, so the
  // candidate can wait again.
  for (auto& key : malformed) {
    std::string value;
    TRY_RESULT(status, db_->get(td::Slice{key}, value));
    TRY_STATUS(token_queue_erase(key));
    if (status == td::KeyValue::GetStatus::Ok) {
      auto identity = token_queue_identity(key, value);
      if (identity.is_ok()) {
        auto index_key = token_index_key(identity.ok());
        TRY_RESULT(indexed, token_index_get(index_key));
        if (indexed == key) {
          TRY_STATUS(token_index_erase(index_key));
        }
      }
    }
    if (token_batch_.entries > 0) {
      --token_batch_.entries;
    }
    if (token_batch_.lost < std::numeric_limits<uint64_t>::max()) {
      ++token_batch_.lost;
    }
    LOG(ERROR) << "wc0-index: dropped a malformed token backlog entry; the token index is incomplete until "
                  "rebuilt, lost="
               << token_batch_.lost;
  }

  // A block can nominate an account of another shard (the source of a
  // notification). Only that shard's state can verify it, so it waits in the
  // backlog for that shard's blocks.
  std::vector<TokenCandidate> own_candidates;
  std::vector<TokenCandidate> foreign_candidates;
  for (const auto& candidate : block_candidates) {
    (token_shard_contains(shard, candidate.address) ? own_candidates : foreign_candidates).push_back(candidate);
  }

  // Split the capacity: the backlog first gets up to its reserved share, the
  // block's own candidates take what is left, and capacity the block does not
  // use goes back to the backlog.
  size_t from_backlog = std::min(backlog.size(), std::min(kTokenBacklogDrainPerBlock, capacity));
  size_t from_block = std::min(own_candidates.size(), capacity - from_backlog);
  size_t spare = capacity - from_backlog - from_block;
  from_backlog += std::min(backlog.size() - from_backlog, spare);

  std::vector<ScheduledTokenCandidate> chosen;
  std::set<TokenCandidate> seen;
  for (size_t i = 0; i < from_backlog; ++i) {
    const auto& entry = backlog[i];
    TRY_STATUS(token_queue_erase(entry.key));
    TRY_STATUS(token_index_erase(token_index_key(entry.scheduled.candidate)));
    if (token_batch_.entries > 0) {
      --token_batch_.entries;
    }
    if (seen.insert(entry.scheduled.candidate).second) {
      chosen.push_back(entry.scheduled);
    }
  }
  if (shares_queue) {
    // Resume after the last entry served, or after everything examined.
    auto& next = from_backlog > 0 && from_backlog < backlog.size() ? backlog[from_backlog - 1].key : last_scanned;
    if (!next.empty()) {
      TRY_STATUS(db_->set(td::Slice{position_key}, td::Slice{next}));
    }
  } else if (from_backlog > 0) {
    // Resume after the last queue served, so every queue gets its turn.
    auto next = static_cast<char>(first_bucket + (backlog_bucket[from_backlog - 1] - first_bucket + 1) % bucket_count);
    TRY_STATUS(db_->set(td::Slice{bucket_cursor_key}, td::Slice{&next, 1}));
  }
  for (size_t i = 0; i < from_block; ++i) {
    if (seen.insert(own_candidates[i]).second) {
      TRY_RESULT(attempts, token_claim(own_candidates[i]));
      chosen.push_back(ScheduledTokenCandidate{own_candidates[i], attempts});
    }
  }
  for (size_t i = from_block; i < own_candidates.size(); ++i) {
    if (seen.count(own_candidates[i]) == 0) {
      TRY_STATUS(token_enqueue(own_candidates[i], 0));
    }
  }
  for (const auto& candidate : foreign_candidates) {
    TRY_STATUS(token_enqueue(candidate, 0));
  }
  TRY_STATUS(token_write_counters());
  token_batch_.scheduled = true;
  return chosen;
}

td::Status WalletIndexDb::retry_token_candidate(const ScheduledTokenCandidate& scheduled) {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: token retry needs a scheduled batch");
  }
  if (scheduled.attempts + 1 >= kMaxTokenCandidateAttempts) {
    TRY_STATUS(token_note_lost(scheduled.candidate, "verification stayed indeterminate"));
  } else {
    TRY_STATUS(token_enqueue(scheduled.candidate, static_cast<uint8_t>(scheduled.attempts + 1)));
  }
  return token_write_counters();
}

td::Status WalletIndexDb::process_token_candidates(
    const std::vector<ScheduledTokenCandidate>& scheduled,
    const std::function<TokenVerifyOutcome(const ScheduledTokenCandidate&, size_t remaining)>& verify) {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: token processing needs a scheduled batch");
  }
  size_t remaining = scheduled.size();
  for (const auto& candidate : scheduled) {
    // An exception is the node failing to finish, not a verdict on the
    // contract: retry it like an indeterminate result.
    auto outcome = TokenVerifyOutcome::Retry;
    try {
      outcome = verify(candidate, remaining);
    } catch (const std::exception& err) {
      LOG(WARNING) << "wc0-index: token candidate failed: " << err.what();
    } catch (...) {
      LOG(WARNING) << "wc0-index: token candidate failed with an unknown error";
    }
    --remaining;
    switch (outcome) {
      case TokenVerifyOutcome::Done:
        break;
      case TokenVerifyOutcome::Retry:
        TRY_STATUS(retry_token_candidate(candidate));
        break;
      case TokenVerifyOutcome::Unverifiable:
        if (token_batch_.unverifiable < std::numeric_limits<uint64_t>::max()) {
          ++token_batch_.unverifiable;
        }
        LOG(WARNING) << "wc0-index: token candidate " << candidate.candidate.address.to_hex()
                     << " depends on another shard's state and cannot be indexed here";
        TRY_STATUS(token_write_counters());
        break;
      case TokenVerifyOutcome::WriteFailed:
        return td::Status::Error("wc0-index: an index write failed while verifying token candidates");
    }
  }
  return td::Status::OK();
}

td::Result<TokenBacklogStats> WalletIndexDb::token_backlog_stats() {
  TRY_RESULT(entries, get_meta_u64(kMetaTokenEntriesSub));
  TRY_RESULT(lost, get_meta_u64(kMetaTokenLostSub));
  TRY_RESULT(unverifiable, get_meta_u64(kMetaTokenUnverifiableSub));
  bool unfinished_block = false;
  const char begin[1] = {static_cast<char>(kIncompleteBlockTag)};
  const char end[1] = {static_cast<char>(kIncompleteBlockTag + 1)};
  auto status = db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1}, [&](td::Slice, td::Slice) {
    unfinished_block = true;
    return td::Status::Error("wc0-index: one mark is enough");
  });
  if (!unfinished_block) {
    TRY_STATUS(std::move(status));
  }
  return TokenBacklogStats{entries, lost, unverifiable, unfinished_block};
}

td::Status WalletIndexDb::for_each_deferred_token_candidate(size_t limit,
                                                            std::function<td::Status(const TokenCandidate&)> cb) {
  const char begin[1] = {static_cast<char>(kTokenQueueTag)};
  const char end[1] = {static_cast<char>(kTokenQueueTag + 1)};
  size_t seen = 0;
  bool limit_reached = false;
  auto status =
      db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1}, [&](td::Slice key, td::Slice value) -> td::Status {
        if (seen >= limit) {
          limit_reached = true;
          return td::Status::Error("wc0-index: limit reached");
        }
        ++seen;
        TRY_RESULT(scheduled, parse_token_queue_entry(key, value));
        return cb(scheduled.candidate);
      });
  return limit_reached ? td::Status::OK() : std::move(status);
}

// --- per-block batched writes ---

td::Status WalletIndexDb::begin_batch() {
  if (batch_open_) {
    return td::Status::Error("wc0-index: batch already open");
  }
  auto s = db_->begin_write_batch();
  if (s.is_error()) return s;
  batch_open_ = true;
  token_batch_ = TokenBatchState{};
  return td::Status::OK();
}

td::Status WalletIndexDb::commit_batch() {
  if (!batch_open_) {
    return td::Status::Error("wc0-index: no batch open");
  }
  batch_open_ = false;
  token_batch_ = TokenBatchState{};
  // commit_write_batch() issues the write with WriteOptions.sync=true, which
  // (combined with manual_wal_flush=true) already syncs the WAL for this
  // write — an additional flush() here would be a redundant, much more
  // expensive full memtable flush.
  return db_->commit_write_batch();
}

void WalletIndexDb::abort_batch() {
  if (!batch_open_) {
    return;
  }
  batch_open_ = false;
  token_batch_ = TokenBatchState{};
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
