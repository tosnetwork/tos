/*
    TOS wc=0 in-process wallet index — implementation.
    See wallet-index.h and https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md.
*/
#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>

#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/optional.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"
#include "vm/cellslice.h"

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
constexpr uint8_t kJettonWalletTag = 0x17;  // 0x17 + wallet(32) -> present(1) + owner(32) + master(32) + lt_be(8)
constexpr uint8_t kJettonPairTag = 0x18;    // 0x18 + owner(32) + master(32) -> present(1) + wallet(32) + lt_be(8)
constexpr uint8_t kPendingBlockTag = 0x19;  // 0x19 + block id (as 0x1E) -> remaining candidates
constexpr uint8_t kTokenParkedTag = 0x1A;   // 0x1A + kind(1) + address(32) -> lt_be(8)
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
// 0x00 0x09 -> 1 once a block may have gone unindexed without a mark.
constexpr uint8_t kMetaNeedsRebuildSub = 0x09;
// 0x00 0x0A -> 1 while an indexing run is active (see begin_indexing_run).
constexpr uint8_t kMetaRunActiveSub = 0x0A;
// 0x00 0x0B -> parked token candidates (u64_be; absent means 0).
constexpr uint8_t kMetaTokenParkedSub = 0x0B;
// 0x00 0x0F -> pending blocks (u64_be); 0x00 0x10 -> the last parked key a
// retry pass took.
constexpr uint8_t kMetaPendingBlocksSub = 0x0F;
constexpr uint8_t kMetaParkedCursorSub = 0x10;

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
constexpr size_t kIncompleteBlockValueLen = 1 + 4;  // sentinel(1) + mc_seqno_be(4)
constexpr size_t kTokenQueueKeyLen = 1 + 1 + 8;
constexpr size_t kTokenQueueValueLen = 1 + 32 + 1 + 8;
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

void make_block_key(uint8_t tag, const tos::BlockIdExt& block_id, char out[kIncompleteBlockKeyLen]) {
  out[0] = static_cast<char>(tag);
  put_u32_be(out + 1, static_cast<uint32_t>(block_id.id.workchain));
  put_u64_be(out + 1 + 4, block_id.id.shard);
  put_u32_be(out + 1 + 4 + 8, block_id.id.seqno);
  std::memcpy(out + 1 + 4 + 8 + 4, block_id.root_hash.as_slice().data(), 32);
  std::memcpy(out + 1 + 4 + 8 + 4 + 32, block_id.file_hash.as_slice().data(), 32);
}

void make_incomplete_block_key(const tos::BlockIdExt& block_id, char out[kIncompleteBlockKeyLen]) {
  make_block_key(kIncompleteBlockTag, block_id, out);
}

tos::BlockIdExt parse_block_key(td::Slice key) {
  tos::WorkchainId workchain = static_cast<tos::WorkchainId>(get_u32_be(key.data() + 1));
  tos::ShardId shard = get_u64_be(key.data() + 1 + 4);
  tos::BlockSeqno seqno = get_u32_be(key.data() + 1 + 4 + 8);
  tos::RootHash root_hash;
  tos::FileHash file_hash;
  root_hash.as_slice().copy_from(td::Slice{key.data() + 1 + 4 + 8 + 4, 32});
  file_hash.as_slice().copy_from(td::Slice{key.data() + 1 + 4 + 8 + 4 + 32, 32});
  return tos::BlockIdExt{workchain, shard, seqno, root_hash, file_hash};
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

// --- jetton wallet records ---

namespace {

constexpr size_t kJettonWalletRecordLen = 1 + 32 + 32 + 8;

struct JettonWalletRecord {
  bool present = false;
  HashKey owner;
  HashKey master;
  uint64_t lt = 0;
};

std::string encode_jetton_wallet_record(const JettonWalletRecord& record) {
  char value[kJettonWalletRecordLen];
  value[0] = record.present ? 1 : 0;
  std::memcpy(value + 1, record.owner.data(), 32);
  std::memcpy(value + 1 + 32, record.master.data(), 32);
  put_u64_be(value + 1 + 32 + 32, record.lt);
  return std::string(value, kJettonWalletRecordLen);
}

td::Result<JettonWalletRecord> decode_jetton_wallet_record(const std::string& value) {
  if (value.size() != kJettonWalletRecordLen) {
    return td::Status::Error("wc0-index: malformed jetton wallet record");
  }
  JettonWalletRecord record;
  record.present = value[0] != 0;
  record.owner.as_slice().copy_from(td::Slice{value.data() + 1, 32});
  record.master.as_slice().copy_from(td::Slice{value.data() + 1 + 32, 32});
  record.lt = get_u64_be(value.data() + 1 + 32 + 32);
  return record;
}

constexpr size_t kJettonPairRecordLen = 1 + 32 + 8;

struct JettonPairRecord {
  bool present = false;
  HashKey wallet;
  uint64_t lt = 0;
};

constexpr uint8_t kPairPresentFlag = 1;

std::string encode_jetton_pair_record(const JettonPairRecord& record) {
  char value[kJettonPairRecordLen];
  value[0] = static_cast<char>(record.present ? kPairPresentFlag : 0);
  std::memcpy(value + 1, record.wallet.data(), 32);
  put_u64_be(value + 1 + 32, record.lt);
  return std::string(value, kJettonPairRecordLen);
}

td::Result<JettonPairRecord> decode_jetton_pair_record(const std::string& value) {
  if (value.size() != kJettonPairRecordLen) {
    return td::Status::Error("wc0-index: malformed jetton pair record");
  }
  JettonPairRecord record;
  auto flags = static_cast<uint8_t>(value[0]);
  record.present = (flags & kPairPresentFlag) != 0;
  record.wallet.as_slice().copy_from(td::Slice{value.data() + 1, 32});
  record.lt = get_u64_be(value.data() + 1 + 32);
  return record;
}

std::string jetton_wallet_key(const HashKey& wallet) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kJettonWalletTag, wallet, key);
  return std::string(key, kSingleHashKeyLen);
}

std::string jetton_pair_key(uint8_t tag, const HashKey& owner, const HashKey& master) {
  char key[kOwnerPairKeyLen];
  make_owner_pair_key(tag, owner, master, key);
  return std::string(key, kOwnerPairKeyLen);
}

}  // namespace

td::Result<bool> WalletIndexDb::get_jetton_record(td::Slice key, std::string& value) {
  auto it = token_batch_.jetton_records.find(key.str());
  if (batch_open_ && it != token_batch_.jetton_records.end()) {
    value = it->second;
    return true;
  }
  TRY_RESULT(status, db_->get(key, value));
  return status != td::KeyValue::GetStatus::NotFound;
}

td::Status WalletIndexDb::put_jetton_record(td::Slice key, td::Slice value) {
  TRY_STATUS(db_->set(key, value));
  if (batch_open_) {
    token_batch_.jetton_records[key.str()] = value.str();
  }
  return td::Status::OK();
}

td::Result<WalletIndexDb::JettonPairDecision> WalletIndexDb::jetton_pair_decision(const HashKey& owner,
                                                                                  const HashKey& master) {
  JettonPairDecision decision;
  std::string record;
  TRY_RESULT(has_record, get_jetton_record(jetton_pair_key(kJettonPairTag, owner, master), record));
  if (has_record) {
    TRY_RESULT(decoded, decode_jetton_pair_record(record));
    decision.known = true;
    decision.has_record = true;
    decision.present = decoded.present;
    decision.wallet = decoded.wallet;
    decision.lt = decoded.lt;
    return decision;
  }
  std::string entry;
  auto entry_key = jetton_pair_key(kJettonTag, owner, master);
  TRY_RESULT(entry_status, db_->get(entry_key, entry));
  if (entry_status == td::KeyValue::GetStatus::NotFound) {
    return decision;
  }
  decision.known = true;
  decision.present = true;
  auto cell_r = vm::std_boc_deserialize(td::Slice{entry});
  if (cell_r.is_ok()) {
    vm::CellSlice cs = vm::load_cell_slice(cell_r.move_as_ok());
    HashKey wallet;
    unsigned long long lt = 0;
    if (cs.fetch_bits_to(wallet.bits(), 256) && cs.fetch_ulong_bool(64, lt)) {
      decision.wallet = wallet;
      decision.lt = lt;
    }
  }
  // An unreadable entry names no wallet and is older than any verdict.
  return decision;
}

td::Status WalletIndexDb::claim_jetton_pair(const HashKey& owner, const HashKey& master, const HashKey& wallet,
                                            td::Ref<vm::Cell> value, uint64_t end_lt) {
  TRY_RESULT(decision, jetton_pair_decision(owner, master));
  if (decision.known && decision.lt > end_lt) {
    // A later block already decided this pair.
    return td::Status::OK();
  }
  TRY_STATUS(put_jetton(owner, master, std::move(value)));
  return put_jetton_record(jetton_pair_key(kJettonPairTag, owner, master),
                           encode_jetton_pair_record(JettonPairRecord{true, wallet, end_lt}));
}

td::Status WalletIndexDb::release_jetton_pair(const HashKey& owner, const HashKey& master, const HashKey& wallet,
                                              uint64_t end_lt) {
  TRY_RESULT(decision, jetton_pair_decision(owner, master));
  if (decision.known && decision.lt > end_lt) {
    // A later block already decided this pair.
    return td::Status::OK();
  }
  if (decision.known && decision.present && decision.wallet != wallet && !decision.wallet.is_zero()) {
    // The pair names another wallet; this wallet's release does not concern it.
    return td::Status::OK();
  }
  TRY_STATUS(erase_jetton(owner, master));
  // The removal is itself a decision: an older verdict must not restore it.
  return put_jetton_record(jetton_pair_key(kJettonPairTag, owner, master),
                           encode_jetton_pair_record(JettonPairRecord{false, wallet, end_lt}));
}

td::Status WalletIndexDb::apply_jetton_verdict(const HashKey& wallet, const JettonVerdict& verdict, uint64_t end_lt) {
  auto wallet_key = jetton_wallet_key(wallet);
  std::string stored;
  TRY_RESULT(found, get_jetton_record(wallet_key, stored));
  td::optional<JettonWalletRecord> record;
  if (found) {
    TRY_RESULT(decoded, decode_jetton_wallet_record(stored));
    record = decoded;
  }
  if (record && record.value().lt > end_lt) {
    // A later block already decided this wallet.
    return td::Status::OK();
  }
  if (record && record.value().present &&
      (!verdict.present || record.value().owner != verdict.owner || record.value().master != verdict.master)) {
    TRY_STATUS(release_jetton_pair(record.value().owner, record.value().master, wallet, end_lt));
  }
  JettonWalletRecord next;
  next.present = verdict.present;
  next.lt = end_lt;
  if (verdict.present) {
    next.owner = verdict.owner;
    next.master = verdict.master;
    TRY_STATUS(claim_jetton_pair(verdict.owner, verdict.master, wallet, verdict.value, end_lt));
  } else {
    // Kept even when nothing was recorded before: an older block indexed later
    // (recovered at a later start, or fetched late) must find this.
    next.owner = HashKey::zero();
    next.master = HashKey::zero();
  }
  return put_jetton_record(wallet_key, encode_jetton_wallet_record(next));
}

td::Result<bool> WalletIndexDb::get_jetton_wallet(const HashKey& wallet, HashKey& owner, HashKey& master) {
  std::string stored;
  TRY_RESULT(found, get_jetton_record(jetton_wallet_key(wallet), stored));
  if (!found) {
    return false;
  }
  TRY_RESULT(record, decode_jetton_wallet_record(stored));
  if (!record.present) {
    return false;
  }
  owner = record.owner;
  master = record.master;
  return true;
}

td::Result<td::optional<WalletIndexDb::JettonWalletState>> WalletIndexDb::jetton_wallet_state(const HashKey& wallet) {
  std::string stored;
  TRY_RESULT(found, get_jetton_record(jetton_wallet_key(wallet), stored));
  if (!found) {
    return td::optional<JettonWalletState>{};
  }
  TRY_RESULT(record, decode_jetton_wallet_record(stored));
  return td::optional<JettonWalletState>(JettonWalletState{record.present, record.owner, record.master, record.lt});
}

td::Status WalletIndexDb::for_each_current_jetton(const HashKey& owner, size_t limit,
                                                  std::function<td::Status(const HashKey&, td::Ref<vm::Cell>)> cb) {
  return for_each_jetton(owner, limit, [&](const HashKey& master, td::Ref<vm::Cell> value) -> td::Status {
    std::string stored;
    TRY_RESULT(status, db_->get(td::Slice{jetton_pair_key(kJettonPairTag, owner, master)}, stored));
    if (status != td::KeyValue::GetStatus::Ok) {
      // A row without the pair record that decided it is not a verified
      // fact: never served as current.
      return td::Status::OK();
    }
    auto record = decode_jetton_pair_record(stored);
    if (record.is_error() || !record.ok().present) {
      return td::Status::OK();
    }
    return cb(master, std::move(value));
  });
}

TokenVerifyOutcome record_jetton_wallet_check(WalletIndexDb& db, const HashKey& wallet, JettonWalletCheck check,
                                              const HashKey& owner, const HashKey& master, td::Ref<vm::Cell> value,
                                              uint64_t end_lt) {
  WalletIndexDb::JettonVerdict verdict{false, HashKey::zero(), HashKey::zero(), {}};
  switch (check) {
    case JettonWalletCheck::Indeterminate:
      // Not a verdict: a check that could not complete says nothing about
      // whether the wallet is still there.
      return TokenVerifyOutcome::Retry;
    case JettonWalletCheck::OtherShard:
      return TokenVerifyOutcome::Unverifiable;
    case JettonWalletCheck::Rejected:
      break;
    case JettonWalletCheck::Verified:
      verdict = {true, owner, master, std::move(value)};
      break;
  }
  auto status = db.apply_jetton_verdict(wallet, verdict, end_lt);
  if (status.is_error()) {
    LOG(WARNING) << "wc0-index: recording jetton wallet failed: " << status.message();
    return TokenVerifyOutcome::WriteFailed;
  }
  return TokenVerifyOutcome::Done;
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
  // Any other version, or none, is reset: the index is dropped whole and
  // starts again, fresh and forward-only, from the blocks applied from now
  // on. Nothing written under another layout is imported or served; the
  // index is derived data outside consensus, and keeps no history it did not
  // index itself. Atomic and WAL-synced, before the index is used.
  LOG(WARNING) << "wc0-index: on-disk schema version " << version << " is not " << kWalletIndexSchemaVersion
               << "; resetting the index (it restarts empty and forward-only from new blocks)";
  TRY_STATUS(db_->begin_write_batch());
  auto migrate = [&]() -> td::Status {
    const char begin[1] = {static_cast<char>(0x00)};
    const char end[1] = {static_cast<char>(0xff)};
    TRY_STATUS(db_->erase_range(td::Slice{begin, 1}, td::Slice{end, 1}));
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

namespace {

constexpr size_t kNftRecordLen = 1 + 32 + 8;

struct NftRecord {
  bool owned = false;
  HashKey owner;
  uint64_t lt = 0;
};

}  // namespace

static td::Status put_nft_record(td::RocksDb& db, const HashKey& nft, bool owned, const HashKey& owner, uint64_t lt) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  char value[kNftRecordLen];
  value[0] = owned ? 1 : 0;
  std::memcpy(value + 1, owner.data(), 32);
  put_u64_be(value + 1 + 32, lt);
  return db.set(td::Slice{key, kSingleHashKeyLen}, td::Slice{value, kNftRecordLen});
}

static td::Result<td::optional<NftRecord>> get_nft_record(td::RocksDb& db, const HashKey& nft) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  std::string value;
  TRY_RESULT(status, db.get(td::Slice{key, kSingleHashKeyLen}, value));
  if (status == td::KeyValue::GetStatus::NotFound) {
    return td::optional<NftRecord>{};
  }
  NftRecord record;
  if (value.size() == 32) {
    record.owned = true;
    record.owner.as_slice().copy_from(td::Slice{value});
    return td::optional<NftRecord>(record);
  }
  if (value.size() != kNftRecordLen) {
    return td::Status::Error("wc0-index: malformed NFT ownership record");
  }
  record.owned = value[0] != 0;
  record.owner.as_slice().copy_from(td::Slice{value.data() + 1, 32});
  record.lt = get_u64_be(value.data() + 1 + 32);
  return td::optional<NftRecord>(record);
}

td::Status WalletIndexDb::put_nft_owner(const HashKey& nft, const HashKey& owner) {
  return put_nft_record(*db_, nft, true, owner, 0);
}

td::Status WalletIndexDb::apply_nft_verdict(const HashKey& item, const NftVerdict& verdict, uint64_t end_lt) {
  TRY_RESULT(record, get_nft_record(*db_, item));
  if (record && record.value().lt > end_lt) {
    // A later block already decided this item.
    return td::Status::OK();
  }
  bool had_owner = record && record.value().owned;
  if (!verdict.owned) {
    if (had_owner) {
      TRY_STATUS(erase_nft(record.value().owner, item));
    }
    // Kept even when nothing was recorded before: an older block indexed
    // later (recovered at a later start, or fetched late) must find this.
    return put_nft_record(*db_, item, false, HashKey::zero(), end_lt);
  }
  if (had_owner && record.value().owner != verdict.owner) {
    TRY_STATUS(erase_nft(record.value().owner, item));
  }
  TRY_STATUS(put_nft(verdict.owner, item, verdict.value));
  return put_nft_record(*db_, item, true, verdict.owner, end_lt);
}

td::Status WalletIndexDb::erase_nft_owner(const HashKey& nft) {
  char key[kSingleHashKeyLen];
  make_owner_prefix(kNftOwnerTag, nft, key);
  return db_->erase(td::Slice{key, kSingleHashKeyLen});
}

td::Result<bool> WalletIndexDb::get_nft_owner(const HashKey& nft, HashKey& owner) {
  TRY_RESULT(record, get_nft_record(*db_, nft));
  if (!record || !record.value().owned) {
    return false;
  }
  owner = record.value().owner;
  return true;
}

// --- crash-recovery markers ---

td::Status WalletIndexDb::put_incomplete_block(const tos::BlockIdExt& block_id, uint32_t mc_seqno) {
  char key[kIncompleteBlockKeyLen];
  make_incomplete_block_key(block_id, key);
  char val[kIncompleteBlockValueLen] = {0};
  put_u32_be(val + 1, mc_seqno);
  auto s = db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{val, kIncompleteBlockValueLen});
  if (s.is_error()) return s;
  // The marker must be durable before the block's entries: a marker that survives
  // a crash flags a block whose indexing never committed. A WAL sync is enough
  // for that (manual_wal_flush=true means writes aren't synced by default) —
  // no need for a full memtable flush.
  return db_->flush_wal(true);
}

td::Status WalletIndexDb::mark_blocks_incomplete(const std::vector<MarkedBlock>& blocks) {
  if (blocks.empty()) {
    return td::Status::OK();
  }
  for (const auto& block : blocks) {
    char key[kIncompleteBlockKeyLen];
    make_incomplete_block_key(block.id, key);
    char val[kIncompleteBlockValueLen] = {0};
    put_u32_be(val + 1, block.mc_seqno);
    TRY_STATUS(marker_db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{val, kIncompleteBlockValueLen}));
  }
  return marker_db_->flush_wal(true);
}

td::Status WalletIndexDb::mark_blocks_incomplete(const std::vector<tos::BlockIdExt>& block_ids) {
  std::vector<MarkedBlock> blocks;
  for (const auto& id : block_ids) {
    blocks.push_back(MarkedBlock{id, 0});
  }
  return mark_blocks_incomplete(blocks);
}

td::Status WalletIndexDb::for_each_marked_block(std::function<td::Status(const MarkedBlock&)> cb) {
  char begin[1] = {static_cast<char>(kIncompleteBlockTag)};
  char end[1] = {static_cast<char>(kIncompleteBlockTag + 1)};
  return db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1}, [&](td::Slice key, td::Slice value) {
    if (key.size() != kIncompleteBlockKeyLen) {
      return td::Status::OK();
    }
    // A malformed value names no package: keep everything for it.
    uint32_t mc_seqno = value.size() == kIncompleteBlockValueLen ? get_u32_be(value.data() + 1) : 0;
    return cb(MarkedBlock{parse_block_key(key), mc_seqno});
  });
}

td::Result<td::optional<uint32_t>> WalletIndexDb::unextracted_block_floor() {
  td::optional<uint32_t> floor;
  TRY_STATUS(for_each_marked_block([&](const MarkedBlock& block) -> td::Status {
    char pending_key[kIncompleteBlockKeyLen];
    make_block_key(kPendingBlockTag, block.id, pending_key);
    std::string value;
    TRY_RESULT(status, db_->get(td::Slice{pending_key, kIncompleteBlockKeyLen}, value));
    if (status == td::KeyValue::GetStatus::Ok) {
      return td::Status::OK();  // its candidates are persisted
    }
    if (!floor || block.mc_seqno < floor.value()) {
      floor = block.mc_seqno;
    }
    return td::Status::OK();
  }));
  return floor;
}

td::Status WalletIndexDb::mark_needs_rebuild() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaNeedsRebuildSub, key);
  const char one[1] = {1};
  TRY_STATUS(marker_db_->set(td::Slice{key, kMetaKeyLen}, td::Slice{one, 1}));
  return marker_db_->flush_wal(true);
}

td::Status WalletIndexDb::begin_indexing_run() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaRunActiveSub, key);
  const char one[1] = {1};
  TRY_STATUS(marker_db_->set(td::Slice{key, kMetaKeyLen}, td::Slice{one, 1}));
  return marker_db_->flush_wal(true);
}

td::Result<bool> WalletIndexDb::indexing_run_active() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaRunActiveSub, key);
  std::string value;
  TRY_RESULT(status, marker_db_->get(td::Slice{key, kMetaKeyLen}, value));
  return status == td::KeyValue::GetStatus::Ok;
}

td::Status WalletIndexDb::end_indexing_run() {
  char key[kMetaKeyLen];
  make_meta_key(kMetaRunActiveSub, key);
  TRY_STATUS(marker_db_->erase(td::Slice{key, kMetaKeyLen}));
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
    return cb(parse_block_key(key));
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
  uint64_t lt = get_u64_be(value.data() + 1 + 32 + 1);
  return ScheduledTokenCandidate{candidate, attempts, lt};
}

std::string encode_token_queue_value(const TokenCandidate& candidate, uint8_t attempts, uint64_t lt) {
  std::string value(kTokenQueueValueLen, '\0');
  value[0] = static_cast<char>(candidate.kind);
  std::memcpy(&value[1], candidate.address.data(), 32);
  value[1 + 32] = static_cast<char>(attempts);
  put_u64_be(&value[1 + 32 + 1], lt);
  return value;
}

std::string token_parked_key(const TokenCandidate& candidate) {
  std::string key(kTokenIndexKeyLen, '\0');
  key[0] = static_cast<char>(kTokenParkedTag);
  key[1] = static_cast<char>(candidate.kind);
  std::memcpy(&key[2], candidate.address.data(), 32);
  return key;
}

uint64_t saturating_add(uint64_t a, uint64_t b) {
  return a > std::numeric_limits<uint64_t>::max() - b ? std::numeric_limits<uint64_t>::max() : a + b;
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

td::Result<std::string> WalletIndexDb::token_queue_value(const std::string& queue_key) {
  auto written = token_batch_.queue_written.find(queue_key);
  if (written != token_batch_.queue_written.end()) {
    return written->second;
  }
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{queue_key}, value));
  if (status != td::KeyValue::GetStatus::Ok) {
    return std::string();
  }
  return value;
}

td::Result<td::optional<uint64_t>> WalletIndexDb::token_parked_lt(const std::string& parked_key) {
  std::string value;
  auto it = token_batch_.parked_overlay.find(parked_key);
  if (it != token_batch_.parked_overlay.end()) {
    value = it->second;
  } else {
    TRY_RESULT(status, db_->get(td::Slice{parked_key}, value));
    if (status != td::KeyValue::GetStatus::Ok) {
      return td::optional<uint64_t>{};
    }
  }
  if (value.empty()) {
    return td::optional<uint64_t>{};
  }
  // A malformed record still names its candidate in its key: keep it parked.
  return td::optional<uint64_t>(value.size() == 8 ? get_u64_be(value.data()) : 0);
}

void WalletIndexDb::token_release_reservation() {
  if (token_batch_.reserved > 0) {
    --token_batch_.reserved;
  }
}

td::Result<uint8_t> WalletIndexDb::token_claim(const TokenCandidate& candidate, uint64_t end_lt) {
  auto index_key = token_index_key(candidate);
  TRY_RESULT(queue_key, token_index_get(index_key));
  uint8_t attempts = 0;
  if (!queue_key.empty()) {
    TRY_RESULT(queued, token_queue_has(queue_key));
    bool claimed = !queued;
    if (queued) {
      TRY_RESULT(value, token_queue_value(queue_key));
      auto parsed = parse_token_queue_entry(queue_key, value);
      if (parsed.is_ok() && parsed.ok().candidate == candidate && parsed.ok().lt > end_lt) {
        // A newer block nominated it: its entry waits for a state at least
        // that new, whatever this older block finds.
        return static_cast<uint8_t>(0);
      }
      // Waiting already: take its queue entry and keep the attempts it has used.
      if (parsed.is_ok() && parsed.ok().candidate == candidate) {
        attempts = parsed.ok().attempts;
      }
      TRY_STATUS(token_queue_erase(queue_key));
      if (token_batch_.entries > 0) {
        --token_batch_.entries;
      }
      claimed = true;
    }
    if (claimed) {
      TRY_STATUS(token_index_erase(index_key));
    }
  }
  // A parked candidate nominated again is verified afresh.
  auto parked_key = token_parked_key(candidate);
  TRY_RESULT(parked_lt, token_parked_lt(parked_key));
  if (parked_lt && parked_lt.value() <= end_lt) {
    TRY_STATUS(db_->erase(td::Slice{parked_key}));
    token_batch_.parked_overlay[parked_key] = std::string();
    if (token_batch_.parked > 0) {
      --token_batch_.parked;
    }
  }
  return attempts;
}

td::Result<bool> WalletIndexDb::token_enqueue(const TokenCandidate& candidate, uint8_t attempts, uint64_t lt,
                                              bool reserved) {
  auto index_key = token_index_key(candidate);
  TRY_RESULT(queue_key, token_index_get(index_key));
  if (!queue_key.empty()) {
    bool added_in_batch = token_batch_.index_overlay.count(index_key) != 0;
    TRY_RESULT(queued, token_queue_has(queue_key));
    if (added_in_batch || queued) {
      // Already waiting; it keeps its place in the queue, and is verified no
      // earlier than the newest block that nominated it.
      TRY_RESULT(value, token_queue_value(queue_key));
      auto parsed = parse_token_queue_entry(queue_key, value);
      if (parsed.is_ok() && parsed.ok().candidate == candidate && parsed.ok().lt < lt) {
        auto updated = encode_token_queue_value(candidate, parsed.ok().attempts, lt);
        TRY_STATUS(db_->set(td::Slice{queue_key}, td::Slice{updated}));
        token_batch_.queue_written[queue_key] = updated;
      }
      if (reserved) {
        token_release_reservation();
      }
      return true;
    }
    // An index entry whose queue entry is gone would refuse this candidate
    // for good; replace it.
    TRY_STATUS(token_index_erase(index_key));
  }
  auto parked_key = token_parked_key(candidate);
  TRY_RESULT(parked_lt, token_parked_lt(parked_key));
  auto held = saturating_add(token_batch_.entries, token_batch_.reserved);
  if (parked_lt && !reserved && held >= token_backlog_limit_) {
    // Nominated again while parked, with no queue room: it stays parked,
    // where the worker's retries reach it, now due no earlier than this
    // nomination.
    if (lt > parked_lt.value()) {
      char value[8];
      put_u64_be(value, lt);
      TRY_STATUS(db_->set(td::Slice{parked_key}, td::Slice{value, sizeof(value)}));
      token_batch_.parked_overlay[parked_key] = std::string(value, sizeof(value));
    }
    return true;
  }
  if (parked_lt) {
    // Nominated again while parked: it waits again with fresh attempts, in
    // queue room that is free or that its verification kept.
    TRY_STATUS(db_->erase(td::Slice{parked_key}));
    token_batch_.parked_overlay[parked_key] = std::string();
    if (token_batch_.parked > 0) {
      --token_batch_.parked;
    }
    attempts = 0;
    lt = std::max(lt, parked_lt.value());
    if (reserved) {
      token_release_reservation();
    }
  } else if (reserved) {
    token_release_reservation();
  } else if (held >= token_backlog_limit_) {
    return false;
  }
  if (token_batch_.next_seq == std::numeric_limits<uint64_t>::max()) {
    return td::Status::Error("wc0-index: token backlog sequence exhausted");
  }
  char key[kTokenQueueKeyLen];
  key[0] = static_cast<char>(kTokenQueueTag);
  key[1] = static_cast<char>(token_bucket(candidate.address));
  put_u64_be(key + 2, token_batch_.next_seq);
  auto value = encode_token_queue_value(candidate, attempts, lt);
  std::string queue_entry(key, kTokenQueueKeyLen);
  TRY_STATUS(db_->set(td::Slice{queue_entry}, td::Slice{value}));
  TRY_STATUS(db_->set(td::Slice{index_key}, td::Slice{key + 1, kTokenQueueKeyLen - 1}));
  token_batch_.index_overlay[index_key] = queue_entry;
  token_batch_.queue_written[queue_entry] = value;
  ++token_batch_.next_seq;
  token_batch_.entries = saturating_add(token_batch_.entries, 1);
  return true;
}

td::Status WalletIndexDb::token_park(const ScheduledTokenCandidate& scheduled) {
  auto parked_key = token_parked_key(scheduled.candidate);
  TRY_RESULT(parked_lt, token_parked_lt(parked_key));
  uint64_t lt = scheduled.lt;
  if (parked_lt) {
    lt = std::max(lt, parked_lt.value());
  } else if (token_batch_.parked >= parked_limit_) {
    // No parking room: it waits again with one attempt left, where it came
    // from. A backlog entry goes back into the queue slot it kept; a block's
    // own candidate stays with its block.
    ScheduledTokenCandidate again{scheduled.candidate, static_cast<uint8_t>(kMaxTokenCandidateAttempts - 1),
                                  scheduled.lt, false};
    if (!scheduled.holds_reservation) {
      token_batch_.overflow.push_back(again);
      return td::Status::OK();
    }
    TRY_RESULT(queued, token_enqueue(scheduled.candidate, again.attempts, scheduled.lt, true));
    if (!queued) {
      return td::Status::Error("wc0-index: a candidate found no room it had kept");
    }
    return td::Status::OK();
  } else {
    token_batch_.parked = saturating_add(token_batch_.parked, 1);
  }
  if (scheduled.holds_reservation) {
    token_release_reservation();
  }
  char value[8];
  put_u64_be(value, lt);
  TRY_STATUS(db_->set(td::Slice{parked_key}, td::Slice{value, sizeof(value)}));
  token_batch_.parked_overlay[parked_key] = std::string(value, sizeof(value));
  LOG(WARNING) << "wc0-index: token candidate " << scheduled.candidate.address.to_hex() << " parked after "
               << static_cast<int>(kMaxTokenCandidateAttempts)
               << " indeterminate verifications; the token index stays incomplete until it is verified";
  return td::Status::OK();
}

td::Status WalletIndexDb::token_write_counters() {
  TRY_STATUS(put_meta_u64(kMetaTokenSeqSub, token_batch_.next_seq));
  TRY_STATUS(put_meta_u64(kMetaTokenEntriesSub, token_batch_.entries));
  TRY_STATUS(put_meta_u64(kMetaTokenUnverifiableSub, token_batch_.unverifiable));
  TRY_STATUS(put_meta_u64(kMetaTokenParkedSub, token_batch_.parked));
  return put_meta_u64(kMetaTokenLostSub, token_batch_.lost);
}

td::Result<std::vector<ScheduledTokenCandidate>> WalletIndexDb::schedule_token_candidates(
    const std::vector<TokenCandidate>& block_candidates, tos::ShardIdFull shard, size_t capacity, uint64_t end_lt) {
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
  TRY_STATUS(token_load_counters());

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
          if (scheduled.lt > end_lt) {
            // Nominated by a newer block than this state: a newer state
            // verifies it.
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

  // The block's candidates, once each, in candidate order: a pass that stops
  // early resumes from the first one it did not handle.
  std::set<TokenCandidate> ordered(block_candidates.begin(), block_candidates.end());
  size_t own_count = 0;
  for (const auto& candidate : ordered) {
    if (token_shard_contains(shard, candidate.address)) {
      ++own_count;
    }
  }

  // Split the capacity: the backlog first gets up to its reserved share, the
  // block's own candidates take what is left, and capacity the block does not
  // use goes back to the backlog.
  size_t from_backlog = std::min(backlog.size(), std::min(kTokenBacklogDrainPerBlock, capacity));
  size_t from_block = std::min(own_count, capacity - from_backlog);
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
      auto taken = entry.scheduled;
      taken.holds_reservation = true;
      chosen.push_back(taken);
      token_batch_.reserved = saturating_add(token_batch_.reserved, 1);
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
  // A block can nominate an account of another shard (the source of a
  // notification). Only that shard's state can verify it, so it waits in the
  // backlog for that shard's blocks. Own candidates past the block's share
  // wait too. A candidate that finds no room stops the pass: it and every
  // later candidate stay with the block, which is not finished until a later
  // pass has handled them.
  size_t block_slots = from_block;
  for (const auto& candidate : ordered) {
    if (seen.count(candidate) != 0) {
      continue;
    }
    if (block_slots > 0 && token_shard_contains(shard, candidate.address)) {
      --block_slots;
      seen.insert(candidate);
      TRY_RESULT(attempts, token_claim(candidate, end_lt));
      chosen.push_back(ScheduledTokenCandidate{candidate, attempts, end_lt, false});
      continue;
    }
    TRY_RESULT(queued, token_enqueue(candidate, 0, end_lt, false));
    if (!queued) {
      token_batch_.first_unhandled = candidate;
      LOG(WARNING) << "wc0-index: token backlog full; the block keeps its remaining candidates from "
                   << candidate.address.to_hex() << " and is resumed when the backlog has room";
      break;
    }
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
    TRY_STATUS(token_park(scheduled));
  } else {
    auto attempts = static_cast<uint8_t>(scheduled.attempts + 1);
    TRY_RESULT(queued, token_enqueue(scheduled.candidate, attempts, scheduled.lt, scheduled.holds_reservation));
    if (!queued) {
      if (scheduled.holds_reservation) {
        return td::Status::Error("wc0-index: a retried token candidate found no room it had kept");
      }
      // The backlog is full: it stays with its block.
      token_batch_.overflow.push_back(ScheduledTokenCandidate{scheduled.candidate, attempts, scheduled.lt, false});
    }
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
        if (candidate.holds_reservation) {
          token_release_reservation();
        }
        break;
      case TokenVerifyOutcome::Retry:
        TRY_STATUS(retry_token_candidate(candidate));
        break;
      case TokenVerifyOutcome::Unverifiable:
        // Its verification needs another shard's state, which this pass
        // does not have: it is parked with its identity, and the worker's
        // retries verify it with the states of every shard it involves.
        TRY_STATUS(token_park(candidate));
        TRY_STATUS(token_write_counters());
        break;
      case TokenVerifyOutcome::WriteFailed:
        return td::Status::Error("wc0-index: an index write failed while verifying token candidates");
    }
  }
  return td::Status::OK();
}

td::Result<bool> WalletIndexDb::token_backlog_has_room() {
  TRY_RESULT(entries, get_meta_u64(kMetaTokenEntriesSub));
  return entries < token_backlog_limit_;
}

td::Status WalletIndexDb::token_load_counters() {
  TRY_RESULT(next_seq, get_meta_u64(kMetaTokenSeqSub));
  TRY_RESULT(entries, get_meta_u64(kMetaTokenEntriesSub));
  TRY_RESULT(lost, get_meta_u64(kMetaTokenLostSub));
  TRY_RESULT(unverifiable, get_meta_u64(kMetaTokenUnverifiableSub));
  TRY_RESULT(parked, get_meta_u64(kMetaTokenParkedSub));
  token_batch_.next_seq = next_seq;
  token_batch_.entries = entries;
  token_batch_.lost = lost;
  token_batch_.unverifiable = unverifiable;
  token_batch_.parked = parked;
  token_batch_.reserved = 0;
  token_batch_.first_unhandled = {};
  token_batch_.overflow.clear();
  return td::Status::OK();
}

td::Status WalletIndexDb::begin_token_pass() {
  if (!batch_open_) {
    return td::Status::Error("wc0-index: a token pass needs an open batch");
  }
  if (token_batch_.scheduled) {
    return td::Status::Error("wc0-index: token candidates already scheduled in this batch");
  }
  TRY_STATUS(token_load_counters());
  token_batch_.scheduled = true;
  return td::Status::OK();
}

td::Status WalletIndexDb::save_token_counters() {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: no token pass is open");
  }
  return token_write_counters();
}

td::Result<bool> WalletIndexDb::park_token_candidate(const ScheduledTokenCandidate& scheduled) {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: no token pass is open");
  }
  auto parked_key = token_parked_key(scheduled.candidate);
  TRY_RESULT(parked_lt, token_parked_lt(parked_key));
  if (!parked_lt && token_batch_.parked >= parked_limit_) {
    return false;
  }
  // No queue room is involved: parking has room, or the candidate is parked
  // already.
  uint64_t lt = parked_lt ? std::max(scheduled.lt, parked_lt.value()) : scheduled.lt;
  if (!parked_lt) {
    token_batch_.parked = saturating_add(token_batch_.parked, 1);
  }
  char value[8];
  put_u64_be(value, lt);
  TRY_STATUS(db_->set(td::Slice{parked_key}, td::Slice{value, sizeof(value)}));
  token_batch_.parked_overlay[parked_key] = std::string(value, sizeof(value));
  return true;
}

td::Status WalletIndexDb::unpark_token_candidate(const TokenCandidate& candidate) {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: no token pass is open");
  }
  auto parked_key = token_parked_key(candidate);
  TRY_RESULT(parked_lt, token_parked_lt(parked_key));
  if (!parked_lt) {
    return td::Status::OK();
  }
  TRY_STATUS(db_->erase(td::Slice{parked_key}));
  token_batch_.parked_overlay[parked_key] = std::string();
  if (token_batch_.parked > 0) {
    --token_batch_.parked;
  }
  return td::Status::OK();
}

td::Result<std::vector<ScheduledTokenCandidate>> WalletIndexDb::next_parked_token_candidates(size_t limit,
                                                                                             bool& wrapped) {
  if (!batch_open_ || !token_batch_.scheduled) {
    return td::Status::Error("wc0-index: no token pass is open");
  }
  char cursor_key[kMetaKeyLen];
  make_meta_key(kMetaParkedCursorSub, cursor_key);
  std::string cursor;
  TRY_RESULT(cursor_status, db_->get(td::Slice{cursor_key, kMetaKeyLen}, cursor));
  const std::string all_begin(1, static_cast<char>(kTokenParkedTag));
  const std::string all_end(1, static_cast<char>(kTokenParkedTag + 1));
  std::string begin = all_begin;
  if (cursor_status == td::KeyValue::GetStatus::Ok && !cursor.empty() &&
      static_cast<uint8_t>(cursor[0]) == kTokenParkedTag) {
    begin = key_after(cursor);
  }
  std::vector<ScheduledTokenCandidate> out;
  std::string last;
  bool limit_hit = false;
  auto status = db_->for_each_in_range(td::Slice{begin}, td::Slice{all_end}, [&](td::Slice key, td::Slice value) {
    if (out.size() >= limit) {
      limit_hit = true;
      return td::Status::Error("wc0-index: pass complete");
    }
    last = key.str();
    if (key.size() != kTokenIndexKeyLen) {
      return td::Status::OK();
    }
    auto kind = static_cast<uint8_t>(key[1]);
    if (kind != static_cast<uint8_t>(TokenKind::Jetton) && kind != static_cast<uint8_t>(TokenKind::Nft)) {
      return td::Status::OK();
    }
    TokenCandidate candidate{static_cast<TokenKind>(kind), HashKey{}};
    std::memcpy(candidate.address.data(), key.data() + 2, 32);
    out.push_back(ScheduledTokenCandidate{candidate, 0, value.size() == 8 ? get_u64_be(value.data()) : 0});
    return td::Status::OK();
  });
  if (!limit_hit) {
    TRY_STATUS(std::move(status));
  }
  wrapped = !limit_hit;
  if (wrapped) {
    // The next pass starts again from the first parked candidate.
    TRY_STATUS(db_->erase(td::Slice{cursor_key, kMetaKeyLen}));
  } else if (!last.empty()) {
    TRY_STATUS(db_->set(td::Slice{cursor_key, kMetaKeyLen}, td::Slice{last}));
  }
  return out;
}

namespace {

constexpr uint8_t kPendingBlockVersion = 1;
constexpr size_t kPendingEntryLen = 1 + 32 + 1;

std::string encode_pending_block(const WalletIndexDb::PendingBlock& pending) {
  std::string value(1 + 8, '\0');
  value[0] = static_cast<char>(kPendingBlockVersion);
  put_u64_be(&value[1], pending.end_lt);
  for (const auto& entry : pending.remaining) {
    char item[kPendingEntryLen];
    item[0] = static_cast<char>(entry.candidate.kind);
    std::memcpy(item + 1, entry.candidate.address.data(), 32);
    item[1 + 32] = static_cast<char>(entry.attempts);
    value.append(item, kPendingEntryLen);
  }
  return value;
}

td::Result<WalletIndexDb::PendingBlock> decode_pending_block(td::Slice value) {
  if (value.size() < 1 + 8 || static_cast<uint8_t>(value[0]) != kPendingBlockVersion ||
      (value.size() - 1 - 8) % kPendingEntryLen != 0) {
    return td::Status::Error("wc0-index: malformed pending-block record");
  }
  WalletIndexDb::PendingBlock pending;
  pending.end_lt = get_u64_be(value.data() + 1);
  for (size_t at = 1 + 8; at < value.size(); at += kPendingEntryLen) {
    auto kind = static_cast<uint8_t>(value[at]);
    if (kind != static_cast<uint8_t>(TokenKind::Jetton) && kind != static_cast<uint8_t>(TokenKind::Nft)) {
      return td::Status::Error("wc0-index: unknown token kind in pending-block record");
    }
    TokenCandidate candidate{static_cast<TokenKind>(kind), HashKey{}};
    std::memcpy(candidate.address.data(), value.data() + at + 1, 32);
    pending.remaining.push_back(
        ScheduledTokenCandidate{candidate, static_cast<uint8_t>(value[at + 1 + 32]), pending.end_lt});
  }
  return pending;
}

}  // namespace

td::Status WalletIndexDb::put_pending_block(const tos::BlockIdExt& block_id, const PendingBlock& pending) {
  char key[kIncompleteBlockKeyLen];
  make_block_key(kPendingBlockTag, block_id, key);
  std::string existing;
  TRY_RESULT(status, db_->get(td::Slice{key, kIncompleteBlockKeyLen}, existing));
  if (status != td::KeyValue::GetStatus::Ok) {
    TRY_RESULT(count, get_meta_u64(kMetaPendingBlocksSub));
    TRY_STATUS(put_meta_u64(kMetaPendingBlocksSub, saturating_add(count, 1)));
  }
  auto value = encode_pending_block(pending);
  return db_->set(td::Slice{key, kIncompleteBlockKeyLen}, td::Slice{value});
}

td::Result<td::optional<WalletIndexDb::PendingBlock>> WalletIndexDb::get_pending_block(
    const tos::BlockIdExt& block_id) {
  char key[kIncompleteBlockKeyLen];
  make_block_key(kPendingBlockTag, block_id, key);
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{key, kIncompleteBlockKeyLen}, value));
  if (status != td::KeyValue::GetStatus::Ok) {
    return td::optional<PendingBlock>{};
  }
  TRY_RESULT(pending, decode_pending_block(value));
  return td::optional<PendingBlock>(std::move(pending));
}

td::Status WalletIndexDb::delete_pending_block(const tos::BlockIdExt& block_id) {
  char key[kIncompleteBlockKeyLen];
  make_block_key(kPendingBlockTag, block_id, key);
  std::string existing;
  TRY_RESULT(status, db_->get(td::Slice{key, kIncompleteBlockKeyLen}, existing));
  if (status == td::KeyValue::GetStatus::Ok) {
    TRY_RESULT(count, get_meta_u64(kMetaPendingBlocksSub));
    TRY_STATUS(put_meta_u64(kMetaPendingBlocksSub, count > 0 ? count - 1 : 0));
  }
  return db_->erase(td::Slice{key, kIncompleteBlockKeyLen});
}

td::Status WalletIndexDb::for_each_pending_block(
    size_t limit, std::function<td::Status(const tos::BlockIdExt&, const PendingBlock&)> cb) {
  const char begin[1] = {static_cast<char>(kPendingBlockTag)};
  const char end[1] = {static_cast<char>(kPendingBlockTag + 1)};
  size_t seen = 0;
  bool limit_reached = false;
  auto status =
      db_->for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1}, [&](td::Slice key, td::Slice value) -> td::Status {
        if (seen >= limit) {
          limit_reached = true;
          return td::Status::Error("wc0-index: limit reached");
        }
        ++seen;
        if (key.size() != kIncompleteBlockKeyLen) {
          LOG(WARNING) << "wc0-index: skipping a malformed pending-block key";
          return td::Status::OK();
        }
        auto pending = decode_pending_block(value);
        if (pending.is_error()) {
          // Its block keeps its incomplete marker: the index stays
          // incomplete, and nothing is claimed about the lost candidates.
          LOG(ERROR) << "wc0-index: " << pending.error().message();
          return td::Status::OK();
        }
        return cb(parse_block_key(key), pending.ok());
      });
  return limit_reached ? td::Status::OK() : std::move(status);
}

td::Status WalletIndexDb::next_pending_block(
    const td::optional<tos::BlockIdExt>& after,
    std::function<td::Status(const tos::BlockIdExt&, const PendingBlock&)> cb) {
  std::string begin(1, static_cast<char>(kPendingBlockTag));
  if (after) {
    char key[kIncompleteBlockKeyLen];
    make_block_key(kPendingBlockTag, after.value(), key);
    begin = std::string(key, kIncompleteBlockKeyLen) + std::string(1, '\0');
  }
  const std::string end(1, static_cast<char>(kPendingBlockTag + 1));
  bool found = false;
  auto status =
      db_->for_each_in_range(td::Slice{begin}, td::Slice{end}, [&](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != kIncompleteBlockKeyLen) {
          return td::Status::OK();
        }
        auto pending = decode_pending_block(value);
        if (pending.is_error()) {
          LOG(ERROR) << "wc0-index: " << pending.error().message();
          return td::Status::OK();
        }
        found = true;
        TRY_STATUS(cb(parse_block_key(key), pending.ok()));
        return td::Status::Error("wc0-index: one is enough");
      });
  return found ? td::Status::OK() : std::move(status);
}

td::optional<std::pair<HashKey, size_t>> WalletIndexDb::next_waiting_token_candidate(size_t from_bucket) {
  td::optional<std::pair<HashKey, size_t>> found;
  auto scan = [&](size_t first, size_t last) {
    if (first > last) {
      return;
    }
    auto begin = token_queue_bucket_prefix(first);
    auto end = token_queue_bucket_end(last);
    db_->for_each_in_range(td::Slice{begin}, td::Slice{end},
                           [&](td::Slice key, td::Slice value) {
                             auto identity = token_queue_identity(key, value);
                             if (identity.is_ok()) {
                               found = std::make_pair(identity.ok().address,
                                                      static_cast<size_t>(static_cast<uint8_t>(key[1])));
                               return td::Status::Error("wc0-index: one is enough");
                             }
                             return td::Status::OK();
                           })
        .ignore();
  };
  from_bucket %= kTokenBacklogBuckets;
  scan(from_bucket, kTokenBacklogBuckets - 1);
  if (!found && from_bucket > 0) {
    scan(0, from_bucket - 1);
  }
  return found;
}

td::Result<uint64_t> WalletIndexDb::pending_block_count() {
  return get_meta_u64(kMetaPendingBlocksSub);
}

td::Result<bool> WalletIndexDb::has_jetton_wallet_record(const HashKey& wallet) {
  std::string value;
  TRY_RESULT(status, db_->get(td::Slice{jetton_wallet_key(wallet)}, value));
  return status == td::KeyValue::GetStatus::Ok;
}

td::Result<TokenBacklogStats> WalletIndexDb::token_backlog_stats() {
  TRY_RESULT(entries, get_meta_u64(kMetaTokenEntriesSub));
  TRY_RESULT(lost, get_meta_u64(kMetaTokenLostSub));
  TRY_RESULT(unverifiable, get_meta_u64(kMetaTokenUnverifiableSub));
  TRY_RESULT(parked, get_meta_u64(kMetaTokenParkedSub));
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
  char rebuild_key[kMetaKeyLen];
  make_meta_key(kMetaNeedsRebuildSub, rebuild_key);
  std::string rebuild_value;
  TRY_RESULT(rebuild_status, db_->get(td::Slice{rebuild_key, kMetaKeyLen}, rebuild_value));
  bool needs_rebuild = rebuild_status == td::KeyValue::GetStatus::Ok;
  TokenBacklogStats stats{entries, lost, unverifiable, unfinished_block, needs_rebuild};
  stats.parked = parked;
  return stats;
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

namespace {
std::mutex g_unavailable_mutex;
std::string g_unavailable_reason;
}  // namespace

void set_wallet_index_unavailable(std::string reason) {
  std::lock_guard<std::mutex> guard(g_unavailable_mutex);
  g_unavailable_reason = std::move(reason);
}

std::string wallet_index_unavailable_reason() {
  std::lock_guard<std::mutex> guard(g_unavailable_mutex);
  return g_unavailable_reason;
}

bool open_wallet_index_db(const std::string& db_root) {
  if (db_root.empty()) {
    set_wallet_index_unavailable("no database root");
    return false;
  }
  auto db_r = WalletIndexDb::open(db_root + "/wc0-index");
  if (db_r.is_error()) {
    LOG(ERROR) << "wc0-index: failed to open: " << db_r.error().message()
               << "; wallet indexing is disabled for this run and the account-index RPC reports it unavailable";
    set_wallet_index_unavailable(PSTRING() << "the index database failed to open: " << db_r.error().message());
    return false;
  }
  set_wallet_index_db(db_r.move_as_ok());
  LOG(INFO) << "wc0-index: opened at " << db_root << "/wc0-index";
  return true;
}

}  // namespace tos_wallet_index
