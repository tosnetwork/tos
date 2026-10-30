/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <limits>
#include <mutex>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "common/errorcode.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/crypto.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "index-reader.h"
#include "index-replay.h"
#include "index-verify.h"

namespace tos::services {
using tos_wallet_index::AccountHead;
using tos_wallet_index::LineageVerdict;
using tos_wallet_index::VerificationState;
using tos_wallet_index::WalletIndexDb;
using tos_wallet_index::WindowShardTip;

td::Result<uint64_t> base_lt_bound(const std::vector<WindowShardTip>& tips, bool has_base,
                                   const td::Bits256& account) {
  if (!has_base) {
    return uint64_t{0};
  }
  auto bound = tos_wallet_index::window_lt_bound(tips, account);
  if (bound.is_error()) {
    return td::Status::Error(kVerifyTerminalError, bound.error().message());
  }
  return bound.move_as_ok();
}

namespace {

td::Status terminal(std::string message) {
  return td::Status::Error(kVerifyTerminalError, message);
}

// A logic or data failure keeps its message and becomes terminal.
td::Status terminal(const td::Status& status) {
  return td::Status::Error(kVerifyTerminalError, status.message());
}

std::string account_text(const td::Bits256& account) {
  return "0:" + account.to_hex();
}

// The basechain shard tips a masterchain block records, with their end lt.
td::Result<std::vector<WindowShardTip>> index_shard_tips(td::Ref<vm::Cell> root) {
  block::gen::Block::Record block;
  block::gen::BlockExtra::Record extra;
  block::gen::McBlockExtra::Record master;
  block::ShardConfig shards;
  if (!(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.extra, extra) && extra.custom.not_null() &&
        extra.custom->size_refs() == 1 && tlb::unpack_cell(extra.custom->prefetch_ref(), master) &&
        shards.unpack(master.shard_hashes))) {
    return terminal("cannot decode masterchain shard tips");
  }
  std::vector<WindowShardTip> tips;
  for (auto& id : shards.get_shard_hash_ids(true)) {
    if (id.workchain != basechainId) {
      continue;
    }
    auto shard = shards.get_shard_hash(id.shard_full(), true);
    if (shard.is_null()) {
      return terminal("missing shard descriptor");
    }
    tips.push_back(WindowShardTip{shard->top_block_id().shard_full(), shard->end_lt()});
    if (tips.size() > 4096) {
      return terminal("too many basechain shards in one masterchain block");
    }
  }
  if (tips.empty()) {
    return terminal("masterchain block records no basechain shard");
  }
  return tips;
}

class ReaderHeadAccounts final : public HeadAccounts {
 public:
  struct Shard {
    ShardIdFull shard;
    td::Ref<vm::CellSlice> accounts;
  };
  explicit ReaderHeadAccounts(std::vector<Shard> shards) : shards_(std::move(shards)) {
  }
  td::Status for_each(const std::function<td::Status(const td::Bits256&, const AccountHead&)>& cb) override {
    for (auto& shard : shards_) {
      vm::AugmentedDictionary dict{shard.accounts, 256, block::tlb::aug_ShardAccounts};
      td::Status status;
      bool complete = dict.check_for_each_extra(
          [&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>, td::ConstBitPtr key, int key_len) {
            if (key_len != 256) {
              status = terminal("malformed account key in the head state");
              return false;
            }
            td::Bits256 account;
            account.bits().copy_from(key, 256);
            auto head = parse(value);
            if (head.is_error()) {
              status = head.move_as_error();
              return false;
            }
            status = cb(account, head.ok());
            return status.is_ok();
          });
      TRY_STATUS(std::move(status));
      if (!complete) {
        return terminal("cannot walk the head state's accounts");
      }
    }
    return td::Status::OK();
  }
  td::Result<td::optional<AccountHead>> find(const td::Bits256& account) override {
    for (auto& shard : shards_) {
      if (!shard_contains(shard.shard.shard, account)) {
        continue;
      }
      vm::AugmentedDictionary dict{shard.accounts, 256, block::tlb::aug_ShardAccounts};
      auto value = dict.lookup(account.bits(), 256);
      if (value.is_null()) {
        return td::optional<AccountHead>{};
      }
      TRY_RESULT(head, parse(value));
      return td::optional<AccountHead>(head);
    }
    return terminal("no head shard contains the account");
  }

 private:
  static td::Result<AccountHead> parse(const td::Ref<vm::CellSlice>& value) {
    if (value.is_null()) {
      return terminal("empty account in the head state");
    }
    auto copy = value;
    auto& cs = copy.write();
    td::Ref<vm::Cell> body;
    td::BitArray<256> hash;
    unsigned long long lt = 0;
    if (!block::gen::t_ShardAccount.unpack_account_descr(cs, body, hash, lt)) {
      return terminal("malformed account in the head state");
    }
    AccountHead head;
    head.last_trans_lt = lt;
    head.last_trans_hash = hash;
    return head;
  }
  std::vector<Shard> shards_;
};

// A block's checked root, or nothing when the node does not hold its bytes.
// Reading the bytes may fail and be retried; bytes that do not match the
// block's identity, or do not decode, are terminal.
td::Result<td::optional<td::Ref<vm::Cell>>> checked_block_root(IndexReader& reader,
                                                               const validator::ConstBlockHandle& handle) {
  const auto& id = handle->id();
  TRY_RESULT(reply, reader.submit_block(handle, IndexReader::Context{}));
  auto raw = reader.take(*reply);
  if (raw.is_error()) {
    if (raw.error().code() == ErrorCode::notready) {
      return td::optional<td::Ref<vm::Cell>>{};
    }
    return raw.move_as_error();
  }
  td::Ref<validator::BlockData> data;
  if (raw.ok().too_large) {
    // Larger than the prefetch lane reads: read and decoded in one request.
    auto read = reader.read_block(handle);
    if (read.is_error()) {
      if (read.error().code() == ErrorCode::notready) {
        return td::optional<td::Ref<vm::Cell>>{};
      }
      return read.move_as_error();
    }
    data = read.move_as_ok();
    if (data.is_null()) {
      return terminal(PSTRING() << "block " << id.to_str() << " has no data");
    }
    td::Bits256 file_hash;
    td::sha256(data->data().as_slice(), file_hash.as_slice());
    if (file_hash != id.file_hash) {
      return terminal(PSTRING() << "the bytes of block " << id.to_str() << " do not match its file hash");
    }
  } else {
    td::Bits256 file_hash;
    td::sha256(raw.ok().data.as_slice(), file_hash.as_slice());
    if (file_hash != id.file_hash) {
      return terminal(PSTRING() << "the bytes of block " << id.to_str() << " do not match its file hash");
    }
    auto decoded = decode_block(id, std::move(raw.ok_ref().data));
    if (decoded.is_error()) {
      return terminal(PSTRING() << "block " << id.to_str() << " does not decode: " << decoded.error().message());
    }
    data = decoded.move_as_ok();
  }
  auto checked = IndexReader::checked_root(handle, data);
  if (checked.is_error()) {
    return terminal(PSTRING() << "block " << id.to_str() << ": " << checked.error().message());
  }
  return td::optional<td::Ref<vm::Cell>>(checked.move_as_ok());
}

class ReaderVerifySource final : public VerifySource {
 public:
  explicit ReaderVerifySource(IndexReader& reader) : reader_(reader) {
  }
  td::Result<BlockIdExt> tip() override {
    return reader_.tip();
  }
  td::Result<td::optional<VerifyMasterchainBlock>> masterchain_block(uint32_t seqno) override {
    auto found = reader_.masterchain(seqno);
    if (found.is_error()) {
      if (found.error().code() == ErrorCode::notready) {
        return td::optional<VerifyMasterchainBlock>{};
      }
      return found.move_as_error();
    }
    auto handle = found.move_as_ok();
    VerifyMasterchainBlock block;
    block.id = handle->id();
    if (!block.id.is_masterchain() || block.id.seqno() != seqno) {
      return terminal(PSTRING() << "the node returned the wrong block for masterchain seqno " << seqno);
    }
    block.applied = handle->is_applied();
    if (!handle->inited_unix_time()) {
      return terminal(PSTRING() << "masterchain block " << seqno << " has no generation time");
    }
    block.unix_time = handle->unix_time();
    if (seqno > 1) {
      if (!handle->inited_prev()) {
        return terminal(PSTRING() << "masterchain block " << seqno << " has no previous block");
      }
      block.handle_prev = handle->one_prev(true);
    }
    TRY_RESULT(read, checked_block_root(reader_, handle));
    if (!read) {
      return td::optional<VerifyMasterchainBlock>{};
    }
    auto root = std::move(read.value());
    if (seqno > 1) {
      // The previous block as the checked bytes name it, not as the handle
      // says: the walk compares the two.
      std::vector<BlockIdExt> prev;
      BlockIdExt master;
      bool after_split = false;
      auto decoded = block::unpack_block_prev_blk_try(root, block.id, prev, master, after_split);
      if (decoded.is_error() || prev.size() != 1) {
        return terminal(PSTRING() << "cannot decode the previous block of masterchain block " << seqno);
      }
      block.prev = prev[0];
    }
    TRY_RESULT_ASSIGN(block.tips, index_shard_tips(std::move(root)));
    return td::optional<VerifyMasterchainBlock>(std::move(block));
  }
  td::Result<std::unique_ptr<HeadAccounts>> accounts(const BlockIdExt& head) override {
    TRY_RESULT(master, reader_.masterchain(head.seqno()));
    if (master->id() != head) {
      return terminal("the node's masterchain block differs from the verified head");
    }
    TRY_RESULT(heads, reader_.shard_heads(master));
    std::vector<ReaderHeadAccounts::Shard> shards;
    for (auto& id : heads) {
      TRY_RESULT(handle, reader_.handle(id));
      TRY_RESULT(root, reader_.state(handle));
      block::gen::ShardStateUnsplit::Record state;
      if (!tlb::unpack_cell(root, state) || state.accounts.is_null()) {
        return terminal("cannot decode a head shard state");
      }
      shards.push_back({id.shard_full(), vm::load_cell_slice_ref(state.accounts)});
    }
    if (shards.empty()) {
      return terminal("the verified head names no basechain shard");
    }
    return std::unique_ptr<HeadAccounts>(new ReaderHeadAccounts(std::move(shards)));
  }
  td::Result<std::vector<td::Bits256>> state_roots(const BlockIdExt& head) override {
    TRY_RESULT(master, reader_.masterchain(head.seqno()));
    if (master->id() != head) {
      return terminal("the node's masterchain block differs from the verified head");
    }
    TRY_RESULT(heads, reader_.shard_heads(master));
    std::vector<td::Bits256> roots;
    for (auto& id : heads) {
      TRY_RESULT(handle, reader_.handle(id));
      TRY_RESULT(root, reader_.state(handle));
      roots.push_back(root->get_hash().bits());
    }
    std::sort(roots.begin(), roots.end());
    return roots;
  }
  td::Status for_each_interval_transaction(
      const VerifyMasterchainBlock& master,
      const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb,
      const std::atomic<bool>* cancel) override {
    auto seqno = master.id.seqno();
    TRY_RESULT(handle, reader_.masterchain(seqno));
    if (handle->id() != master.id) {
      return terminal(PSTRING() << "the node's masterchain block " << seqno << " changed during the block pass");
    }
    TRY_RESULT(heads, reader_.shard_heads(handle));
    auto walked = replay_interval(std::move(heads), seqno, [this](BlockIdExt id) { return reader_.handle(id); });
    if (walked.is_error()) {
      return terminal(PSTRING() << "the shard blocks of masterchain block " << seqno
                                << " cannot be walked: " << walked.error().message());
    }
    return walk_interval_blocks(
        walked.ok(), [this](const validator::BlockHandle& block) { return checked_block_root(reader_, block); }, cb,
        cancel);
  }

 private:
  IndexReader& reader_;
};

// Index writes in batches of a bounded size, under the index write lock.
class Batches {
 public:
  Batches(WalletIndexDb& db, size_t limit) : db_(db), limit_(limit == 0 ? 1 : limit) {
  }
  Batches(const Batches&) = delete;
  Batches& operator=(const Batches&) = delete;
  ~Batches() {
    abort();
  }
  td::Status begin() {
    lock_ = std::unique_lock<std::mutex>(db_.write_mutex());
    auto status = db_.begin_batch();
    if (status.is_error()) {
      lock_.unlock();
      return status;
    }
    open_ = true;
    writes_ = 0;
    return td::Status::OK();
  }
  // Count one write; commit and start another batch when this one is full.
  td::Status wrote() {
    if (++writes_ < limit_) {
      return td::Status::OK();
    }
    TRY_STATUS(commit());
    return begin();
  }
  td::Status commit() {
    if (!open_) {
      return td::Status::Error("no verification batch is open");
    }
    open_ = false;
    auto status = db_.commit_batch();
    lock_.unlock();
    return status;
  }
  void abort() {
    if (open_) {
      db_.abort_batch();
      open_ = false;
    }
    if (lock_.owns_lock()) {
      lock_.unlock();
    }
  }

 private:
  WalletIndexDb& db_;
  size_t limit_;
  size_t writes_ = 0;
  bool open_ = false;
  std::unique_lock<std::mutex> lock_;
};

// Record the refusal: the index is never served, and a restart refuses it
// again before reading the source.
td::Result<VerifyOutcome> refuse(WalletIndexDb& db, std::string reason, td::optional<td::Bits256> account = {}) {
  Batches batch(db, 1);
  TRY_STATUS(batch.begin());
  TRY_STATUS(db.put_verification_state(VerificationState::Refused));
  TRY_STATUS(batch.commit());
  VerifyOutcome outcome;
  outcome.step = VerifyStep::Refused;
  outcome.reason = std::move(reason);
  outcome.account = std::move(account);
  return outcome;
}

VerifyOutcome wait_for_node(std::string reason) {
  VerifyOutcome outcome;
  outcome.step = VerifyStep::Wait;
  outcome.reason = std::move(reason);
  return outcome;
}

// The shard tips of consecutive masterchain blocks, oldest first.
class TipTable {
 public:
  explicit TipTable(size_t limit_bytes) : limit_bytes_(limit_bytes) {
  }
  td::Status push(std::vector<WindowShardTip> tips) {
    // The tips, the vector that holds them and its allocation.
    bytes_ += tips.size() * sizeof(WindowShardTip) + sizeof(tips) + 16;
    if (bytes_ > limit_bytes_) {
      return terminal(PSTRING() << "the masterchain window needs more than " << (limit_bytes_ >> 20)
                                << " MiB of shard tips to verify; it is not verified");
    }
    blocks_.push_back(std::move(tips));
    return td::Status::OK();
  }
  // The walk reads newest first; lookups go oldest first.
  void finish(uint32_t first_seqno) {
    std::reverse(blocks_.begin(), blocks_.end());
    first_seqno_ = first_seqno;
  }
  size_t size() const {
    return blocks_.size();
  }
  uint32_t seqno(size_t i) const {
    return first_seqno_ + static_cast<uint32_t>(i);
  }
  td::Result<uint64_t> bound(size_t i, const td::Bits256& account) const {
    return base_lt_bound(blocks_[i], true, account);
  }

 private:
  size_t limit_bytes_;
  size_t bytes_ = 0;
  uint32_t first_seqno_ = 0;
  std::vector<std::vector<WindowShardTip>> blocks_;
};

}  // namespace

std::unique_ptr<VerifySource> make_reader_verify_source(IndexReader& reader) {
  return std::make_unique<ReaderVerifySource>(reader);
}

td::Result<VerifyOutcome> prepare_quarantined_index(WalletIndexDb& db, VerifySource& source,
                                                    const VerifyLimits& limits) {
  auto state = db.get_verification_state();
  if (state.is_error()) {
    return terminal(state.error());
  }
  if (state.ok() != VerificationState::Quarantined) {
    return terminal("only a quarantined index is prepared for verification");
  }
  auto record = db.verification_record();
  if (record.is_error()) {
    return terminal(record.error());
  }
  if (record.ok()) {
    return terminal("the quarantined index is already prepared for verification");
  }
  TRY_RESULT(stored, db.replay_checkpoint());
  if (!stored || stored.value().committed.seqno() == 0) {
    return refuse(db, "the snapshot has no replay checkpoint");
  }
  auto checkpoint = stored.value().committed;
  auto anchor = stored.value().anchor;
  TRY_RESULT(tip, source.tip());
  if (!tip.is_masterchain() || tip.seqno() == 0) {
    return td::Status::Error("source has no applied masterchain block");
  }
  if (checkpoint.seqno() > tip.seqno()) {
    return wait_for_node(PSTRING() << "the node has not reached the snapshot checkpoint " << checkpoint.seqno()
                                   << " (it is at " << tip.seqno() << ")");
  }
  TRY_RESULT(top, source.masterchain_block(checkpoint.seqno()));
  if (!top) {
    return refuse(db, PSTRING() << "snapshot older than this node's history: the node does not hold its checkpoint "
                                << checkpoint.seqno());
  }
  if (top.value().id != checkpoint) {
    return refuse(db, PSTRING() << "the snapshot checkpoint is not this node's masterchain block "
                                << checkpoint.seqno());
  }
  if (!top.value().applied) {
    return terminal("the node holds the snapshot checkpoint but has not applied it");
  }
  // The anchor is authenticated only by this node's own block 1; a node
  // that joined later cannot check it, and the record says so.
  bool anchor_verified = false;
  TRY_RESULT(first_block, source.masterchain_block(1));
  if (first_block) {
    if (first_block.value().id != anchor) {
      return refuse(db, "the snapshot anchor is not this node's first block");
    }
    anchor_verified = true;
  }

  // Walk down from the checkpoint over the contiguous run of blocks the node
  // holds, each linked to the one above it, to the window base.
  constexpr uint32_t retention = tos_wallet_index::kEventRetentionSeconds;
  bool has_cutoff = top.value().unix_time > retention;
  uint32_t cutoff = has_cutoff ? top.value().unix_time - retention : 0;
  TipTable table(limits.tip_table_bytes);
  // A block's previous identity is taken from its checked bytes, and the
  // node's handle must record the same.
  auto linked_inside = [](const VerifyMasterchainBlock& block) {
    return (!block.prev && !block.handle_prev && block.id.seqno() == 1) ||
           (block.prev && block.handle_prev && block.prev.value() == block.handle_prev.value());
  };
  if (!linked_inside(top.value())) {
    return terminal(PSTRING() << "masterchain block " << checkpoint.seqno()
                              << " is not linked: its bytes and the node's handle name different previous blocks");
  }
  auto above = top.value();
  TRY_STATUS(table.push(std::move(top.value().tips)));
  bool has_base = true;
  uint32_t base = checkpoint.seqno();
  uint32_t horizon_time = above.unix_time;
  for (uint32_t seqno = checkpoint.seqno() - 1;; --seqno) {
    if (seqno == 0) {
      // Every block from the chain's first one is inside the window.
      has_base = false;
      base = 0;
      horizon_time = 0;
      break;
    }
    TRY_RESULT(block, source.masterchain_block(seqno));
    if (!block) {
      // The lowest block the node holds is the verified horizon; what it
      // already referenced cannot be checked and is dropped.
      break;
    }
    if (!above.prev || above.prev.value() != block.value().id) {
      return terminal(PSTRING() << "the node's masterchain blocks " << seqno << " and " << seqno + 1
                                << " are not linked");
    }
    if (!linked_inside(block.value())) {
      return terminal(PSTRING() << "masterchain block " << seqno
                                << " is not linked: its bytes and the node's handle name different previous blocks");
    }
    if (!block.value().applied) {
      return terminal(PSTRING() << "the node holds masterchain block " << seqno << " but has not applied it");
    }
    base = seqno;
    horizon_time = block.value().unix_time;
    bool outside = has_cutoff && block.value().unix_time < cutoff;
    above.id = block.value().id;
    above.prev = block.value().prev;
    TRY_STATUS(table.push(std::move(block.value().tips)));
    if (outside) {
      break;
    }
  }
  table.finish(has_base ? base : 1);
  // With a base block it is row 0 of the table and assigns no row.
  size_t first = has_base ? 1 : 0;
  size_t last = table.size() - 1;

  VerifyOutcome outcome;
  td::optional<VerifyOutcome> refusal;
  Batches batch(db, limits.batch_writes);
  TRY_STATUS(batch.begin());
  // Age rows come from the chain only, and a restart before this step was
  // recorded starts it again from nothing.
  TRY_STATUS(db.clear_event_ages());
  TRY_STATUS(db.clear_unverified_accounts());
  td::Bits256 current = td::Bits256::zero();
  bool have_current = false;
  uint64_t lower = 0, upper = 0;
  auto status = db.for_each_event_record([&](const td::Bits256& account, uint64_t lt, td::Slice) -> td::Status {
    if (!have_current || account != current) {
      current = account;
      have_current = true;
      lower = 0;
      if (has_base) {
        TRY_RESULT_ASSIGN(lower, table.bound(0, account));
      }
      TRY_RESULT_ASSIGN(upper, table.bound(last, account));
    }
    if (lt <= lower) {
      ++outcome.dropped;
      TRY_STATUS(db.erase_event(account, lt));
      return batch.wrote();
    }
    if (lt >= upper) {
      VerifyOutcome refused;
      refused.reason = PSTRING() << "row " << lt << " of " << account_text(account)
                                 << " is newer than the snapshot checkpoint";
      refused.account = account;
      refusal = std::move(refused);
      return td::Status::Error("refused");
    }
    // The first block whose tip for the row's shard reaches past the row
    // referenced it; tips only move forward.
    size_t lo = first, hi = last;
    while (lo < hi) {
      size_t mid = lo + (hi - lo) / 2;
      TRY_RESULT(bound, table.bound(mid, account));
      if (bound > lt) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    ++outcome.kept;
    TRY_STATUS(db.put_event_age(account, lt, table.seqno(lo)));
    return batch.wrote();
  });
  if (refusal) {
    batch.abort();
    return refuse(db, refusal.value().reason, refusal.value().account);
  }
  TRY_STATUS(std::move(status));
  TRY_STATUS(db.put_window_base(base));
  WalletIndexDb::VerificationRecord prepared;
  prepared.schema = tos_wallet_index::kWalletIndexSchemaVersion;
  prepared.checkpoint = checkpoint;
  prepared.base = base;
  prepared.horizon_seqno = base;
  prepared.horizon_time = horizon_time;
  prepared.anchor_verified = anchor_verified;
  TRY_STATUS(db.put_verification_record(prepared));
  TRY_STATUS(batch.commit());
  outcome.step = VerifyStep::Done;
  return outcome;
}

td::Result<VerifyOutcome> verify_index_at_head(WalletIndexDb& db, VerifySource& source, const BlockIdExt& head,
                                               const VerifyLimits& limits) {
  auto state = db.get_verification_state();
  if (state.is_error()) {
    return terminal(state.error());
  }
  if (state.ok() != VerificationState::Quarantined) {
    return terminal("only a quarantined index is verified at the head");
  }
  auto stored_record = db.verification_record();
  if (stored_record.is_error()) {
    return terminal(stored_record.error());
  }
  if (!stored_record.ok()) {
    return terminal("the quarantined index is not prepared for verification");
  }
  auto record = stored_record.ok().value();
  if (record.head) {
    return terminal("the index was already verified at a head");
  }
  TRY_RESULT(checkpoint, db.replay_checkpoint());
  if (!checkpoint || checkpoint.value().committed != head) {
    return terminal("the index has not replayed to the head it is verified at");
  }
  if (head.seqno() < record.checkpoint.seqno()) {
    return terminal("the head is older than the snapshot checkpoint");
  }
  TRY_RESULT(base, db.get_window_base());
  if (base < record.base) {
    return terminal("the window base moved below the verified base");
  }
  bool has_base = base != 0;
  std::vector<WindowShardTip> base_tips;
  if (has_base) {
    TRY_RESULT(block, source.masterchain_block(base));
    if (!block) {
      return terminal(PSTRING() << "the node no longer holds the window base, masterchain block " << base);
    }
    base_tips = std::move(block.value().tips);
  }
  TRY_RESULT(accounts, source.accounts(head));

  VerifyOutcome outcome;
  td::optional<VerifyOutcome> refusal;
  auto refuse_with = [&](const td::Bits256& account, std::string reason) {
    VerifyOutcome refused;
    refused.reason = PSTRING() << account_text(account) << ": " << reason;
    refused.account = account;
    refusal = std::move(refused);
    return td::Status::Error("refused");
  };

  // Rows first: every account with rows, newest first, checked against its
  // head in the state, or marked unverified when the state cannot vouch for
  // it. Rows already outside the window, and rows past the per-account
  // retention, are dropped: they cannot be checked, so they are not served.
  Batches batch(db, limits.batch_writes);
  TRY_STATUS(batch.begin());
  TRY_STATUS(db.clear_unverified_accounts());
  struct Group {
    td::Bits256 account = td::Bits256::zero();
    bool active = false;
    uint64_t bound = 0;
    size_t bytes = 0;
    std::vector<td::Ref<vm::Cell>> rows;
  } group;
  auto finish = [&]() -> td::Status {
    if (!group.active) {
      return td::Status::OK();
    }
    group.active = false;
    TRY_RESULT(found, accounts->find(group.account));
    auto result = tos_wallet_index::verify_account_lineage(group.account, found, group.bound, group.rows,
                                                           tos_wallet_index::kMaxEventsPerAccount);
    std::vector<td::Ref<vm::Cell>>().swap(group.rows);
    group.bytes = 0;
    switch (result.verdict) {
      case LineageVerdict::Complete:
      case LineageVerdict::OutsideWindow:
        return td::Status::OK();
      case LineageVerdict::NeedsBlocks: {
        auto reason = found ? UnverifiedReason::StartsInWindow : UnverifiedReason::Absent;
        TRY_STATUS(db.put_unverified_account(group.account, static_cast<uint8_t>(reason)));
        ++outcome.unverified;
        return batch.wrote();
      }
      case LineageVerdict::Refused:
        return refuse_with(group.account, result.reason);
    }
    return refuse_with(group.account, "unknown lineage verdict");
  };
  auto status = db.for_each_event_record([&](const td::Bits256& account, uint64_t lt, td::Slice value) -> td::Status {
    if (!group.active || account != group.account) {
      TRY_STATUS(finish());
      group.account = account;
      group.active = true;
      TRY_RESULT_ASSIGN(group.bound, base_lt_bound(base_tips, has_base, account));
    }
    if (lt <= group.bound || group.rows.size() >= tos_wallet_index::kMaxEventsPerAccount) {
      TRY_STATUS(db.erase_event(account, lt));
      return batch.wrote();
    }
    group.bytes += value.size();
    if (group.bytes > limits.account_rows_bytes) {
      return terminal(PSTRING() << "the history of " << account_text(account) << " exceeds "
                                << (limits.account_rows_bytes >> 20) << " MiB; it is not verified");
    }
    auto cell = vm::std_boc_deserialize(value);
    if (cell.is_error()) {
      return refuse_with(account, PSTRING() << "row " << lt << " does not decode");
    }
    auto link = tos_wallet_index::parse_transaction_link(cell.ok());
    if (link.is_ok() && link.ok().lt != lt) {
      // The row would be served under a logical time it does not have.
      return refuse_with(account, PSTRING() << "row " << lt << " holds the transaction at " << link.ok().lt);
    }
    group.rows.push_back(cell.move_as_ok());
    return td::Status::OK();
  });
  if (status.is_ok()) {
    status = finish();
  }
  if (refusal) {
    batch.abort();
    return refuse(db, refusal.value().reason, refusal.value().account);
  }
  TRY_STATUS(std::move(status));
  TRY_STATUS(batch.commit());

  // Then the state: an account whose last transaction is inside the window
  // must have rows, and every account with rows was checked above.
  status = accounts->for_each([&](const td::Bits256& account, const AccountHead& account_head) -> td::Status {
    TRY_RESULT(bound, base_lt_bound(base_tips, has_base, account));
    if (account_head.last_trans_lt <= bound) {
      return td::Status::OK();
    }
    TRY_RESULT(has_rows, db.has_events(account));
    if (has_rows) {
      return td::Status::OK();
    }
    auto result = tos_wallet_index::verify_account_lineage(account, account_head, bound, {},
                                                           tos_wallet_index::kMaxEventsPerAccount);
    if (result.verdict == LineageVerdict::Refused) {
      return refuse_with(account, result.reason);
    }
    return refuse_with(account, "in-window history is missing");
  });
  if (refusal) {
    return refuse(db, refusal.value().reason, refusal.value().account);
  }
  TRY_STATUS(std::move(status));

  // Ownership is not derived at the head yet, so the index is at most Partial.
  record.head = head;
  record.unverified = outcome.unverified;
  TRY_STATUS(batch.begin());
  TRY_STATUS(db.put_verification_record(record));
  TRY_STATUS(db.put_verification_state(VerificationState::Partial));
  TRY_STATUS(batch.commit());
  outcome.step = VerifyStep::Done;
  return outcome;
}

td::Status terminal_gap(const std::string& block) {
  return terminal("the window has a gap: the node does not hold shard block " + block);
}

td::Status walk_block_transactions(
    const td::Ref<vm::Cell>& root,
    const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb) {
  block::gen::Block::Record blk;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(root, blk) && tlb::unpack_cell(blk.extra, extra))) {
    return terminal("a window block does not decode");
  }
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks};
  td::Status status;
  bool complete = accounts.check_for_each_extra(
      [&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>, td::ConstBitPtr, int) -> bool {
        block::gen::AccountBlock::Record account_block;
        if (!tlb::csr_unpack(value, account_block)) {
          return true;  // replay skips it too
        }
        td::Bits256 account = account_block.account_addr;
        vm::AugmentedDictionary transactions{vm::DictNonEmpty(), account_block.transactions, 64,
                                             block::tlb::aug_AccountTransactions};
        bool walked = transactions.check_for_each_extra(
            [&](td::Ref<vm::CellSlice> tvalue, td::Ref<vm::CellSlice>, td::ConstBitPtr, int) -> bool {
              auto cell = tvalue->prefetch_ref();
              if (cell.is_null()) {
                return true;
              }
              block::gen::Transaction::Record transaction;
              if (!tlb::unpack_cell(cell, transaction)) {
                return true;
              }
              status = cb(account, static_cast<uint64_t>(transaction.lt), cell->get_hash().bits());
              return status.is_ok();
            });
        return walked && status.is_ok();
      });
  TRY_STATUS(std::move(status));
  if (!complete) {
    return terminal("cannot walk the transactions of a window block");
  }
  return td::Status::OK();
}

namespace {
using BlockPassPhase = WalletIndexDb::BlockPassPhase;

// What a block pass must be bound to now, or an error when the index is not
// at the point where it runs.
td::Result<WalletIndexDb::BlockPassRecord> current_binding(WalletIndexDb& db, VerifySource& source) {
  auto state = db.get_verification_state();
  if (state.is_error()) {
    return terminal(state.error());
  }
  if (state.ok() != VerificationState::Partial) {
    return terminal("the block pass runs only on a partly verified index");
  }
  auto record = db.verification_record();
  if (record.is_error()) {
    return terminal(record.error());
  }
  if (!record.ok() || !record.ok().value().head) {
    return terminal("the index was not verified at a head");
  }
  WalletIndexDb::BlockPassRecord binding;
  binding.schema = tos_wallet_index::kWalletIndexSchemaVersion;
  binding.head = record.ok().value().head.value();
  TRY_RESULT(checkpoint, db.replay_checkpoint());
  if (!checkpoint || checkpoint.value().committed != binding.head) {
    return terminal("replay moved past the verified head before the block pass finished");
  }
  TRY_RESULT_ASSIGN(binding.base, db.get_window_base());
  TRY_RESULT_ASSIGN(binding.roots, source.state_roots(binding.head));
  return binding;
}

bool same_binding(const WalletIndexDb::BlockPassRecord& a, const WalletIndexDb::BlockPassRecord& b) {
  return a.schema == b.schema && a.head == b.head && a.roots == b.roots && a.base == b.base;
}

VerifyOutcome working(std::string phase) {
  VerifyOutcome outcome;
  outcome.step = VerifyStep::Working;
  outcome.reason = std::move(phase);
  return outcome;
}

td::Status write_pass_record(WalletIndexDb& db, const WalletIndexDb::BlockPassRecord& record, bool clear = false) {
  Batches batch(db, 1);
  TRY_STATUS(batch.begin());
  if (clear) {
    TRY_STATUS(db.clear_block_pass_work());
  }
  TRY_STATUS(db.put_block_pass_record(record));
  return batch.commit();
}
}  // namespace

td::Result<bool> block_pass_done(WalletIndexDb& db) {
  TRY_RESULT(record, db.block_pass_record());
  return record && record.value().phase == BlockPassPhase::Done;
}

td::Result<VerifyOutcome> run_block_pass_step(WalletIndexDb& db, VerifySource& source, const VerifyLimits& limits,
                                              const std::atomic<bool>* cancel) {
  auto cancelled = [cancel] { return cancel != nullptr && cancel->load(); };
  TRY_RESULT(binding, current_binding(db, source));
  auto stored = db.block_pass_record();
  if (stored.is_error()) {
    return terminal(stored.error());
  }
  const auto& head = binding.head;
  if (!stored.ok() || !same_binding(stored.ok().value(), binding)) {
    // A new pass, or one bound to a different head, state or base: nothing
    // of the old one, or of the ownership derivation, is kept.
    auto fresh = binding;
    fresh.phase = BlockPassPhase::Authenticate;
    fresh.cursor = head.seqno();
    fresh.expected = head;
    TRY_STATUS(write_pass_record(db, fresh, true));
    return working(PSTRING() << "blocks: authenticating from " << head.seqno());
  }
  auto record = stored.ok().value();
  if (record.phase == BlockPassPhase::Done) {
    VerifyOutcome done;
    done.step = VerifyStep::Done;
    return done;
  }
  bool has_base = record.base != 0;
  std::vector<WindowShardTip> base_tips;
  if (has_base) {
    TRY_RESULT(block, source.masterchain_block(record.base));
    if (!block) {
      return terminal(PSTRING() << "the node no longer holds the window base, masterchain block " << record.base);
    }
    base_tips = std::move(block.value().tips);
  }
  auto linked_inside = [](const VerifyMasterchainBlock& block) {
    return (!block.prev && !block.handle_prev && block.id.seqno() == 1) ||
           (block.prev && block.handle_prev && block.prev.value() == block.handle_prev.value());
  };

  if (record.phase == BlockPassPhase::Authenticate) {
    // Down from H to the block above the base, each block the one its
    // successor's checked bytes name; the base itself must match too.
    for (uint32_t steps = 0; steps < limits.authenticate_per_step && !cancelled(); ++steps) {
      auto seqno = record.cursor;
      if (seqno == record.base) {
        if (has_base) {
          TRY_RESULT(block, source.masterchain_block(seqno));
          if (!block || !record.expected || block.value().id != record.expected.value()) {
            return terminal(PSTRING() << "the window base, masterchain block " << seqno
                                      << ", is not linked to the verified head");
          }
        } else if (record.expected) {
          return terminal("the verified head does not reach the chain's first block");
        }
        record.phase = record.base == head.seqno() ? BlockPassPhase::Compare : BlockPassPhase::Collect;
        record.cursor = record.base + 1;
        // Collection starts above the base, whose identity `expected` holds
        // (unset when the window starts at the chain's first block).
        TRY_STATUS(write_pass_record(db, record));
        return working(PSTRING() << "blocks: collecting from " << record.cursor);
      }
      TRY_RESULT(block, source.masterchain_block(seqno));
      if (!block) {
        return terminal(PSTRING() << "the window has a gap: the node does not hold masterchain block " << seqno);
      }
      if (!record.expected || block.value().id != record.expected.value() || !linked_inside(block.value()) ||
          !block.value().applied) {
        return terminal(PSTRING() << "masterchain block " << seqno << " is not linked to the verified head");
      }
      record.expected = block.value().prev;
      record.cursor = seqno - 1;
    }
    TRY_STATUS(write_pass_record(db, record));
    return working(PSTRING() << "blocks: authenticating at " << record.cursor);
  }

  if (record.phase == BlockPassPhase::Collect) {
    TRY_RESULT(accounts, source.accounts(head));
    for (uint32_t steps = 0; steps < limits.intervals_per_step && !cancelled(); ++steps) {
      auto seqno = record.cursor;
      TRY_RESULT(block, source.masterchain_block(seqno));
      if (!block) {
        return terminal(PSTRING() << "the window has a gap: the node does not hold masterchain block " << seqno);
      }
      // The interval's block is the one the authenticated chain names.
      bool linked = linked_inside(block.value()) &&
                    ((!record.expected && !block.value().prev) ||
                     (record.expected && block.value().prev && block.value().prev.value() == record.expected.value()));
      if (!linked || !block.value().applied || (seqno == head.seqno() && block.value().id != head)) {
        return terminal(PSTRING() << "masterchain block " << seqno << " is not the authenticated one");
      }
      // Which accounts the head state cannot vouch for, decided once each.
      std::map<td::Bits256, bool> scope;
      Batches batch(db, std::numeric_limits<size_t>::max());
      TRY_STATUS(batch.begin());
      auto collected = record.collected;
      // A write batch entry (key, value and the batch's own framing), and a
      // scope decision (its tree node).
      constexpr size_t kRowBytes = 41 + 32 + 16;
      constexpr size_t kScopeBytes = 32 + 1 + 64;
      size_t interval_bytes = 0;
      auto charge = [&](size_t bytes) -> td::Status {
        interval_bytes += bytes;
        if (interval_bytes > limits.interval_bytes) {
          return terminal(PSTRING() << "masterchain interval " << seqno << " needs more than "
                                    << (limits.interval_bytes >> 20) << " MiB to collect; it is not verified");
        }
        return td::Status::OK();
      };
      auto status = source.for_each_interval_transaction(
          block.value(),
          [&](const td::Bits256& account, uint64_t lt, const td::Bits256& hash) -> td::Status {
            auto it = scope.find(account);
            if (it == scope.end()) {
              TRY_STATUS(charge(kScopeBytes));
              TRY_RESULT(marked, db.is_unverified_account(account));
              bool in_scope = marked;
              if (!in_scope) {
                TRY_RESULT(found, accounts->find(account));
                in_scope = !found;
              }
              it = scope.emplace(account, in_scope).first;
            }
            if (!it->second) {
              return td::Status::OK();
            }
            TRY_RESULT(bound, base_lt_bound(base_tips, has_base, account));
            if (lt <= bound) {
              return td::Status::OK();
            }
            if (++collected > limits.collected_rows_max) {
              return terminal(PSTRING() << "the block pass would collect more than " << limits.collected_rows_max
                                        << " rows; it is not verified");
            }
            TRY_STATUS(charge(kRowBytes));
            return db.put_collected(account, lt, hash);
          },
          cancel);
      if (status.is_error()) {
        batch.abort();
        return std::move(status);
      }
      record.collected = collected;
      record.expected = block.value().id;
      record.cursor = seqno + 1;
      if (seqno == head.seqno()) {
        record.phase = BlockPassPhase::Compare;
        record.compared = td::optional<td::Bits256>{};
      }
      TRY_STATUS(db.put_block_pass_record(record));
      TRY_STATUS(batch.commit());
      if (record.phase == BlockPassPhase::Compare) {
        return working("blocks: comparing");
      }
    }
    return working(PSTRING() << "blocks: collecting at " << record.cursor << " of " << head.seqno());
  }

  // Compare, account by account in key order, over the collected accounts
  // and the marked ones.
  for (uint32_t steps = 0; steps < limits.compare_per_step && !cancelled(); ++steps) {
    TRY_RESULT(collected_next, db.next_collected_account(record.compared));
    TRY_RESULT(marked_next, db.next_unverified_account(record.compared));
    if (!collected_next && !marked_next) {
      record.phase = BlockPassPhase::Done;
      TRY_STATUS(write_pass_record(db, record));
      VerifyOutcome done;
      done.step = VerifyStep::Done;
      return done;
    }
    td::Bits256 account = !collected_next                 ? marked_next.value()
                          : !marked_next                  ? collected_next.value()
                          : collected_next.value() < marked_next.value() ? collected_next.value()
                                                                         : marked_next.value();
    TRY_RESULT(bound, base_lt_bound(base_tips, has_base, account));
    std::vector<std::pair<uint64_t, td::Bits256>> imported, collected;
    TRY_STATUS(db.for_each_event(account, tos_wallet_index::kMaxEventsPerAccount,
                                 [&](uint64_t lt, td::Ref<vm::Cell> cell) -> td::Status {
                                   if (lt > bound) {
                                     imported.emplace_back(lt, cell->get_hash().bits());
                                   }
                                   return td::Status::OK();
                                 }));
    TRY_STATUS(db.for_each_collected(account, tos_wallet_index::kMaxEventsPerAccount,
                                     [&](uint64_t lt, const td::Bits256& hash) -> td::Status {
                                       collected.emplace_back(lt, hash);
                                       return td::Status::OK();
                                     }));
    if (imported != collected) {
      std::string why;
      if (imported.empty()) {
        why = "the snapshot omits the account's history in the window";
      } else {
        size_t i = 0;
        while (i < imported.size() && i < collected.size() && imported[i] == collected[i]) {
          ++i;
        }
        why = i < collected.size() ? PSTRING() << "the window's blocks hold a transaction at " << collected[i].first
                                               << " the snapshot does not match"
                                   : PSTRING() << "the snapshot holds a row at " << imported[i].first
                                               << " the window's blocks do not";
      }
      return refuse(db, PSTRING() << account_text(account) << ": " << why, account);
    }
    Batches batch(db, 1);
    TRY_STATUS(batch.begin());
    TRY_STATUS(db.erase_unverified_account(account));
    record.compared = account;
    TRY_STATUS(db.put_block_pass_record(record));
    TRY_STATUS(batch.commit());
  }
  return working("blocks: comparing");
}

const char* verification_state_name(VerificationState state) {
  switch (state) {
    case VerificationState::Full:
      return "full";
    case VerificationState::Quarantined:
      return "quarantined";
    case VerificationState::Partial:
      return "partial";
    case VerificationState::Refused:
      return "refused";
  }
  return "unknown";
}

bool VerifyRetry::failed(td::Slice error, double now, uint32_t unix_now) {
  std::lock_guard<std::mutex> guard(mutex_);
  auto message = truncated(error);
  bool first = attempts_ == 0;
  if (first) {
    since_ = unix_now;
  }
  if (attempts_ != std::numeric_limits<uint64_t>::max()) {
    ++attempts_;
  }
  bool log = first || message != last_error_ || now - last_logged_ >= kLogIntervalSeconds;
  if (log) {
    last_logged_ = now;
  }
  last_error_ = std::move(message);
  next_attempt_ = now + delay_after(attempts_);
  return log;
}

void VerifyRetry::succeeded() {
  std::lock_guard<std::mutex> guard(mutex_);
  attempts_ = 0;
  since_ = 0;
  last_error_.clear();
  next_attempt_ = 0;
  last_logged_ = 0;
}

double VerifyRetry::next_attempt() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return next_attempt_;
}

uint64_t VerifyRetry::attempts() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return attempts_;
}

double VerifyRetry::delay_after(uint64_t attempts) {
  double delay = kFirstDelaySeconds;
  for (uint64_t i = 1; i < attempts && delay < kMaxDelaySeconds; ++i) {
    delay = std::min(delay * 2, kMaxDelaySeconds);
  }
  return delay;
}

std::string VerifyRetry::truncated(td::Slice error) {
  size_t size = std::min(error.size(), kMaxErrorBytes);
  if (size < error.size()) {
    // Back up to the start of the sequence the cut would split.
    while (size > 0 && (static_cast<unsigned char>(error[size]) & 0xC0) == 0x80) {
      --size;
    }
  }
  return error.substr(0, size).str();
}

std::string VerifyRetry::json() const {
  std::lock_guard<std::mutex> guard(mutex_);
  if (attempts_ == 0) {
    return "null";
  }
  td::StringBuilder sb;
  sb << "{\"attempts\":" << attempts_ << ",\"since\":" << since_ << ",\"last_error\":" << td::JsonString(last_error_)
     << "}";
  return sb.as_cslice().str();
}

std::string ServingGate::json_fields() const {
  std::string body = std::string(",\"verification\":\"") + verification_state_name(state()) + "\",\"verified_horizon\":";
  if (!horizon_known_.load()) {
    body += "null";
  } else {
    body += "{\"masterchain_seqno\":" + std::to_string(horizon_seqno_.load()) +
            ",\"unix_time\":" + std::to_string(horizon_time_.load()) +
            ",\"unverified_accounts\":" + std::to_string(unverified_.load()) + "}";
  }
  body += ",\"verification_retry\":" + retry.json() + ",\"verification_phase\":";
  {
    std::lock_guard<std::mutex> guard(phase_mutex_);
    if (held_) {
      td::StringBuilder sb;
      sb << td::JsonString(phase_);
      body += sb.as_cslice().str();
    } else {
      body += "null";
    }
  }
  return body;
}

}  // namespace tos::services
