/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Verification of an imported wallet index against the local node's chain:
// the window walk, the age keys it assigns, and the check at the head, over a
// fixture source and a real index database.
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "services/index-verify.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator-engine/wallet-index.h"
#include "vm/cells/CellBuilder.h"

namespace {
using tos::BlockIdExt;
using tos::ShardIdFull;
using tos::services::HeadAccounts;
using tos::services::prepare_quarantined_index;
using tos::services::ServingGate;
using tos::services::verify_index_at_head;
using tos::services::VerifyLimits;
using tos::services::VerifyMasterchainBlock;
using tos::services::VerifyRetry;
using tos::services::VerifySource;
using tos::services::VerifyStep;
using tos_wallet_index::AccountHead;
using tos_wallet_index::VerificationState;
using tos_wallet_index::WalletIndexDb;
using tos_wallet_index::WindowShardTip;

constexpr uint64_t kLeft = 0x4000000000000000ull;   // addresses starting with bit 0
constexpr uint64_t kRight = 0xC000000000000000ull;  // addresses starting with bit 1
constexpr uint64_t kAll = 0x8000000000000000ull;
// Masterchain blocks are this far apart, so the retention window spans six of
// them: at checkpoint 20 its base is block 13.
constexpr uint32_t kBlockSeconds = 100000;

td::Bits256 address(unsigned char top) {
  td::Bits256 out = td::Bits256::zero();
  out.as_slice()[0] = static_cast<char>(top);
  out.as_slice()[31] = 7;
  return out;
}

BlockIdExt master_id(uint32_t seqno, unsigned char salt = 0) {
  td::Bits256 root = td::Bits256::zero(), file = td::Bits256::zero();
  root.as_slice()[0] = static_cast<char>(seqno & 0xff);
  root.as_slice()[1] = static_cast<char>(seqno >> 8);
  root.as_slice()[2] = static_cast<char>(salt);
  file.as_slice()[0] = static_cast<char>(seqno & 0xff);
  file.as_slice()[3] = 1;
  return BlockIdExt{tos::masterchainId, tos::shardIdAll, seqno, root, file};
}

td::Ref<vm::Cell> transaction(const td::Bits256& account, uint64_t lt, const td::Bits256& prev_hash, uint64_t prev_lt,
                              unsigned body = 0) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(7, 4) && cb.store_bits_bool(account.cbits(), 256) && cb.store_long_bool(lt, 64) &&
        cb.store_bits_bool(prev_hash.cbits(), 256) && cb.store_long_bool(prev_lt, 64) &&
        cb.store_long_bool(static_cast<long long>(lt / 10), 32) && cb.store_long_bool(body, 8));
  return cb.finalize();
}

// An account's transactions, oldest first; the first has predecessor
// `first_prev_lt` (0: none, an account creation).
std::vector<td::Ref<vm::Cell>> history(const td::Bits256& account, const std::vector<uint64_t>& lts,
                                       uint64_t first_prev_lt) {
  std::vector<td::Ref<vm::Cell>> out;
  td::Bits256 prev = first_prev_lt == 0 ? td::Bits256::zero() : address(0xEE);
  uint64_t prev_lt = first_prev_lt;
  for (auto lt : lts) {
    out.push_back(transaction(account, lt, prev, prev_lt));
    prev = out.back()->get_hash().bits();
    prev_lt = lt;
  }
  return out;
}

AccountHead head_of(const std::vector<td::Ref<vm::Cell>>& oldest_first) {
  auto link = tos_wallet_index::parse_transaction_link(oldest_first.back()).move_as_ok();
  return AccountHead{link.lt, link.hash};
}

class FixtureAccounts final : public HeadAccounts {
 public:
  FixtureAccounts(std::map<td::Bits256, AccountHead> heads, std::shared_ptr<int> walk_failures)
      : heads_(std::move(heads)), walk_failures_(std::move(walk_failures)) {
  }
  td::Status for_each(const std::function<td::Status(const td::Bits256&, const AccountHead&)>& cb) override {
    if (walk_failures_ && *walk_failures_ > 0) {
      --*walk_failures_;
      return td::Status::Error("transient state read failure");
    }
    for (auto& [account, head] : heads_) {
      TRY_STATUS(cb(account, head));
    }
    return td::Status::OK();
  }
  td::Result<td::optional<AccountHead>> find(const td::Bits256& account) override {
    auto it = heads_.find(account);
    if (it == heads_.end()) {
      return td::optional<AccountHead>{};
    }
    return td::optional<AccountHead>(it->second);
  }

 private:
  std::map<td::Bits256, AccountHead> heads_;
  std::shared_ptr<int> walk_failures_;
};

// Masterchain blocks 1..tip, each `kBlockSeconds` after the one before.
// Without a split (`split_at` 1) there are two basechain shards and the right
// one's logical time lags the left one's. Otherwise one shard covers
// everything before `split_at` and its halves continue from its end lt.
struct FixtureSource final : public VerifySource {
  explicit FixtureSource(uint32_t tip_in, uint32_t split_at = 1) : tip_seqno(tip_in) {
    for (uint32_t s = 1; s <= tip_seqno; ++s) {
      VerifyMasterchainBlock block;
      block.id = master_id(s);
      if (s > 1) {
        block.prev = master_id(s - 1);
        block.handle_prev = master_id(s - 1);
      }
      block.applied = true;
      block.unix_time = s * kBlockSeconds;
      if (s < split_at) {
        block.tips = {WindowShardTip{ShardIdFull{0, kAll}, 1000ull * s}};
      } else {
        uint64_t right = split_at == 1 ? 100ull * s + 50 : 1000ull * (split_at - 1) + 100ull * (s - split_at + 1) + 50;
        block.tips = {WindowShardTip{ShardIdFull{0, kLeft}, 1000ull * s}, WindowShardTip{ShardIdFull{0, kRight}, right}};
      }
      blocks[s] = block;
    }
  }
  td::Result<BlockIdExt> tip() override {
    return master_id(tip_seqno);
  }
  td::Result<td::optional<VerifyMasterchainBlock>> masterchain_block(uint32_t seqno) override {
    auto error = errors.find(seqno);
    if (error != errors.end()) {
      return td::Status::Error(error->second);
    }
    auto it = blocks.find(seqno);
    if (it == blocks.end()) {
      return td::optional<VerifyMasterchainBlock>{};
    }
    return td::optional<VerifyMasterchainBlock>(it->second);
  }
  td::Result<std::unique_ptr<HeadAccounts>> accounts(const BlockIdExt& head) override {
    if (head != master_id(head.seqno())) {
      return td::Status::Error("no such head");
    }
    return std::unique_ptr<HeadAccounts>(new FixtureAccounts(heads, walk_failures));
  }
  uint32_t tip_seqno;
  // The head state's walk fails this many times before it succeeds.
  std::shared_ptr<int> walk_failures = std::make_shared<int>(0);
  std::map<uint32_t, VerifyMasterchainBlock> blocks;
  std::map<uint32_t, std::string> errors;
  std::map<td::Bits256, AccountHead> heads;
};

struct TempIndex {
  TempIndex() {
    dir = td::mkdtemp(td::get_temporary_dir(), "wallet-index-verify").move_as_ok();
    db = WalletIndexDb::open(dir + "/index").move_as_ok();
  }
  ~TempIndex() {
    db.reset();
    td::rmrf(dir).ignore();
  }
  // What an untrusted import leaves: the schema, the checkpoint, the rows and
  // the Quarantined state.
  void import(const BlockIdExt& checkpoint, const std::vector<td::Ref<vm::Cell>>& rows,
              const BlockIdExt& anchor = master_id(1)) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    db->begin_batch().ensure();
    for (const auto& row : rows) {
      auto link = tos_wallet_index::parse_transaction_link(row).move_as_ok();
      db->put_event(link.account, link.lt, row).ensure();
    }
    db->put_verification_state(VerificationState::Quarantined).ensure();
    db->commit_batch().ensure();
    db->commit_replay_checkpoint({anchor, checkpoint}).ensure();
  }
  // Replay to `head`, as the service does after the preparation.
  void replayed_to(const BlockIdExt& head) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    db->commit_replay_checkpoint({master_id(1), head}).ensure();
  }
  void add(const td::Ref<vm::Cell>& row) {
    auto link = tos_wallet_index::parse_transaction_link(row).move_as_ok();
    put(link.account, link.lt, row);
  }
  void put(const td::Bits256& account, uint64_t lt, const td::Ref<vm::Cell>& row) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    db->begin_batch().ensure();
    db->put_event(account, lt, row).ensure();
    db->commit_batch().ensure();
  }
  void erase(const td::Bits256& account, uint64_t lt) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    db->begin_batch().ensure();
    db->erase_event(account, lt).ensure();
    db->commit_batch().ensure();
  }
  // (account, lt) -> masterchain block of every age row.
  std::map<std::pair<td::Bits256, uint64_t>, uint32_t> ages() {
    std::map<std::pair<td::Bits256, uint64_t>, uint32_t> out;
    db->for_each_key_with_prefix(td::Slice("\x14", 1), 1u << 20, [&](td::Slice key) {
        CHECK(key.size() == 1 + 4 + 32 + 8);
        uint32_t mc = 0;
        uint64_t lt = 0;
        for (int i = 0; i < 4; ++i)
          mc = (mc << 8) | static_cast<uint8_t>(key[1 + i]);
        for (int i = 0; i < 8; ++i)
          lt = (lt << 8) | static_cast<uint8_t>(key[1 + 4 + 32 + i]);
        td::Bits256 account;
        account.as_slice().copy_from(key.substr(1 + 4, 32));
        out[{account, lt}] = mc;
        return td::Status::OK();
      }).ensure();
    return out;
  }
  std::set<uint64_t> lts(const td::Bits256& account) {
    std::set<uint64_t> out;
    db->for_each_event(account, 1u << 20, [&](uint64_t lt, td::Ref<vm::Cell>) {
        out.insert(lt);
        return td::Status::OK();
      }).ensure();
    return out;
  }
  VerificationState state() {
    return db->get_verification_state().move_as_ok();
  }
  std::string dir;
  std::unique_ptr<WalletIndexDb> db;
};

bool contains(const std::string& text, const std::string& part) {
  return text.find(part) != std::string::npos;
}
}  // namespace

// Each kept row is keyed by the masterchain block that first referenced it,
// per shard, so a shard whose logical time lags the other is not judged by
// the other's progress; rows the window base already referenced are dropped.
TEST(WalletIndexVerify, rows_get_the_block_that_first_referenced_them_per_shard) {
  FixtureSource source(20);
  TempIndex index;
  auto left = address(0x10), right = address(0x90);
  // Base block 13: left bound 13000, right bound 1350.
  std::vector<td::Ref<vm::Cell>> rows;
  for (auto& row : history(left, {12500, 13000, 13001, 16999, 17000, 19999}, 0))
    rows.push_back(row);
  for (auto& row : history(right, {1300, 1351, 1450, 1451, 2049}, 0))
    rows.push_back(row);
  index.import(master_id(20), rows);
  auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  ASSERT_EQ(outcome.kept, 8u);
  ASSERT_EQ(outcome.dropped, 3u);
  std::map<std::pair<td::Bits256, uint64_t>, uint32_t> expected = {
      {{left, 13001}, 14}, {{left, 16999}, 17}, {{left, 17000}, 18},  {{left, 19999}, 20},
      {{right, 1351}, 14}, {{right, 1450}, 15}, {{right, 1451}, 15}, {{right, 2049}, 20}};
  ASSERT_TRUE(index.ages() == expected);
  ASSERT_TRUE(index.lts(left) == (std::set<uint64_t>{13001, 16999, 17000, 19999}));
  ASSERT_TRUE(index.lts(right) == (std::set<uint64_t>{1351, 1450, 1451, 2049}));
  ASSERT_EQ(index.db->get_window_base().move_as_ok(), 13u);
  auto record = index.db->verification_record().move_as_ok();
  ASSERT_TRUE(record);
  ASSERT_EQ(record.value().base, 13u);
  ASSERT_EQ(record.value().horizon_time, 13 * kBlockSeconds);
  ASSERT_TRUE(record.value().checkpoint == master_id(20));
  ASSERT_TRUE(!record.value().head);
  ASSERT_TRUE(index.state() == VerificationState::Quarantined);
}

// Across a split inside the window, an account's row is keyed by the tip of
// whichever shard covered it then: the parent before the split, its half after.
TEST(WalletIndexVerify, rows_are_keyed_across_a_split_in_the_window) {
  FixtureSource source(20, 16);
  TempIndex index;
  auto right = address(0x90);
  // One shard to block 15 (end lt 1000*s); from 16 the right half ends at
  // 15150, 15250, ... An lt of 14500 is referenced by block 15. One of 15150
  // is not referenced by block 16, whose right tip ends exactly there, so by
  // block 17, as is 15151.
  index.import(master_id(20), history(right, {14500, 15150, 15151}, 0));
  auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  std::map<std::pair<td::Bits256, uint64_t>, uint32_t> expected = {
      {{right, 14500}, 15}, {{right, 15150}, 17}, {{right, 15151}, 17}};
  ASSERT_TRUE(index.ages() == expected);
}

// The walk stops at the first block the node does not hold: the block above
// the gap is the verified horizon and everything it referenced is dropped. A
// gap below the window base changes nothing.
TEST(WalletIndexVerify, the_window_walk_stops_at_a_gap_and_reports_the_horizon) {
  auto left = address(0x10);
  {
    FixtureSource source(20);
    source.blocks.erase(16);
    TempIndex index;
    index.import(master_id(20), history(left, {15000, 17500, 19000}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Done);
    ASSERT_EQ(outcome.dropped, 1u);
    auto record = index.db->verification_record().move_as_ok().value();
    ASSERT_EQ(record.base, 17u);
    ASSERT_EQ(record.horizon_seqno, 17u);
    ASSERT_EQ(record.horizon_time, 17 * kBlockSeconds);
    ASSERT_EQ(index.db->get_window_base().move_as_ok(), 17u);
    ASSERT_TRUE(index.lts(left) == (std::set<uint64_t>{17500, 19000}));
  }
  {
    FixtureSource source(20);
    source.blocks.erase(9);
    TempIndex index;
    index.import(master_id(20), history(left, {15000}, 0));
    ASSERT_TRUE(prepare_quarantined_index(*index.db, source).move_as_ok().step == VerifyStep::Done);
    ASSERT_EQ(index.db->verification_record().move_as_ok().value().base, 13u);
  }
  {
    // A chain younger than the window: everything from block 1 is kept.
    FixtureSource source(5);
    TempIndex index;
    index.import(master_id(5), history(left, {500, 4500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Done);
    ASSERT_EQ(outcome.kept, 2u);
    ASSERT_EQ(index.db->verification_record().move_as_ok().value().base, 0u);
    std::map<std::pair<td::Bits256, uint64_t>, uint32_t> expected = {{{left, 500}, 1}, {{left, 4500}, 5}};
    ASSERT_TRUE(index.ages() == expected);
  }
}

// A failed lookup is never read as "not held", and blocks that do not link
// are never walked over: the preparation fails and records nothing.
TEST(WalletIndexVerify, a_lookup_error_or_an_unlinked_block_stops_the_walk_without_a_record) {
  auto left = address(0x10);
  {
    FixtureSource source(20);
    source.errors[15] = "transient source failure";
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(!index.db->verification_record().move_as_ok());
    ASSERT_TRUE(index.state() == VerificationState::Quarantined);
  }
  {
    FixtureSource source(20);
    source.blocks[16].prev = master_id(15, 1);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(contains(outcome.error().message().str(), "not linked"));
    ASSERT_TRUE(!index.db->verification_record().move_as_ok());
  }
  {
    // A forged segment: an applied sibling stands where block 15 was, while
    // block 16 still names the real one.
    FixtureSource source(20);
    source.blocks[15].id = master_id(15, 2);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(contains(outcome.error().message().str(), "not linked"));
    ASSERT_TRUE(!index.db->verification_record().move_as_ok());
    ASSERT_TRUE(index.state() == VerificationState::Quarantined);
  }
  {
    // A handle whose recorded previous block is not the one its own bytes
    // name.
    FixtureSource source(20);
    source.blocks[16].handle_prev = master_id(15, 3);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(contains(outcome.error().message().str(), "not linked"));
    ASSERT_TRUE(!index.db->verification_record().move_as_ok());
  }
  {
    // A transient source failure is retryable, not terminal.
    FixtureSource source(20);
    source.errors[15] = "transient source failure";
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(!tos::services::is_terminal_verify_error(outcome.error()));
  }
}

// The checkpoint's anchor is authenticated only by this node's own block 1:
// a different one refuses the snapshot, and without block 1 the record says
// the anchor is unverified.
TEST(WalletIndexVerify, the_anchor_is_checked_against_this_nodes_first_block) {
  auto left = address(0x10);
  {
    FixtureSource source(20);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0), master_id(1, 4));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(contains(outcome.reason, "anchor is not this node's first block"));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  }
  {
    FixtureSource source(20);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0));
    ASSERT_TRUE(prepare_quarantined_index(*index.db, source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(index.db->verification_record().move_as_ok().value().anchor_verified);
  }
  {
    // A node that joined later cannot check any anchor, a forged one included.
    FixtureSource source(20);
    for (uint32_t s = 1; s < 10; ++s)
      source.blocks.erase(s);
    TempIndex index;
    index.import(master_id(20), history(left, {17500}, 0), master_id(1, 4));
    ASSERT_TRUE(prepare_quarantined_index(*index.db, source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(!index.db->verification_record().move_as_ok().value().anchor_verified);
  }
}

// The checkpoint binds the snapshot to this node's chain: a block the node
// has a different identity for, one older than the node's history, and a row
// newer than the checkpoint all refuse it; a checkpoint the node has not
// reached yet waits.
TEST(WalletIndexVerify, the_checkpoint_must_be_this_nodes_block) {
  auto left = address(0x10);
  {
    FixtureSource source(20);
    TempIndex index;
    index.import(master_id(18, 9), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(contains(outcome.reason, "not this node's masterchain block"));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  }
  {
    FixtureSource source(20);
    for (uint32_t s = 1; s < 8; ++s)
      source.blocks.erase(s);
    TempIndex index;
    index.import(master_id(5), history(left, {4500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(contains(outcome.reason, "snapshot older than this node's history"));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  }
  {
    FixtureSource source(20);
    TempIndex index;
    index.import(master_id(18), history(left, {17500, 18000}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(contains(outcome.reason, "newer than the snapshot checkpoint"));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  }
  {
    FixtureSource source(20);
    source.tip_seqno = 17;
    TempIndex index;
    index.import(master_id(18), history(left, {17500}, 0));
    auto outcome = prepare_quarantined_index(*index.db, source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Wait);
    ASSERT_TRUE(index.state() == VerificationState::Quarantined);
    ASSERT_TRUE(!index.db->verification_record().move_as_ok());
  }
}

namespace {
// An honest index at checkpoint 20, replayed to head 22 (window base 13,
// left bound 13000, right bound 1350), and the head state of every account.
struct HeadCase {
  HeadCase() : source(22) {
    // Linked across the window bound: complete.
    linked = history(a, {12000, 13500, 15000, 21000}, 11000);
    // Created inside the window: the state cannot show an earlier life.
    created = history(b, {1400, 1500}, 0);
    // Destroyed inside the window: absent from the head state.
    destroyed = history(d, {14000, 16000}, 13900);
    // Last active before the window: no rows.
    dormant = history(e, {9000}, 8000);
    source.heads[a] = head_of(linked);
    source.heads[b] = head_of(created);
    source.heads[e] = head_of(dormant);
  }
  void import(TempIndex& index) {
    // Rows up to the checkpoint come from the snapshot; the newest row of
    // `linked` comes later, from the replay to the head.
    std::vector<td::Ref<vm::Cell>> rows(linked.begin(), linked.end() - 1);
    rows.insert(rows.end(), created.begin(), created.end());
    rows.insert(rows.end(), destroyed.begin(), destroyed.end());
    index.import(master_id(20), rows);
    auto prepared = prepare_quarantined_index(*index.db, source).move_as_ok();
    CHECK(prepared.step == VerifyStep::Done);
    index.add(linked.back());
    index.replayed_to(master_id(22));
  }
  td::Result<tos::services::VerifyOutcome> verify(TempIndex& index) {
    return verify_index_at_head(*index.db, source, master_id(22));
  }
  FixtureSource source;
  td::Bits256 a = address(0x10), b = address(0x90), d = address(0x20), e = address(0x30), f = address(0x40);
  std::vector<td::Ref<vm::Cell>> linked, created, destroyed, dormant;
};
}  // namespace

// An honest import is Partial, never Full: accounts created inside the
// window and accounts absent from the head are marked for the window's
// blocks, and ownership is not derived yet.
TEST(WalletIndexVerify, an_honest_import_is_partial_with_the_unprovable_accounts_marked) {
  HeadCase c;
  TempIndex index;
  c.import(index);
  auto outcome = c.verify(index).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  ASSERT_EQ(outcome.unverified, 2u);
  ASSERT_TRUE(index.state() == VerificationState::Partial);
  ASSERT_TRUE(!index.db->is_unverified_account(c.a).move_as_ok());
  ASSERT_TRUE(index.db->is_unverified_account(c.b).move_as_ok());
  ASSERT_TRUE(index.db->is_unverified_account(c.d).move_as_ok());
  ASSERT_TRUE(!index.db->is_unverified_account(c.e).move_as_ok());
  auto record = index.db->verification_record().move_as_ok().value();
  ASSERT_TRUE(record.head && record.head.value() == master_id(22));
  ASSERT_EQ(record.unverified, 2u);
  // The row the window base had referenced was dropped by the preparation.
  ASSERT_TRUE(index.lts(c.a) == (std::set<uint64_t>{13500, 15000, 21000}));
}

// Every contradiction with the head state refuses the import and names the
// account: a changed row, an omitted one, a row injected for an account
// whose last transaction is before the window, a row served under another
// logical time, and in-window history left out entirely.
TEST(WalletIndexVerify, rows_that_contradict_the_head_state_refuse_the_import) {
  auto refused = [](const std::function<void(HeadCase&, TempIndex&)>& tamper, td::Bits256 HeadCase::*who,
                    const std::string& why) {
    HeadCase c;
    TempIndex index;
    c.import(index);
    tamper(c, index);
    auto outcome = c.verify(index).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(outcome.account && outcome.account.value() == c.*who);
    ASSERT_TRUE(contains(outcome.reason, why));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  };
  // Tampered: a row's body changed under the same logical time.
  refused([](HeadCase& c, TempIndex& index) { index.put(c.a, 15000, transaction(c.a, 15000, td::Bits256::zero(), 13500, 1)); },
          &HeadCase::a, "not hash-linked");
  // Omitted: a middle row deleted.
  refused([](HeadCase& c, TempIndex& index) { index.erase(c.a, 15000); }, &HeadCase::a, "not hash-linked");
  // Injected: a row for an account last active before the window.
  refused([](HeadCase& c, TempIndex& index) { index.add(transaction(c.e, 17000, c.dormant.back()->get_hash().bits(), 9000)); },
          &HeadCase::e, "newer than the account's last transaction");
  // A row stored under a logical time its transaction does not have.
  refused([](HeadCase& c, TempIndex& index) { index.put(c.a, 15001, c.linked[2]); }, &HeadCase::a,
          "holds the transaction at");
  // Missing: an account active in the window with no rows at all.
  refused(
      [](HeadCase& c, TempIndex&) {
        c.source.heads[c.f] = head_of(history(c.f, {18000}, 17000));
      },
      &HeadCase::f, "in-window history is missing");
}

// A recreated account whose first incarnation's rows were left out still
// links from its head down to the recreation: it is marked for the window's
// blocks, never accepted as complete.
TEST(WalletIndexVerify, a_recreated_account_missing_its_first_life_is_never_complete) {
  HeadCase c;
  TempIndex index;
  auto r = address(0x50);
  auto second = history(r, {18000, 19000}, 0);
  c.source.heads[r] = head_of(second);
  c.import(index);
  for (auto& row : second)
    index.add(row);
  auto outcome = c.verify(index).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  ASSERT_TRUE(index.db->is_unverified_account(r).move_as_ok());
  ASSERT_TRUE(index.state() == VerificationState::Partial);
}

// A head check that fails after its first pass has committed (several
// batches of it) and is run again ends exactly as one that never failed.
TEST(WalletIndexVerify, an_interrupted_head_check_reruns_to_the_same_result) {
  VerifyLimits small;
  small.batch_writes = 1;
  HeadCase straight, interrupted;
  TempIndex straight_index, interrupted_index;
  straight.import(straight_index);
  interrupted.import(interrupted_index);
  auto expected = verify_index_at_head(*straight_index.db, straight.source, master_id(22), small).move_as_ok();
  *interrupted.source.walk_failures = 1;
  auto failed = verify_index_at_head(*interrupted_index.db, interrupted.source, master_id(22), small);
  ASSERT_TRUE(failed.is_error());
  ASSERT_TRUE(!tos::services::is_terminal_verify_error(failed.error()));
  ASSERT_TRUE(interrupted_index.state() == VerificationState::Quarantined);
  ASSERT_TRUE(!interrupted_index.db->verification_record().move_as_ok().value().head);
  auto rerun = verify_index_at_head(*interrupted_index.db, interrupted.source, master_id(22), small).move_as_ok();
  ASSERT_TRUE(rerun.step == VerifyStep::Done && expected.step == VerifyStep::Done);
  ASSERT_EQ(rerun.unverified, expected.unverified);
  ASSERT_TRUE(interrupted_index.state() == VerificationState::Partial);
  for (auto& account : {straight.a, straight.b, straight.d, straight.e}) {
    ASSERT_TRUE(interrupted_index.lts(account) == straight_index.lts(account));
    ASSERT_EQ(interrupted_index.db->is_unverified_account(account).move_as_ok(),
              straight_index.db->is_unverified_account(account).move_as_ok());
  }
  ASSERT_TRUE(interrupted_index.ages() == straight_index.ages());
}

// A failure that never clears is retried with a delay doubling from 5 s to
// a 5 min cap, logged on its first occurrence, when it changes and at most
// every 5 min otherwise, and reported with its attempts, since when and the
// last error, truncated without splitting a character; success resets it.
TEST(WalletIndexVerify, retries_back_off_to_a_cap_and_stay_visible) {
  std::vector<double> delays;
  for (uint64_t attempts = 1; attempts <= 9; ++attempts)
    delays.push_back(VerifyRetry::delay_after(attempts));
  ASSERT_TRUE(delays == (std::vector<double>{5, 10, 20, 40, 80, 160, 300, 300, 300}));
  VerifyRetry retry;
  ASSERT_EQ(retry.json(), std::string("null"));
  ASSERT_TRUE(retry.failed("source not ready", 1000, 1700000000));
  ASSERT_EQ(retry.next_attempt(), 1005.0);
  ASSERT_TRUE(!retry.failed("source not ready", 1005, 1700000005));
  ASSERT_EQ(retry.next_attempt(), 1015.0);
  ASSERT_TRUE(retry.failed("another failure", 1015, 1700000015));
  ASSERT_TRUE(!retry.failed("another failure", 1035, 1700000035));
  ASSERT_TRUE(retry.failed("another failure", 1315, 1700000315));
  ASSERT_EQ(retry.attempts(), 5u);
  ASSERT_TRUE(contains(retry.json(),
                       "{\"attempts\":5,\"since\":1700000000,\"last_error\":\"another failure\"}"));
  retry.succeeded();
  ASSERT_EQ(retry.attempts(), 0u);
  ASSERT_EQ(retry.json(), std::string("null"));
  // A message of two-byte characters is cut at a character boundary.
  std::string wide;
  for (int i = 0; i < 400; ++i)
    wide += "\xc3\xa9";
  auto cut = VerifyRetry::truncated(wide);
  ASSERT_TRUE(cut.size() <= VerifyRetry::kMaxErrorBytes && cut.size() % 2 == 0 && !cut.empty());
  ASSERT_EQ(VerifyRetry::truncated("short"), std::string("short"));
}

// The serving gate: Full is served, Partial only when the operator allowed
// it, Quarantined and Refused never; /readyz names the state.
TEST(WalletIndexVerify, the_serving_gate_follows_the_verification_state) {
  ServingGate strict(false), lenient(true);
  for (auto* gate : {&strict, &lenient}) {
    ASSERT_TRUE(!gate->serving());
    ASSERT_TRUE(contains(gate->json_fields(),
                         "\"verification\":\"quarantined\",\"verified_horizon\":null,\"verification_retry\":null"));
    gate->set(VerificationState::Refused);
    ASSERT_TRUE(!gate->serving());
    gate->set(VerificationState::Full);
    ASSERT_TRUE(gate->serving());
    ASSERT_TRUE(!gate->partial());
  }
  strict.set(VerificationState::Partial);
  lenient.set(VerificationState::Partial);
  ASSERT_TRUE(!strict.serving());
  ASSERT_TRUE(lenient.serving());
  ASSERT_TRUE(lenient.partial());
  lenient.set_horizon(13, 1300000, 2);
  ASSERT_TRUE(contains(lenient.json_fields(),
                       "\"verification\":\"partial\",\"verified_horizon\":{\"masterchain_seqno\":13,\"unix_time\":"
                       "1300000,\"unverified_accounts\":2}"));
}
