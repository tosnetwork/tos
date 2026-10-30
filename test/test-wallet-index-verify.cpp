/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Verification of an imported wallet index against the local node's chain:
// the window walk, the age keys it assigns, and the check at the head, over a
// fixture source and a real index database.
#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "services/index-verify.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

#include "wallet-index-chain-fixture.h"

namespace {
using tos::BlockIdExt;
using tos::ShardIdFull;
using tos::services::block_pass_done;
using tos::services::HeadAccounts;
using tos::services::prepare_quarantined_index;
using tos::services::run_block_pass_step;
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
                              unsigned body = 0, const td::Ref<vm::Cell>& attached = {}) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(7, 4) && cb.store_bits_bool(account.cbits(), 256) && cb.store_long_bool(lt, 64) &&
        cb.store_bits_bool(prev_hash.cbits(), 256) && cb.store_long_bool(prev_lt, 64) &&
        cb.store_long_bool(static_cast<long long>(lt / 10), 32) && cb.store_long_bool(body, 8));
  if (attached.not_null()) {
    CHECK(cb.store_ref_bool(attached));
  }
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
  // `scale`: the left shard's tip at block s ends at scale * s.
  explicit FixtureSource(uint32_t tip_in, uint32_t split_at = 1, uint64_t scale = 1000) : tip_seqno(tip_in) {
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
        block.tips = {WindowShardTip{ShardIdFull{0, kAll}, scale * s}};
      } else {
        uint64_t right = split_at == 1 ? 100ull * s + 50 : 1000ull * (split_at - 1) + 100ull * (s - split_at + 1) + 50;
        block.tips = {WindowShardTip{ShardIdFull{0, kLeft}, scale * s}, WindowShardTip{ShardIdFull{0, kRight}, right}};
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
  td::Result<std::vector<td::Bits256>> state_roots(const BlockIdExt& head) override {
    if (head != master_id(head.seqno())) {
      return td::Status::Error("no such head");
    }
    if (states.empty()) {
      return std::vector<td::Bits256>{root};
    }
    std::vector<td::Bits256> roots;
    for (auto& state : states) {
      roots.push_back(state.root->get_hash().bits());
    }
    std::sort(roots.begin(), roots.end());
    return roots;
  }
  td::Result<std::vector<tos_wallet_index::OwnershipHeadState>> head_states(const BlockIdExt& head) override {
    if (head != master_id(head.seqno()) || states.empty()) {
      return td::Status::Error("no head states");
    }
    return states;
  }
  td::Status for_each_interval_transaction(
      const VerifyMasterchainBlock& master,
      const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb,
      const std::atomic<bool>*) override {
    for (auto& [account, lt, hash] : intervals[master.id.seqno()]) {
      TRY_STATUS(cb(account, lt, hash));
    }
    return td::Status::OK();
  }
  td::Status for_each_interval_transaction_cell(
      const VerifyMasterchainBlock& master,
      const std::function<td::Status(const td::Bits256&, uint64_t, const td::Ref<vm::Cell>&)>& cb,
      const std::atomic<bool>*) override {
    for (auto& cell : interval_cells[master.id.seqno()]) {
      auto link = tos_wallet_index::parse_transaction_link(cell).move_as_ok();
      TRY_STATUS(cb(link.account, link.lt, cell));
    }
    return td::Status::OK();
  }
  td::Result<BlockIdExt> first_block_from_head(const BlockIdExt& head) override {
    if (head != master_id(head.seqno()) || !first_block) {
      return td::Status::Error(tos::services::kVerifyTerminalError, "the head's state does not record block 1");
    }
    return first_block.value();
  }
  // The window's blocks hold these transactions, each in the interval of the
  // first masterchain block whose tip for its shard ends above it.
  void hold(const std::vector<td::Ref<vm::Cell>>& cells) {
    for (auto& cell : cells) {
      auto link = tos_wallet_index::parse_transaction_link(cell).move_as_ok();
      for (uint32_t m = 1; m <= tip_seqno; ++m) {
        if (tos_wallet_index::window_lt_bound(blocks.at(m).tips, link.account).move_as_ok() > link.lt) {
          intervals[m].emplace_back(link.account, link.lt, link.hash);
          interval_cells[m].push_back(cell);
          break;
        }
      }
    }
  }
  td::Bits256 root = td::Bits256::zero();
  std::map<uint32_t, std::vector<std::tuple<td::Bits256, uint64_t, td::Bits256>>> intervals;
  std::map<uint32_t, std::vector<td::Ref<vm::Cell>>> interval_cells;
  // Block 1's identity as the head's state records it.
  td::optional<BlockIdExt> first_block = master_id(1);
  // H's basechain shard states, for the ownership derivation.
  std::vector<tos_wallet_index::OwnershipHeadState> states;
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
      {{left, 13001}, 14}, {{left, 16999}, 17}, {{left, 17000}, 18}, {{left, 19999}, 20},
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
  auto refused = [](const std::function<void(HeadCase&, TempIndex&)>& tamper, td::Bits256 HeadCase::* who,
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
  refused([](HeadCase& c,
             TempIndex& index) { index.put(c.a, 15000, transaction(c.a, 15000, td::Bits256::zero(), 13500, 1)); },
          &HeadCase::a, "not hash-linked");
  // Omitted: a middle row deleted.
  refused([](HeadCase& c, TempIndex& index) { index.erase(c.a, 15000); }, &HeadCase::a, "not hash-linked");
  // Injected: a row for an account last active before the window.
  refused([](HeadCase& c,
             TempIndex& index) { index.add(transaction(c.e, 17000, c.dormant.back()->get_hash().bits(), 9000)); },
          &HeadCase::e, "newer than the account's last transaction");
  // A row stored under a logical time its transaction does not have.
  refused([](HeadCase& c, TempIndex& index) { index.put(c.a, 15001, c.linked[2]); }, &HeadCase::a,
          "holds the transaction at");
  // Missing: an account active in the window with no rows at all.
  refused([](HeadCase& c, TempIndex&) { c.source.heads[c.f] = head_of(history(c.f, {18000}, 17000)); }, &HeadCase::f,
          "in-window history is missing");
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
  ASSERT_TRUE(contains(retry.json(), "{\"attempts\":5,\"since\":1700000000,\"last_error\":\"another failure\"}"));
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

namespace {
// Run the block pass step by step until it stops working.
td::Result<tos::services::VerifyOutcome> pass_to_end(TempIndex& index, FixtureSource& source,
                                                     const VerifyLimits& limits = {}) {
  for (int i = 0; i < 1000000; ++i) {
    TRY_RESULT(outcome, run_block_pass_step(*index.db, source, limits));
    if (outcome.step != VerifyStep::Working) {
      return outcome;
    }
  }
  return td::Status::Error("the block pass never finished");
}

// A HeadCase verified at its head, Partial, its window's blocks holding every
// transaction of its accounts.
void verified(HeadCase& c, TempIndex& index) {
  c.import(index);
  for (auto* chain : {&c.linked, &c.created, &c.destroyed, &c.dormant})
    c.source.hold(*chain);
  CHECK(c.verify(index).move_as_ok().step == VerifyStep::Done);
}

bool no_marks(TempIndex& index) {
  return !index.db->next_unverified_account(td::optional<td::Bits256>{}).move_as_ok();
}
}  // namespace

// The window's blocks settle what the head state could not: an account
// created inside the window and one destroyed there both match their rows,
// and their marks are cleared; the index stays Partial (ownership is next).
TEST(WalletIndexVerify, the_block_pass_clears_the_accounts_the_blocks_prove) {
  HeadCase c;
  TempIndex index;
  verified(c, index);
  ASSERT_TRUE(!no_marks(index));
  auto outcome = pass_to_end(index, c.source).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  ASSERT_TRUE(no_marks(index));
  ASSERT_TRUE(block_pass_done(*index.db).move_as_ok());
  ASSERT_TRUE(index.state() == VerificationState::Partial);
}

// What the head state cannot see, the blocks refuse: an account destroyed in
// the window and left out of the snapshot entirely, a recreated account whose
// first life was left out, and a changed row of a destroyed account.
TEST(WalletIndexVerify, the_block_pass_refuses_what_the_snapshot_left_out_or_changed) {
  {
    HeadCase c;
    TempIndex index;
    auto g = address(0x60);
    c.source.hold(history(g, {15500, 16500}, 15000));
    verified(c, index);
    auto outcome = pass_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(outcome.account && outcome.account.value() == g);
    ASSERT_TRUE(contains(outcome.reason, "omits the account's history"));
    ASSERT_TRUE(index.state() == VerificationState::Refused);
  }
  {
    HeadCase c;
    TempIndex index;
    auto r = address(0x50);
    auto first = history(r, {16000, 16500}, 15900);
    auto second = history(r, {18000, 19000}, 0);
    c.source.heads[r] = head_of(second);
    c.source.hold(first);
    c.source.hold(second);
    c.import(index);
    for (auto& row : second)
      index.add(row);
    for (auto* chain : {&c.linked, &c.created, &c.destroyed, &c.dormant})
      c.source.hold(*chain);
    ASSERT_TRUE(c.verify(index).move_as_ok().step == VerifyStep::Done);
    auto outcome = pass_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(outcome.account && outcome.account.value() == r);
    ASSERT_TRUE(contains(outcome.reason, "16500"));
  }
  {
    HeadCase c;
    TempIndex index;
    verified(c, index);
    index.put(c.d, 16000, transaction(c.d, 16000, c.destroyed[0]->get_hash().bits(), 14000, 9));
    auto outcome = pass_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Refused);
    ASSERT_TRUE(outcome.account && outcome.account.value() == c.d);
  }
}

// A masterchain block missing from the window, or not the one the verified
// head names, stops the pass as terminal without advancing it.
TEST(WalletIndexVerify, the_block_pass_stops_at_a_gap_or_a_foreign_block) {
  for (int foreign = 0; foreign < 2; ++foreign) {
    HeadCase c;
    TempIndex index;
    verified(c, index);
    if (foreign) {
      c.source.blocks[18].id = master_id(18, 6);
    } else {
      c.source.blocks.erase(18);
    }
    auto outcome = pass_to_end(index, c.source);
    ASSERT_TRUE(outcome.is_error());
    ASSERT_TRUE(tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(!block_pass_done(*index.db).move_as_ok());
    ASSERT_TRUE(!no_marks(index));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
  }
}

// One block, one interval and one account per step, interrupted between any
// two steps, ends exactly as one uninterrupted pass. A different binding (the
// head state's roots) discards the pass and its results and starts again.
TEST(WalletIndexVerify, the_block_pass_resumes_and_restarts_on_a_new_binding) {
  VerifyLimits small;
  small.authenticate_per_step = 1;
  small.intervals_per_step = 1;
  small.compare_per_step = 1;
  HeadCase straight, stepped;
  TempIndex straight_index, stepped_index;
  verified(straight, straight_index);
  verified(stepped, stepped_index);
  ASSERT_TRUE(pass_to_end(straight_index, straight.source).move_as_ok().step == VerifyStep::Done);
  int steps = 0;
  for (; steps < 12; ++steps) {
    ASSERT_TRUE(run_block_pass_step(*stepped_index.db, stepped.source, small).move_as_ok().step == VerifyStep::Working);
  }
  // The head state's roots change: everything collected so far is dropped.
  stepped.source.root.as_slice()[0] = 1;
  auto restarted = run_block_pass_step(*stepped_index.db, stepped.source, small).move_as_ok();
  ASSERT_TRUE(restarted.step == VerifyStep::Working && contains(restarted.reason, "authenticating from 22"));
  ASSERT_TRUE(!stepped_index.db->next_collected_account(td::optional<td::Bits256>{}).move_as_ok());
  ASSERT_TRUE(pass_to_end(stepped_index, stepped.source, small).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(no_marks(stepped_index) && no_marks(straight_index));
  for (auto& account : {straight.a, straight.b, straight.d, straight.e})
    ASSERT_TRUE(stepped_index.lts(account) == straight_index.lts(account));
}

// The pass bounds every account by the window base the index holds at the
// head, also when replay moved it after the snapshot's checkpoint; and an
// account with more in-window transactions than the retention compares its
// newest kMaxEventsPerAccount on both sides.
TEST(WalletIndexVerify, the_block_pass_uses_the_base_at_the_head_and_the_retention_cap) {
  {
    HeadCase c;
    TempIndex index;
    c.import(index);
    {
      std::lock_guard<std::mutex> guard(index.db->write_mutex());
      auto base = tos::services::read_base_record(c.source, 14).move_as_ok();
      index.db->commit_replay_checkpoint({master_id(1), master_id(22)}, 14u, base).ensure();
    }
    for (auto* chain : {&c.linked, &c.created, &c.destroyed, &c.dormant})
      c.source.hold(*chain);
    ASSERT_TRUE(c.verify(index).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(pass_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(no_marks(index));
    ASSERT_TRUE(index.lts(c.d) == (std::set<uint64_t>{16000}));
  }
  {
    // Left tips end at 10000 * s: base 13 bounds at 130000, checkpoint 20 at 200000.
    FixtureSource source(22, 1, 10000);
    TempIndex index;
    auto big = address(0x70);
    std::vector<uint64_t> lts;
    for (uint64_t lt = 130001; lt <= 140005; ++lt)
      lts.push_back(lt);
    auto rows = history(big, lts, 129000);
    index.import(master_id(20), rows);
    ASSERT_TRUE(prepare_quarantined_index(*index.db, source).move_as_ok().step == VerifyStep::Done);
    index.replayed_to(master_id(22));
    source.hold(rows);
    ASSERT_TRUE(verify_index_at_head(*index.db, source, master_id(22)).move_as_ok().step == VerifyStep::Done);
    ASSERT_EQ(index.lts(big).size(), tos_wallet_index::kMaxEventsPerAccount);
    ASSERT_TRUE(pass_to_end(index, source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(no_marks(index));
  }
}

// One interval's collection is bounded in memory: an interval needing more
// than the bound stops the pass as terminal without advancing it.
TEST(WalletIndexVerify, an_interval_over_the_memory_bound_stops_the_pass) {
  HeadCase c;
  TempIndex index;
  verified(c, index);
  VerifyLimits tight;
  tight.interval_bytes = 100;
  auto outcome = pass_to_end(index, c.source, tight);
  ASSERT_TRUE(outcome.is_error());
  ASSERT_TRUE(tos::services::is_terminal_verify_error(outcome.error()));
  ASSERT_TRUE(contains(outcome.error().message().str(), "MiB to collect"));
  ASSERT_TRUE(!index.db->next_collected_account(td::optional<td::Bits256>{}).move_as_ok());
  ASSERT_TRUE(!block_pass_done(*index.db).move_as_ok());
}

// The service never replays, drains or prunes a partly verified index: it
// runs the block pass, then holds at the verified head until ownership is
// derived, also after a restart that finds the pass complete.
TEST(WalletIndexVerify, a_partial_index_holds_replay_at_the_head) {
  using tos::services::next_service_action;
  using tos::services::ServiceAction;
  for (bool prepared : {false, true}) {
    ASSERT_TRUE(next_service_action(VerificationState::Partial, prepared, false) == ServiceAction::BlockPass);
    ASSERT_TRUE(next_service_action(VerificationState::Partial, prepared, true) == ServiceAction::HoldForOwnership);
    ASSERT_TRUE(next_service_action(VerificationState::Refused, prepared, true) == ServiceAction::Stop);
    ASSERT_TRUE(next_service_action(VerificationState::Full, prepared, true) == ServiceAction::Replay);
  }
  ASSERT_TRUE(next_service_action(VerificationState::Quarantined, false, false) == ServiceAction::Prepare);
  ASSERT_TRUE(next_service_action(VerificationState::Quarantined, true, false) == ServiceAction::Replay);
}

namespace {
using tos_wallet_index::OwnershipHeadState;
namespace fixture = wallet_index_fixture;

// A token value as the index stores it: the wallet and the verdict's lt.
td::Ref<vm::Cell> token_value(const td::Bits256& wallet, uint64_t lt) {
  vm::CellBuilder cb;
  CHECK(cb.store_bits_bool(wallet.cbits(), 256) && cb.store_long_bool(static_cast<long long>(lt), 64));
  return cb.finalize();
}

void record_token(WalletIndexDb& db, const td::Bits256& wallet, const td::Bits256& owner, const td::Bits256& master,
                  uint64_t lt) {
  std::lock_guard<std::mutex> guard(db.write_mutex());
  db.begin_batch().ensure();
  CHECK(tos_wallet_index::record_token_wallet_check(db, wallet, tos_wallet_index::TokenWalletCheck::Verified, owner,
                                                    master, token_value(wallet, lt),
                                                    lt) == tos_wallet_index::TokenVerifyOutcome::Done);
  db.commit_batch().ensure();
}

void record_nft(WalletIndexDb& db, const td::Bits256& item, const td::Bits256& owner, uint64_t lt) {
  std::lock_guard<std::mutex> guard(db.write_mutex());
  db.begin_batch().ensure();
  db.apply_nft_verdict(item, WalletIndexDb::NftVerdict{true, owner, token_value(item, lt)}, lt).ensure();
  db.commit_batch().ensure();
}

// An account whose getters cannot run: active, with code but no data, as
// valid TL-B (the state's balance still evaluates) that neither the writer's
// loader nor the derivation can run a getter on.
td::Ref<vm::Cell> undecodable_account(const td::Bits256& address) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(1, 1) && cb.store_long_bool(4, 3) && cb.store_long_bool(0, 8) &&
        cb.store_bits_bool(address.cbits(), 256) && cb.store_long_bool(0, 3) && cb.store_long_bool(0, 3) &&
        cb.store_long_bool(0, 3) && cb.store_long_bool(0, 32) && cb.store_long_bool(0, 1) &&
        cb.store_long_bool(0, 64) && cb.store_long_bool(0, 4) && cb.store_long_bool(0, 1) &&
        cb.store_long_bool(1, 1)                                 // account_active
        && cb.store_long_bool(0, 1) && cb.store_long_bool(0, 1)  // fixed_prefix_length, special
        && cb.store_long_bool(1, 1) && cb.store_ref_bool(vm::CellBuilder{}.store_long(0x30, 8).finalize())  // code
        && cb.store_long_bool(0, 1)                                                                         // no data
        && cb.store_long_bool(0, 1));                                                                       // library
  return cb.finalize();
}

BlockIdExt shard_block(uint64_t shard, uint32_t seqno) {
  td::Bits256 root = td::Bits256::zero(), file = td::Bits256::zero();
  root.as_slice()[0] = static_cast<char>(seqno);
  root.as_slice()[1] = static_cast<char>(shard >> 56);
  file.as_slice()[0] = 1;
  return BlockIdExt{0, shard, seqno, root, file};
}

// Two halves of the basechain at the head: the left one ends at 6000, the
// right one at 6100.
std::vector<OwnershipHeadState> halves(td::Ref<vm::Cell> left, td::Ref<vm::Cell> right) {
  return {OwnershipHeadState{shard_block(kLeft, 40), ShardIdFull{0, kLeft}, 6000, std::move(left)},
          OwnershipHeadState{shard_block(kRight, 41), ShardIdFull{0, kRight}, 6100, std::move(right)}};
}

tos_wallet_index::OwnershipStep derive_all(WalletIndexDb& db, const std::vector<OwnershipHeadState>& states,
                                           size_t limit = 1000) {
  tos_wallet_index::OwnershipStep total;
  for (size_t index = 0; index < states.size(); ++index) {
    auto from = td::Bits256::zero();
    for (;;) {
      std::lock_guard<std::mutex> guard(db.write_mutex());
      db.begin_batch().ensure();
      auto step = tos_wallet_index::derive_ownership_range(db, states, index, from, limit, nullptr).move_as_ok();
      db.commit_batch().ensure();
      total.examined += step.examined;
      total.verdicts += step.verdicts;
      total.parked += step.parked;
      if (!step.next) {
        break;
      }
      from = step.next.value();
    }
  }
  return total;
}

void reconcile_all(WalletIndexDb& db, const std::vector<OwnershipHeadState>& states) {
  for (auto kind : {tos_wallet_index::TokenKind::Fungible, tos_wallet_index::TokenKind::Nft}) {
    td::optional<td::Bits256> after;
    for (;;) {
      std::lock_guard<std::mutex> guard(db.write_mutex());
      db.begin_batch().ensure();
      auto step = tos_wallet_index::reconcile_ownership_records(db, states, kind, after, 1, nullptr).move_as_ok();
      db.commit_batch().ensure();
      if (!step.next) {
        break;
      }
      after = step.next;
    }
  }
}
}  // namespace

// Ownership is derived from the head's states: a token wallet whose master
// is in the other shard, and an NFT whose collection is, verify at their
// shard state's end lt; a verdict replay left below that lt is replaced, one
// above it is kept; a contract that is no token wallet leaves no record.
TEST(WalletIndexVerify, ownership_is_derived_at_the_head_across_shards) {
  TempIndex index;
  auto owner = address(0x05), stale_owner = address(0x06);
  auto wallet = address(0x10), other_wallet = address(0x11), item = address(0x12);
  auto master = address(0x90), collection = address(0x91);
  auto states =
      halves(fixture::shard_state({fixture::token_wallet(wallet, owner, master),
                                   fixture::token_wallet(other_wallet, owner, master),
                                   fixture::nft_item(item, collection, owner)}),
             fixture::shard_state({fixture::token_master(master, wallet), fixture::nft_collection(collection, item)}));
  record_token(*index.db, wallet, stale_owner, master, 100);
  record_token(*index.db, other_wallet, owner, master, 9000);
  auto total = derive_all(*index.db, states);
  ASSERT_EQ(total.examined, 5u);
  ASSERT_EQ(total.parked, 0u);
  auto derived = index.db->token_wallet_state(wallet).move_as_ok();
  ASSERT_TRUE(derived && derived.value().present && derived.value().owner == owner && derived.value().lt == 6000);
  // The master resolves the owner to `wallet`, not to `other_wallet`: that
  // one is rejected at 6000, but its record from 9000 is newer and stays.
  auto kept = index.db->token_wallet_state(other_wallet).move_as_ok();
  ASSERT_TRUE(kept && kept.value().present && kept.value().lt == 9000);
  td::Bits256 nft_owner;
  ASSERT_TRUE(index.db->get_nft_owner(item, nft_owner).move_as_ok() && nft_owner == owner);
  ASSERT_TRUE(!index.db->has_token_wallet_record(master).move_as_ok());
  ASSERT_TRUE(!index.db->has_token_wallet_record(collection).move_as_ok());
}

// A recorded token wallet or NFT whose account is gone from the head, or
// holds no code there, is removed by the reconciliation: the derivation
// never visits it.
TEST(WalletIndexVerify, recorded_ownership_of_accounts_gone_from_the_head_is_removed) {
  TempIndex index;
  auto owner = address(0x05), gone = address(0x14), codeless = address(0x15), item = address(0x16);
  auto states = halves(fixture::shard_state({fixture::without_code(codeless)}), fixture::shard_state({}));
  record_token(*index.db, gone, owner, address(0x90), 100);
  record_token(*index.db, codeless, owner, address(0x90), 100);
  record_nft(*index.db, item, owner, 100);
  ASSERT_EQ(derive_all(*index.db, states).verdicts, 0u);
  reconcile_all(*index.db, states);
  for (auto& account : {gone, codeless}) {
    auto state = index.db->token_wallet_state(account).move_as_ok();
    ASSERT_TRUE(state && !state.value().present);
  }
  td::Bits256 nft_owner;
  ASSERT_TRUE(!index.db->get_nft_owner(item, nft_owner).move_as_ok());
}

// An account whose state does not decode is never skipped: both of its
// verifications are parked, at its shard state's end lt (not the
// masterchain head's), and the range goes on after it.
TEST(WalletIndexVerify, an_undecodable_account_is_parked_at_its_shard_state) {
  TempIndex index;
  auto broken = address(0x20), wallet = address(0x21), owner = address(0x05), master = address(0x90);
  auto states = halves(
      fixture::shard_state({fixture::token_wallet(wallet, owner, master)}, {{broken, undecodable_account(broken)}}),
      fixture::shard_state({fixture::token_master(master, wallet)}));
  auto total = derive_all(*index.db, states, 1);
  ASSERT_EQ(total.parked, 2u);
  ASSERT_TRUE(index.db->token_wallet_state(wallet).move_as_ok().value().present);
  ASSERT_EQ(index.db->token_backlog_stats().move_as_ok().parked, 2u);
  // Reading the parked candidates takes a token pass, as the writer's retry does.
  bool wrapped = false;
  std::vector<tos_wallet_index::ScheduledTokenCandidate> parked;
  {
    std::lock_guard<std::mutex> guard(index.db->write_mutex());
    index.db->begin_batch().ensure();
    index.db->begin_token_pass().ensure();
    parked = index.db->next_parked_token_candidates(10, wrapped).move_as_ok();
    index.db->abort_batch();
  }
  ASSERT_EQ(parked.size(), 2u);
  for (auto& entry : parked) {
    ASSERT_TRUE(entry.candidate.address == broken);
    ASSERT_EQ(entry.lt, 6000u);
  }
}

// The writer's retries during the hold read the head's states only.
TEST(WalletIndexVerify, the_pinned_fetcher_answers_with_the_head_states) {
  auto states = halves(fixture::shard_state({}), fixture::shard_state({}));
  auto fetcher = tos::services::make_head_state_fetcher(states);
  for (auto [account, end_lt] :
       {std::pair<td::Bits256, uint64_t>{address(0x10), 6000}, std::pair<td::Bits256, uint64_t>{address(0x90), 6100}}) {
    td::optional<tos_wallet_index::Wc0NewestState> answer;
    fetcher(account, [&](td::Result<tos_wallet_index::Wc0NewestState> result) { answer = result.move_as_ok(); });
    ASSERT_TRUE(answer && answer.value().end_lt == end_lt);
    ASSERT_TRUE(answer.value().state_root->get_hash() == states[end_lt == 6000 ? 0 : 1].root->get_hash());
  }
}

namespace {
// A HeadCase through its block pass, its head states set.
void passed(HeadCase& c, TempIndex& index, std::vector<OwnershipHeadState> states) {
  c.source.states = std::move(states);
  verified(c, index);
  CHECK(pass_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
}

td::Result<tos::services::VerifyOutcome> ownership_to_end(TempIndex& index, FixtureSource& source,
                                                          const VerifyLimits& limits = {}, int max_steps = 100000) {
  td::optional<tos::services::VerifyOutcome> last;
  for (int i = 0; i < max_steps; ++i) {
    TRY_RESULT(outcome, tos::services::run_ownership_step(*index.db, source, limits));
    if (outcome.step != VerifyStep::Working || outcome.drain) {
      return outcome;
    }
    last = std::move(outcome);
  }
  // Stopped after `max_steps` working steps: the last one.
  if (!last) {
    return td::Status::Error("no ownership step ran");
  }
  return last.value();
}
}  // namespace

// The index becomes Full only when the derivation and the reconciliation
// are done and no token work is owed; a parked candidate keeps it Partial,
// held, with the drain owed.
TEST(WalletIndexVerify, the_index_is_full_only_when_no_ownership_work_is_owed) {
  {
    HeadCase c;
    TempIndex index;
    auto wallet = address(0x10), owner = address(0x05), master = address(0x90);
    passed(c, index,
           halves(fixture::shard_state({fixture::token_wallet(wallet, owner, master)}),
                  fixture::shard_state({fixture::token_master(master, wallet)})));
    auto outcome = ownership_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Done);
    ASSERT_TRUE(index.state() == VerificationState::Full);
    ASSERT_TRUE(index.db->token_wallet_state(wallet).move_as_ok().value().present);
  }
  {
    HeadCase c;
    TempIndex index;
    auto broken = address(0x20);
    passed(c, index,
           halves(fixture::shard_state({}, {{broken, undecodable_account(broken)}}), fixture::shard_state({})));
    auto outcome = ownership_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Working && outcome.drain);
    ASSERT_TRUE(contains(outcome.reason, "2 parked"));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
    // Draining cannot decide an account that does not decode: still owed.
    auto again = tos::services::run_ownership_step(*index.db, c.source).move_as_ok();
    ASSERT_TRUE(again.drain && index.state() == VerificationState::Partial);
  }
  {
    // The head's states changed from the bound ones: never Full.
    HeadCase c;
    TempIndex index;
    passed(c, index, halves(fixture::shard_state({}), fixture::shard_state({})));
    c.source.states[0].root = fixture::shard_state({fixture::without_code(address(0x33))});
    auto outcome = tos::services::run_ownership_step(*index.db, c.source);
    ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
  }
}

namespace {
// The index of `index`, installed as the process's wallet index for the
// writer's drain, and given back when the scope ends.
struct Installed {
  explicit Installed(TempIndex& index) : index_(index) {
    tos_wallet_index::set_wallet_index_db(std::move(index.db));
    tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds(0));
  }
  ~Installed() {
    tos_wallet_index::set_wc0_index_state_fetcher(nullptr);
    tos_wallet_index::release_wc0_index_state();
    tos_wallet_index::set_wallet_index_db(nullptr);
    index_.db = WalletIndexDb::open(index_.dir + "/index").move_as_ok();
  }
  WalletIndexDb& db() {
    return *tos_wallet_index::wallet_index_db();
  }
  TempIndex& index_;
};

std::vector<OwnershipHeadState> whole(td::Ref<vm::Cell> root, uint64_t end_lt = 6000) {
  return {OwnershipHeadState{shard_block(kAll, 40), ShardIdFull{0, kAll}, end_lt, std::move(root)}};
}
}  // namespace

// A candidate already parked for an account that is active without code at
// the head is decided by the ownership drain (nothing to run, so no token
// wallet), not held forever as indeterminate.
TEST(WalletIndexVerify, the_ownership_drain_decides_a_parked_account_without_code) {
  TempIndex index;
  auto codeless = address(0x15);
  Installed installed(index);
  auto& db = installed.db();
  {
    std::lock_guard<std::mutex> guard(db.write_mutex());
    db.begin_batch().ensure();
    db.begin_token_pass().ensure();
    tos_wallet_index::ScheduledTokenCandidate scheduled{
        tos_wallet_index::TokenCandidate{tos_wallet_index::TokenKind::Fungible, codeless},
        tos_wallet_index::kMaxTokenCandidateAttempts, 6000};
    ASSERT_TRUE(db.park_token_candidate(scheduled).move_as_ok());
    db.save_token_counters().ensure();
    db.commit_batch().ensure();
  }
  ASSERT_EQ(db.token_backlog_stats().move_as_ok().parked, 1u);
  tos::services::pin_writer_to_head(whole(fixture::shard_state({fixture::without_code(codeless)})));
  for (int i = 0; i < 100 && db.token_backlog_stats().move_as_ok().parked != 0; ++i) {
    tos_wallet_index::drain_wc0_ownership(nullptr);
  }
  ASSERT_EQ(db.token_backlog_stats().move_as_ok().parked, 0u);
}

// The pin drops the state the writer cached from replay: a pending block,
// which takes a cached state new enough for it before asking the fetcher,
// is verified at the head, not at that older state.
TEST(WalletIndexVerify, pinning_to_the_head_drops_an_older_cached_state) {
  TempIndex index;
  auto wallet = address(0x10), master = address(0x30), old_owner = address(0x05), owner = address(0x06);
  Installed installed(index);
  auto& db = installed.db();
  auto old_state =
      fixture::shard_state({fixture::token_wallet(wallet, old_owner, master), fixture::token_master(master, wallet)});
  // Replay indexed a block with its state: the writer now caches that state.
  auto replayed = fixture::block(5, 5000, 1000, {});
  auto boc = vm::std_boc_serialize(replayed, 31).move_as_ok();
  td::Bits256 file_hash;
  td::sha256(boc.as_slice(), file_hash.as_slice());
  BlockIdExt replayed_id{0, kAll, 5, replayed->get_hash().bits(), file_hash};
  ASSERT_TRUE(tos_wallet_index::wc0_index_block(replayed, old_state, replayed_id, true, 5) ==
              tos_wallet_index::Wc0IndexResult::Done);
  {
    std::lock_guard<std::mutex> guard(db.write_mutex());
    db.begin_batch().ensure();
    WalletIndexDb::PendingBlock pending;
    pending.end_lt = 1000;
    pending.remaining.push_back(tos_wallet_index::ScheduledTokenCandidate{
        tos_wallet_index::TokenCandidate{tos_wallet_index::TokenKind::Fungible, wallet}, 0, 1000});
    db.put_pending_block(shard_block(kAll, 3), pending).ensure();
    db.commit_batch().ensure();
  }
  tos::services::pin_writer_to_head(whole(
      fixture::shard_state({fixture::token_wallet(wallet, owner, master), fixture::token_master(master, wallet)})));
  for (int i = 0; i < 100 && db.pending_block_count().move_as_ok() != 0; ++i) {
    tos_wallet_index::drain_wc0_ownership(nullptr);
  }
  ASSERT_EQ(db.pending_block_count().move_as_ok(), 0u);
  auto state = db.token_wallet_state(wallet).move_as_ok();
  ASSERT_TRUE(state && state.value().present && state.value().owner == owner && state.value().lt == 6000);
}

// The derivation interrupted after any committed step, and the index
// reopened, ends with the same verdicts as an uninterrupted one.
TEST(WalletIndexVerify, an_interrupted_derivation_resumes_from_its_progress) {
  auto owner = address(0x05), master = address(0x90);
  auto states = halves(
      fixture::shard_state({fixture::token_wallet(address(0x10), owner, master),
                            fixture::token_wallet(address(0x11), owner, master), fixture::without_code(address(0x12))}),
      fixture::shard_state({fixture::token_master(master, address(0x11))}));
  HeadCase straight_case, stepped_case;
  TempIndex straight, stepped;
  passed(straight_case, straight, states);
  passed(stepped_case, stepped, states);
  ASSERT_TRUE(ownership_to_end(straight, straight_case.source).move_as_ok().step == VerifyStep::Done);
  VerifyLimits one;
  one.ownership_per_step = 1;
  ASSERT_TRUE(ownership_to_end(stepped, stepped_case.source, one, 3).move_as_ok().step == VerifyStep::Working);
  stepped.db.reset();
  stepped.db = WalletIndexDb::open(stepped.dir + "/index").move_as_ok();
  ASSERT_TRUE(ownership_to_end(stepped, stepped_case.source, one).move_as_ok().step == VerifyStep::Done);
  for (auto& account : {address(0x10), address(0x11), address(0x12)}) {
    auto a = straight.db->token_wallet_state(account).move_as_ok();
    auto b = stepped.db->token_wallet_state(account).move_as_ok();
    ASSERT_EQ(static_cast<bool>(a), static_cast<bool>(b));
    if (a) {
      ASSERT_TRUE(a.value().present == b.value().present && a.value().owner == b.value().owner &&
                  a.value().lt == b.value().lt);
    }
  }
}

// Each obligation withholds Full on its own: queued and pending token work
// keep the index held with the drain owed; an unfinished block or a needed
// rebuild stop it as terminal; candidate losses the derivation superseded do
// not, and are cleared when it becomes Full.
TEST(WalletIndexVerify, every_obligation_withholds_full_on_its_own) {
  auto states = [] { return halves(fixture::shard_state({}), fixture::shard_state({})); };
  auto in_batch = [](TempIndex& index, const std::function<void(WalletIndexDb&)>& write) {
    std::lock_guard<std::mutex> guard(index.db->write_mutex());
    index.db->begin_batch().ensure();
    write(*index.db);
    index.db->commit_batch().ensure();
  };
  {
    HeadCase c;
    TempIndex index;
    passed(c, index, states());
    in_batch(index, [](WalletIndexDb& db) {
      db.schedule_token_candidates(
            {tos_wallet_index::TokenCandidate{tos_wallet_index::TokenKind::Fungible, address(0x41)}},
            ShardIdFull{0, kLeft}, 0, 1000)
          .ensure();
      db.save_token_counters().ensure();
    });
    ASSERT_EQ(index.db->token_backlog_stats().move_as_ok().entries, 1u);
    auto outcome = ownership_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.drain && contains(outcome.reason, "1 queued"));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
  }
  {
    HeadCase c;
    TempIndex index;
    passed(c, index, states());
    in_batch(index, [](WalletIndexDb& db) {
      WalletIndexDb::PendingBlock pending;
      pending.end_lt = 1000;
      pending.remaining.push_back(tos_wallet_index::ScheduledTokenCandidate{
          tos_wallet_index::TokenCandidate{tos_wallet_index::TokenKind::Nft, address(0x42)}, 0, 1000});
      db.put_pending_block(shard_block(kLeft, 3), pending).ensure();
    });
    auto outcome = ownership_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.drain && contains(outcome.reason, "1 unfinished blocks"));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
  }
  for (bool rebuild : {false, true}) {
    HeadCase c;
    TempIndex index;
    passed(c, index, states());
    if (rebuild) {
      index.db->mark_needs_rebuild().ensure();
    } else {
      index.db->put_incomplete_block(shard_block(kLeft, 4), 4).ensure();
    }
    auto outcome = ownership_to_end(index, c.source);
    ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(index.state() == VerificationState::Partial);
  }
  {
    HeadCase c;
    TempIndex index;
    passed(c, index, states());
    in_batch(index, [](WalletIndexDb& db) { db.add_lost_token_candidates_for_testing(3).ensure(); });
    auto outcome = ownership_to_end(index, c.source).move_as_ok();
    ASSERT_TRUE(outcome.step == VerifyStep::Done && contains(outcome.reason, "3 lost"));
    ASSERT_TRUE(index.state() == VerificationState::Full);
    ASSERT_EQ(index.db->token_backlog_stats().move_as_ok().lost, 0u);
  }
}

// The drain of the hold does token work only: a block marked for recovery,
// whose recovery would write history, is left as it is.
TEST(WalletIndexVerify, the_ownership_drain_never_writes_history) {
  TempIndex index;
  tos_wallet_index::set_wallet_index_db(std::move(index.db));
  auto* db = tos_wallet_index::wallet_index_db();
  auto marked = shard_block(kLeft, 7);
  db->put_incomplete_block(marked, 7).ensure();
  auto rows_before = 0;
  db->for_each_key_with_prefix(td::Slice("\x12", 1), 1u << 20, [&](td::Slice) {
      ++rows_before;
      return td::Status::OK();
    }).ensure();
  tos_wallet_index::drain_wc0_ownership(nullptr);
  ASSERT_TRUE(db->has_incomplete_block(marked).move_as_ok());
  auto rows_after = 0;
  db->for_each_key_with_prefix(td::Slice("\x12", 1), 1u << 20, [&](td::Slice) {
      ++rows_after;
      return td::Status::OK();
    }).ensure();
  ASSERT_EQ(rows_before, rows_after);
  tos_wallet_index::set_wallet_index_db(nullptr);
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

namespace {
using tos::services::run_build_step;

td::Result<tos::services::VerifyOutcome> build_to_end(TempIndex& index, FixtureSource& source,
                                                      const VerifyLimits& limits = {}) {
  for (int i = 0; i < 100000; ++i) {
    TRY_RESULT(outcome, run_build_step(*index.db, source, limits));
    if (outcome.step != VerifyStep::Working) {
      return outcome;
    }
  }
  return td::Status::Error("the build never finished");
}

// A HeadCase whose window's blocks hold every transaction of its accounts,
// with two empty basechain shard states at the head for the derivation.
void held(HeadCase& c) {
  c.source.states = halves(fixture::shard_state({}), fixture::shard_state({}));
  for (auto* chain : {&c.linked, &c.created, &c.destroyed, &c.dormant})
    c.source.hold(*chain);
}

std::vector<td::Ref<vm::Cell>> every_row(HeadCase& c) {
  std::vector<td::Ref<vm::Cell>> all;
  for (auto* chain : {&c.linked, &c.created, &c.destroyed, &c.dormant})
    all.insert(all.end(), chain->begin(), chain->end());
  return all;
}

void reopen(TempIndex& index) {
  index.db.reset();
  index.db = WalletIndexDb::open(index.dir + "/index").move_as_ok();
}

bool same_rows(HeadCase& c, TempIndex& left, TempIndex& right) {
  if (left.ages() != right.ages()) {
    return false;
  }
  for (auto& account : {c.a, c.b, c.d, c.e, c.f}) {
    if (left.lts(account) != right.lts(account)) {
      return false;
    }
  }
  return true;
}
}  // namespace

// A fresh index built from the window's blocks holds the rows and age rows
// an import of every row prepared at the same head would hold, and is
// published Partial at that head with its block pass done; the ownership
// derivation then makes it Full.
TEST(WalletIndexVerify, a_fresh_index_is_built_from_the_windows_blocks) {
  HeadCase c;
  held(c);
  TempIndex built, imported;
  ASSERT_TRUE(built.db->is_fresh().move_as_ok());
  auto outcome = build_to_end(built, c.source).move_as_ok();
  ASSERT_TRUE(outcome.step == VerifyStep::Done);
  imported.import(master_id(22), every_row(c));
  ASSERT_TRUE(prepare_quarantined_index(*imported.db, c.source).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(!built.ages().empty());
  ASSERT_TRUE(same_rows(c, built, imported));
  // Rows the window base referenced are not built: the dormant account's.
  ASSERT_TRUE(built.lts(c.e).empty());
  ASSERT_TRUE(built.state() == VerificationState::Partial);
  ASSERT_TRUE(!built.db->build_record().move_as_ok());
  auto checkpoint = built.db->replay_checkpoint().move_as_ok().value();
  ASSERT_TRUE(checkpoint.anchor == master_id(1) && checkpoint.committed == master_id(22));
  auto record = built.db->verification_record().move_as_ok().value();
  auto expected = imported.db->verification_record().move_as_ok().value();
  ASSERT_EQ(record.base, expected.base);
  ASSERT_EQ(record.horizon_seqno, expected.horizon_seqno);
  ASSERT_EQ(record.horizon_time, expected.horizon_time);
  ASSERT_TRUE(record.checkpoint == master_id(22) && record.head && record.head.value() == master_id(22));
  ASSERT_EQ(built.db->get_window_base().move_as_ok(), record.base);
  ASSERT_TRUE(record.base > 0);
  ASSERT_TRUE(built.db->window_base_record().move_as_ok().value().block == master_id(record.base));
  ASSERT_TRUE(built.db->history_window().is_ok());
  ASSERT_TRUE(block_pass_done(*built.db).move_as_ok());
  ASSERT_TRUE(no_marks(built));
  ASSERT_TRUE(ownership_to_end(built, c.source).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(built.state() == VerificationState::Full);
}

// A restart after the Partial publication and before the derivation is
// done finds an index that is neither fresh nor being built: the service
// holds it for ownership at the built head, which then makes it Full.
TEST(WalletIndexVerify, a_restart_after_the_build_resumes_the_derivation) {
  using tos::services::next_service_action;
  using tos::services::ServiceAction;
  HeadCase c;
  held(c);
  auto wallet = address(0x10), owner = address(0x05), master = address(0x90);
  c.source.states = halves(fixture::shard_state({fixture::token_wallet(wallet, owner, master)}),
                           fixture::shard_state({fixture::token_master(master, wallet)}));
  TempIndex index;
  ASSERT_TRUE(build_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
  VerifyLimits small;
  small.ownership_per_step = 1;
  ASSERT_TRUE(tos::services::run_ownership_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
  ASSERT_TRUE(index.state() == VerificationState::Partial);
  reopen(index);
  ASSERT_TRUE(!index.db->is_fresh().move_as_ok());
  ASSERT_TRUE(!index.db->build_record().move_as_ok());
  bool prepared = static_cast<bool>(index.db->verification_record().move_as_ok());
  bool pass_done = block_pass_done(*index.db).move_as_ok();
  ASSERT_TRUE(next_service_action(index.state(), prepared, pass_done) == ServiceAction::HoldForOwnership);
  ASSERT_TRUE(ownership_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(index.state() == VerificationState::Full);
  ASSERT_TRUE(index.db->token_wallet_state(wallet).move_as_ok().value().present);
}

// A build in steps, interrupted by a restart, ends with what one straight
// build writes; until it is published the index is Quarantined, its record
// written with that state before any row.
TEST(WalletIndexVerify, an_interrupted_build_resumes_to_the_same_index) {
  VerifyLimits small;
  small.intervals_per_step = 1;
  HeadCase straight, stepped;
  held(straight);
  held(stepped);
  TempIndex straight_index, stepped_index;
  ASSERT_TRUE(build_to_end(straight_index, straight.source).move_as_ok().step == VerifyStep::Done);
  auto first = run_build_step(*stepped_index.db, stepped.source, small).move_as_ok();
  ASSERT_TRUE(first.step == VerifyStep::Working);
  ASSERT_TRUE(stepped_index.state() == VerificationState::Quarantined);
  ASSERT_TRUE(stepped_index.ages().empty());
  auto record = stepped_index.db->build_record().move_as_ok().value();
  ASSERT_TRUE(record.head == master_id(22));
  ASSERT_EQ(record.cursor, record.base + 1);
  for (int i = 0; i < 3; ++i) {
    ASSERT_TRUE(run_build_step(*stepped_index.db, stepped.source, small).move_as_ok().step == VerifyStep::Working);
  }
  ASSERT_EQ(stepped_index.db->build_record().move_as_ok().value().cursor, record.base + 4);
  reopen(stepped_index);
  ASSERT_TRUE(stepped_index.state() == VerificationState::Quarantined);
  ASSERT_TRUE(build_to_end(stepped_index, stepped.source, small).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(same_rows(straight, straight_index, stepped_index));
  ASSERT_TRUE(stepped_index.state() == VerificationState::Partial);
}

// A build whose head the source no longer holds as recorded (other state
// roots, or a substituted block) is replaced: the replacement is computed
// first, and only then are the built rows cleared, in the batch that writes
// it. When it cannot be computed nothing is cleared.
TEST(WalletIndexVerify, a_build_on_a_lost_binding_is_replaced_before_anything_is_cleared) {
  VerifyLimits small;
  small.intervals_per_step = 1;
  {
    HeadCase c;
    held(c);
    TempIndex index;
    for (int i = 0; i < 4; ++i)
      ASSERT_TRUE(run_build_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
    auto rows = index.ages();
    ASSERT_TRUE(!rows.empty());
    auto before = index.db->build_record().move_as_ok().value();
    c.source.states[0].root = fixture::shard_state({fixture::without_code(address(0x33))});
    // The replacement's window walk fails: the build stays as it was.
    c.source.errors[18] = "transient read failure";
    auto failed = run_build_step(*index.db, c.source, small);
    ASSERT_TRUE(failed.is_error() && !tos::services::is_terminal_verify_error(failed.error()));
    ASSERT_TRUE(index.ages() == rows);
    ASSERT_EQ(index.db->build_record().move_as_ok().value().cursor, before.cursor);
    c.source.errors.clear();
    auto restarted = run_build_step(*index.db, c.source, small).move_as_ok();
    ASSERT_TRUE(restarted.step == VerifyStep::Working && contains(restarted.reason, "restarted"));
    ASSERT_TRUE(index.ages().empty());
    auto replaced = index.db->build_record().move_as_ok().value();
    ASSERT_TRUE(replaced.roots != before.roots);
    ASSERT_EQ(replaced.cursor, replaced.base + 1);
    ASSERT_TRUE(index.state() == VerificationState::Quarantined);
    // The rebuilt index is the one a straight build over the new states writes.
    HeadCase fresh;
    held(fresh);
    fresh.source.states = c.source.states;
    TempIndex straight;
    ASSERT_TRUE(build_to_end(straight, fresh.source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(build_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
    ASSERT_TRUE(same_rows(c, straight, index));
  }
  {
    // The head block substituted under the same seqno: never built to.
    HeadCase c;
    held(c);
    TempIndex index;
    for (int i = 0; i < 2; ++i)
      ASSERT_TRUE(run_build_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
    auto rows = index.ages();
    c.source.blocks[22].id = master_id(22, 5);
    auto refused = run_build_step(*index.db, c.source, small);
    ASSERT_TRUE(refused.is_error() && tos::services::is_terminal_verify_error(refused.error()));
    ASSERT_TRUE(index.ages() == rows);
    ASSERT_TRUE(index.db->build_record().move_as_ok().value().head == master_id(22));
  }
}

// The head must be a block the source holds and has applied, with its full
// identity; anything else is terminal before a record is written.
TEST(WalletIndexVerify, a_build_starts_only_at_an_applied_held_head) {
  for (int variant = 0; variant < 2; ++variant) {
    HeadCase c;
    held(c);
    if (variant == 0) {
      c.source.blocks[22].applied = false;
    } else {
      c.source.blocks[22].id = master_id(22, 5);
    }
    TempIndex index;
    auto outcome = run_build_step(*index.db, c.source);
    ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(index.db->is_fresh().move_as_ok());
  }
}

// Block 1's identity comes from the head's state; when that state does not
// record it the build is never published, and the index stays Quarantined
// with its record until it can be.
TEST(WalletIndexVerify, a_build_is_published_only_with_block_1_from_the_heads_state) {
  HeadCase c;
  held(c);
  c.source.first_block = {};
  TempIndex index;
  auto outcome = build_to_end(index, c.source);
  ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
  ASSERT_TRUE(index.state() == VerificationState::Quarantined);
  ASSERT_TRUE(!index.db->replay_checkpoint().move_as_ok());
  ASSERT_TRUE(!index.db->verification_record().move_as_ok());
  ASSERT_TRUE(index.db->build_record().move_as_ok().value().cursor == 23u);
  c.source.first_block = master_id(1, 9);
  ASSERT_TRUE(build_to_end(index, c.source).move_as_ok().step == VerifyStep::Done);
  ASSERT_TRUE(index.db->replay_checkpoint().move_as_ok().value().anchor == master_id(1, 9));
}

// One account with more transactions in one interval than the retention
// keeps gets only its newest kMaxEventsPerAccount; later intervals trim it
// as replay does.
TEST(WalletIndexVerify, a_build_keeps_the_newest_rows_of_an_account_per_interval) {
  // Left tips end at 20000 * s: at head 22 the base is 15, interval 16
  // spans logical times [300000, 320000).
  FixtureSource source(22, 1, 20000);
  auto big = address(0x70);
  std::vector<uint64_t> lts;
  for (uint64_t lt = 300001; lt <= 310005; ++lt)
    lts.push_back(lt);
  for (uint64_t lt = 320001; lt <= 320003; ++lt)
    lts.push_back(lt);
  source.hold(history(big, lts, 299000));
  ASSERT_EQ(source.interval_cells[16].size(), 10005u);
  VerifyLimits small;
  small.intervals_per_step = 1;
  TempIndex index;
  ASSERT_TRUE(run_build_step(*index.db, source, small).move_as_ok().step == VerifyStep::Working);
  ASSERT_EQ(index.db->build_record().move_as_ok().value().base, 15u);
  ASSERT_TRUE(run_build_step(*index.db, source, small).move_as_ok().step == VerifyStep::Working);
  auto after16 = index.lts(big);
  ASSERT_EQ(after16.size(), tos_wallet_index::kMaxEventsPerAccount);
  ASSERT_EQ(*after16.begin(), 300006u);
  ASSERT_EQ(*after16.rbegin(), 310005u);
  ASSERT_TRUE(build_to_end(index, source, small).move_as_ok().step == VerifyStep::Done);
  auto kept = index.lts(big);
  ASSERT_EQ(kept.size(), tos_wallet_index::kMaxEventsPerAccount);
  ASSERT_EQ(*kept.begin(), 300009u);
  ASSERT_EQ(*kept.rbegin(), 320003u);
}

// The build stops as terminal, without advancing, at an interval over the
// memory bound, a gap that appeared in the window, or a block not linked to
// the one below it; and an index holding data without a build record is
// never built over.
TEST(WalletIndexVerify, a_build_stops_at_a_bound_a_gap_or_an_unlinked_block) {
  VerifyLimits small;
  small.intervals_per_step = 1;
  auto stops_at = [&](HeadCase& c, TempIndex& index, const VerifyLimits& limits, const std::string& reason) {
    auto cursor = index.db->build_record().move_as_ok().value().cursor;
    td::Result<tos::services::VerifyOutcome> outcome = td::Status::Error("not run");
    for (int i = 0; i < 100; ++i) {
      outcome = run_build_step(*index.db, c.source, limits);
      if (outcome.is_error() || outcome.ok().step != VerifyStep::Working) {
        break;
      }
      cursor = index.db->build_record().move_as_ok().value().cursor;
    }
    CHECK(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
    CHECK(contains(outcome.error().message().str(), reason));
    CHECK(index.db->build_record().move_as_ok().value().cursor == cursor);
    CHECK(index.state() == VerificationState::Quarantined);
  };
  {
    HeadCase c;
    held(c);
    TempIndex index;
    ASSERT_TRUE(run_build_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
    VerifyLimits tight = small;
    tight.interval_bytes = 100;
    stops_at(c, index, tight, "MiB to build");
  }
  {
    HeadCase c;
    held(c);
    TempIndex index;
    ASSERT_TRUE(run_build_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
    c.source.blocks.erase(18);
    stops_at(c, index, small, "the window has a gap");
  }
  {
    HeadCase c;
    held(c);
    TempIndex index;
    ASSERT_TRUE(run_build_step(*index.db, c.source, small).move_as_ok().step == VerifyStep::Working);
    // The block's bytes and its handle agree, on a block that is not the
    // one the build linked last.
    c.source.blocks[18].prev = master_id(17, 3);
    c.source.blocks[18].handle_prev = master_id(17, 3);
    stops_at(c, index, small, "is not linked");
  }
  {
    HeadCase c;
    held(c);
    TempIndex index;
    index.add(c.linked.front());
    auto outcome = run_build_step(*index.db, c.source);
    ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
    ASSERT_TRUE(contains(outcome.error().message().str(), "never built over"));
    ASSERT_TRUE(!index.db->build_record().move_as_ok());
  }
}

namespace {
// A chain of `cells` full cells, distinct per `seed`.
td::Ref<vm::Cell> payload(uint64_t seed, int cells) {
  td::Ref<vm::Cell> next;
  for (int i = 0; i < cells; ++i) {
    vm::CellBuilder cb;
    CHECK(cb.store_long_bool(static_cast<long long>(seed), 64) && cb.store_long_bool(i, 32) &&
          cb.store_zeroes_bool(1023 - 96));
    if (next.not_null()) {
      CHECK(cb.store_ref_bool(next));
    }
    next = cb.finalize();
  }
  return next;
}
}  // namespace

// A row is charged its transaction's cells, not a fixed size: ten
// transactions of forty cells each exceed a bound ten small ones fit in.
TEST(WalletIndexVerify, a_build_charges_each_row_its_transactions_cells) {
  VerifyLimits limits;
  limits.intervals_per_step = 1;
  limits.interval_bytes = size_t{64} << 10;
  auto account = address(0x10);
  for (bool heavy : {false, true}) {
    FixtureSource source(22);
    std::vector<td::Ref<vm::Cell>> rows;
    td::Bits256 prev = address(0xEE);
    uint64_t prev_lt = 14000;
    // At head 22 the base is 15: interval 16 holds logical times [15000, 16000).
    for (uint64_t lt = 15001; lt <= 15010; ++lt) {
      rows.push_back(transaction(account, lt, prev, prev_lt, 0, heavy ? payload(lt, 40) : td::Ref<vm::Cell>{}));
      prev = rows.back()->get_hash().bits();
      prev_lt = lt;
    }
    source.hold(rows);
    ASSERT_EQ(source.interval_cells[16].size(), 10u);
    TempIndex index;
    ASSERT_TRUE(run_build_step(*index.db, source, limits).move_as_ok().step == VerifyStep::Working);
    auto outcome = run_build_step(*index.db, source, limits);
    if (heavy) {
      ASSERT_TRUE(outcome.is_error() && tos::services::is_terminal_verify_error(outcome.error()));
      ASSERT_TRUE(contains(outcome.error().message().str(), "to build; it is not built"));
      ASSERT_TRUE(index.lts(account).empty());
    } else {
      ASSERT_TRUE(outcome.move_as_ok().step == VerifyStep::Working);
      ASSERT_EQ(index.lts(account).size(), 10u);
    }
  }
}

namespace {
using tos::services::first_block_from_head_state;

// A masterchain state of block `seqno` as the chain stores it, recording `first` as
// masterchain block 1 in its OldMcBlocks (only the zerostate when unset), unpacked by
// the production configuration reader.
td::Ref<vm::Cell> masterchain_state(const td::optional<BlockIdExt>& first, uint32_t seqno = 22) {
  vm::Dictionary params{32};
  CHECK(params.set_ref(td::BitArray<32>::zero(), vm::CellBuilder{}.store_zeroes(256).finalize()));
  vm::CellBuilder r1;
  CHECK(r1.store_long_bool(0, 16)                                                            // flags
        && r1.store_long_bool(0, 32) && r1.store_long_bool(0, 32)                            // validator_info
        && r1.store_long_bool(0, 1)                                                          //   nx_cc_updated
        && r1.store_long_bool(0, 1) && r1.store_long_bool(0, 1) && r1.store_zeroes_bool(64)  // prev_blocks: empty
        && r1.store_long_bool(0, 1)                                                          // after_key_block
        && r1.store_long_bool(0, 1));                                                        // last_key_block
  vm::CellBuilder extra;
  CHECK(extra.store_long_bool(0xcc26, 16) && extra.store_long_bool(0, 1)  // shard_hashes: empty
        && extra.store_zeroes_bool(256) && extra.store_ref_bool(params.get_root_cell()) &&
        extra.store_ref_bool(r1.finalize()) && extra.store_zeroes_bool(4 + 1));  // global_balance
  vm::CellBuilder rest;
  CHECK(rest.store_zeroes_bool(64 + 64 + 5 + 5 + 1 + 1));
  vm::CellBuilder root;
  CHECK(root.store_long_bool(0x9023afe2, 32) && root.store_long_bool(3, 32)  // shard_state, global_id
        && root.store_long_bool(0, 2) && root.store_long_bool(0, 6) && root.store_long_bool(tos::masterchainId, 32) &&
        root.store_long_bool(0, 64)                   // shard_id
        && root.store_long_bool(seqno, 32)            // seq_no
        && root.store_zeroes_bool(32 + 32 + 64 + 32)  // vert_seq_no ... min_ref_mc_seqno
        && root.store_ref_bool(vm::CellBuilder{}.finalize()) && root.store_long_bool(0, 1) &&
        root.store_ref_bool(vm::CellBuilder{}.finalize()) && root.store_ref_bool(rest.finalize()) &&
        root.store_long_bool(1, 1) && root.store_ref_bool(extra.finalize()));
  td::Ref<vm::Cell> cell = root.finalize();
  block::gen::ShardStateUnsplit::Record state;
  CHECK(tlb::unpack_cell(cell, state));
  block::gen::McStateExtra::Record mc;
  CHECK(tlb::unpack_cell(state.custom->prefetch_ref(), mc));
  vm::AugmentedDictionary prev{mc.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  // Every masterchain state records the zerostate, as a key block.
  std::vector<std::tuple<uint32_t, bool, BlockIdExt>> entries = {{0u, true, master_id(0, 1)}};
  if (first) {
    entries.emplace_back(1u, false, first.value());
  }
  for (auto& [seqno, key, id] : entries) {
    vm::CellBuilder entry;
    CHECK(entry.store_bool_bool(key) && entry.store_long_bool(1000 * seqno, 64) && entry.store_long_bool(seqno, 32) &&
          entry.store_bits_bool(id.root_hash.cbits(), 256) && entry.store_bits_bool(id.file_hash.cbits(), 256));
    CHECK(prev.set(td::BitArray<32>{static_cast<long long>(seqno)}.cbits(), 32, entry.as_cellslice_ref()));
  }
  mc.r1.prev_blocks = prev.get_root();
  td::Ref<vm::Cell> mc_cell;
  CHECK(tlb::pack_cell(mc_cell, mc));
  state.custom = vm::CellBuilder{}.store_long(1, 1).store_ref(mc_cell).as_cellslice_ref();
  CHECK(tlb::pack_cell(cell, state));
  return cell;
}

// A masterchain block whose state update names `state` as its new state;
// `ordinary`: a plain cell where the update belongs.
td::Ref<vm::Cell> head_block(const td::Ref<vm::Cell>& state, bool ordinary = false) {
  auto empty = vm::CellBuilder{}.finalize();
  td::Ref<vm::Cell> update =
      ordinary ? vm::CellBuilder{}.store_long(4, 8).finalize()
               : vm::CellBuilder::create_merkle_update(vm::CellBuilder::create_pruned_branch(empty, 1),
                                                       vm::CellBuilder::create_pruned_branch(state, 1));
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x11ef55aa, 32) && cb.store_long_bool(3, 32) && cb.store_ref_bool(empty) &&
        cb.store_ref_bool(empty) && cb.store_ref_bool(update) && cb.store_ref_bool(empty));
  return cb.finalize();
}

bool terminal_with(const td::Result<BlockIdExt>& result, const std::string& reason) {
  return result.is_error() && tos::services::is_terminal_verify_error(result.error()) &&
         contains(result.error().message().str(), reason);
}
}  // namespace

// Block 1's identity is read from the masterchain state the head's block
// names, never from another state: one substituted under the head, also one
// that differs only in block 1's root or file hash, is refused, as is a
// state without block 1 or a block without a state update.
TEST(WalletIndexVerify, block_1_comes_from_the_state_the_heads_block_names) {
  auto head = master_id(22);
  auto first = master_id(1, 4);
  auto state = masterchain_state(first);
  auto block = head_block(state);
  auto found = first_block_from_head_state(head, block, state);
  ASSERT_TRUE(found.is_ok());
  ASSERT_TRUE(found.ok() == first);
  auto other_root = master_id(1, 7);
  auto other_file = first;
  other_file.file_hash.as_slice()[5] = 9;
  for (auto& substitute : {other_root, other_file}) {
    auto other = masterchain_state(substitute);
    ASSERT_TRUE(terminal_with(first_block_from_head_state(head, block, other), "not the one its block names"));
    // Bound to its own block, the same state is read as it records.
    ASSERT_TRUE(first_block_from_head_state(head, head_block(other), other).move_as_ok() == substitute);
  }
  auto without = masterchain_state({});
  ASSERT_TRUE(
      terminal_with(first_block_from_head_state(head, head_block(without), without), "does not record masterchain"));
  ASSERT_TRUE(
      terminal_with(first_block_from_head_state(head, head_block(state, true), state), "no valid state update"));
  ASSERT_TRUE(terminal_with(first_block_from_head_state(head, block, td::Ref<vm::Cell>{}), "not the one its block"));
  ASSERT_TRUE(terminal_with(first_block_from_head_state(head, state, state), "does not decode"));
  // A state of another block, named by the head's block, is not the head's.
  auto elsewhere = masterchain_state(first, 21);
  ASSERT_TRUE(terminal_with(first_block_from_head_state(head, head_block(elsewhere), elsewhere), "does not decode"));
}
