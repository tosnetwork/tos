/*
    TOS wc=0 in-process wallet index — side-channel RocksDB.

    Serves wallet "aggregate" queries (jetton list, NFT list, account events)
    directly from the node, with no external indexer: a standalone, per-validator
    RocksDB at `${db_root}/wc0-index`, parallel to celldb/statedb and completely
    outside the consensus state cell tree. It never contributes to any
    state hash; operators can prune/rebuild independently without a hardfork.

    Writes happen best-effort on block apply (off the consensus path): a failed
    write only degrades RPC for that block, it never blocks consensus.

    See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md.
*/
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "td/utils/bits.h"
#include "td/utils/buffer.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

namespace td {
class RocksDb;
}

namespace tos_wallet_index {

// How much per-account event history this index keeps. Well above what a
// normal account accumulates, so ordinary reads never reach it, and finite
// so the index does not grow for the life of the node. Declared here so
// the retention test can assert against the exact bound.
constexpr size_t kMaxEventsPerAccount = 10000;
// Extra events a trim pass may drop *beyond* replacing this block's additions.
// A pass always deletes at least as many rows as were added for the account in
// the block (so the bound cannot be outrun no matter how many events an account
// gains per block) plus this drain, which brings a pre-existing backlog down
// over successive blocks. Trimming stays bounded work per call.
constexpr size_t kEventTrimDrainPerPass = 256;

// Global age-based retention. The per-account cap above bounds one account's
// history but not the number of accounts, so one-transaction accounts would
// accumulate forever. Events whose block gen_utime is older than this window
// are dropped regardless of account, so total index size is bounded by the
// retention window rather than by the count of distinct accounts ever seen.
// Aligned to the archive TTL. Declared here so the retention test can assert
// the exact bound.
constexpr uint32_t kEventRetentionSeconds = 7 * 24 * 60 * 60;  // 7 days
// Extra expired age rows a per-block prune may drop beyond the number added in
// the block. As with kEventTrimDrainPerPass, a prune pass always removes at
// least as many rows as the block added (plus this drain), so a high
// fresh-account insert rate cannot outrun the global bound and any backlog
// shrinks block by block. A fixed budget alone would not hold the bound.
constexpr size_t kEventPruneDrainPerBlock = 256;
// wc0-index on-disk schema version, bumped when a key layout changes so open()
// can migrate. Version 1 introduces the event-age index (0x14) and global
// retention; a database with no version key predates this and is treated as
// version 0.
constexpr uint32_t kWalletIndexSchemaVersion = 1;

// Bound the TVM verification work a single block can demand: token candidates
// verified per block, the block's own and deferred ones together. Candidates
// past the bound are deferred to a durable backlog rather than dropped.
constexpr size_t kMaxTokenCandidatesPerBlock = 1024;
// Share of that bound reserved for the backlog while it is non-empty, so the
// backlog drains even when every block brings a full load of its own.
constexpr size_t kTokenBacklogDrainPerBlock = kMaxTokenCandidatesPerBlock / 2;
// The backlog is split into 256 FIFO queues by the top byte of the address,
// so a shard (of depth <= 8) reads only its own queues and entries of another
// shard can never stand in front of its own. A shard drains its queues round
// robin, taking at most an equal share from each per pass, so a queue that
// keeps refilling cannot starve the others.
constexpr size_t kTokenBacklogBuckets = 256;
// Entries examined per queue per pass. Only matters for shards deeper than 8
// levels, which share a queue with a sibling and skip its entries.
constexpr size_t kTokenBacklogScanPerBucket = 4 * kMaxTokenCandidatesPerBlock;
// Verification attempts a candidate gets. A candidate whose verification is
// indeterminate (the node, not the contract, prevented an answer) goes back to
// the end of its queue until it has used them all; then it is given up and
// counted as lost.
constexpr uint8_t kMaxTokenCandidateAttempts = 4;
// Distinct candidates the backlog may hold. A candidate already in the backlog
// is not added twice. Past this, new deferrals are refused and counted as lost,
// which marks the token index incomplete until it is rebuilt.
constexpr uint64_t kMaxTokenBacklogEntries = 1u << 20;

using HashKey = td::Bits256;  // owner / master / nft / account / tx hash

enum class TokenKind : uint8_t { Jetton = 0, Nft = 1 };

struct TokenCandidate {
  TokenKind kind;
  HashKey address;
  bool operator<(const TokenCandidate& other) const {
    if (kind != other.kind) {
      return kind < other.kind;
    }
    return address < other.address;
  }
  bool operator==(const TokenCandidate& other) const {
    return kind == other.kind && address == other.address;
  }
};

struct ScheduledTokenCandidate {
  TokenCandidate candidate;
  // Verification attempts already made before this one.
  uint8_t attempts;
};

struct TokenBacklogStats {
  uint64_t entries;
  // Candidates given up after their last attempt, refused for capacity, or
  // found malformed. Non-zero means the token index may be missing updates.
  uint64_t lost;
  // Candidates whose verification needs another shard's state (a jetton
  // master or NFT collection outside the shard being indexed). This index
  // verifies against one shard's state, so they cannot be indexed here.
  uint64_t unverifiable;
  // Blocks marked in progress: one being indexed right now, or one whose
  // indexing failed and was rolled back, leaving its updates unapplied.
  uint64_t incomplete_blocks;
};

// Completeness of the token index as RPC answers report it: a JSON object
// value. `complete` is false while candidates wait, while any block's
// indexing is unfinished, and once any candidate was lost or could not be
// verified; only rebuilding the index clears lost and unverifiable.
inline std::string format_token_index_state(const TokenBacklogStats& stats) {
  bool complete = stats.entries == 0 && stats.lost == 0 && stats.unverifiable == 0 && stats.incomplete_blocks == 0;
  return "{\"complete\":" + std::string(complete ? "true" : "false") + ",\"pending\":" + std::to_string(stats.entries) +
         ",\"lost\":" + std::to_string(stats.lost) + ",\"unverifiable\":" + std::to_string(stats.unverifiable) +
         ",\"incomplete_blocks\":" + std::to_string(stats.incomplete_blocks) + "}";
}

// What became of one scheduled candidate's verification.
enum class TokenVerifyOutcome {
  Done,          // a verdict was reached and its index writes joined the batch
  Retry,         // the node could not reach a verdict this time
  Unverifiable,  // the verdict needs another shard's state
  WriteFailed,   // an index write failed; the block must not commit
};

class WalletIndexDb {
 public:
  // Open (or create) the index DB at `path`. The directory is created if needed.
  static td::Result<std::unique_ptr<WalletIndexDb>> open(std::string path);
  // A read-only view of the index as committed at this moment. Reads through
  // it (the token state and the lists an answer is built from) all see the
  // same commit; writes through it fail.
  td::Result<std::unique_ptr<WalletIndexDb>> read_snapshot();

  WalletIndexDb(const WalletIndexDb&) = delete;
  WalletIndexDb& operator=(const WalletIndexDb&) = delete;
  ~WalletIndexDb();

  // --- Jetton ownership: 0x10 + owner(32) + master(32) -> value cell ---
  td::Status put_jetton(const HashKey& owner, const HashKey& master, td::Ref<vm::Cell> value);
  td::Status erase_jetton(const HashKey& owner, const HashKey& master);
  // Walk at most `limit` jetton masters held by `owner`. Callback receives
  // (master, value cell).
  td::Status for_each_jetton(
      const HashKey& owner, size_t limit,
      std::function<td::Status(const HashKey& master, td::Ref<vm::Cell>)> cb);

  // --- NFT ownership: 0x11 + owner(32) + nft(32) -> value cell ---
  td::Status put_nft(const HashKey& owner, const HashKey& nft, td::Ref<vm::Cell> value);
  td::Status erase_nft(const HashKey& owner, const HashKey& nft);
  td::Status for_each_nft(
      const HashKey& owner, size_t limit,
      std::function<td::Status(const HashKey& nft, td::Ref<vm::Cell>)> cb);

  // --- Account event feed: 0x12 + account(32) + ~lt_be(8) -> value cell ---
  // Keys store the bitwise complement of lt so RocksDB's ascending iteration
  // yields newest events first and `limit` bounds the scan to the most recent.
  td::Status put_event(const HashKey& account, uint64_t lt, td::Ref<vm::Cell> value);
  // Drops the oldest events of an account once it holds more than the retained
  // history. Called on the write path inside the block's batch, before commit,
  // so its scan sees only committed rows -- not the `added_this_block` rows just
  // written into the batch. It keeps that many fewer committed rows so the total
  // after commit stays within kMaxEventsPerAccount, and deletes at least
  // `added_this_block` rows so the bound cannot be outrun. Bounded work per call.
  td::Status trim_events(const HashKey& account, size_t added_this_block);

  // --- Event age index: 0x14 + gen_utime_be(4) + account(32) + lt_be(8) -> sentinel ---
  // Written alongside every put_event so the index can be pruned by block time,
  // reaching entire dormant accounts that the per-account trim_events never
  // revisits. Keyed by gen_utime first (a shard-agnostic global time scale;
  // account+lt break ties) so a time range scan finds the oldest events. Stores
  // plain lt (not ~lt) so the pruner can reconstruct the 0x12 event key.
  // Joins the current write batch.
  td::Status put_event_age(const HashKey& account, uint64_t lt, uint32_t gen_utime);
  // Delete event rows (and their age companions) whose block gen_utime is
  // strictly older than `cutoff_gen_utime`, at most `budget` of them, so work
  // per block is bounded and any backlog drains over successive blocks. Events
  // exactly at the cutoff are retained. Deletes join the current batch.
  td::Status prune_events_by_age(uint32_t cutoff_gen_utime, size_t budget);
  // Non-decreasing chain-time watermark (max block gen_utime indexed); read
  // returns 0 when unset, put joins the current batch. The writer advances it to
  // max(current, block gen_utime) so a late or recovery block cannot regress the
  // prune cutoff and silently retain expired rows.
  td::Result<uint32_t> get_event_watermark();
  td::Status put_event_watermark(uint32_t gen_utime);
  // Advance the watermark to max(current, gen_utime) and prune events older than
  // the resulting cutoff (at most age_rows_added + drain of them), within the
  // current batch. Fails closed: any error -- including a watermark read error,
  // which must never fall back to 0 and regress the watermark -- is returned so
  // the caller aborts the block instead of committing a broken retention state.
  td::Status advance_retention(uint32_t gen_utime, size_t age_rows_added);
  td::Status for_each_key_with_prefix(td::Slice prefix, size_t limit,
                                      std::function<td::Status(td::Slice)> cb);
  // Walk at most `limit` events for `account`, newest first.
  td::Status for_each_event(
      const HashKey& account, size_t limit,
      std::function<td::Status(uint64_t lt, td::Ref<vm::Cell>)> cb);
  td::Status for_each_event_before(
      const HashKey& account, uint64_t before_lt, size_t limit,
      std::function<td::Status(uint64_t lt, td::Ref<vm::Cell>)> cb);
  td::Result<td::Ref<vm::Cell>> get_event(const HashKey& account, uint64_t lt);

  // --- NFT current-owner reverse map: 0x13 + nft(32) -> owner(32) ---
  // Tracks the last verified owner of each indexed NFT so the writer can erase
  // the previous owner's 0x11 entry when ownership changes (no stale entries).
  td::Status put_nft_owner(const HashKey& nft, const HashKey& owner);
  td::Status erase_nft_owner(const HashKey& nft);
  // Returns true and fills `owner` if a previous owner is recorded. Reads
  // committed state only — an open write batch is not visible — which is what
  // the writer wants: the pre-block owner.
  td::Result<bool> get_nft_owner(const HashKey& nft, HashKey& owner);

  // --- Deferred token candidates ---
  //   0x15 + bucket(1) + seq_be(8) -> kind(1) + address(32) + attempts(1)
  //   0x16 + kind(1) + address(32) -> bucket(1) + seq_be(8)   (its queue entry)
  // Choose the token candidates a block of wc=0 `shard` verifies: at most
  // `capacity` (<= kMaxTokenCandidatesPerBlock) of them. While the shard's
  // queues hold entries, up to kTokenBacklogDrainPerBlock of the capacity goes
  // to them; the block's own candidates fill the rest, and those that do not
  // fit are deferred. A block candidate already waiting is claimed from the
  // backlog with the attempts it has used. Pass capacity 0 to defer all of a
  // block's candidates (no state to verify against). Chosen backlog entries
  // are erased. Every write joins the open batch, so an aborted block leaves
  // the backlog as it was. Requires an open batch and runs once per batch.
  td::Result<std::vector<ScheduledTokenCandidate>> schedule_token_candidates(
      const std::vector<TokenCandidate>& block_candidates, tos::ShardIdFull shard,
      size_t capacity = kMaxTokenCandidatesPerBlock);
  // Hand back a scheduled candidate whose verification was indeterminate: it
  // rejoins the end of its queue, or is counted as lost after its last
  // attempt. Joins the open batch; requires schedule_token_candidates first.
  td::Status retry_token_candidate(const ScheduledTokenCandidate& scheduled);
  // Verify every scheduled candidate with `verify` (given the candidate and
  // how many remain, this one included) and record what it could not finish:
  // Retry and an exception hand the candidate back, Unverifiable is counted,
  // and WriteFailed stops and returns an error so the caller aborts the block.
  td::Status process_token_candidates(
      const std::vector<ScheduledTokenCandidate>& scheduled,
      const std::function<TokenVerifyOutcome(const ScheduledTokenCandidate&, size_t remaining)>& verify);
  // Backlog size and lost/unverifiable counts, as committed.
  td::Result<TokenBacklogStats> token_backlog_stats();
  // Lower the backlog bound (never above kMaxTokenBacklogEntries) so tests can
  // reach it without writing a million rows.
  void set_token_backlog_limit(uint64_t limit) {
    token_backlog_limit_ = limit < kMaxTokenBacklogEntries ? limit : kMaxTokenBacklogEntries;
  }
  // Walk at most `limit` deferred candidates (committed state), queue by queue.
  td::Status for_each_deferred_token_candidate(size_t limit, std::function<td::Status(const TokenCandidate&)> cb);

  // --- Crash-recovery marker: 0x1E + workchain_be(4) + shard_be(8) + seqno_be(4)
  //     + root_hash(32) + file_hash(32) -> sentinel(1) ---
  // Keyed off the full BlockIdExt (workchain+shard+seqno+both hashes), not
  // seqno alone: a different shard can reuse the same seqno after a
  // split/merge, so seqno by itself is not a unique identifier, and if the
  // same position were ever re-applied with a different hash, a
  // position-only key would let the new marker silently overwrite the old
  // one instead of being a distinct entry. Keying on the full id also means
  // recovery already has everything needed for an exact get_block_handle()
  // lookup — no separate account/shard-prefix search that could resolve to
  // the wrong shard's block.
  // put_incomplete_block is durable on return (WAL-synced); delete_incomplete_block
  // joins the open write batch when one is active.
  td::Status put_incomplete_block(const tos::BlockIdExt& block_id);
  td::Status delete_incomplete_block(const tos::BlockIdExt& block_id);
  td::Result<bool> has_incomplete_block(const tos::BlockIdExt& block_id);
  // Crash-recovery scan: calls `cb(block_id)` for every currently-recorded
  // incomplete-block marker. Markers are only ever left behind by a crash
  // mid-block or a parse failure (see wallet-index-writer.cpp); callers are
  // expected to re-fetch and re-index each flagged block, then
  // delete_incomplete_block() on success — and to leave the marker in place
  // (not delete it) if re-indexing is itself incomplete, e.g. post-apply
  // state isn't available, so a later attempt can still backfill it.
  td::Status for_each_incomplete_block(std::function<td::Status(const tos::BlockIdExt& block_id)> cb);

  // --- Per-block batched writes ---
  // Writers must hold write_mutex() across begin_batch()..commit_batch()/abort_batch():
  // the underlying td::RocksDb write batch is a single unsynchronized member, and
  // block-apply actors can run concurrently. Readers (for_each_*) need no lock —
  // they iterate committed state only.
  std::mutex& write_mutex() { return write_mutex_; }
  // Route subsequent put_/erase_ calls into an atomic batch.
  td::Status begin_batch();
  // Atomically commit the batch and sync the WAL for it (one of two WAL
  // syncs per block — the other is put_incomplete_block()'s own sync,
  // durable before this one, before indexing even starts).
  td::Status commit_batch();
  // Drop the batch (e.g. after a parse error) so no partial block is written.
  void abort_batch();

 private:
  explicit WalletIndexDb(std::unique_ptr<td::RocksDb> db);
  td::Status put_cell(td::Slice key, td::Ref<vm::Cell> value);
  // Iterate keys in [prefix, next(prefix)) — a bounded range scan, never a full
  // table walk. Visits at most `limit` keys.
  td::Status for_each_with_prefix(
      td::Slice prefix, size_t limit,
      std::function<td::Status(td::Slice key, td::Ref<vm::Cell>)> cb);

  // Bring the on-disk layout up to kWalletIndexSchemaVersion. Runs once in
  // open() before the DB is used; migrates atomically (WAL-synced) and refuses
  // to open a database written by a newer, unknown version.
  td::Status migrate_schema();
  // Delete every key in the single-byte-tag namespace [tag, tag+1). Migration
  // only; routes through the active write batch.
  td::Status clear_namespace(uint8_t tag);

  std::unique_ptr<td::RocksDb> db_;
  std::mutex write_mutex_;
  bool batch_open_ = false;

  // Token backlog bookkeeping for the open batch. Counters are loaded from
  // committed state when scheduling starts and written back with every change;
  // the overlay records index entries written in the batch, which committed
  // reads cannot see: the queue key they point to, or empty once erased.
  struct TokenBatchState {
    bool scheduled = false;
    uint64_t next_seq = 0;
    uint64_t entries = 0;
    uint64_t lost = 0;
    uint64_t unverifiable = 0;
    std::map<std::string, std::string> index_overlay;
    // Queue rows already erased in the batch, which committed reads still see.
    std::set<std::string> queue_erased;
  };
  TokenBatchState token_batch_;
  uint64_t token_backlog_limit_ = kMaxTokenBacklogEntries;
  td::Result<uint64_t> get_meta_u64(uint8_t sub);
  td::Status put_meta_u64(uint8_t sub, uint64_t value);
  td::Result<std::string> token_index_get(const std::string& index_key);
  td::Status token_index_erase(const std::string& index_key);
  td::Result<bool> token_queue_has(const std::string& queue_key);
  td::Status token_queue_erase(const std::string& queue_key);
  td::Result<uint8_t> token_claim(const TokenCandidate& candidate);
  td::Status token_enqueue(const TokenCandidate& candidate, uint8_t attempts);
  td::Status token_note_lost(const TokenCandidate& candidate, td::Slice reason);
  td::Status token_write_counters();
};

// Module-scope singleton. Returns nullptr until the
// validator opens the index at startup.
WalletIndexDb* wallet_index_db();
void set_wallet_index_db(std::unique_ptr<WalletIndexDb> db);

// Open the index at `${db_root}/wc0-index` and install it as the singleton.
// Best-effort: logs and leaves the singleton null on failure.
void open_wallet_index_db(const std::string& db_root);

}  // namespace tos_wallet_index
