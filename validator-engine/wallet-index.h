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
#include "td/utils/optional.h"
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
// version 0. Version 2 introduces the jetton wallet record (0x17). Version 3
// suppresses jetton rows written without a pair record (0x18): a database
// upgraded from an earlier version with any jetton row records that its
// legacy jetton rows await reconstruction, and no RPC serves them until the
// reconstruction has verified each against chain state and published the
// result (see reconstruct_legacy_jetton_rows).
constexpr uint32_t kWalletIndexSchemaVersion = 3;
// Legacy jetton rows examined per reconstruction pass.
constexpr size_t kLegacyJettonRowsPerPass = 256;

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
// the end of its queue until it has used them all; then it is parked: its
// identity is kept, the token index reports itself incomplete while any
// candidate is parked, and the indexing worker retries parked candidates
// itself, a bounded number at a time after a pause, against the newest state
// it has, until each reaches a definite result. A later nomination also
// verifies it afresh.
constexpr uint8_t kMaxTokenCandidateAttempts = 4;
// Distinct candidates the backlog queues may hold. A candidate already
// waiting is not added twice. A block whose candidates do not all fit stops
// deferring at the first that does not; the rest of its candidates are
// persisted with the block (see put_pending_block), so the block's own data
// is never needed again, and the block stays marked unfinished until the
// indexing worker has verified them. Parked candidates do not take queue
// room: they have their own bound.
constexpr uint64_t kMaxTokenBacklogEntries = 1u << 20;
// Parked candidates the index may hold. Past it, a candidate that exhausts
// its attempts waits in its queue again instead, with one attempt left.
constexpr uint64_t kMaxParkedTokenCandidates = 1u << 20;
// Blocks whose remaining candidates the index may hold at once. While this
// many are unfinished, the indexing worker finishes them before it indexes
// another block; blocks applied meanwhile wait in its queue or, past that,
// stay marked for recovery as any block the worker could not take.
constexpr size_t kMaxPendingTokenBlocks = 1024;

using HashKey = td::Bits256;  // owner / master / nft / account / tx hash

// An applied block the index has not finished, with its generation time.
struct MarkedBlock {
  tos::BlockIdExt id;
  uint32_t gen_utime = 0;
};

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
  // End logical time of the newest block that nominated it. Only a state at
  // least this new can verify it; an older one could only give a verdict the
  // nominating block has already overtaken.
  uint64_t lt = 0;
  // Taken from the backlog: its queue slot stays reserved for it until it has
  // an outcome, so it can always go back. A block's own candidate holds no
  // slot; when it has to wait and the backlog is full, it stays with its
  // block (overflow_block_candidates).
  bool holds_reservation = false;
};

struct TokenBacklogStats {
  uint64_t entries;
  // Candidates given up after their last attempt, refused for capacity, or
  // found malformed. Non-zero means the token index may be missing updates.
  uint64_t lost;
  // Counted by older binaries for candidates whose verification needed
  // another shard's state, which they could not keep. Such candidates are
  // now parked with their identity and verified later.
  uint64_t unverifiable;
  // Whether any block is marked in progress: one being indexed right now, or
  // one whose indexing failed and was rolled back, leaving its updates
  // unapplied. Only presence is read, so the check costs one key however many
  // marks have piled up.
  bool unfinished_block;
  // Some block may have gone unindexed with no mark to recover it by; only
  // rebuilding the index makes it complete again.
  bool needs_rebuild = false;
  // Candidates whose verification stayed indeterminate through every
  // attempt. Their identities are kept; a later nomination retries them.
  uint64_t parked = 0;
  // Jetton rows from before pair records existed are not yet all verified
  // and published; until they are, they are left out of every answer.
  bool legacy_unverified = false;
};

// Completeness of the token index as RPC answers report it: a JSON object
// value. `complete` is false while candidates wait, while any block's
// indexing is unfinished, and once any candidate was lost or could not be
// verified; only rebuilding the index clears lost and unverifiable.
inline std::string format_token_index_state(const TokenBacklogStats& stats) {
  bool complete = stats.entries == 0 && stats.lost == 0 && stats.unverifiable == 0 && !stats.unfinished_block &&
                  !stats.needs_rebuild && stats.parked == 0 && !stats.legacy_unverified;
  return "{\"complete\":" + std::string(complete ? "true" : "false") + ",\"pending\":" + std::to_string(stats.entries) +
         ",\"lost\":" + std::to_string(stats.lost) + ",\"unverifiable\":" + std::to_string(stats.unverifiable) +
         ",\"unfinished_block\":" + std::string(stats.unfinished_block ? "true" : "false") +
         ",\"needs_rebuild\":" + std::string(stats.needs_rebuild ? "true" : "false") +
         ",\"parked\":" + std::to_string(stats.parked) +
         ",\"legacy_unverified\":" + std::string(stats.legacy_unverified ? "true" : "false") + "}";
}

// What became of one scheduled candidate's verification.
enum class TokenVerifyOutcome {
  Done,          // a verdict was reached and its index writes joined the batch
  Retry,         // the node could not reach a verdict this time
  Unverifiable,  // the verdict needs another shard's state
  WriteFailed,   // an index write failed; the block must not commit
};

class WalletIndexSnapshot;

class WalletIndexDb {
 public:
  // Open (or create) the index DB at `path`. The directory is created if needed.
  static td::Result<std::unique_ptr<WalletIndexDb>> open(std::string path);

  WalletIndexDb(const WalletIndexDb&) = delete;
  WalletIndexDb& operator=(const WalletIndexDb&) = delete;
  ~WalletIndexDb();

  // --- Jetton ownership: 0x10 + owner(32) + master(32) -> value cell ---
  td::Status put_jetton(const HashKey& owner, const HashKey& master, td::Ref<vm::Cell> value);
  td::Status erase_jetton(const HashKey& owner, const HashKey& master);
  // Walk at most `limit` jetton rows of `owner`, as stored: legacy and
  // unpublished rows included. Answers use for_each_current_jetton instead.
  // Callback receives (master, value cell).
  td::Status for_each_jetton(
      const HashKey& owner, size_t limit,
      std::function<td::Status(const HashKey& master, td::Ref<vm::Cell>)> cb);

  // --- Jetton wallet record: 0x17 + wallet(32) -> present(1) + owner(32) + master(32) + lt_be(8) ---
  // The last verdict on a jetton wallet and the logical time of the block it
  // came from; present = 0 records that the wallet was found not to be a
  // jetton wallet acknowledged by its master at that time. It is the reverse
  // of the 0x10 entry, so a wallet whose owner or master changes, or which
  // stops verifying, can have its old 0x10 entry removed. Whether the 0x10
  // entry itself changes is decided by the pair record below.
  struct JettonVerdict {
    bool present;
    HashKey owner;
    HashKey master;
    td::Ref<vm::Cell> value;  // the 0x10 entry for (owner, master) when present
  };
  // Record what the post-state of the block ending at `end_lt` says about
  // `wallet` (into the open batch), unless its record is from a later block.
  // The previous pair is released when the owner or master changed or the
  // wallet is no longer present, and the new pair is claimed; each only if the
  // pair's record is not from a later block, and a release only while the
  // pair still names this wallet. Call it only with a definite verdict; a
  // verification that could not complete must leave the record as it is.
  // `reconstructed`: the verdict comes from reconstructing legacy rows; a
  // pair it claims that had no pair record stays out of answers until the
  // reconstruction is published.
  td::Status apply_jetton_verdict(const HashKey& wallet, const JettonVerdict& verdict, uint64_t end_lt,
                                  bool reconstructed = false);
  // Returns true and fills `owner` and `master` if the wallet's last verdict
  // found it present.
  td::Result<bool> get_jetton_wallet(const HashKey& wallet, HashKey& owner, HashKey& master);

  // The wallet's last recorded verdict, as the open batch leaves it.
  struct JettonWalletState {
    bool present = false;
    HashKey owner = HashKey::zero();
    HashKey master = HashKey::zero();
    uint64_t lt = 0;
  };
  td::Result<td::optional<JettonWalletState>> jetton_wallet_state(const HashKey& wallet);

  // Walk at most `limit` jetton masters held by `owner` that are current: a
  // row whose pair record names it, and, for a row reconstructed from legacy
  // data, only once the reconstruction is published. Rows written before pair
  // records existed are never returned. Callback receives (master, value).
  td::Status for_each_current_jetton(const HashKey& owner, size_t limit,
                                     std::function<td::Status(const HashKey& master, td::Ref<vm::Cell>)> cb);

  // --- Legacy jetton reconstruction ---
  // A jetton row (0x10) with no pair record was written by a binary that kept
  // no reverse record for it: its owner/master mapping may be stale and
  // nothing could retract it. Reconstruction verifies each such row's wallet
  // against chain state and records the verdict (wallet and pair records),
  // pass by pass from a durable cursor; reconstructed pairs stay out of
  // answers until a full sweep finds no legacy row left, which publishes
  // them all at once. A row that cannot be verified (its wallet unreadable,
  // or its verification needs a state this node does not have) keeps the
  // reconstruction unpublished and the index explicitly incomplete.
  //   meta 0x0C -> 1 while reconstruction is pending
  //   meta 0x0D -> the last 0x10 key examined in the current sweep
  //   meta 0x0E -> legacy rows left undecided earlier in the current sweep
  struct LegacyJettonRow {
    HashKey owner;
    HashKey master;
    bool has_wallet = false;  // false when the row's value cannot be read
    HashKey wallet = HashKey::zero();
    uint64_t lt = 0;
  };
  struct LegacyJettonRows {
    std::vector<LegacyJettonRow> rows;
    std::string last_key;      // last 0x10 key examined
    bool reached_end = false;  // the sweep has examined every row
  };
  td::Result<bool> legacy_jettons_pending();
  // The legacy rows among the next `limit` jetton rows after the cursor
  // (committed state). Requires an open batch.
  td::Result<LegacyJettonRows> legacy_jetton_rows(size_t limit);
  // Decide one legacy row by a verdict on its wallet as of `lt` (into the
  // open batch): the row is kept, with a pair record, when the verdict names
  // its owner and master, and removed otherwise. True when the row is
  // decided; false when a later decision already covers its pair and wallet
  // in a way that leaves it undecided.
  td::Result<bool> decide_legacy_jetton(const LegacyJettonRow& row, const JettonVerdict& verdict, uint64_t lt);
  // Record the pass (into the open batch): move the cursor, and at the end
  // of a sweep either publish (no legacy row was left undecided) or start a
  // new sweep. Returns true when this published the reconstruction.
  td::Result<bool> finish_legacy_jetton_pass(const LegacyJettonRows& pass, uint64_t undecided);

  // --- Jetton pair record: 0x18 + owner(32) + master(32) -> flags(1) + wallet(32) + lt_be(8) ---
  // flags: bit 0 present, bit 1 reconstructed from a legacy row.
  // The last decision on the (owner, master) 0x10 entry, shared by every
  // wallet that has claimed the pair: which wallet it names, or that it was
  // removed, and the logical time of the block that decided it. An older
  // block's verdict, for any wallet, neither replaces nor removes a newer
  // decision. A pair with no record (written before records existed) takes
  // its decision from the 0x10 entry's own wallet and lt.

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

  // --- NFT ownership record: 0x13 + nft(32) -> owned(1) + owner(32) + lt_be(8) ---
  // (A record written by an older binary is just owner(32): owned, lt 0.)
  // The last verdict on the item and the logical time of the block it came
  // from; owned = 0 records that the item was found unowned at that time.
  // Blocks can be indexed out of order -- startup recovery re-indexes old
  // blocks while new ones arrive -- so apply_nft_verdict ignores a verdict
  // older than the record.
  // Tracks the last verified owner of each indexed NFT so the writer can erase
  // the previous owner's 0x11 entry when ownership changes (no stale entries).
  td::Status put_nft_owner(const HashKey& nft, const HashKey& owner);
  td::Status erase_nft_owner(const HashKey& nft);
  // Returns true and fills `owner` if a previous owner is recorded. Reads
  // committed state only — an open write batch is not visible — which is what
  // the writer wants: the pre-block owner.
  td::Result<bool> get_nft_owner(const HashKey& nft, HashKey& owner);
  struct NftVerdict {
    bool owned;
    HashKey owner;
    td::Ref<vm::Cell> value;  // the 0x11 entry for (owner, item) when owned
  };
  // Record what the post-state of the block ending at `end_lt` says about
  // `item` (into the open batch), unless the item's record is from a later
  // block. Moves the 0x11 entry when the owner changed, removes it when the
  // item is no longer owned.
  td::Status apply_nft_verdict(const HashKey& item, const NftVerdict& verdict, uint64_t end_lt);

  // --- Deferred token candidates ---
  //   0x15 + bucket(1) + seq_be(8) -> kind(1) + address(32) + attempts(1) + lt_be(8)
  //     (an entry written by an older binary has no lt: it counts as lt 0)
  //   0x16 + kind(1) + address(32) -> bucket(1) + seq_be(8)   (its queue entry)
  //   0x1A + kind(1) + address(32) -> lt_be(8)                 (parked)
  // Choose the token candidates a block of wc=0 `shard` ending at `end_lt`
  // verifies: at most `capacity` (<= kMaxTokenCandidatesPerBlock) of them.
  // While the shard's queues hold entries this state can verify (nominated at
  // or before `end_lt`), up to kTokenBacklogDrainPerBlock of the capacity goes
  // to them; the block's own candidates fill the rest in candidate order, and
  // those that do not fit are deferred. A block candidate already waiting is
  // claimed from the backlog with the attempts it has used, unless a newer
  // block nominated it. Pass capacity 0 to defer all of a block's candidates
  // (no state to verify against). Chosen backlog entries are erased. Every
  // write joins the open batch, so an aborted block leaves the backlog as it
  // was. Requires an open batch and runs once per batch.
  // When the backlog has no room for a deferral, deferring stops there:
  // first_unhandled_block_candidate() then names the first block candidate
  // neither chosen nor queued, and that one and every later candidate are
  // left to a later pass over the block. Room is kept for every chosen
  // candidate to go back to the backlog, so a retry never needs room.
  td::Result<std::vector<ScheduledTokenCandidate>> schedule_token_candidates(
      const std::vector<TokenCandidate>& block_candidates, tos::ShardIdFull shard, size_t capacity, uint64_t end_lt);
  // After schedule_token_candidates: the first block candidate (in candidate
  // order) that was neither chosen nor queued, if deferring stopped early.
  td::optional<TokenCandidate> first_unhandled_block_candidate() const {
    return token_batch_.first_unhandled;
  }
  // After processing: the block's own candidates that must wait but found
  // neither queue nor parking room. The caller keeps them with the block.
  const std::vector<ScheduledTokenCandidate>& overflow_block_candidates() const {
    return token_batch_.overflow;
  }
  // Hand back a scheduled candidate whose verification was indeterminate: it
  // rejoins the end of its queue, or is parked after its last attempt. Joins
  // the open batch; requires schedule_token_candidates first.
  td::Status retry_token_candidate(const ScheduledTokenCandidate& scheduled);
  // Verify every scheduled candidate with `verify` (given the candidate and
  // how many remain, this one included) and record what it could not finish:
  // Retry and an exception hand the candidate back, Unverifiable is counted,
  // and WriteFailed stops and returns an error so the caller aborts the block.
  td::Status process_token_candidates(
      const std::vector<ScheduledTokenCandidate>& scheduled,
      const std::function<TokenVerifyOutcome(const ScheduledTokenCandidate&, size_t remaining)>& verify);
  // Whether the backlog queues, as committed, have room for another deferral.
  td::Result<bool> token_backlog_has_room();
  // Start a pass that verifies candidates outside schedule_token_candidates
  // (a pending block's or parked ones): loads the counters into the open
  // batch. Its writes join the batch; save_token_counters() ends it.
  td::Status begin_token_pass();
  td::Status save_token_counters();
  // Within such a pass: park a candidate whose attempts are used up or whose
  // verification needs a state not at hand, release a parked one that
  // reached a definite result.
  // False when parking is full: the caller keeps the candidate in its own
  // durable record instead.
  td::Result<bool> park_token_candidate(const ScheduledTokenCandidate& scheduled);
  td::Status unpark_token_candidate(const TokenCandidate& candidate);
  // Within such a pass: up to `limit` parked candidates from the parked
  // cursor on, wrapping round at the end; `wrapped` tells whether this pass
  // reached the end. The cursor moves past them (into the batch).
  td::Result<std::vector<ScheduledTokenCandidate>> next_parked_token_candidates(size_t limit, bool& wrapped);

  // --- Blocks whose token candidates are not all handled yet ---
  //   0x19 + workchain_be(4) + shard_be(8) + seqno_be(4) + root_hash(32) + file_hash(32)
  //     -> version(1) = 1 + end_lt_be(8) + n * (kind(1) + address(32) + attempts(1))
  // The block's remaining candidates themselves, so a later pass needs
  // neither the block nor its state, however long archive pruning leaves
  // them. The block keeps its incomplete-block marker beside this record.
  // Writes join the open batch.
  struct PendingBlock {
    uint64_t end_lt = 0;
    std::vector<ScheduledTokenCandidate> remaining;
  };
  td::Status put_pending_block(const tos::BlockIdExt& block_id, const PendingBlock& pending);
  td::Result<td::optional<PendingBlock>> get_pending_block(const tos::BlockIdExt& block_id);
  td::Status delete_pending_block(const tos::BlockIdExt& block_id);
  // Calls `cb` for at most `limit` pending blocks, in key order (committed).
  td::Status for_each_pending_block(size_t limit,
                                    std::function<td::Status(const tos::BlockIdExt&, const PendingBlock&)> cb);
  // The first pending block after `after` in key order (from the start when
  // `after` is empty), handed to `cb`; nothing when there is none after it.
  td::Status next_pending_block(const td::optional<tos::BlockIdExt>& after,
                                std::function<td::Status(const tos::BlockIdExt&, const PendingBlock&)> cb);
  // The address of the first waiting candidate in queue `from_bucket` or a
  // later one, wrapping round, with its queue (committed); nothing when the
  // backlog is empty.
  td::optional<std::pair<HashKey, size_t>> next_waiting_token_candidate(size_t from_bucket);
  // How many blocks are pending (committed).
  td::Result<uint64_t> pending_block_count();
  // Whether a verdict on `wallet` has been recorded (committed state).
  td::Result<bool> has_jetton_wallet_record(const HashKey& wallet);
  // Backlog size and lost/unverifiable/parked counts, as committed.
  td::Result<TokenBacklogStats> token_backlog_stats();
  // Lower the backlog bound (never above kMaxTokenBacklogEntries) so tests can
  // reach it without writing a million rows.
  void set_token_backlog_limit(uint64_t limit) {
    token_backlog_limit_ = limit < kMaxTokenBacklogEntries ? limit : kMaxTokenBacklogEntries;
  }
  // Lower the parked bound likewise.
  void set_parked_token_limit(uint64_t limit) {
    parked_limit_ = limit < kMaxParkedTokenCandidates ? limit : kMaxParkedTokenCandidates;
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
  // The marker's value keeps the block's generation time: until the block's
  // token candidates are extracted (indexed, or persisted with the block), the
  // archive must keep the block, and the generation time tells archive
  // pruning how far back to keep (see unextracted_block_floor). 0 means
  // unknown, which keeps everything.
  td::Status put_incomplete_block(const tos::BlockIdExt& block_id, uint32_t gen_utime = 0);
  // Mark several blocks in progress with one WAL sync. Writes through a
  // separate handle, so it neither joins nor waits for a write batch another
  // thread has open; safe to call without write_mutex().
  td::Status mark_blocks_incomplete(const std::vector<MarkedBlock>& blocks);
  td::Status mark_blocks_incomplete(const std::vector<tos::BlockIdExt>& block_ids);
  // The earliest generation time among marked blocks whose candidates are not
  // yet extracted (no pending record beside the marker), or nothing when
  // there is none (committed state). Archive pruning must keep every block
  // generated at or after it.
  td::Result<td::optional<uint32_t>> unextracted_block_floor();
  // Every marker with its generation time (0 when unknown), committed state.
  td::Status for_each_marked_block(std::function<td::Status(const MarkedBlock&)> cb);
  // Durably record that the index may be missing a block nothing can recover
  // (same separate handle; no write_mutex needed). Cleared only by rebuilding.
  td::Status mark_needs_rebuild();
  // --- Indexing-run marker (meta 0x0A) ---
  // Indexing is asynchronous: a block is applied before the recorder thread
  // durably marks it, so a stop in between leaves a block that is neither
  // indexed nor marked, and is never applied again. The run marker is written
  // and WAL-synced before any block can be queued, and removed only after a
  // clean finish; finding it at startup means the previous run may have lost a
  // block, so the index must not be reported complete.
  td::Status begin_indexing_run();
  td::Result<bool> indexing_run_active();
  td::Status end_indexing_run();
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
  friend class WalletIndexSnapshot;
  explicit WalletIndexDb(std::unique_ptr<td::RocksDb> db);
  // A second WalletIndexDb over a RocksDB snapshot. Private: its write methods
  // would reach the live database, so it is handed out only as a
  // WalletIndexSnapshot.
  td::Result<std::unique_ptr<WalletIndexDb>> read_snapshot();
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
  // The decision currently recorded for a jetton pair: its pair record, or for
  // a pair written before pair records existed, the 0x10 entry's own wallet
  // and lt. `known` is false when the pair has neither.
  struct JettonPairDecision {
    bool known = false;
    bool has_record = false;  // decided by a pair record, not by a legacy row
    bool reconstructed = false;
    bool present = false;
    HashKey wallet = HashKey::zero();
    uint64_t lt = 0;
  };
  td::Result<JettonPairDecision> jetton_pair_decision(const HashKey& owner, const HashKey& master);
  // Reads a jetton record as the open batch leaves it.
  td::Result<bool> get_jetton_record(td::Slice key, std::string& value);
  // Writes a jetton record into the open batch, visible to later reads in it.
  td::Status put_jetton_record(td::Slice key, td::Slice value);
  // Decide the (owner, master) pair for `wallet` as of the block ending at
  // `end_lt`: claim it (point the 0x10 entry at the wallet) or release it
  // (remove the entry if it names the wallet). Ignored when the pair's own
  // record is from a later block; a release is also ignored while the pair
  // names another wallet.
  td::Status claim_jetton_pair(const HashKey& owner, const HashKey& master, const HashKey& wallet,
                               td::Ref<vm::Cell> value, uint64_t end_lt, bool reconstructed);
  td::Status release_jetton_pair(const HashKey& owner, const HashKey& master, const HashKey& wallet, uint64_t end_lt);

  std::unique_ptr<td::RocksDb> db_;
  // Same database, own (never batched) write path, for mark_blocks_incomplete.
  std::unique_ptr<td::RocksDb> marker_db_;
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
    uint64_t parked = 0;
    // Chosen candidates not yet verified: each keeps room to go back.
    uint64_t reserved = 0;
    td::optional<TokenCandidate> first_unhandled;
    std::vector<ScheduledTokenCandidate> overflow;
    std::map<std::string, std::string> index_overlay;
    // Queue rows already erased in the batch, which committed reads still see.
    std::set<std::string> queue_erased;
    // Queue rows written in the batch, which committed reads do not see yet.
    std::map<std::string, std::string> queue_written;
    // Parked rows written (value) or erased (empty) in the batch.
    std::map<std::string, std::string> parked_overlay;
    // Jetton wallet and pair records written in the batch, which committed
    // reads do not see yet: key -> value.
    std::map<std::string, std::string> jetton_records;
  };
  TokenBatchState token_batch_;
  uint64_t token_backlog_limit_ = kMaxTokenBacklogEntries;
  uint64_t parked_limit_ = kMaxParkedTokenCandidates;
  td::Result<uint64_t> get_meta_u64(uint8_t sub);
  td::Status put_meta_u64(uint8_t sub, uint64_t value);
  td::Result<std::string> token_index_get(const std::string& index_key);
  td::Status token_index_erase(const std::string& index_key);
  td::Result<bool> token_queue_has(const std::string& queue_key);
  td::Status token_queue_erase(const std::string& queue_key);
  td::Result<uint8_t> token_claim(const TokenCandidate& candidate, uint64_t end_lt);
  // Queue `candidate`. False when the backlog has no room; `reserved` uses
  // the room a chosen candidate kept, so it always succeeds.
  td::Result<bool> token_enqueue(const TokenCandidate& candidate, uint8_t attempts, uint64_t lt, bool reserved);
  td::Status token_park(const ScheduledTokenCandidate& scheduled);
  td::Status token_load_counters();
  td::Result<std::string> token_queue_value(const std::string& queue_key);
  td::Result<td::optional<uint64_t>> token_parked_lt(const std::string& parked_key);
  void token_release_reservation();
  td::Status token_write_counters();
};

// The index as committed at one moment, for building an answer whose parts
// must agree: every read through it sees the same commit. It offers reads
// only; the index is written through WalletIndexDb alone.
class WalletIndexSnapshot {
 public:
  static td::Result<WalletIndexSnapshot> of(WalletIndexDb& db);

  td::Result<TokenBacklogStats> token_backlog_stats() {
    return view_->token_backlog_stats();
  }
  td::Status for_each_nft(const HashKey& owner, size_t limit,
                          std::function<td::Status(const HashKey& nft, td::Ref<vm::Cell>)> cb) {
    return view_->for_each_nft(owner, limit, std::move(cb));
  }
  td::Status for_each_current_jetton(const HashKey& owner, size_t limit,
                                     std::function<td::Status(const HashKey& master, td::Ref<vm::Cell>)> cb) {
    return view_->for_each_current_jetton(owner, limit, std::move(cb));
  }
  td::Result<bool> has_jetton_wallet_record(const HashKey& wallet) {
    return view_->has_jetton_wallet_record(wallet);
  }

 private:
  explicit WalletIndexSnapshot(std::unique_ptr<WalletIndexDb> view) : view_(std::move(view)) {
  }
  std::unique_ptr<WalletIndexDb> view_;
};

// The result of checking one jetton-wallet candidate against a block's
// post-state.
enum class JettonWalletCheck {
  Verified,       // its master resolves (owner) back to it
  Rejected,       // the post-state definitely does not show it as a jetton wallet
  Indeterminate,  // the node could not reach a verdict (budget, virtualization)
  OtherShard,     // the verdict needs another shard's state
};

// Record a jetton-wallet check in the index (into the open batch). Only a
// definite verdict changes the index: Verified records the wallet under
// (owner, master) with `value`, Rejected removes what it had. Indeterminate
// and OtherShard leave the wallet's record and entry as they are.
TokenVerifyOutcome record_jetton_wallet_check(WalletIndexDb& db, const HashKey& wallet, JettonWalletCheck check,
                                              const HashKey& owner, const HashKey& master, td::Ref<vm::Cell> value,
                                              uint64_t end_lt);

// Module-scope singleton. Returns nullptr until the
// validator opens the index at startup.
WalletIndexDb* wallet_index_db();
void set_wallet_index_db(std::unique_ptr<WalletIndexDb> db);

// Open the index at `${db_root}/wc0-index` and install it as the singleton.
// On failure the singleton stays null, the reason is kept for
// wallet_index_unavailable_reason(), and false is returned.
bool open_wallet_index_db(const std::string& db_root);

// Why the index this node meant to keep is not available (it failed to open,
// or could not be made safe to index into); empty when nothing failed. RPC
// reports this instead of "disabled", so a failure is not mistaken for a node
// that never kept an index.
void set_wallet_index_unavailable(std::string reason);
std::string wallet_index_unavailable_reason();

}  // namespace tos_wallet_index
