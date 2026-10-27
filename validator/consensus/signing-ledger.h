/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

// The validator's own-decision log: the durable authority for what this node has decided to
// sign in each consensus session, kept apart from the session database.
//
// Every vote this node signs, and every leader window it produces candidates in, is first
// recorded here. A decision that conflicts with one already recorded is refused, so after
// any loss or rollback of a session's database the node can still only sign decisions it
// may already have signed, never a different one. Signing the same decision again is
// permitted: two signatures over one vote are one vote to every peer.
//
// Layout, under <db_root>/consensus/signing-ledger/:
//   ledger           the header: the validator it belongs to, the identity of this
//                    directory, the floor and one entry per admitted session. Replaced
//                    atomically.
//   log.<session>    one append-only file of fixed-size, hash-chained decision records per
//                    admitted session. Each record is durable before it is acknowledged.
//
// The header and each log are bound to the inode and birth time of what they were created
// as, so a copied or recreated file is not mistaken for the one this node wrote. A log
// and the session journal also check each other at startup: a signed vote in the journal
// with no decision in the log means the log lost it, and the session is fenced. Only a
// consistent rollback of both, preserving inode numbers and birth times, escapes these
// checks; that is outside what a local record can detect.
//
// Without a trusted ledger the node's earlier signing is unknown: a pending ledger replaces
// it, every session is fenced until the fence block, and afterwards only sessions above the
// fence sign (see "Unknown signing history" below).

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "td/actor/actor.h"
#include "td/actor/coro_task.h"
#include "td/utils/Status.h"
#include "tos/tos-types.h"

namespace tos::validator::consensus::signing {

// ===== Decisions and the conflict rules =====

enum class DecisionKind : std::uint8_t { Notarize = 1, Finalize = 2, Skip = 3, LeaderWindow = 4 };

// One thing this node may sign. `slot` is the referenced slot of a vote, or the window
// ordinal (start slot / slots per leader window) of a leader window. `candidate` is the
// candidate hash of a notarize or finalize vote and zero otherwise.
struct Decision {
  DecisionKind kind = DecisionKind::Skip;
  std::uint32_t slot = 0;
  td::Bits256 candidate = td::Bits256::zero();

  bool operator==(const Decision& other) const {
    return kind == other.kind && slot == other.slot && candidate == other.candidate;
  }
};

std::string to_string(const Decision& decision);

enum class Check { New, Same, Conflict };

// What this node has decided, per slot, and the rules the protocol reports as misbehaviour
// when one validator signs both of two votes in one slot:
//   notarize(A) and notarize(B), B != A
//   finalize(A) and finalize(B), B != A
//   notarize(A) and finalize(B), B != A
//   finalize and skip
// A skip beside a notarize is allowed, and a decision equal to one already made is the
// same decision. A leader window is decided at most once.
class DecisionIndex {
 public:
  Check check(const Decision& decision) const;
  // Precondition: check(decision) == Check::New.
  void apply(const Decision& decision);
  // The sequence number a decision equal to this one was recorded under.
  std::optional<std::int64_t> seq_of(const Decision& decision) const;
  void remember_seq(const Decision& decision, std::int64_t seq);
  std::size_t size() const {
    return count_;
  }

 private:
  struct Slot {
    std::optional<td::Bits256> notarize;
    std::optional<td::Bits256> finalize;
    bool skip = false;
  };
  std::map<std::uint32_t, Slot> slots_;
  std::set<std::uint32_t> leader_windows_;
  std::vector<std::pair<Decision, std::int64_t>> seqs_;
  std::size_t count_ = 0;
};

// ===== Limits =====

inline constexpr std::size_t kRecordBytes = 64;
inline constexpr std::size_t kMaxLogRecords = 16384;
inline constexpr std::size_t kMaxLogBytes = kMaxLogRecords * kRecordBytes;
inline constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
inline constexpr std::size_t kMaxEntries = 1024;
inline constexpr std::size_t kMaxSetAside = 4;

// ===== Durable file operations, replaceable by tests that inject failures =====

class FileOps {
 public:
  virtual ~FileOps() = default;
  virtual long pwrite(int fd, const void* data, std::size_t size, long offset);
  virtual int fdatasync(int fd);
  virtual int fsync(int fd);
  virtual int ftruncate(int fd, long length);
  // Writes `bytes` to <dir>/<name> through a temporary name, flushes it, renames it into
  // place and flushes the directory. Either the old or the new file is there afterwards.
  virtual td::Status replace_file(const std::string& dir, const std::string& name, const std::string& bytes);
};

std::shared_ptr<FileOps> default_file_ops();

// The identity of a file or directory as created: its inode and birth time. A copy, a
// restore or a recreation gets a different birth time even when the inode is reused.
struct Binding {
  std::uint64_t ino = 0;
  std::int64_t btime_sec = 0;
  std::uint32_t btime_nsec = 0;

  bool empty() const {
    return ino == 0 && btime_sec == 0 && btime_nsec == 0;
  }
  bool operator==(const Binding& other) const {
    return ino == other.ino && btime_sec == other.btime_sec && btime_nsec == other.btime_nsec;
  }
};

// The binding of `path`, or an error when the filesystem does not report a birth time.
td::Result<Binding> binding_of(const std::string& path);
td::Result<Binding> binding_of_fd(int fd);

// ===== The per-session log =====

// One loaded log: its decisions in order, how far it verifies, and its chain head.
struct LoadedLog {
  std::vector<std::pair<std::int64_t, Decision>> decisions;
  std::size_t verified_bytes = 0;
  std::array<unsigned char, 16> chain{};
  bool torn_tail = false;
};

// Reads and verifies the log open at `fd` for `session`. A partial last record is reported
// as a torn tail and excluded; a bad record anywhere else, a broken chain, a decision that
// conflicts with an earlier one, or a log above the limits is an error.
td::Result<LoadedLog> load_log(int fd, const td::Bits256& session);

// The chain value a log for `session` starts from.
std::array<unsigned char, 16> chain_start(const td::Bits256& session);

std::string encode_record(const Decision& decision, std::int64_t seq, const std::array<unsigned char, 16>& previous,
                          std::array<unsigned char, 16>& next);

enum class ReserveResult { Reserved, AlreadyDecided, Conflict, Failed };

struct Reservation {
  ReserveResult result = ReserveResult::Failed;
  std::int64_t seq = 0;
};

// Serializes every reservation of one session from its check to its acknowledgement: a
// request waits until the one before it has been written, flushed and applied, so two
// conflicting requests can never both pass the check.
class SessionDecisionLog : public td::actor::Actor {
 public:
  // Suspends a reservation after its check and before its write, for tests that must hold
  // persistence between the two. Null in production.
  using WriteGate = std::function<td::actor::StartedTask<>(const Decision&)>;

  SessionDecisionLog(td::Bits256 session, int fd, LoadedLog loaded, std::shared_ptr<FileOps> ops,
                     std::shared_ptr<std::atomic<bool>> stopped, WriteGate gate);
  ~SessionDecisionLog() override;

  td::actor::Task<Reservation> reserve(Decision decision);

  // For tests and diagnostics: how many records are durable.
  td::actor::Task<std::size_t> durable_records();

 private:
  using ReservationPromise = decltype(td::actor::StartedTask<Reservation>::make_bridge().second);
  struct Pending {
    Decision decision;
    ReservationPromise promise;
  };

  td::actor::Task<> drain();
  td::actor::Task<Reservation> handle(const Decision& decision);
  bool recover();

  td::Bits256 session_;
  int fd_;
  DecisionIndex index_;
  std::int64_t next_seq_ = 0;
  std::size_t verified_bytes_ = 0;
  std::array<unsigned char, 16> chain_{};
  std::shared_ptr<FileOps> ops_;
  std::shared_ptr<std::atomic<bool>> stopped_;
  WriteGate gate_;
  std::deque<Pending> queue_;
  bool draining_ = false;
  bool failed_ = false;
};

// What a validator group gets for one session: either admission to sign, with the decisions
// already recorded and the log to record new ones in, or a fence and its reason.
struct Admission {
  bool fenced = true;
  std::string reason;
  td::Bits256 session = td::Bits256::zero();
  std::vector<std::pair<std::int64_t, Decision>> decisions;
  td::actor::ActorId<SessionDecisionLog> log;
  // Set when the session's log can no longer record anything; nothing is signed after.
  std::shared_ptr<std::atomic<bool>> stopped;

  bool signing_stopped() const {
    return fenced || (stopped && stopped->load(std::memory_order_acquire));
  }
  bool leader_window_recorded(std::uint32_t window) const;

  static std::shared_ptr<const Admission> fence(td::Bits256 session, std::string reason);
};

// ===== The header and the ledger =====

struct HeaderEntry {
  td::Bits256 session = td::Bits256::zero();
  Binding log;  // empty until the log file exists and is bound
};

// ===== Unknown signing history =====
//
// A ledger created where none could be trusted (none was there, or the one there was
// copied, replaced or damaged) cannot know what the node signed before this process
// started. It starts pending, with the process's start time t0, and fences every session.
// The first masterchain block applied with gen_utime >= t0 + kHistoryMarginSeconds is the
// fence block M: under the clock assumptions (hosts within 30 s of true time, block times
// at most 30 s ahead of an honest validator's clock) M was produced after the earlier
// signer stopped. The ledger then records, for every shard lineage at M, its catchain
// counter, and from then on fences every session whose lineage is related to an entry
// with a counter at most two above it: the largest counter any session built before M,
// current or tentative, can carry. A session of a lineage no entry relates to, a
// workchain absent at M included, stays fenced.

inline constexpr std::uint32_t kHistoryMarginSeconds = 91;
inline constexpr std::uint32_t kFenceCounterMargin = 2;
inline constexpr std::size_t kMaxFenceEntries = 256;
// What get_shard_cc_seqno answers when it cannot derive a counter.
inline constexpr std::uint32_t kCounterSentinel = ~0U;

enum class History : std::uint8_t {
  // Everything this node signed is in this ledger: it was created where the node had
  // never signed (the genesis ceremony, a test).
  Complete = 0,
  // Created over an unknown history; waiting for the fence block. Nothing is admitted.
  Pending = 1,
  // The fence block was applied; sessions are admitted only above the fence.
  Established = 2,
};

struct FenceEntry {
  std::int32_t workchain = 0;
  std::uint64_t shard = 0;
  std::uint32_t cc = 0;

  bool operator==(const FenceEntry& other) const = default;
};

// Whether the fence keeps the session of `shard` with catchain counter `cc` from signing.
// Fails closed: a sentinel counter, or no related entry, is fenced. The bound is computed
// in 64 bits, so an entry near the top of the counter range fences everything above it
// rather than wrapping.
bool fenced_by_history(const std::vector<FenceEntry>& fence, ShardIdFull shard, std::uint32_t cc);

struct Header {
  td::Bits256 validator = td::Bits256::zero();
  Binding dir;
  std::optional<BlockIdExt> floor;
  History history = History::Complete;
  // The start time the pending history waits from (unix seconds, rounded up).
  std::uint64_t t0 = 0;
  std::vector<FenceEntry> fence;
  std::vector<HeaderEntry> entries;
};

std::string encode_header(const Header& header);
td::Result<Header> decode_header(td::Slice bytes);

std::string ledger_dir(const std::string& db_root);

// Creates a complete ledger for `validator` in an empty `dir`: one that asserts the node
// has never signed. Only what knows that, the genesis ceremony or a test, may call this.
// `floor`, when given, is the block the ledger's history starts at (the zerostate).
td::Status create_ledger(const std::string& dir, const td::Bits256& validator,
                         std::shared_ptr<FileOps> ops = default_file_ops(),
                         std::optional<BlockIdExt> floor = std::nullopt);

enum class LedgerStatus { Trusted, Absent, Untrusted };

class SigningLedger : public td::actor::Actor {
 public:
  // `clock` reads unix seconds, for tests of the start time; null reads the system clock.
  SigningLedger(std::string dir, std::shared_ptr<FileOps> ops = default_file_ops(),
                SessionDecisionLog::WriteGate gate = nullptr, std::function<double()> clock = nullptr);

  void start_up() override;

  // The admission for `session` of `shard` with catchain counter `cc`, signed by
  // `validator`. Repeated calls for one admitted session in one process return the same
  // log. Where no ledger could be trusted, the first call creates a pending one.
  td::actor::Task<std::shared_ptr<const Admission>> admit(td::Bits256 validator, td::Bits256 session, ShardIdFull shard,
                                                          std::uint32_t cc);

  // Offers the masterchain block `block`, generated at `gen_utime`, with the catchain
  // counter of every shard lineage at it, as the fence block of a pending history. Answers
  // whether the history is settled (complete or established) afterwards.
  td::actor::Task<bool> offer_fence_block(BlockIdExt block, std::uint32_t gen_utime, std::vector<FenceEntry> lineages);

  td::actor::Task<History> history();

  // Forgets sessions that can no longer be recreated, and raises the floor to `floor`, in
  // one header write; their logs are deleted only after it.
  td::actor::Task<> prune(std::vector<td::Bits256> sessions, BlockIdExt floor);

  td::actor::Task<std::optional<BlockIdExt>> floor();
  td::actor::Task<LedgerStatus> status();

 private:
  td::Status write_header();
  std::string log_path(const td::Bits256& session) const;
  std::shared_ptr<const Admission> admit_now(const td::Bits256& validator, const td::Bits256& session,
                                             ShardIdFull shard, std::uint32_t cc);
  // Replaces an absent or untrusted ledger with a pending one for `validator`.
  td::Status start_unknown_history(const td::Bits256& validator);

  std::string dir_;
  std::shared_ptr<FileOps> ops_;
  SessionDecisionLog::WriteGate gate_;
  std::function<double()> clock_;
  // This process's start, rounded up: the earliest a pending history created now may say
  // the earlier signer stopped.
  std::uint64_t started_at_ = 0;
  LedgerStatus status_ = LedgerStatus::Absent;
  std::string untrusted_reason_;
  Header header_;
  std::map<td::Bits256, std::shared_ptr<const Admission>> admitted_;
  std::map<td::Bits256, td::actor::ActorOwn<SessionDecisionLog>> logs_;
};

}  // namespace tos::validator::consensus::signing
