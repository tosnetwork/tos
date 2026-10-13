/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "tos/tos-types.h"

// Startup archive catch-up for a stale validator: the pure policy.
//
// A validator restarted after a long stop used to skip the archive importer,
// because the startup sync predicate returns "in sync" for any node with a
// usable validator key, and then fetched its whole backlog block by block. This
// header holds every decision of the startup catch-up mode (entry, discovery of
// verified progress, import accounting and exit) as plain values and functions
// with injected clocks, so each decision can be tested without a manager. The
// manager only wires them to the network, the importer and the database.
//
// The mode is startup-only. It is decided once per process, before any validator
// group can be built, and ends in a terminal state; a validator that falls
// behind while running is not affected.
namespace tos::validator::startup_catchup {

// A key-holding validator whose last applied masterchain block is at least this
// old at startup enters the mode. It is an entry threshold only: inside the mode
// import continues until the ordinary 80-second freshness rule holds.
inline constexpr double kStaleValidatorAgeSeconds = 300.0;
// The legacy freshness rule of the startup sync predicate.
inline constexpr double kFreshAgeSeconds = 80.0;
// The legacy shard-client lag beyond which startup must import archives.
inline constexpr BlockSeqno kMaxShardClientLag = 16;

// Discovery of verified progress: one monotonic window covering peer selection,
// queries and proof verification.
inline constexpr double kDiscoveryWindowSeconds = 30.0;
// Two separate limits govern discovery. At most kProbePeers probe slots are occupied
// at a time (outstanding or explicitly negative), and kProbePeers distinct explicit
// "no next block" answers end discovery early. An inconclusive answer frees its slot
// for a replacement peer, so within one window up to kProbeBudget distinct peers can
// be contacted.
inline constexpr std::uint32_t kProbePeers = 3;
// Probes per 30-second discovery window, shared by every restart after the frontier
// moved.
inline constexpr std::uint32_t kProbeBudget = 2 * kProbePeers;
// Per-probe query timeout, further capped by the discovery window.
inline constexpr double kProbeQueryTimeoutSeconds = 5.0;
// Peer selection is retried this often while fewer than K peers were probed.
inline constexpr double kPeerReselectSeconds = 2.0;
// The proof check of a successor needs this much of the window left to start.
inline constexpr double kProofCheckSeconds = 2.0;

// One import attempt: its network and compute children are bounded by this.
inline constexpr double kImportAttemptSeconds = 300.0;
// Consecutive failed attempts with a verified successor before giving up.
inline constexpr std::uint32_t kMaxConsecutiveFailures = 3;
// Delay between a failed attempt and the next one, as the legacy archive loop.
inline constexpr double kRetryDelaySeconds = 2.0;
// An attempt whose bounded children have not all settled this long after its
// deadline is reported as a defect; the attempt keeps waiting for them.
inline constexpr double kSettlementWatchdogSeconds = 60.0;

// New cleanup records written by one startup inventory of orphaned validator
// session directories. Counted after the durable point read, so directories that
// already have a record never use a slot.
inline constexpr std::size_t kMaxStartupOrphanRecords = 256;

inline BlockSeqno saturating_add(BlockSeqno a, BlockSeqno b) {
  BlockSeqno out = 0;
  if (__builtin_add_overflow(a, b, &out)) {
    return static_cast<BlockSeqno>(-1);
  }
  return out;
}

inline std::uint32_t saturating_sub(std::uint32_t a, std::uint32_t b) {
  return a > b ? a - b : 0;
}

inline std::uint32_t saturating_inc(std::uint32_t a) {
  return a == static_cast<std::uint32_t>(-1) ? a : a + 1;
}

// ---------------------------------------------------------------------------
// The startup sync predicate.
// ---------------------------------------------------------------------------

// Which return of the startup sync predicate fired. The order of the checks is
// the legacy order and must not change; the enum only labels the return.
enum class SyncReason {
  BelowSyncUpto,      // the configured sync target is not reached: out of sync
  ShardClientLag,     // the shard client lags the masterchain by more than 16
  Fresh,              // the last masterchain block is younger than 80 s: in sync
  NewerKeyBlock,      // a newer key block is known: out of sync
  StaleValidator,     // the validator short-circuit: in sync, except inside the mode
  StaleNonValidator,  // not a validator of the restored set: out of sync
};

inline const char* sync_reason_name(SyncReason reason) {
  switch (reason) {
    case SyncReason::BelowSyncUpto:
      return "below sync target";
    case SyncReason::ShardClientLag:
      return "shard client lag";
    case SyncReason::Fresh:
      return "fresh";
    case SyncReason::NewerKeyBlock:
      return "newer key block known";
    case SyncReason::StaleValidator:
      return "stale validator";
    case SyncReason::StaleNonValidator:
      return "stale non-validator";
  }
  return "unknown";
}

// A reason the catch-up mode never handles: startup must import as it always did.
inline bool is_mandatory(SyncReason reason) {
  return reason == SyncReason::BelowSyncUpto || reason == SyncReason::ShardClientLag ||
         reason == SyncReason::NewerKeyBlock;
}

struct SyncInputs {
  BlockSeqno masterchain_seqno = 0;
  BlockSeqno shard_client_seqno = 0;
  BlockSeqno sync_upto = 0;
  double block_unix_time = 0;
  double now = 0;  // the system clock, the clock the 80-second rule always used
  BlockSeqno known_key_block_seqno = 0;
};

// Classify the startup state in the legacy order. `is_validator` is evaluated
// only when the earlier checks did not decide, exactly as before: it reports
// whether the node holds groups or is a member of the restored masterchain set.
template <class IsValidatorFn>
SyncReason classify_sync(const SyncInputs& in, IsValidatorFn&& is_validator) {
  auto seqno = in.masterchain_seqno < in.shard_client_seqno ? in.masterchain_seqno : in.shard_client_seqno;
  if (seqno < in.sync_upto) {
    return SyncReason::BelowSyncUpto;
  }
  if (saturating_add(in.shard_client_seqno, kMaxShardClientLag) < in.masterchain_seqno) {
    return SyncReason::ShardClientLag;
  }
  if (in.block_unix_time + kFreshAgeSeconds > in.now) {
    return SyncReason::Fresh;
  }
  if (in.masterchain_seqno < in.known_key_block_seqno) {
    return SyncReason::NewerKeyBlock;
  }
  if (is_validator()) {
    return SyncReason::StaleValidator;
  }
  return SyncReason::StaleNonValidator;
}

// The value of the startup sync predicate ("out of sync") for a classification.
// Outside the mode this is the legacy value. Inside it, the stale-validator
// short-circuit reports out of sync so import continues until the 80-second rule
// holds; every other reason keeps its legacy value.
inline bool out_of_sync_value(SyncReason reason, bool catchup_active) {
  switch (reason) {
    case SyncReason::BelowSyncUpto:
    case SyncReason::ShardClientLag:
    case SyncReason::NewerKeyBlock:
    case SyncReason::StaleNonValidator:
      return true;
    case SyncReason::Fresh:
      return false;
    case SyncReason::StaleValidator:
      return catchup_active;
  }
  return true;
}

// Age of the last masterchain block on the system clock. A block time in the
// future is age zero.
inline double block_age_seconds(double now, double block_unix_time) {
  return block_unix_time >= now ? 0.0 : now - block_unix_time;
}

// ---------------------------------------------------------------------------
// Entry.
// ---------------------------------------------------------------------------

enum class EntryRefusal {
  None,             // enter the mode
  MandatorySync,    // a mandatory reason holds: the legacy path imports anyway
  NotStale,         // younger than the entry threshold
  NoValidatorKeys,  // a node without validator keys can never build a group
  GroupsExist,      // a group already exists (a defect at this point)
  OperatorImport,   // operator-supplied import files keep the legacy path
  HardforkNext,     // the next block is a configured hardfork
  AlreadyDecided,   // the decision was taken earlier in this process
};

inline const char* entry_refusal_name(EntryRefusal refusal) {
  switch (refusal) {
    case EntryRefusal::None:
      return "entered";
    case EntryRefusal::MandatorySync:
      return "mandatory sync reason";
    case EntryRefusal::NotStale:
      return "not stale";
    case EntryRefusal::NoValidatorKeys:
      return "no validator keys held";
    case EntryRefusal::GroupsExist:
      return "validator or observer groups already exist";
    case EntryRefusal::OperatorImport:
      return "operator import files present";
    case EntryRefusal::HardforkNext:
      return "next block is a configured hardfork";
    case EntryRefusal::AlreadyDecided:
      return "already decided in this process";
  }
  return "unknown";
}

struct EntryInputs {
  SyncReason reason = SyncReason::Fresh;
  double age_seconds = 0;
  bool holds_validator_keys = false;  // any validator key, member of the restored set or not
  bool groups_empty = true;
  bool imports_empty = true;
  bool next_is_hardfork = false;
};

inline EntryRefusal evaluate_entry(const EntryInputs& in) {
  if (is_mandatory(in.reason)) {
    return EntryRefusal::MandatorySync;
  }
  if (in.reason == SyncReason::Fresh || in.age_seconds < kStaleValidatorAgeSeconds) {
    return EntryRefusal::NotStale;
  }
  if (!in.holds_validator_keys) {
    return EntryRefusal::NoValidatorKeys;
  }
  if (!in.groups_empty) {
    return EntryRefusal::GroupsExist;
  }
  if (!in.imports_empty) {
    return EntryRefusal::OperatorImport;
  }
  if (in.next_is_hardfork) {
    return EntryRefusal::HardforkNext;
  }
  return EntryRefusal::None;
}

// ---------------------------------------------------------------------------
// The mode's lifecycle.
// ---------------------------------------------------------------------------

enum class Phase { Off, Candidate, Discovering, Importing, Done };

enum class ExitReason {
  NotEntered,           // the entry test refused
  NotStale,             // local replay made the tip younger than the entry threshold
  NoVerifiedSuccessor,  // no peer proved a successor of the exact local tip
  Fresh,                // the 80-second rule holds
  Abandoned,            // the attempt budget is spent
};

inline const char* exit_reason_name(ExitReason reason) {
  switch (reason) {
    case ExitReason::NotEntered:
      return "NotEntered";
    case ExitReason::NotStale:
      return "NotStale";
    case ExitReason::NoVerifiedSuccessor:
      return "NoVerifiedSuccessor";
    case ExitReason::Fresh:
      return "Fresh";
    case ExitReason::Abandoned:
      return "Abandoned";
  }
  return "unknown";
}

// Off -> Candidate -> Discovering <-> Importing -> Done. The decision is taken
// once (`decide`), and Done is terminal for the life of the process.
class Mode {
 public:
  // The one entry decision of the process. Returns whether the mode was entered.
  // A second call, or a call after Done, never enters it again.
  bool decide(EntryRefusal refusal) {
    if (phase_ != Phase::Off) {
      return false;
    }
    if (refusal != EntryRefusal::None) {
      phase_ = Phase::Done;
      exit_reason_ = ExitReason::NotEntered;
      return false;
    }
    phase_ = Phase::Candidate;
    entered_ = true;
    return true;
  }
  void set_discovering() {
    if (active()) {
      phase_ = Phase::Discovering;
    }
  }
  void set_importing() {
    if (active()) {
      phase_ = Phase::Importing;
    }
  }
  // Ends the mode. Returns false if it had already ended.
  bool finish(ExitReason reason) {
    if (phase_ == Phase::Done) {
      return false;
    }
    if (phase_ == Phase::Off) {
      phase_ = Phase::Done;
      exit_reason_ = ExitReason::NotEntered;
      return true;
    }
    phase_ = Phase::Done;
    exit_reason_ = reason;
    return true;
  }
  bool active() const {
    return phase_ == Phase::Candidate || phase_ == Phase::Discovering || phase_ == Phase::Importing;
  }
  // Validator and observer groups are fenced while the mode is active.
  bool fence_closed() const {
    return active();
  }
  bool done() const {
    return phase_ == Phase::Done;
  }
  bool entered() const {
    return entered_;
  }
  Phase phase() const {
    return phase_;
  }
  std::optional<ExitReason> exit_reason() const {
    return exit_reason_;
  }

 private:
  Phase phase_ = Phase::Off;
  bool entered_ = false;
  std::optional<ExitReason> exit_reason_;
};

// ---------------------------------------------------------------------------
// Discovery of verified progress.
// ---------------------------------------------------------------------------

enum class ProbeAnswerKind {
  Verified,       // a proof of a successor of the exact queried block passed verification
  Empty,          // the peer explicitly answered it has no next block
  Inconclusive,   // timeout, transport error, malformed or failed proof
  FrontierMoved,  // the local tip changed: the answer is about an old block
};

inline const char* probe_answer_name(ProbeAnswerKind kind) {
  switch (kind) {
    case ProbeAnswerKind::Verified:
      return "verified";
    case ProbeAnswerKind::Empty:
      return "empty";
    case ProbeAnswerKind::Inconclusive:
      return "inconclusive";
    case ProbeAnswerKind::FrontierMoved:
      return "frontier moved";
  }
  return "unknown";
}

struct ProbeAnswer {
  ProbeAnswerKind kind = ProbeAnswerKind::Inconclusive;
  BlockIdExt next;
  std::string detail;

  static ProbeAnswer verified(BlockIdExt next) {
    return ProbeAnswer{ProbeAnswerKind::Verified, next, {}};
  }
  static ProbeAnswer empty() {
    return ProbeAnswer{ProbeAnswerKind::Empty, {}, {}};
  }
  static ProbeAnswer inconclusive(std::string detail) {
    return ProbeAnswer{ProbeAnswerKind::Inconclusive, {}, std::move(detail)};
  }
  static ProbeAnswer frontier_moved() {
    return ProbeAnswer{ProbeAnswerKind::FrontierMoved, {}, {}};
  }
};

// The result of the manager's verification entry for one probe answer.
enum class SuccessorVerdict { Verified, FrontierMoved };

enum class RoundOutcome { Pending, Verified, NoVerifiedSuccessor, FrontierMoved };

struct RoundResult {
  RoundOutcome outcome = RoundOutcome::NoVerifiedSuccessor;
  BlockIdExt next;
  std::uint32_t probes_used = 0;
  std::uint32_t explicit_negatives = 0;
};

// One discovery round about one exact local tip. Distinct peers only: a peer is
// probed at most once and only its first answer counts. At most `peers` probes
// are outstanding or explicitly negative at a time; an inconclusive answer frees
// its slot for a new peer, up to `budget` probes (and so up to `budget` distinct
// peers) in total. The round is decided by the first verified successor,
// by `peers` distinct explicit negatives, by an answer saying the frontier moved,
// or at the deadline.
template <class PeerId>
class DiscoveryRound {
 public:
  DiscoveryRound(double deadline, std::uint32_t peers, std::uint32_t budget)
      : deadline_(deadline), peers_(peers), budget_(budget) {
  }

  // Of the offered peers, the ones to probe now.
  std::vector<PeerId> select(double now, const std::vector<PeerId>& offered) {
    std::vector<PeerId> out;
    if (decided(now)) {
      return out;
    }
    for (const auto& peer : offered) {
      if (used_ >= budget_ || occupied() >= peers_) {
        break;
      }
      if (tried_.count(peer) > 0) {
        continue;
      }
      tried_.insert(peer);
      outstanding_.insert(peer);
      used_ = saturating_inc(used_);
      out.push_back(peer);
    }
    return out;
  }

  // Whether peer selection should be retried.
  bool wants_peers(double now) const {
    return !decided(now) && used_ < budget_ && occupied() < peers_;
  }

  void on_answer(const PeerId& peer, const ProbeAnswer& answer) {
    if (outstanding_.erase(peer) == 0) {
      return;  // never probed, or already answered: a second answer counts nothing
    }
    switch (answer.kind) {
      case ProbeAnswerKind::Verified:
        if (!verified_) {
          verified_ = answer.next;
        }
        break;
      case ProbeAnswerKind::Empty:
        negatives_ = saturating_inc(negatives_);
        break;
      case ProbeAnswerKind::FrontierMoved:
        frontier_moved_ = true;
        break;
      case ProbeAnswerKind::Inconclusive:
        break;
    }
  }

  RoundOutcome outcome(double now) const {
    if (verified_) {
      return RoundOutcome::Verified;
    }
    if (frontier_moved_) {
      return RoundOutcome::FrontierMoved;
    }
    if (negatives_ >= peers_) {
      return RoundOutcome::NoVerifiedSuccessor;
    }
    if (now >= deadline_) {
      return RoundOutcome::NoVerifiedSuccessor;
    }
    return RoundOutcome::Pending;
  }

  bool decided(double now) const {
    return outcome(now) != RoundOutcome::Pending;
  }

  RoundResult result(double now) const {
    RoundResult r;
    r.outcome = outcome(now);
    if (r.outcome == RoundOutcome::Pending) {
      r.outcome = RoundOutcome::NoVerifiedSuccessor;
    }
    if (verified_) {
      r.next = *verified_;
    }
    r.probes_used = used_;
    r.explicit_negatives = negatives_;
    return r;
  }

  std::uint32_t probes_used() const {
    return used_;
  }
  std::uint32_t explicit_negatives() const {
    return negatives_;
  }
  std::size_t outstanding() const {
    return outstanding_.size();
  }
  double deadline() const {
    return deadline_;
  }

 private:
  std::size_t occupied() const {
    return outstanding_.size() + negatives_;
  }

  double deadline_;
  std::uint32_t peers_;
  std::uint32_t budget_;
  std::uint32_t used_ = 0;
  std::uint32_t negatives_ = 0;
  bool frontier_moved_ = false;
  std::optional<BlockIdExt> verified_;
  std::set<PeerId> tried_;
  std::set<PeerId> outstanding_;
};

// The per-probe query timeout: the fixed cap, or what is left of the window.
// Zero or less means the probe must not be sent.
inline double probe_timeout_seconds(double now, double deadline) {
  double left = deadline - now;
  return left < kProbeQueryTimeoutSeconds ? left : kProbeQueryTimeoutSeconds;
}

// ---------------------------------------------------------------------------
// Import attempts.
// ---------------------------------------------------------------------------

struct AttemptResult {
  BlockSeqno masterchain_before = 0;
  BlockSeqno masterchain_after = 0;
  // The durable shard-client seqno before the attempt, and after its outcome was
  // made durable (equal to `before` when nothing was persisted).
  BlockSeqno shard_client_before = 0;
  BlockSeqno shard_client_after = 0;
  bool errored = false;
};

enum class AfterAttempt {
  Continue,    // progress: import the next slice
  Rediscover,  // no progress: prove a successor before trying again
};

enum class AfterRediscovery { Retry, ExitNoVerifiedSuccessor, ExitAbandoned };

// Consecutive-failure accounting. An attempt progresses iff the coherent applied
// shard-client frontier advanced durably; masterchain-only progress does not
// count, and an attempt that errored after advancing still progressed.
class ImportAccounting {
 public:
  AfterAttempt record(const AttemptResult& r) {
    attempts_ = saturating_inc(attempts_);
    if (r.shard_client_after > r.shard_client_before) {
      consecutive_failures_ = 0;
      return AfterAttempt::Continue;
    }
    consecutive_failures_ = saturating_inc(consecutive_failures_);
    return AfterAttempt::Rediscover;
  }

  AfterRediscovery after_rediscovery(bool verified_successor) const {
    if (!verified_successor) {
      return AfterRediscovery::ExitNoVerifiedSuccessor;
    }
    if (consecutive_failures_ >= kMaxConsecutiveFailures) {
      return AfterRediscovery::ExitAbandoned;
    }
    return AfterRediscovery::Retry;
  }

  std::uint32_t consecutive_failures() const {
    return consecutive_failures_;
  }
  std::uint32_t attempts() const {
    return attempts_;
  }

 private:
  std::uint32_t consecutive_failures_ = 0;
  std::uint32_t attempts_ = 0;
};

// What one bounded import attempt reports, once every child it started has
// settled: the masterchain top it reached, the coherent shard-client frontier
// (every required shard applied up to it), and the first error, if any.
struct ImportOutcome {
  BlockSeqno masterchain_top = 0;
  BlockSeqno coherent_shard_client_seqno = 0;
  td::Status first_error;
};

}  // namespace tos::validator::startup_catchup
