/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "consensus/bus.h"

#include "certificate.h"

namespace tos::validator::consensus::simplex {

// One of this node's own votes, as the journal held it at startup. An empty signature
// means only the intent was durable: the vote decision was committed but no signature
// ever became observable, so the node may sign it once more. A present signature is the
// exact evidence this node already emitted, and is replayed rather than reproduced.
struct BootstrapVote {
  Vote vote;
  td::int64 seqno = 0;
  td::BufferSlice signature;
};

// What Pool did with a request to cast one of this node's own votes.
enum class VoteCastOutcome : td::uint8 {
  // Pool took the vote past its gates. An intent may have been committed, a signature
  // produced, or the vote applied and sent; or one of those steps failed. None of it can be
  // undone, so the caller must neither cast the vote again nor treat it as not cast.
  Submitted,
  // Refused before any intent was committed, because finality was behind when the request
  // reached Pool. The vote was not journalled, signed, applied or sent: nothing about it
  // exists outside the caller, who may keep it and request it again once finality catches
  // up. This is the only outcome after which that is allowed.
  SuppressedBeforeIntentFinalityBehind,
  // Refused before any intent was committed, because the vote journal is unusable. Asking
  // again cannot succeed while this group lives.
  SuppressedBeforeIntentJournalUnusable,
};

td::StringBuilder& operator<<(td::StringBuilder& sb, VoteCastOutcome outcome);

struct BroadcastVote {
  // Routine and frequent: traced at DEBUG, so the default log keeps hours of the
  // events an incident analysis needs (candidates, certificates, finalization).
  using LogToDebug = std::true_type;

  using ReturnType = VoteCastOutcome;

  Vote vote;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

// Test-only ordering control for Pool's finality gate on this node's own votes. A test that
// must deliver a backlog transition between a vote's arrival at the gate and its refusal, or
// between the refusal and its delivery to the requester, cannot rely on actor scheduling.
// Unset in production.
enum class VoteGatePoint : td::uint8 {
  BeforeFinalityGate,
  AfterFinalitySuppression,
};
using VoteGateHookForTest = std::function<td::actor::StartedTask<>(const Vote&, VoteGatePoint)>;

// The two halves of this node's own vote journal. They are awaited requests rather than
// notifications on purpose: the order below is the correctness property, and incidental
// actor fan-out cannot be relied on to place a durable write ahead of a local apply or a
// network send.
//
//   commit the intent -> sign -> commit the exact signed bytes -> apply -> broadcast
//
// The intent commits the vote decision, which is what stops the node choosing a different
// vote for the same slot across a crash. The signed record commits the bytes themselves.
// Until that second write returns, nothing may apply the vote locally, put it in a
// certificate or send it, because ML-DSA-44 signing is randomized: a signature produced
// again after a restart is equally valid and a different object, and a peer may already
// hold the first one inside a certificate.
struct PersistOwnVoteIntent {
  // Routine and frequent: traced at DEBUG, so the default log keeps hours of the
  // events an incident analysis needs (candidates, certificates, finalization).
  using LogToDebug = std::true_type;

  // The journal sequence number this vote was committed under. The signed record replaces
  // the intent under the same key and must carry the same number.
  using ReturnType = td::int64;

  Vote vote;

  std::string contents_to_string() const;
};

struct PersistOwnSignedVote {
  // Routine and frequent: traced at DEBUG, so the default log keeps hours of the
  // events an incident analysis needs (candidates, certificates, finalization).
  using LogToDebug = std::true_type;

  using ReturnType = td::Unit;

  Vote vote;
  td::int64 seqno;
  td::BufferSlice signature;

  std::string contents_to_string() const;
};

struct NotarizationObserved {
  CandidateId id;
  NotarCertRef certificate;

  std::string contents_to_string() const;
};

struct FinalizationObserved {
  CandidateId id;
  FinalCertRef certificate;

  std::string contents_to_string() const;
};

struct LeaderWindowObserved {
  using ReturnType = td::Unit;

  td::uint32 start_slot;
  ParentId base;

  std::string contents_to_string() const;
};

struct WaitForParent {
  // Routine and frequent: traced at DEBUG, so the default log keeps hours of the
  // events an incident analysis needs (candidates, certificates, finalization).
  using LogToDebug = std::true_type;

  using ReturnType = std::optional<MisbehaviorRef>;

  CandidateRef candidate;

  std::string contents_to_string() const;
};

struct ResolveCandidate {
  struct Result {
    CandidateRef candidate;
    NotarCertRef notar;
  };

  using ReturnType = Result;

  CandidateId id;

  std::string contents_to_string() const;
};

// Read-only observability: number of CandidateStates the resolver currently
// tracks in memory whose slot is at or above min_slot. Used by diagnostics
// and by tests that assert a peer cannot grow this map with out-of-window ids
// through the network request path (query with a slot above any live slot to
// isolate injected entries from legitimate in-flight consensus state).
struct QueryResolverTrackedStateCount {
  using ReturnType = size_t;

  td::uint32 min_slot = 0;

  std::string contents_to_string() const;
};

// Read-only observability of what Consensus keeps to recover once a finalization backlog
// clears: skip ranges whose timeout expired while behind, and votes Pool refused before
// their intent. The sizes are what bounds that state; nothing here changes it.
struct QueryConsensusRecoveryState {
  struct Result {
    size_t deferred_skip_windows = 0;
    // Slots covered by the deferred ranges, summed over windows.
    size_t deferred_skip_slots = 0;
    size_t suppressed_votes = 0;
    td::uint32 current_window = 0;
  };

  using ReturnType = Result;

  std::string contents_to_string() const;
};

// Read-only observability of finalization attempts and backpressure.
struct QueryFinalizationState {
  struct Result {
    // Finalizations this resolver has entered and finished since it came up. They are
    // reported as a pair rather than as a gauge because the number that matters is the
    // difference: a gap that never closes is a finalization waiting on a verdict nobody is
    // left to deliver, which is exactly what a terminal state read as "not yet" produces.
    size_t finalizations_started = 0;
    size_t finalizations_settled = 0;
    // Finalizations rescheduled after a failure that may not recur. Non-zero means the
    // resolver has held on to a certificate whose first conversion attempt did not succeed,
    // rather than dropping it with nothing left to re-trigger it. The second counter is the
    // subset refused before the attempt began, by the concurrency limit; they are reported
    // apart because they fail in different places and were fixed in different places, and a
    // total alone lets either one of them go missing unnoticed.
    size_t finalization_retries = 0;
    size_t finalization_retries_at_admission = 0;
    // Finalizations that have been failing long enough to have been reported once, and are
    // still being retried. There is no counter for finalizations given up on, because none
    // is: an agreed certificate is retried for as long as the group lives.
    size_t finalizations_stalled = 0;
    // Certificates held un-converted right now, and whether the group has been told to stop
    // adding to them. Nothing is ever dropped to bring the first number down; the second is
    // how it is kept from growing.
    size_t pending_finalizations = 0;
    bool backlog_over_limit = false;
    // The most certificates counted as pending at any one time since the resolver came up,
    // the limit above which the group is told to stop, and the most certificates held
    // unfinalized at once, including one whose first attempt is still running. Together
    // they bound what the backpressure lets the backlog reach, which a reading taken now and
    // then cannot.
    size_t pending_finalizations_peak = 0;
    size_t pending_finalizations_max = 0;
    size_t unfinalized_held_peak = 0;
    // Held for a reason retrying cannot mend. Counted apart from the rest because it is the
    // one an operator has to act on rather than wait out.
    size_t finalizations_stalled_permanently = 0;
    // Conversion attempts made for the queried slot.
    size_t slot_attempts = 0;
    // Callers parked on this resolver at the time of the query: coroutines waiting for an
    // in-flight finalization to deliver a verdict, and callers waiting for a state
    // resolution someone else started. A stop must fail every one of them; a count that
    // survives teardown is a coroutine that will never run again and holds the actor.
    size_t inflight_waiters = 0;
    size_t state_waiters = 0;
  };

  using ReturnType = Result;

  td::uint32 slot = 0;

  std::string contents_to_string() const;
};

// Read-only observability of vote ingress, counted per outcome. The split is the property
// itself: a vote carries authority because of the signature on it, never because of the
// transport it arrived on. A vote relayed by one validator over its own authenticated
// transport, carrying another validator's signature, must land in `refused_bad_signature`
// -- it got past every other gate and was refused exactly where attribution is decided --
// and must never be counted as the relayer's vote.
struct QueryVoteIngress {
  struct Result {
    size_t accepted = 0;
    size_t refused_bad_signature = 0;
  };

  using ReturnType = Result;

  std::string contents_to_string() const;
};

struct StoreCandidate {
  using ReturnType = td::Unit;

  CandidateRef candidate;
  std::string contents_to_string() const;
};

struct ResolveState {
  struct Result {
    ChainStateRef state;
    std::optional<double> gen_utime_exact = std::nullopt;
  };

  using ReturnType = Result;

  ParentId id;
  // Diagnostic provenance only: state identity and cache lookup still use id.
  // A notarization request supplies its signed candidate; leader-base reads do not.
  std::optional<CandidateId> requesting_candidate = std::nullopt;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

struct SaveCertificate {
  using ReturnType = td::Unit;

  CertificateRef<Vote> cert;

  std::string contents_to_string() const;
};

// Litequery: snapshot of the current round for the lite server.
struct QueryValidatorGroupInfo {
  struct CandidateWeight {
    CandidateId id;
    ValidatorWeight notarize_weight;  // "approved" in liteServer terms
    ValidatorWeight finalize_weight;  // "signed" in liteServer terms
    // Present when the candidate data was locally observed.
    std::optional<CandidateRef> candidate;
  };

  struct Result {
    td::uint32 current_slot;
    ParentId last_finalized_block;
    std::vector<CandidateWeight> candidates;
  };

  using ReturnType = Result;

  std::string contents_to_string() const;
};

class Bus : public consensus::Bus {
 public:
  using Parent = consensus::Bus;
  using Events =
      td::TypeList<BroadcastVote, PersistOwnVoteIntent, PersistOwnSignedVote, NotarizationObserved,
                   FinalizationObserved, LeaderWindowObserved, WaitForParent, ResolveCandidate, StoreCandidate,
                   ResolveState, SaveCertificate, QueryValidatorGroupInfo, QueryResolverTrackedStateCount,
                   QueryFinalizationState, QueryVoteIngress, QueryConsensusRecoveryState>;

  Bus() = default;

  std::vector<CertificateRef<Vote>> bootstrap_certificates;
  std::vector<BootstrapVote> bootstrap_votes;

  // Set when the journal held a record this node cannot honestly replay: a signed vote
  // whose stored bytes do not verify under the consensus key the set records for us. The
  // node must not manufacture a replacement signature for a vote it may already have
  // emitted, so the group starts quiescent rather than voting. Empty when the journal was
  // consistent.
  std::string vote_journal_failure;

  td::uint32 first_nonannounced_window = 0;

  // See VoteGateHookForTest. Empty outside tests.
  VoteGateHookForTest vote_gate_hook_for_test;
};

using BusHandle = td::actor::BusHandle<Bus>;

// Always relinquish the bridge's bus handle, including when the database close
// reports an error. The caller still awaits the bus stop promise before acting
// on the close result.
td::actor::Task<> close_and_release_bus(BusHandle& bus);

struct Pool {
  static void register_in(td::actor::Runtime&);
};

struct Consensus {
  static void register_in(td::actor::Runtime&);
};

struct CandidateResolver {
  static void register_in(td::actor::Runtime&);
};

struct StateResolver {
  static void register_in(td::actor::Runtime&);
};

struct MetricCollector {
  static void register_in(td::actor::Runtime&);
};

struct Db {
  static void register_in(td::actor::Runtime&);
};

struct DefaultCollatorSchedule {
  static void provide_for(td::actor::Runtime&);
};

}  // namespace tos::validator::consensus::simplex
