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

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "validator/consensus/validator-cleanup.h"

// Stateful adapter that drives validator consensus-DB cleanup while enforcing
// the safety invariants the pure coordinator cannot: generation-scoped closure,
// an in-flight-delete reservation that fences reopen, and erase bound to the
// retiring incarnation. It has NO actor/DB dependencies so it is unit-testable
// and can be driven through every crash/reopen ordering deterministically; the
// ValidatorManager forwards group lifecycle events here and supplies the GC
// oracles, a live-query, an (async) deleter, and a durable erase. Must be confined
// to the manager's actor thread.
//
// Resident set. The durable store can hold any number of records (a node that ran
// with cleanup disabled keeps one per retired session). Only a bounded window of
// them is resident here: the caller pages the store in key order on request
// (next_page_request / on_page_loaded) and the adapter keeps at most
// resident_limit() entries, evicting only closed, not-in-flight entries -- whose
// records are durable, so nothing that authorizes a deletion is ever lost. A
// runtime retirement is always admitted (its closure must be tracked), so the only
// excess over the limit is retirements still awaiting their close and reservations
// still in flight.
namespace tos::validator::consensus {

// A record reserved for deletion. The caller threads BOTH tokens back through
// completion: `generation` identifies the incarnation (rejects a completion from
// an older incarnation), and `attempt_id` identifies this specific delete attempt
// (rejects a stale/duplicate completion from an EARLIER attempt of the SAME
// incarnation, e.g. a worker that finished late after a retry was dispatched).
struct ReservedValidatorDelete {
  PendingValidatorConsensusDbCleanup record;
  uint64_t generation = 0;
  uint64_t attempt_id = 0;
};

// A request for the next page of durable records: read at most `max_keys` keys
// strictly after `after_key` and hand the result back with the same `token`.
struct ValidatorCleanupPageRequest {
  std::string after_key;
  size_t max_keys = 0;
  uint64_t token = 0;
};

class ValidatorCleanupManager {
 public:
  static constexpr size_t kDefaultResidentLimit = 4096;
  // Retired keys tracked while one page read is in flight: the smallest ones after
  // the page's start key. Larger keys are forgotten, and the page is then admitted
  // only up to the largest key still tracked (see on_page_loaded).
  static constexpr size_t kMaxRetiredDuringPage = 1024;

  ValidatorCleanupManager() = default;
  explicit ValidatorCleanupManager(size_t resident_limit) : resident_limit_(std::max<size_t>(resident_limit, 1)) {
  }

  // Records loaded from durable storage at a fresh startup. Before any group is
  // created in this process nothing owns the directory, so the retiring actor is
  // effectively closed -- closure is established by the fresh process + exclusive
  // ownership, not an invented ack. Generation 0 is the pre-any-creation baseline.
  //
  // A late load must NEVER overwrite knowledge of a RUNTIME incarnation: block
  // application can create/retire a group before this load's callback returns (the
  // startup load is not the only path to update_shards), and overwriting a live or
  // already-retired session with generation 0 / closed=true would corrupt the
  // state the deletion decision relies on. So this is insert-if-absent: if the
  // session is already tracked (live or pending), the runtime state wins and the
  // stale durable record is dropped here (it is superseded by the runtime
  // incarnation and replaced or cleaned when that incarnation next retires). This
  // makes correctness independent of whether the load races ahead of group
  // creation, rather than relying on an ordering barrier alone.
  //
  // The same holds for a record paged in later in this process: it is resident
  // again only if it is not live, not already resident (a runtime retirement
  // wins), and its earlier resident copy was evicted -- which happens only after
  // its close was confirmed. Returns false when the record was not admitted; a
  // record refused for lack of room stays on disk and is reached by a later page.
  bool on_loaded_at_startup(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    if (live_generation_.count(session) > 0 || pending_.count(session) > 0) {
      return false;
    }
    if (pending_.size() >= resident_limit_) {
      disk_backlog_ = true;
      return false;
    }
    pending_[session] = Entry{std::move(record), /*retired_generation=*/0, /*closed=*/true, EntryState::Pending};
    return true;
  }

  // Next page of the durable backlog to read, or nothing. A page is requested
  // only while records may exist on disk that are not resident, no other page is
  // in flight, and either at least a quarter of the window is free or the window
  // is stalled: every resident record was examined since the last reservation and
  // none was eligible. A stalled window evicts up to a quarter of its closed,
  // ineligible entries (their records stay on disk and come back on a later
  // sweep) so records it has not seen yet get examined. Once a whole sweep has
  // reserved nothing, rotation waits for the GC block to move: until then no
  // decision can change, and rotating again would only reread the store.
  std::optional<ValidatorCleanupPageRequest> next_page_request() {
    if (page_in_flight_ || !disk_backlog_) {
      return std::nullopt;
    }
    size_t room = pending_.size() < resident_limit_ ? resident_limit_ - pending_.size() : 0;
    if (room * 4 < resident_limit_) {
      if (pending_.empty() || examined_since_reservation_ < pending_.size() ||
          (rotation_idle_gc_ && last_gc_ == rotation_idle_gc_)) {
        return std::nullopt;
      }
      examined_since_reservation_ = 0;
      size_t quota = std::max<size_t>(resident_limit_ / 4, 1);
      for (auto it = pending_.begin(); it != pending_.end() && quota > 0;) {
        if (it->second.state == EntryState::Pending && it->second.closed && it->second.examined_ineligible) {
          it = pending_.erase(it);
          evicted_in_sweep_ = true;
          --quota;
        } else {
          ++it;
        }
      }
      room = pending_.size() < resident_limit_ ? resident_limit_ - pending_.size() : 0;
      if (room == 0) {
        return std::nullopt;
      }
    }
    page_in_flight_ = true;
    retired_during_page_.clear();
    page_overrun_ = false;
    page_after_key_ = sweep_cursor_;
    return ValidatorCleanupPageRequest{sweep_cursor_, room, ++page_token_};
  }

  // The page read for `request`. Admits its records while there is room and
  // advances the sweep. The read may predate a runtime retirement made while it was
  // in flight, so the page may carry the record that retirement superseded: such a
  // session's page copy is skipped (its current record is resident, or on disk and
  // reached by a later sweep), while every other record is admitted and the cursor
  // advances, so retirements of unrelated sessions cannot starve paging.
  // Only retirements whose keys fall after the page's start key can matter, and the
  // adapter tracks the kMaxRetiredDuringPage smallest of them. If more landed, the
  // forgotten ones all lie above the largest tracked key, so the page is trusted only
  // up to that key: records at or below it are checked exactly, the rest are left for
  // the next read, and the cursor moves to that key. It is strictly after the start
  // key, so every read makes progress however many retirements overlap it.
  // When a sweep of the whole range finishes without any eviction or refusal, every
  // durable record is resident (or belongs to a live session) and paging stops until
  // the next eviction. Returns the number of records admitted.
  size_t on_page_loaded(const ValidatorCleanupPageRequest& request, ValidatorCleanupPage page) {
    if (!page_in_flight_ || request.token != page_token_) {
      return 0;
    }
    page_in_flight_ = false;
    // Largest key the tracked retirements cover exactly, when some were forgotten.
    std::optional<std::string> trusted_up_to;
    if (page_overrun_ && !retired_during_page_.empty()) {
      trusted_up_to = *retired_during_page_.rbegin();
    }
    size_t admitted = 0;
    std::string resume = request.after_key;
    for (auto& record : page.records) {
      auto key = validator_cleanup_key(record.session_id);
      if (trusted_up_to && key > *trusted_up_to) {
        // Beyond what the tracked retirements cover: read it again next time.
        sweep_cursor_ = *trusted_up_to;
        disk_backlog_ = true;
        retired_during_page_.clear();
        return admitted;
      }
      if (retired_during_page_.count(key) > 0) {
        resume = key;
        disk_backlog_ = true;  // its current record may be on disk, not resident
        continue;
      }
      auto session = record.session_id;
      if (live_generation_.count(session) > 0 || pending_.count(session) > 0) {
        resume = key;  // refused by insert-if-absent; nothing to make room for
        continue;
      }
      // A full window (runtime retirements arrived meanwhile) makes room by evicting
      // one closed entry: its record is durable and comes back on a later sweep, so the
      // sweep keeps moving however many retirements fill the window.
      if (pending_.size() >= resident_limit_ && !evict_one_closed(request.token)) {
        // Nothing evictable (every entry awaits its close or is in flight): resume here.
        sweep_cursor_ = resume;
        disk_backlog_ = true;
        retired_during_page_.clear();
        return admitted;
      }
      resume = key;
      if (on_loaded_at_startup(std::move(record))) {
        pending_[session].admitted_by_page = request.token;
        ++admitted;
      }
    }
    retired_during_page_.clear();
    sweep_cursor_ = page.last_key.empty() ? resume : page.last_key;
    if (trusted_up_to && *trusted_up_to < sweep_cursor_) {
      // Keys after the trusted bound that held no valid record are re-read too.
      sweep_cursor_ = *trusted_up_to;
      disk_backlog_ = true;
      return admitted;
    }
    if (page.reached_end) {
      if (!evicted_in_sweep_) {
        disk_backlog_ = false;
      }
      if (!reserved_in_sweep_ && !evicted_unexamined_in_sweep_) {
        rotation_idle_gc_ = last_gc_;
      }
      sweep_cursor_.clear();
      evicted_in_sweep_ = false;
      evicted_unexamined_in_sweep_ = false;
      reserved_in_sweep_ = false;
    }
    return admitted;
  }

  // The caller could not read a requested page; it may ask again later.
  void on_page_failed(const ValidatorCleanupPageRequest& request) {
    if (page_in_flight_ && request.token == page_token_) {
      page_in_flight_ = false;
      retired_during_page_.clear();
    }
  }

  size_t resident_limit() const {
    return resident_limit_;
  }

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while
  // a delete is in flight. Assigns a PROCESS-WIDE monotonically increasing
  // incarnation token (never per-session and never reset), so a later incarnation
  // of a session always has a strictly greater generation than any earlier one --
  // a stale close/delete callback carrying an older generation can therefore never
  // match a newer incarnation. The token is retained only while the session is
  // live (released at retirement), so this map is bounded by the number of
  // concurrently-live sessions, not by all sessions ever created. Also drops any
  // pending cleanup entry -- the directory is being reused by a live group.
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session] = ++next_generation_;
    auto it = pending_.find(session);
    if (it != pending_.end()) {
      if (it->second.state != EntryState::Pending) {
        // Defensive: the caller must fence creation while a delete is in flight, so
        // reaching here means the fence was bypassed; keep outstanding_ consistent.
        --outstanding_;
      }
      pending_.erase(it);
    }
  }

  // The current incarnation of `session` retired; `record` is its durable cleanup
  // record (persisted before the actor is allowed to close). Consumes and RELEASES
  // the live incarnation token (the session is no longer live), returning it so the
  // manager can tag the close callback. A retiring group must have been created; if
  // its token is somehow absent, mint a fresh unique one rather than reuse a stale
  // value. A re-retirement overwrites the prior pending entry.
  uint64_t on_group_retired(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    // Defensive: never overwrite an entry whose delete is already in flight
    // (Deleting/Erasing). This cannot happen in production -- creation is fenced
    // while in flight, so a session cannot be re-created and re-retired mid-delete
    // -- but overwriting it would abandon the running worker and permanently
    // elevate outstanding_. Keep the in-flight operation intact and report its
    // generation.
    auto existing = pending_.find(session);
    if (existing != pending_.end() && existing->second.state != EntryState::Pending) {
      return existing->second.retired_generation;
    }
    uint64_t gen;
    auto it = live_generation_.find(session);
    if (it != live_generation_.end()) {
      gen = it->second;
      live_generation_.erase(it);
    } else {
      gen = ++next_generation_;
    }
    pending_[session] = Entry{std::move(record), gen, /*closed=*/false, EntryState::Pending};
    // A page in flight may carry the record this retirement supersedes.
    if (page_in_flight_) {
      auto key = validator_cleanup_key(session);
      if (key > page_after_key_) {  // the page reads only keys after its start key
        retired_during_page_.insert(std::move(key));
        if (retired_during_page_.size() > kMaxRetiredDuringPage) {
          retired_during_page_.erase(std::prev(retired_during_page_.end()));
          page_overrun_ = true;
        }
      }
    }
    // This entry is not closed yet, so trimming keeps it.
    trim_to_limit();
    return gen;
  }

  // The retiring actor confirmed its bus stopped and DB closed, tagged with the
  // generation it was retired at. Accepted ONLY if it matches the pending entry's
  // generation: a stale ack from an older incarnation (after a reopen/re-retire)
  // is ignored, so it can never mark a newer incarnation closed.
  void on_close_confirmed(const ValidatorSessionId& session, uint64_t generation) {
    auto it = pending_.find(session);
    if (it != pending_.end() && it->second.retired_generation == generation) {
      it->second.closed = true;
      // A burst of retirements can push the window over its limit while their closes
      // are outstanding; each close makes one more entry evictable.
      trim_to_limit();
    }
  }

  // True while a delete (or its durable erase) is in progress for `session`. The
  // reservation is held from delete dispatch through the durable-erase ack, so the
  // group-creation path MUST refuse/defer creating a group for it that whole time
  // -- a reopen can never race an in-flight delete of the same directory.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    auto it = pending_.find(session);
    return it != pending_.end() && it->second.state != EntryState::Pending;
  }

  // Select up to `delete_budget` eligible records, RESERVE them (Pending ->
  // Deleting), and return each with its incarnation generation as an operation
  // token. The caller deletes each directory asynchronously and MUST thread the
  // (session, generation) back through on_delete_completed / on_erase_acknowledged,
  // so a stale completion cannot act on a replacement entry. Eligibility is the
  // four-condition gate with is_closed taken from this adapter's per-incarnation
  // closure.
  // `dispatch_budget` caps reservations made THIS pass; `scan_budget` caps entries
  // EXAMINED this pass (so a large backlog of ineligible records cannot make one
  // pass walk the whole table); `max_outstanding` caps total concurrent
  // Deleting+Erasing reservations ACROSS passes (so a slow async worker cannot let
  // in-flight work grow unbounded). scan_budget / max_outstanding default to
  // unbounded for callers that only want the dispatch cap.
  // `on_examined`, if set, is called with (session, eligible) for a Pending record this
  // pass examined whenever that record's decision differs from the last one reported for
  // it -- always on its first examination in this process, and again when it flips (an
  // ineligible record becoming eligible, or a failed delete returning to Pending and being
  // re-examined). It proves, per session, that a record was evaluated and what was decided,
  // without inferring examination from budget arithmetic; reporting only changes keeps it
  // bounded to a few lines per record although passes run on every GC advance.
  using CleanupExaminedFn = std::function<void(const ValidatorSessionId&, bool /*eligible*/)>;
  std::vector<ReservedValidatorDelete> begin_eligible_deletes(
      const BlockIdExt& gc_checkpoint, const CleanupAncestorOfGcFn& ancestor_or_equal_of_gc,
      const GcShardCatchainSeqnoFn& gc_shard_catchain_seqno, const CleanupSessionIsLiveFn& is_live,
      size_t dispatch_budget, size_t scan_budget = std::numeric_limits<size_t>::max(),
      size_t max_outstanding = std::numeric_limits<size_t>::max(), const CleanupExaminedFn& on_examined = {}) {
    std::vector<ReservedValidatorDelete> reserved;
    last_gc_ = gc_checkpoint;
    if (pending_.empty() || dispatch_budget == 0) {
      return reserved;
    }
    // Round-robin: resume scanning at the cursor and wrap once, examining each entry
    // at most once this pass, so a prefix of persistently-failing records cannot
    // monopolize the budget every pass and starve later ones. The cursor advances
    // even on scan-budget exhaustion. The cursor is a session-id value, so a removed
    // cursor session simply resolves to the next.
    size_t scan_limit = std::min(scan_budget, pending_.size());
    auto it = pending_.lower_bound(retry_cursor_);
    for (size_t examined = 0;
         examined < scan_limit && reserved.size() < dispatch_budget && outstanding_ < max_outstanding; ++examined) {
      if (it == pending_.end()) {
        it = pending_.begin();
      }
      auto& entry = it->second;
      if (entry.state == EntryState::Pending) {
        auto is_closed = [&entry](const ValidatorSessionId&) { return entry.closed; };
        bool eligible = validator_cleanup_eligible(entry.record, gc_checkpoint, ancestor_or_equal_of_gc,
                                                   gc_shard_catchain_seqno, is_live, is_closed);
        entry.examined = true;
        entry.examined_ineligible = !eligible;
        ++examined_since_reservation_;
        if (on_examined && entry.last_reported_eligible != eligible) {
          entry.last_reported_eligible = eligible;
          on_examined(it->first, eligible);
        }
        if (eligible) {
          entry.state = EntryState::Deleting;
          entry.attempt_id = ++next_attempt_;  // fresh per-attempt token
          ++outstanding_;
          reserved.push_back(ReservedValidatorDelete{entry.record, entry.retired_generation, entry.attempt_id});
        }
      }
      ++it;
    }
    // Resume the next pass after the last entry examined.
    retry_cursor_ = (it == pending_.end()) ? ValidatorSessionId{} : it->first;
    if (!reserved.empty()) {
      examined_since_reservation_ = 0;
      reserved_in_sweep_ = true;
    }
    return reserved;
  }

  // Report the result of a dispatched delete for the operation identified by
  // (session, generation). Rejected unless the entry still exists, its incarnation
  // matches `generation`, and it is in the Deleting state -- so a stale completion
  // (e.g. for an incarnation replaced despite the fence) cannot act on a newer
  // entry. On confirmed removal, DISPATCH the durable erase (via the injected
  // callback) and move to Erasing; the reservation is NOT released and the record
  // is NOT dropped until on_erase_acknowledged. On unconfirmed removal, return to
  // Pending for a later retry.
  // Must be called ONLY when a dispatched delete ATTEMPT truly finishes (the worker
  // reports success or failure), never speculatively on a timeout -- a timeout does
  // not prove the worker stopped, so the caller must keep the ownership fence and
  // not re-dispatch until the outstanding attempt is confirmed done or cancelled.
  // Rejected unless the entry exists, matches the incarnation `generation` AND the
  // `attempt_id`, and is in Deleting -- so a stale/duplicate completion from an
  // earlier attempt (of this or an older incarnation) cannot act. On confirmed
  // removal, move to Erasing (keeping the same attempt token) and dispatch the
  // durable erase; the record is NOT dropped and the reservation NOT released yet.
  // On reported failure, return to Pending for a fresh attempt on a later pass.
  void on_delete_completed(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id,
                           bool confirmed_gone,
                           const std::function<void(const ValidatorSessionId&, uint64_t, uint64_t)>&
                               dispatch_durable_erase) {
    auto it = pending_.find(session);
    if (it == pending_.end() || it->second.retired_generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != EntryState::Deleting) {
      return;  // stale / replaced / wrong attempt / not in flight -> ignore
    }
    if (confirmed_gone) {
      it->second.state = EntryState::Erasing;  // still outstanding until the erase is acked
      dispatch_durable_erase(session, generation, attempt_id);
    } else {
      it->second.state = EntryState::Pending;  // retry with a fresh attempt on a later pass
      it->second.last_reported_eligible.reset();  // report the retry's decision again
      --outstanding_;
    }
  }

  // The durable erase for the operation (session, generation, attempt_id) has been
  // acknowledged as committed. Only now is the record dropped and the reservation
  // released. Rejected unless the entry still matches that incarnation AND attempt
  // and is in Erasing, so a late erase ack cannot remove a replacement record.
  void on_erase_acknowledged(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id) {
    auto it = pending_.find(session);
    if (it == pending_.end() || it->second.retired_generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != EntryState::Erasing) {
      return;
    }
    pending_.erase(it);
    --outstanding_;
  }

  size_t pending_count() const {
    return pending_.size();
  }

  // Number of currently-live sessions whose incarnation token is retained. Bounded
  // by concurrently-live sessions (released at retirement); exposed so a test can
  // prove the bookkeeping does not grow with historical session churn.
  size_t live_session_count() const {
    return live_generation_.size();
  }

 private:
  // Make room for a record of page `page_token`: evict one closed, not-in-flight
  // entry. Preference: examined and ineligible, then any examined entry, then an
  // unexamined runtime retirement. A record admitted from this same page is never
  // evicted before a pass has examined it -- the page would otherwise push out its own
  // records undecided. Evicting any unexamined entry means the current sweep can no
  // longer prove that every record was examined, so it will not pause rotation when it
  // finishes. Returns false when nothing is evictable; the caller stops the page there.
  bool evict_one_closed(uint64_t page_token) {
    auto examined_victim = pending_.end();
    auto unexamined_victim = pending_.end();
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
      const auto& entry = it->second;
      if (entry.state != EntryState::Pending || !entry.closed) {
        continue;
      }
      if (entry.examined) {
        if (entry.examined_ineligible) {
          examined_victim = it;
          break;
        }
        if (examined_victim == pending_.end()) {
          examined_victim = it;
        }
      } else if (entry.admitted_by_page != page_token && unexamined_victim == pending_.end()) {
        unexamined_victim = it;
      }
    }
    auto victim = examined_victim != pending_.end() ? examined_victim : unexamined_victim;
    if (victim == pending_.end()) {
      return false;
    }
    if (!victim->second.examined) {
      evicted_unexamined_in_sweep_ = true;
    }
    pending_.erase(victim);
    disk_backlog_ = true;
    evicted_in_sweep_ = true;
    return true;
  }

  // Keep the window bounded: evict closed, not-in-flight entries (their records are
  // durable, so the store still holds every deletion authority) until the window is
  // within its limit or nothing else is evictable. Examined entries go first; if an
  // unexamined one must go to hold the bound, the current sweep can no longer prove
  // that every record was examined, so it does not pause rotation when it finishes.
  void trim_to_limit() {
    for (bool examined_only : {true, false}) {
      for (auto evict = pending_.begin(); pending_.size() > resident_limit_ && evict != pending_.end();) {
        auto& entry = evict->second;
        if (entry.state == EntryState::Pending && entry.closed && (entry.examined || !examined_only)) {
          if (!entry.examined) {
            evicted_unexamined_in_sweep_ = true;
          }
          evict = pending_.erase(evict);
          disk_backlog_ = true;
          evicted_in_sweep_ = true;
        } else {
          ++evict;
        }
      }
    }
  }

  // Pending: retired, not yet being reclaimed. Deleting: a filesystem delete is in
  // flight. Erasing: the directory is confirmed gone and the durable record erase
  // is in flight. The reservation (is_delete_in_flight) is held in Deleting and
  // Erasing; the entry is dropped only after the erase is acknowledged.
  enum class EntryState { Pending, Deleting, Erasing };
  struct Entry {
    PendingValidatorConsensusDbCleanup record;
    uint64_t retired_generation = 0;
    bool closed = false;
    EntryState state = EntryState::Pending;
    uint64_t attempt_id = 0;  // token of the current Deleting/Erasing attempt
    // Last eligibility decision passed to on_examined, so repeated passes over an
    // unchanged record do not report it again.
    std::optional<bool> last_reported_eligible;
    // Examined and found ineligible on its latest examination: a stalled window
    // evicts these first.
    bool examined_ineligible = false;
    // Examined by at least one pass since it became resident.
    bool examined = false;
    // Token of the page that admitted it (0 for a runtime retirement).
    uint64_t admitted_by_page = 0;
  };
  std::map<ValidatorSessionId, Entry> pending_;
  // Incarnation token of each currently-live session (created, not yet retired).
  std::map<ValidatorSessionId, uint64_t> live_generation_;
  // Process-wide monotonically increasing incarnation token source. Never reset, so
  // no two incarnations (across the whole process lifetime) ever share a token.
  uint64_t next_generation_ = 0;
  // Process-wide monotonically increasing per-delete-attempt token source, so no
  // two delete attempts (even of the same incarnation) ever share a token.
  uint64_t next_attempt_ = 0;
  // Round-robin resume point for begin_eligible_deletes, so retries are fair and a
  // failing prefix cannot starve later records. Default-constructed sorts first.
  ValidatorSessionId retry_cursor_{};
  // Count of entries currently Deleting or Erasing (reserved). Caps concurrent
  // in-flight cleanup work via max_outstanding.
  size_t outstanding_ = 0;

  // Resident window over the durable backlog (see the class comment).
  size_t resident_limit_ = kDefaultResidentLimit;
  // True while records may exist on disk that are not resident. Starts true: a
  // fresh process has not read the store yet.
  bool disk_backlog_ = true;
  // Key after which the next page is read; empty means the start of the range.
  std::string sweep_cursor_;
  // An entry was evicted since the current sweep began, so a finished sweep does
  // not prove that everything on disk is resident.
  bool evicted_in_sweep_ = false;
  // An entry no pass had examined was evicted since the current sweep began.
  bool evicted_unexamined_in_sweep_ = false;
  bool page_in_flight_ = false;
  uint64_t page_token_ = 0;
  // Keys of sessions retired while the current page was in flight, after the page's
  // start key: the kMaxRetiredDuringPage smallest. page_overrun_ records that larger
  // ones were forgotten.
  std::set<std::string> retired_during_page_;
  bool page_overrun_ = false;
  std::string page_after_key_;
  // Pending records examined since the last pass that reserved anything.
  size_t examined_since_reservation_ = 0;
  // Something was reserved since the current sweep began.
  bool reserved_in_sweep_ = false;
  // GC block of the latest pass, and the GC block at which a whole sweep reserved
  // nothing (rotation is paused while the two are equal).
  std::optional<BlockIdExt> last_gc_;
  std::optional<BlockIdExt> rotation_idle_gc_;
};

}  // namespace tos::validator::consensus
