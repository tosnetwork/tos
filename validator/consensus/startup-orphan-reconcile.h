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
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "td/actor/actor.h"
#include "td/utils/logging.h"
#include "validator/consensus/db-path.h"
#include "validator/consensus/directory-cursor.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/consensus/validator-cleanup.h"
#include "validator/startup-catchup.h"

// Startup inventory of orphaned validator session directories.
//
// A validator group's directory normally gets its cleanup record when the group
// retires. A session open before a shutdown may never be reopened (startup
// catch-up fences groups while it imports, and a restored init block can be older
// than the previous process's sessions), so nothing would ever retire it and its
// directory would stay on disk for ever. Once per startup, at prestart
// completion, after the group fence opened and groups were reconciled on the
// final state, this pass lists the consensus directory and records every
// directory whose session can never be selected again: a canonical validator
// directory, not live or tentative, not fenced as destroyed, with a known current
// catchain seqno for its shard strictly above its own, and no durable cleanup
// record. Deletion then follows the ordinary cleanup ticks.
//
// The listing is read one entry at a time through a cursor, and each candidate's
// durable record is point-read before the next entry is read, so neither the
// listing nor the candidate list is ever held: memory is the cursor, one pending
// read, and at most kMaxStartupOrphanRecords new records. The cost is one pass
// over the directory, O(number of directories).
//
// The limit counts only records confirmed missing by the point read, so
// directories that already have a record never take a slot. For a fixed backlog
// whose reads and writes succeed, every orphan is recorded within
// ceil(orphans / limit) startups. A directory whose point read fails is skipped,
// counted and reported, and stays for a later startup.
//
// The commit follows the retirement path of the group update: the survivors of a
// final recheck enter the in-memory destroyed-session set before the write is
// issued, the write carries that complete set together with the new records in
// one synced batch, and only after it is acknowledged is each session's close
// confirmed, which makes it eligible for cleanup in this process.
//
// The free functions are templates over the owner actor `Self`, so the manager
// and the test harness run the same code. `Self` must expose:
//   actor methods
//     void startup_orphan_point_read(td::uint64 token, StartupOrphanCandidate candidate,
//         td::Result<std::optional<PendingValidatorConsensusDbCleanup>> record);
//     void startup_orphan_persisted(td::uint64 token,
//         std::vector<std::pair<ValidatorSessionId, td::uint64>> retired, td::Result<td::Unit> result);
//   plain methods
//     void startup_orphan_read_record(ValidatorSessionId session,
//         td::Promise<std::optional<PendingValidatorConsensusDbCleanup>> promise);  // the durable point read
//     void startup_orphan_persist(std::vector<ValidatorSessionId> destroyed,
//         std::vector<PendingValidatorConsensusDbCleanup> records, td::Promise<td::Unit> promise);
//         // the synced complete-set retirement write
//     StartupOrphanReconcile& startup_orphan_reconcile();
//     bool startup_orphan_session_live(const ValidatorSessionId& session);  // live or tentative group
//     std::set<ValidatorSessionId>& startup_orphan_destroyed_sessions();
//     ValidatorCleanupManager& startup_orphan_cleanup_manager();
//     std::optional<CatchainSeqno> startup_orphan_current_catchain_seqno(ShardIdFull shard);
//     BlockIdExt startup_orphan_retirement_checkpoint();
//     void startup_orphan_reconcile_finished(StartupOrphanSummary summary);
namespace tos::validator::consensus {

struct StartupOrphanCandidate {
  ValidatorSessionId session;
  ShardIdFull shard;
  CatchainSeqno catchain_seqno = 0;
  std::string dir_name;
};

enum class OrphanDirVerdict { NotDirectory, NotCanonical, Live, Destroyed, UnknownCatchain, NotObsolete, Candidate };

// The synchronous filter applied to every listed entry.
template <class IsLive, class IsDestroyed, class CurrentCatchain>
OrphanDirVerdict classify_orphan_dir(const DirectoryCursor::Entry& entry, IsLive&& is_live, IsDestroyed&& is_destroyed,
                                     CurrentCatchain&& current_catchain_seqno, StartupOrphanCandidate* out) {
  if (!entry.is_directory) {
    return OrphanDirVerdict::NotDirectory;
  }
  auto session = consensus_db_session_id(entry.name);
  if (!session) {
    return OrphanDirVerdict::NotCanonical;
  }
  auto parsed = parse_canonical_validator_dir_name(entry.name, *session);
  if (!parsed) {
    return OrphanDirVerdict::NotCanonical;  // observer directories and anything else
  }
  if (is_live(*session)) {
    return OrphanDirVerdict::Live;
  }
  if (is_destroyed(*session)) {
    return OrphanDirVerdict::Destroyed;
  }
  std::optional<CatchainSeqno> current = current_catchain_seqno(parsed->shard);
  if (!current) {
    return OrphanDirVerdict::UnknownCatchain;
  }
  if (!(parsed->catchain_seqno < *current)) {
    return OrphanDirVerdict::NotObsolete;
  }
  if (out != nullptr) {
    *out = StartupOrphanCandidate{*session, parsed->shard, parsed->catchain_seqno, entry.name};
  }
  return OrphanDirVerdict::Candidate;
}

struct StartupOrphanSummary {
  std::size_t directories = 0;       // entries listed
  std::size_t candidates = 0;        // passed the synchronous filter
  std::size_t already_recorded = 0;  // a durable record exists
  std::size_t read_failures = 0;     // point read failed; skipped until a later startup
  std::size_t deferred = 0;          // confirmed unrecorded, left out by the record limit
  std::size_t rechecked_out = 0;     // dropped by the final recheck
  std::size_t recorded = 0;          // records written and closes confirmed
  std::size_t peak_held = 0;         // most candidates and records held at once
  bool listing_failed = false;
  bool persist_failed = false;
};

class StartupOrphanReconcile {
 public:
  td::Status begin(std::string db_root, std::size_t record_limit = startup_catchup::kMaxStartupOrphanRecords) {
    db_root_ = std::move(db_root);
    record_limit_ = record_limit;
    token_ = token_ + 1;
    active_ = true;
    summary_ = {};
    records_.clear();
    pending_reads_ = 0;
    auto cursor = DirectoryCursor::open(consensus_db_root(db_root_));
    if (cursor.is_error()) {
      return cursor.move_as_error();
    }
    cursor_ = cursor.move_as_ok();
    return td::Status::OK();
  }

  // Accounting for one point read; returns whether it produced a new record.
  bool on_point_read(const StartupOrphanCandidate& candidate,
                     td::Result<std::optional<PendingValidatorConsensusDbCleanup>> record,
                     const BlockIdExt& retirement_checkpoint) {
    if (pending_reads_ > 0) {
      pending_reads_--;
    }
    if (record.is_error()) {
      summary_.read_failures++;
      return false;
    }
    if (record.ok().has_value()) {
      summary_.already_recorded++;
      return false;
    }
    if (records_.size() >= record_limit_) {
      summary_.deferred++;
      return false;
    }
    records_.push_back(make_validator_cleanup_record(candidate.session, candidate.shard, candidate.catchain_seqno,
                                                     retirement_checkpoint));
    note_held();
    return true;
  }

  void on_read_issued() {
    pending_reads_++;
    summary_.candidates++;
    note_held();
  }

  void note_held() {
    summary_.peak_held = std::max(summary_.peak_held, records_.size() + pending_reads_);
  }

  DirectoryCursor& cursor() {
    return cursor_;
  }
  StartupOrphanSummary& summary() {
    return summary_;
  }
  std::vector<PendingValidatorConsensusDbCleanup>& records() {
    return records_;
  }
  const std::string& db_root() const {
    return db_root_;
  }
  td::uint64 token() const {
    return token_;
  }
  bool active() const {
    return active_;
  }
  void finish() {
    active_ = false;
    records_.clear();
  }

 private:
  std::string db_root_;
  std::size_t record_limit_ = startup_catchup::kMaxStartupOrphanRecords;
  td::uint64 token_ = 0;
  bool active_ = false;
  DirectoryCursor cursor_;
  std::vector<PendingValidatorConsensusDbCleanup> records_;
  std::size_t pending_reads_ = 0;
  StartupOrphanSummary summary_;
};

template <class Self>
void finish_startup_orphan_reconcile(Self* self) {
  auto& st = self->startup_orphan_reconcile();
  auto summary = st.summary();
  st.finish();
  if (summary.read_failures > 0) {
    LOG(WARNING) << "startup inventory of validator session directories: " << summary.read_failures
                 << " candidate(s) skipped because their cleanup record could not be read; they are checked again "
                    "at the next startup";
  }
  if (summary.deferred > 0) {
    LOG(WARNING) << "startup inventory of validator session directories: record limit reached; " << summary.deferred
                 << " candidates deferred to next startup";
  }
  if (summary.listing_failed) {
    LOG(WARNING) << "startup inventory of validator session directories could not list the consensus directory to "
                    "the end";
  }
  LOG(INFO) << "startup inventory of validator session directories: directories=" << summary.directories
            << " candidates=" << summary.candidates << " already_recorded=" << summary.already_recorded
            << " recorded=" << summary.recorded << " deferred=" << summary.deferred
            << " read_failures=" << summary.read_failures << " rechecked_out=" << summary.rechecked_out;
  self->startup_orphan_reconcile_finished(summary);
}

template <class Self>
void commit_startup_orphans(Self* self, td::actor::ActorId<Self> self_id) {
  auto& st = self->startup_orphan_reconcile();
  auto& destroyed = self->startup_orphan_destroyed_sessions();
  auto& cleanup = self->startup_orphan_cleanup_manager();
  // Recheck on the owner's actor, immediately before the commit: the asynchronous
  // reads gave groups, deletes and retirements time to change.
  std::vector<PendingValidatorConsensusDbCleanup> survivors;
  for (auto& record : st.records()) {
    if (self->startup_orphan_session_live(record.session_id) || cleanup.is_delete_in_flight(record.session_id) ||
        destroyed.count(record.session_id) > 0 ||
        !is_real_directory(consensus_db_root(st.db_root()) + record.dir_name)) {
      st.summary().rechecked_out++;
      continue;
    }
    survivors.push_back(record);
  }
  if (survivors.empty()) {
    finish_startup_orphan_reconcile(self);
    return;
  }
  // The fences enter memory before the write is issued, so every later complete-set
  // write issued from this actor already carries them.
  for (auto& record : survivors) {
    destroyed.insert(record.session_id);
  }
  std::vector<std::pair<ValidatorSessionId, td::uint64>> retired;
  for (auto& record : survivors) {
    retired.emplace_back(record.session_id, cleanup.on_group_retired(record));
  }
  self->startup_orphan_persist(
      std::vector<ValidatorSessionId>(destroyed.begin(), destroyed.end()), std::move(survivors),
      [self_id, token = st.token(), retired = std::move(retired)](td::Result<td::Unit> R) mutable {
        td::actor::send_closure(self_id, &Self::startup_orphan_persisted, token, std::move(retired), std::move(R));
      });
}

template <class Self>
void advance_startup_orphan_reconcile(Self* self, td::actor::ActorId<Self> self_id) {
  auto& st = self->startup_orphan_reconcile();
  while (true) {
    auto next = st.cursor().next();
    if (next.is_error()) {
      LOG(WARNING) << "startup inventory of validator session directories: " << next.error();
      st.summary().listing_failed = true;
      break;
    }
    auto entry = next.move_as_ok();
    if (!entry) {
      break;
    }
    st.summary().directories++;
    StartupOrphanCandidate candidate;
    auto verdict = classify_orphan_dir(
        *entry, [self](const ValidatorSessionId& s) { return self->startup_orphan_session_live(s); },
        [self](const ValidatorSessionId& s) { return self->startup_orphan_destroyed_sessions().count(s) > 0; },
        [self](ShardIdFull shard) { return self->startup_orphan_current_catchain_seqno(shard); }, &candidate);
    if (verdict != OrphanDirVerdict::Candidate) {
      continue;
    }
    st.on_read_issued();
    auto session = candidate.session;
    self->startup_orphan_read_record(
        session, [self_id, token = st.token(), candidate = std::move(candidate)](
                     td::Result<std::optional<PendingValidatorConsensusDbCleanup>> R) mutable {
          td::actor::send_closure(self_id, &Self::startup_orphan_point_read, token, std::move(candidate), std::move(R));
        });
    return;  // the next entry is read when this point read reports
  }
  commit_startup_orphans(self, self_id);
}

template <class Self>
void begin_startup_orphan_reconcile(Self* self, td::actor::ActorId<Self> self_id, std::string db_root) {
  auto& st = self->startup_orphan_reconcile();
  auto status = st.begin(std::move(db_root));
  if (status.is_error()) {
    LOG(WARNING) << "startup inventory of validator session directories: " << status;
    st.summary().listing_failed = true;
    finish_startup_orphan_reconcile(self);
    return;
  }
  advance_startup_orphan_reconcile(self, self_id);
}

template <class Self>
void handle_startup_orphan_point_read(Self* self, td::actor::ActorId<Self> self_id, td::uint64 token,
                                      StartupOrphanCandidate candidate,
                                      td::Result<std::optional<PendingValidatorConsensusDbCleanup>> record) {
  auto& st = self->startup_orphan_reconcile();
  if (!st.active() || token != st.token()) {
    return;
  }
  st.on_point_read(candidate, std::move(record), self->startup_orphan_retirement_checkpoint());
  advance_startup_orphan_reconcile(self, self_id);
}

template <class Self>
void handle_startup_orphans_persisted(Self* self, td::uint64 token,
                                      std::vector<std::pair<ValidatorSessionId, td::uint64>> retired,
                                      td::Result<td::Unit> result) {
  auto& st = self->startup_orphan_reconcile();
  if (!st.active() || token != st.token()) {
    return;
  }
  if (result.is_error()) {
    // The closes stay unconfirmed: nothing becomes eligible for deletion on a write
    // that may not be durable.
    LOG(ERROR) << "startup inventory of validator session directories: persisting " << retired.size()
               << " cleanup record(s) failed: " << result.error();
    st.summary().persist_failed = true;
    finish_startup_orphan_reconcile(self);
    return;
  }
  // No actor owns these sessions, so nothing else will confirm their close.
  auto& cleanup = self->startup_orphan_cleanup_manager();
  for (auto& [session, generation] : retired) {
    cleanup.on_close_confirmed(session, generation);
  }
  st.summary().recorded += retired.size();
  finish_startup_orphan_reconcile(self);
}

}  // namespace tos::validator::consensus
