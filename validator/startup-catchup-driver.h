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

#include "td/actor/coro_task.h"
#include "td/actor/coro_utils.h"
#include "td/utils/logging.h"
#include "validator/startup-catchup.h"

// The startup catch-up mode loop: discovery of a verified successor, then bounded
// import attempts, until the ordinary freshness rule holds, no peer proves progress,
// or the attempt budget is spent.
//
// One coroutine runs every step in order and nothing else is dispatched meanwhile:
// an attempt is awaited until every child it started has settled, and the
// shard-client update that makes its outcome durable is awaited (without a deadline)
// before the attempt is counted and before the mode can end. So when the mode ends,
// no import and no shard-client update is in flight.
//
// It is a template over the owner `Self`, so the manager and the test harness run the
// same loop. `Self` must provide, on its actor:
//   double catchup_monotonic_now();
//   BlockIdExt catchup_tip();                      // the exact local masterchain tip
//   BlockSeqno catchup_masterchain_seqno();
//   BlockSeqno catchup_shard_client_seqno();      // the durable shard-client seqno
//   bool catchup_out_of_sync();                    // the sync predicate, mode active
//   void catchup_phase(Phase phase);
//   td::actor::Task<RoundResult> catchup_probe_round(BlockIdExt prev, double deadline, std::uint32_t budget);
//   td::actor::Task<ImportOutcome> catchup_import_attempt(double attempt_deadline);
//   td::actor::Task<td::Unit> catchup_persist_shard_client(BlockSeqno seqno);
//   td::actor::Task<td::Unit> catchup_sleep(double seconds);
namespace tos::validator::startup_catchup {

struct DiscoveryDecision {
  bool verified = false;
  BlockIdExt next;
  std::uint32_t probes_used = 0;
  std::uint32_t rounds = 0;
};

// One discovery window: rounds about the exact local tip, restarted from the new tip
// whenever it moves, sharing one deadline and one probe budget.
template <class Self>
td::actor::Task<DiscoveryDecision> discover_successor(Self* self) {
  const double deadline = self->catchup_monotonic_now() + kDiscoveryWindowSeconds;
  std::uint32_t budget = kProbeBudget;
  DiscoveryDecision decision;
  while (true) {
    auto prev = self->catchup_tip();
    decision.rounds = saturating_inc(decision.rounds);
    auto round = co_await self->catchup_probe_round(prev, deadline, budget).wrap();
    bool time_left = self->catchup_monotonic_now() < deadline;
    if (round.is_error()) {
      // The network side was not ready: retry within the window, as peer selection does.
      LOG(INFO) << "startup catch-up discovery round failed: " << round.error();
      if (!time_left || budget == 0) {
        co_return decision;
      }
      co_await self->catchup_sleep(kPeerReselectSeconds);
      continue;
    }
    auto result = round.move_as_ok();
    budget = saturating_sub(budget, result.probes_used);
    decision.probes_used += result.probes_used;
    // Accept a successor only of the tip it was proven for: the tip may have moved
    // while the proof was being checked.
    bool tip_unchanged = self->catchup_tip() == prev;
    if (result.outcome == RoundOutcome::Verified && tip_unchanged) {
      decision.verified = true;
      decision.next = result.next;
      co_return decision;
    }
    bool restart = result.outcome == RoundOutcome::FrontierMoved || !tip_unchanged;
    if (restart && budget > 0 && time_left) {
      LOG(INFO) << "startup catch-up discovery: the local tip moved from " << prev.to_str() << "; restarting from "
                << self->catchup_tip().to_str() << " with " << budget << " probes left";
      continue;
    }
    co_return decision;
  }
}

template <class Self>
td::actor::Task<ExitReason> run_startup_catchup(Self* self) {
  self->catchup_phase(Phase::Discovering);
  auto discovered = co_await discover_successor(self);
  if (!discovered.verified) {
    co_return ExitReason::NoVerifiedSuccessor;
  }
  LOG(WARNING) << "startup catch-up: a peer proved successor " << discovered.next.to_str() << " of the local tip";
  ImportAccounting accounting;
  td::Status last_error;
  while (true) {
    if (!self->catchup_out_of_sync()) {
      co_return ExitReason::Fresh;
    }
    self->catchup_phase(Phase::Importing);
    AttemptResult attempt;
    attempt.masterchain_before = self->catchup_masterchain_seqno();
    attempt.shard_client_before = self->catchup_shard_client_seqno();
    auto outcome = co_await self->catchup_import_attempt(self->catchup_monotonic_now() + kImportAttemptSeconds).wrap();
    BlockSeqno coherent = attempt.shard_client_before;
    if (outcome.is_error()) {
      attempt.errored = true;
      last_error = outcome.move_as_error();
    } else {
      auto value = outcome.move_as_ok();
      coherent = value.coherent_shard_client_seqno;
      if (value.first_error.is_error()) {
        attempt.errored = true;
        last_error = std::move(value.first_error);
      }
    }
    if (coherent > attempt.shard_client_before) {
      // Make the coherent frontier durable before counting it; this write is awaited
      // whatever the attempt deadline.
      auto persisted = co_await self->catchup_persist_shard_client(coherent).wrap();
      if (persisted.is_error()) {
        attempt.errored = true;
        last_error = persisted.move_as_error_prefix("shard-client update: ");
      }
    }
    attempt.masterchain_after = self->catchup_masterchain_seqno();
    attempt.shard_client_after = self->catchup_shard_client_seqno();
    LOG(INFO) << "startup catch-up attempt " << accounting.attempts() + 1 << ": masterchain "
              << attempt.masterchain_before << " -> " << attempt.masterchain_after << ", shard client "
              << attempt.shard_client_before << " -> " << attempt.shard_client_after
              << (attempt.errored ? ", error: " + last_error.to_string() : std::string());
    if (accounting.record(attempt) == AfterAttempt::Continue) {
      continue;
    }
    self->catchup_phase(Phase::Discovering);
    auto rediscovered = co_await discover_successor(self);
    switch (accounting.after_rediscovery(rediscovered.verified)) {
      case AfterRediscovery::ExitNoVerifiedSuccessor:
        co_return ExitReason::NoVerifiedSuccessor;
      case AfterRediscovery::ExitAbandoned:
        LOG(WARNING) << "startup catch-up abandoned after " << accounting.attempts() << " attempts ("
                     << accounting.consecutive_failures() << " consecutive without progress); last error: "
                     << (last_error.is_error() ? last_error.to_string() : std::string("none"))
                     << "; frontier: masterchain " << self->catchup_masterchain_seqno() << ", shard client "
                     << self->catchup_shard_client_seqno();
        co_return ExitReason::Abandoned;
      case AfterRediscovery::Retry:
        break;
    }
    co_await self->catchup_sleep(kRetryDelaySeconds);
  }
}

}  // namespace tos::validator::startup_catchup
