/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <cstring>

#include "td/actor/SharedFuture.h"
#include "td/actor/coro_task.h"
#include "td/actor/coro_utils.h"
#include "td/utils/CancellationToken.h"
#include "validator/measurement/measurement-contract.h"

#include "bus.h"
#include "stats.h"

namespace tos::validator::consensus {

namespace {

measurement::TraceId measurement_trace_id(const CandidateId& id) {
  measurement::TraceId result{};
  std::memcpy(result.data(), id.hash.data(), result.size());
  return result;
}

class BlockProducerImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator();
  }

  void start_up() {
    target_rate_ = owning_bus()->config.noncritical_params.target_rate;
    no_empty_blocks_on_error_timeout_ = owning_bus()->config.noncritical_params.no_empty_blocks_on_error_timeout;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const NoncriticalParamsUpdated> event) {
    target_rate_ = event->params.target_rate;
    no_empty_blocks_on_error_timeout_ = event->params.no_empty_blocks_on_error_timeout;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const Start> event) {
    td::uint32 seqno = event->state->next_seqno() - 1;
    last_mc_finalized_seqno_ = std::max(last_mc_finalized_seqno_, seqno);
    last_consensus_finalized_seqno_ = std::max(last_consensus_finalized_seqno_, seqno);
    last_consensus_finalized_at_ = td::Timestamp::now();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizationBacklog> event) {
    // Finality can catch up, and when it does this group produces again.
    finality_behind_ = event->over_limit;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    current_leader_window_ = std::nullopt;
    cancellation_source_.cancel();
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizeBlock> event) {
    if (event->signatures->is_final()) {
      last_consensus_finalized_seqno_ = std::max(last_consensus_finalized_seqno_, event->candidate->block_id().seqno());
      last_consensus_finalized_at_ = td::Timestamp::now();
    }
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const OurLeaderWindowStarted> event) {
    CHECK(current_leader_window_ < event->start_slot);

    current_leader_window_ = event->start_slot;
    cancellation_source_ = td::CancellationTokenSource();
    generate_candidates(event).start().detach();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const BlockFinalizedInMasterchain> event) {
    last_mc_finalized_seqno_ = std::max(event->block.seqno(), last_mc_finalized_seqno_);
    last_consensus_finalized_seqno_ = std::max(last_mc_finalized_seqno_, last_consensus_finalized_seqno_);
  }

 private:
  bool should_generate_empty_block(const ChainStateRef& state) {
    if (state->is_before_split()) {
      return true;
    }
    if (owning_bus()->shard.is_masterchain()) {
      return last_consensus_finalized_seqno_ + 1 < state->next_seqno();
    } else {
      return last_mc_finalized_seqno_ + 8 < state->next_seqno();
    }
  }

  td::actor::Task<> generate_candidates(std::shared_ptr<const OurLeaderWindowStarted> event) {
    auto& bus = *owning_bus();

    auto window = current_leader_window_;
    if (window == std::nullopt) {
      co_return td::Unit{};
    }

    ChainStateRef state = event->state;
    ParentId parent = event->base;
    bool block_generation_active = false;
    td::actor::SharedFuture<GeneratedCandidate> block_generation;
    // External messages already taken by the candidates of this window. The pool keeps them until
    // their block is applied, so each later slot must skip them rather than refuse them.
    td::PersistentTreap<td::Bits256, td::Unit> processed_external_messages;

    std::chrono::milliseconds hard_timeout = std::max(target_rate_ * 3, std::chrono::milliseconds(60'000));
    std::chrono::milliseconds start_collate_before =
        bus.shard.is_masterchain() ? std::chrono::milliseconds(0) : target_rate_;
    td::Timestamp slot_start = event->start_time;

    std::optional<tos::health::ActionObservation> observation;

    for (td::uint32 slot = event->start_slot; current_leader_window_ == window && slot < event->end_slot; ++slot) {
      if (!observation) {
        const tos::health::ActionLedger::Key key{tos::health::Action::Proposal, tos::health::Origin::Live, slot, {}};
        observation.emplace(tos::health::Action::Proposal, tos::health::Origin::Live, tos::health::consensus_stats,
                            &bus.health_session.proposal_ledger, &key);
      }
      if (finality_behind_) {
        observation->finish(tos::health::Phase::FinalitySuppressed);
        break;
      }
      co_await td::actor::coro_sleep(slot_start - start_collate_before);
      if (current_leader_window_ != window) {
        observation->finish(tos::health::Phase::Superseded);
        break;
      }
      bool is_first_block = !parent.has_value();
      if (!block_generation_active && (!should_generate_empty_block(state) || is_first_block)) {
        block_generation_active = true;
        CollateParams params{
            .shard = bus.shard,
            .min_masterchain_block_id = state->min_mc_block_id(),
            .prev = state->block_ids(),
            .creator = bus.local_id->validator_id,
            .skip_store_candidate = true,
            .utime = slot_start.at_unix(),
            .hard_timeout = slot_start + hard_timeout,
            .prev_block_data = state->block_data(),
            .prev_block_state_roots = state->state(),
            .processed_external_messages = processed_external_messages,
        };
        if (bus.shard.is_masterchain()) {
          params.soft_timeout = slot_start + target_rate_;
        } else {
          params.soft_timeout = slot_start;
          params.wait_externals_until = slot_start;
        }
        block_generation = td::actor::ask(bus.manager, &ManagerFacade::collate_block, std::move(params),
                                          cancellation_source_.get_cancellation_token());
        owning_bus().publish<TraceEvent>(stats::CollateStarted::create(slot));
      }
      co_await td::actor::coro_sleep(slot_start);

      std::optional<GeneratedCandidate> generated_candidate;
      if (block_generation_active) {
        auto r_candidate =
            co_await td::actor::await_with_timeout(block_generation.get(), slot_start + target_rate_).wrap();
        // The first block in the session cannot be empty
        bool allow_empty =
            !is_first_block && !(last_consensus_finalized_at_ + no_empty_blocks_on_error_timeout_).is_in_past();
        if (r_candidate.is_error() && !allow_empty) {
          observation->observe(tos::health::Phase::Retry);
          LOG(WARNING) << "Generating the first block: "
                       << (r_candidate.error().code() == td::actor::AWAIT_TIMEOUT_CODE
                               ? "takes too long"
                               : r_candidate.error().to_string())
                       << ", don't generate empty block "
                       << (is_first_block ? "(first block)" : "(no finalized blocks for too long)");
          --slot;
          if (r_candidate.error().code() != td::actor::AWAIT_TIMEOUT_CODE) {
            block_generation_active = false;
            co_await td::actor::coro_sleep(td::Timestamp::in(0.1));
          }
          slot_start = std::max(slot_start, td::Timestamp::now());
          continue;
        }
        if (r_candidate.is_ok()) {
          generated_candidate = r_candidate.move_as_ok();
          block_generation_active = false;
        } else if (r_candidate.error().code() == td::actor::AWAIT_TIMEOUT_CODE) {
          generated_candidate = std::nullopt;
          LOG(WARNING) << "Generating an empty block for slot " << slot << ": block collation takes too long";
        } else {
          generated_candidate = std::nullopt;
          LOG(WARNING) << "Generating an empty block for slot " << slot << ": collation error: " << r_candidate.error();
          block_generation_active = false;
        }
      } else {
        generated_candidate = std::nullopt;
        LOG(WARNING) << "Generating an empty block for slot " << slot << ": new_seqno=" << state->next_seqno()
                     << ", last_consensus_finalized_seqno_=" << last_consensus_finalized_seqno_
                     << ", last_mc_finalized_seqno_=" << last_mc_finalized_seqno_
                     << ", before_split=" << state->is_before_split();
      }
      if (current_leader_window_ != window) {
        observation->finish(tos::health::Phase::Superseded);
        break;
      }

      CandidateId id;
      std::variant<BlockIdExt, BlockCandidate> block;
      std::optional<adnl::AdnlNodeIdShort> collator;
      if (generated_candidate.has_value()) {
        td::actor::send_closure(bus.manager, &ManagerFacade::cache_block_candidate,
                                generated_candidate->candidate.clone());
        // ChainState::apply crashes (LOG_CHECK / move_as_ok / LOG(FATAL)) on a
        // malformed candidate. That is safe only because this candidate is
        // self-collated by this node's own Collator (bridge.cpp collate_block,
        // self_collated=true): CollationManager remote routing is future work
        // (V-022) and the legacy remote-collation path is fail-closed. If an
        // untrusted, collator-supplied candidate is ever routed here, it must
        // be fully validated (or apply made fail-soft) before this call.
        state = state->apply(generated_candidate->candidate);
        processed_external_messages = generated_candidate->processed_external_messages;
        block = std::move(generated_candidate->candidate);
        if (!generated_candidate->collator_node_id.is_zero()) {
          collator = adnl::AdnlNodeIdShort{generated_candidate->collator_node_id};
        }
        id = CandidateHashData::create_full(generated_candidate->candidate, parent).build_id_with(slot);
        owning_bus().publish<TraceEvent>(stats::CollateFinished::create(slot, id));
      } else {
        CHECK(parent.has_value());
        observation->observe(tos::health::Phase::Empty);
        auto referenced_block = state->assert_normal();
        block = referenced_block;
        id = CandidateHashData::create_empty(referenced_block, *parent).build_id_with(slot);
        owning_bus().publish<TraceEvent>(stats::CollatedEmpty::create(id));
      }

      // With an own-decision log, a leader window is recorded there before its first
      // candidate is signed, and only the runtime that recorded it produces in it. A window
      // already in the log when this runtime started was produced in by an earlier one; a
      // candidate now could differ from what that one signed, so this runtime forfeits it.
      if (const auto& admission = bus.signing_admission) {
        const td::uint32 window_index = *window / bus.config.slots_per_leader_window;
        if (admission->signing_stopped()) {
          observation->finish(tos::health::Phase::JournalSuppressed);
          LOG(WARNING) << "consensus: the decision log admits no signing in this session; no candidate for slot "
                       << slot;
          break;
        }
        if (recorded_window_ != window_index) {
          if (admission->leader_window_recorded(window_index)) {
            observation->finish(tos::health::Phase::JournalSuppressed);
            LOG(WARNING) << "consensus: leader window " << window_index
                         << " was recorded before this restart; producing nothing in it";
            break;
          }
          auto reserved = co_await td::actor::ask(
                              admission->log, &signing::SessionDecisionLog::reserve,
                              signing::Decision{signing::DecisionKind::LeaderWindow, window_index, td::Bits256::zero()})
                              .wrap();
          // Only a reservation made now grants this runtime the window: an answer that it
          // was already decided means another runtime made it.
          if (reserved.is_error() || reserved.ok().result != signing::ReserveResult::Reserved) {
            observation->finish(tos::health::Phase::IntentFailure);
            LOG(WARNING) << "consensus: leader window " << window_index
                         << " was not recorded in the decision log; producing nothing in it";
            break;
          }
          recorded_window_ = window_index;
        }
        if (current_leader_window_ != window) {
          observation->finish(tos::health::Phase::Superseded);
          break;
        }
        if (finality_behind_) {
          observation->finish(tos::health::Phase::FinalitySuppressed);
          break;
        }
      }

      auto id_to_sign = serialize_tl_object(id.to_tl(), true);
      auto data_to_sign = create_serialize_tl_object<tl::dataToSign>(bus.session_id, std::move(id_to_sign));
      // Signed by the node's custodied post-quantum consensus key, under the frozen
      // simplex_sign_context, never the network keyring. Fail closed: with no signer or a
      // signing failure, stop producing rather than emit an unsigned or classical candidate.
      if (bus.pq_signer == nullptr) {
        observation->finish(tos::health::Phase::MissingSigner);
        LOG(ERROR) << "consensus: no post-quantum consensus signer; not producing a candidate";
        break;
      }
      // Checked again immediately before signing, with no suspension in between: the session's
      // decision log may have stopped while the window reservation above was waiting.
      if (bus.signing_admission && bus.signing_admission->signing_stopped()) {
        observation->finish(tos::health::Phase::JournalSuppressed);
        LOG(WARNING) << "consensus: the decision log stopped before the candidate for slot " << slot
                     << " was signed; not producing it";
        break;
      }
      const auto to_sign = data_to_sign.as_slice();
      auto pq_signature = bus.pq_signer->sign_consensus(std::string_view(to_sign.data(), to_sign.size()));
      if (!pq_signature.has_value()) {
        observation->finish(tos::health::Phase::SignFailure);
        LOG(ERROR) << "consensus: the post-quantum signer failed to sign a candidate; not producing it"
                   << (bus.pq_signer->expired_now() ? " (the consensus key has expired)" : "");
        break;
      }
      observation->observe(tos::health::Phase::Signed);
      td::BufferSlice signature(pq_signature->signature);
      auto candidate = td::make_ref<Candidate>(id, parent, bus.local_id->idx, std::move(block), std::move(signature));
      if (current_leader_window_ != window) {
        observation->finish(tos::health::Phase::Superseded);
        break;
      }
      if (finality_behind_) {
        observation->finish(tos::health::Phase::FinalitySuppressed);
        // Collation began before the round stopped taking candidates. Publishing now would
        // put one into a round that has stopped, or add to a finality backlog nothing is
        // draining.
        break;
      }
      measurement::record_trace_lazy([&] { return measurement_trace_id(candidate->id); },
                                     measurement::TraceStage::candidate_generated);
      owning_bus().publish<CandidateGenerated>(candidate, collator);
      observation->observe(tos::health::Phase::CandidatePublished);
      owning_bus().publish<CandidateReceived>(candidate);
      owning_bus().publish<TraceEvent>(stats::CandidateReceived::create(candidate, true));
      parent = id;

      observation->finish();
      observation.reset();
      bus.health_session.proposal_ledger.retire_before(slot);

      slot_start += target_rate_;
    }

    if (current_leader_window_ == window) {
      current_leader_window_ = std::nullopt;
    }

    co_return td::Unit{};
  }

  std::optional<td::uint32> current_leader_window_;
  // The leader window (an ordinal) this runtime recorded in the decision log, and so may
  // produce candidates in. Windows only move forward, so one is enough.
  std::optional<td::uint32> recorded_window_;
  td::CancellationTokenSource cancellation_source_;

  // Set while more agreed certificates are waiting to be finalized than the resolver will
  // hold. Producing more would add to a pile nothing is draining.
  bool finality_behind_ = false;

  BlockSeqno last_consensus_finalized_seqno_ = 0;
  BlockSeqno last_mc_finalized_seqno_ = 0;
  std::chrono::milliseconds target_rate_;

  std::chrono::milliseconds no_empty_blocks_on_error_timeout_;
  td::Timestamp last_consensus_finalized_at_;
};

}  // namespace

void BlockProducer::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<BlockProducerImpl>("BlockProducer");
}

}  // namespace tos::validator::consensus
