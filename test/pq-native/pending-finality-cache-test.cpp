#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "block/mc-config.h"
#include "validator/finality-cache-policy.h"
#include "validator/full-node-serializer.hpp"
#include "validator/pending-finality-ingress.h"

#include "pq-block-signature-test-common.h"

namespace {

using pq_block_signature_test::candidate;
using pq_block_signature_test::clone_pairs;
using pq_block_signature_test::Fixture;
using pq_block_signature_test::require_ok;
using tos::validator::PendingFinalityCapacity;

constexpr auto SharedCapacity = PendingFinalityCapacity::Shared;
constexpr auto ValidatorCapacity = PendingFinalityCapacity::ValidatorReserved;
constexpr auto NoExpiry = tos::validator::pending_finality_no_expiry;

struct ProcessingResult {
  bool accepted{false};
  std::vector<const block::BlockSignatureSet *> attempted;
};

ProcessingResult process_finality_candidates(const std::vector<td::Ref<block::BlockSignatureSet>> &arrivals,
                                             const block::PQFinalityVerificationContext &context) {
  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> store;
  int sender = 0;
  for (const auto &signature_set : arrivals) {
    auto serialized_bytes = serialize_tl_object(signature_set->tl(), true).size();
    if (!store.admit(0, sender++, signature_set, serialized_bytes, SharedCapacity, false, true, NoExpiry).admitted()) {
      return {};
    }
  }
  auto *candidates = store.get_if_exists(0);
  ProcessingResult result;
  while (auto candidate = candidates->begin_processing(0)) {
    result.attempted.push_back(candidate->evidence.get());
    bool accepted = block::verify_pq_finality(context, *candidate->evidence, block::FinalityRole::Final).is_ok();
    candidates->complete_front(candidate.token, accepted);
    if (accepted) {
      result.accepted = true;
      return result;
    }
  }
  return result;
}

block::ShardConfig make_split_shard_config(tos::CatchainSeqno catchain_seqno, tos::ShardIdFull &real_shard,
                                           tos::ShardIdFull &deeper_shard) {
  auto make_leaf = [&](tos::ShardIdFull shard, unsigned seqno, const char *label) {
    auto root_hash = pq_block_signature_test::hash_of(std::string(label) + "-root");
    auto file_hash = pq_block_signature_test::hash_of(std::string(label) + "-file");
    td::Ref<block::McShardHash> descriptor{true,
                                           tos::BlockId{shard, seqno},
                                           1,
                                           2,
                                           1,
                                           root_hash,
                                           file_hash,
                                           block::CurrencyCollection{},
                                           block::CurrencyCollection{},
                                           1,
                                           1,
                                           catchain_seqno,
                                           shard.shard};
    vm::CellBuilder builder;
    td::Ref<vm::Cell> leaf;
    if (!builder.store_bool_bool(false) || !descriptor->pack(builder) || !builder.finalize_to(leaf)) {
      std::cerr << "PENDING_FINALITY_SHARD_WINDOW_FIXTURE_FAILURE: could not build shard leaf\n";
      std::exit(1);
    }
    return leaf;
  };

  auto all = tos::ShardIdFull{tos::basechainId, tos::shardIdAll};
  auto left = tos::shard_child(all, true);
  real_shard = tos::shard_child(all, false);
  deeper_shard = tos::shard_child(real_shard, true);
  auto left_leaf = make_leaf(left, 10, "left");
  auto right_leaf = make_leaf(real_shard, 11, "right");
  vm::CellBuilder branch_builder;
  td::Ref<vm::Cell> branch;
  if (!branch_builder.store_bool_bool(true) || !branch_builder.store_ref_bool(std::move(left_leaf)) ||
      !branch_builder.store_ref_bool(std::move(right_leaf)) || !branch_builder.finalize_to(branch)) {
    std::cerr << "PENDING_FINALITY_SHARD_WINDOW_FIXTURE_FAILURE: could not build split shard tree\n";
    std::exit(1);
  }
  vm::Dictionary dictionary{32};
  if (!dictionary.set_ref(td::BitArray<32>{tos::basechainId}, std::move(branch), vm::Dictionary::SetMode::Add)) {
    std::cerr << "PENDING_FINALITY_SHARD_WINDOW_FIXTURE_FAILURE: could not build shard dictionary\n";
    std::exit(1);
  }
  return block::ShardConfig{dictionary.get_root_cell()};
}

}  // namespace

int main() {
  constexpr std::array ingress_rejection_names{
      std::pair{tos::validator::PendingFinalityIngressRejection::None, "none"},
      std::pair{tos::validator::PendingFinalityIngressRejection::MissingRemoteByteCount, "missing_remote_byte_count"},
      std::pair{tos::validator::PendingFinalityIngressRejection::MissingLocalMeasurement, "missing_local_measurement"},
  };
  for (const auto &[rejection, expected] : ingress_rejection_names) {
    if (std::string_view{tos::validator::pending_finality_ingress_rejection_name(rejection)} != expected) {
      std::cerr << "PENDING_FINALITY_REJECTION_NAME_FAILURE: ingress rejection lost its stable name\n";
      return 1;
    }
  }
  constexpr std::array store_rejection_names{
      std::pair{tos::validator::PendingFinalityRejection::None, "none"},
      std::pair{tos::validator::PendingFinalityRejection::Policy, "policy"},
      std::pair{tos::validator::PendingFinalityRejection::SenderAlreadyPending, "sender_already_pending"},
      std::pair{tos::validator::PendingFinalityRejection::SenderBudget, "sender_budget"},
      std::pair{tos::validator::PendingFinalityRejection::SharedBudget, "shared_budget"},
      std::pair{tos::validator::PendingFinalityRejection::ValidatorReservedBudget, "validator_reserved_budget"},
  };
  for (const auto &[rejection, expected] : store_rejection_names) {
    if (std::string_view{tos::validator::pending_finality_rejection_name(rejection)} != expected) {
      std::cerr << "PENDING_FINALITY_REJECTION_NAME_FAILURE: store rejection lost its stable name\n";
      return 1;
    }
  }
  if (tos::validator::pending_finality_failure_action(tos::ErrorCode::timeout, 0, 60) !=
      tos::validator::PendingFinalityFailureAction::Retry) {
    std::cerr << "PENDING_FINALITY_TIMEOUT_CLASSIFICATION_FAILURE: verification timeout was treated as permanent\n";
    return 1;
  }
  if (!tos::validator::pending_finality_exceeds_budget(0, std::numeric_limits<std::size_t>::max(), 0, 10)) {
    std::cerr
        << "PENDING_FINALITY_BUDGET_ARITHMETIC_FAILURE: removed bytes exceeded current accounting without rejection\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> permanent_failure;
  permanent_failure.admit(0, 0, 7, 4096, SharedCapacity, false, true, NoExpiry);
  auto *permanent_candidates = permanent_failure.get_if_exists(0);
  auto permanent_attempt = permanent_candidates->begin_processing(0);
  if (!permanent_attempt ||
      permanent_candidates->resolve_front_failure(permanent_attempt.token, tos::ErrorCode::protoviolation, 0).action !=
          tos::validator::PendingFinalityFailureAction::DiscardPermanent ||
      !permanent_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_PERMANENT_FAILURE: inconsistent evidence was retained for retry\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> expired_failure;
  expired_failure.admit(0, 0, 7, 4096, SharedCapacity, false, true, tos::validator::pending_finality_retention_seconds);
  auto *expired_candidates = expired_failure.get_if_exists(0);
  double retry_time = 0;
  while (retry_time < tos::validator::pending_finality_retention_seconds) {
    auto attempt = expired_candidates->begin_processing(retry_time);
    if (!attempt) {
      std::cerr << "PENDING_FINALITY_RETRY_DEADLINE_FAILURE: candidate was unavailable at its scheduled retry\n";
      return 1;
    }
    auto failure = expired_candidates->resolve_front_failure(attempt.token, tos::ErrorCode::notready, retry_time);
    if (failure.action != tos::validator::PendingFinalityFailureAction::Retry || failure.retry_at <= retry_time ||
        failure.retry_at > tos::validator::pending_finality_retention_seconds) {
      std::cerr << "PENDING_FINALITY_RETRY_DEADLINE_FAILURE: backoff escaped the retention deadline\n";
      return 1;
    }
    retry_time = failure.retry_at;
  }
  if (expired_failure.erase_expired(retry_time) != 1 || expired_failure.get_if_exists(0) != nullptr ||
      tos::validator::pending_finality_failure_action(tos::ErrorCode::notready, retry_time, retry_time) !=
          tos::validator::PendingFinalityFailureAction::DiscardExpired) {
    std::cerr << "PENDING_FINALITY_RETRY_DEADLINE_FAILURE: expired candidate retained its sender slot\n";
    return 1;
  }

  auto check_stale_attempt = [](bool late_success) {
    tos::validator::PendingFinalityStore<int, int, int> store;
    store.admit(0, 10, 1, 4096, SharedCapacity, false, true, 1);
    store.admit(0, 11, 2, 4096, SharedCapacity, false, true, NoExpiry);
    auto *candidates = store.get_if_exists(0);
    auto attempt_a = candidates->begin_processing(0);
    if (!attempt_a || attempt_a->evidence != 1 || candidates->erase_expired(1) != 1) {
      std::cerr << "PENDING_FINALITY_STALE_ATTEMPT_SETUP_FAILURE: could not expire in-flight candidate A\n";
      return false;
    }
    auto attempt_b = candidates->begin_processing(1);
    if (!attempt_b || attempt_b->evidence != 2) {
      std::cerr << "PENDING_FINALITY_STALE_ATTEMPT_SETUP_FAILURE: candidate B did not begin after A expired\n";
      return false;
    }

    bool stale_ignored = false;
    if (late_success) {
      const bool marked = candidates->mark_front_verified(attempt_a.token);
      const bool completed = candidates->complete_front(attempt_a.token, true);
      stale_ignored = !marked && !completed && candidates->size() == 1 && candidates->is_processing(attempt_b.token) &&
                      !attempt_b->verified && attempt_b->evidence == 2;
      if (!stale_ignored) {
        std::cerr << "PENDING_FINALITY_STALE_ATTEMPT_SUCCESS_FAILURE: A's late success mutated candidate B\n";
      }
    } else {
      candidates->resolve_front_failure(attempt_a.token, tos::ErrorCode::protoviolation, 1);
      stale_ignored = candidates->size() == 1 && candidates->is_processing(attempt_b.token) && attempt_b->evidence == 2;
      if (!stale_ignored) {
        std::cerr << "PENDING_FINALITY_STALE_ATTEMPT_PERMANENT_FAILURE: A's late permanent error removed candidate B\n";
      }
    }
    if (!stale_ignored) {
      return false;
    }
    if (!candidates->mark_front_verified(attempt_b.token) || !attempt_b->verified ||
        !candidates->complete_front(attempt_b.token, true) || !candidates->empty()) {
      std::cerr << "PENDING_FINALITY_CURRENT_ATTEMPT_FAILURE: candidate B's own result did not land\n";
      return false;
    }
    return true;
  };
  const bool stale_permanent_ignored = check_stale_attempt(false);
  const bool stale_success_ignored = check_stale_attempt(true);
  if (!stale_permanent_ignored || !stale_success_ignored) {
    return 1;
  }

  auto check_recreated_queue_stale_attempt = [](bool late_success) {
    tos::validator::PendingFinalityStore<int, int, int> store;
    store.admit(0, 10, 1, 4096, SharedCapacity, false, true, 1);
    auto *first_queue = store.get_if_exists(0);
    auto attempt_a = first_queue->begin_processing(0);
    if (!attempt_a || store.erase_expired(1) != 1 || store.get_if_exists(0) != nullptr) {
      std::cerr << "PENDING_FINALITY_QUEUE_REUSE_SETUP_FAILURE: expired queue Q1 was not destroyed\n";
      return false;
    }
    if (!store.admit(0, 11, 2, 4096, SharedCapacity, false, true, NoExpiry).admitted()) {
      std::cerr << "PENDING_FINALITY_QUEUE_REUSE_SETUP_FAILURE: replacement queue Q2 was not created\n";
      return false;
    }
    auto *second_queue = store.get_if_exists(0);
    auto attempt_b = second_queue->begin_processing(1);
    if (!attempt_b || attempt_b->evidence != 2) {
      std::cerr << "PENDING_FINALITY_QUEUE_REUSE_SETUP_FAILURE: candidate B did not begin in Q2\n";
      return false;
    }

    bool stale_ignored = false;
    if (late_success) {
      const bool marked = second_queue->mark_front_verified(attempt_a.token);
      const bool completed = second_queue->complete_front(attempt_a.token, true);
      stale_ignored = !marked && !completed && second_queue->size() == 1 &&
                      second_queue->is_processing(attempt_b.token) && !attempt_b->verified && attempt_b->evidence == 2;
      if (!stale_ignored) {
        std::cerr << "PENDING_FINALITY_QUEUE_REUSE_SUCCESS_FAILURE: Q1's late success mutated Q2 candidate B\n";
      }
    } else {
      second_queue->resolve_front_failure(attempt_a.token, tos::ErrorCode::protoviolation, 1);
      stale_ignored =
          second_queue->size() == 1 && second_queue->is_processing(attempt_b.token) && attempt_b->evidence == 2;
      if (!stale_ignored) {
        std::cerr
            << "PENDING_FINALITY_QUEUE_REUSE_PERMANENT_FAILURE: Q1's late permanent error removed Q2 candidate B\n";
      }
    }
    if (!stale_ignored) {
      return false;
    }
    if (!second_queue->mark_front_verified(attempt_b.token) || !attempt_b->verified ||
        !second_queue->complete_front(attempt_b.token, true) || !second_queue->empty()) {
      std::cerr << "PENDING_FINALITY_QUEUE_REUSE_CURRENT_FAILURE: Q2 candidate B's own result did not land\n";
      return false;
    }
    return true;
  };
  const bool recreated_queue_permanent_ignored = check_recreated_queue_stale_attempt(false);
  const bool recreated_queue_success_ignored = check_recreated_queue_stale_attempt(true);
  if (!recreated_queue_permanent_ignored || !recreated_queue_success_ignored) {
    return 1;
  }

  auto peer = tos::PublicKeyHash::zero();
  auto missing_remote_bytes = tos::validator::prepare_pending_finality_ingress(&peer, 0);
  if (missing_remote_bytes.admitted() ||
      missing_remote_bytes.rejection != tos::validator::PendingFinalityIngressRejection::MissingRemoteByteCount) {
    std::cerr << "PENDING_FINALITY_INGRESS_ACCOUNTING_FAILURE: remote evidence without received bytes was admitted\n";
    return 1;
  }
  auto remote = tos::validator::prepare_pending_finality_ingress(&peer, 12345);
  if (!remote.admitted() || remote.sender.local || remote.sender.peer != peer || remote.accounted_bytes != 12345) {
    std::cerr << "PENDING_FINALITY_INGRESS_SENDER_FAILURE: authenticated peer was not charged to its own sender\n";
    return 1;
  }
  auto missing_local_measurement = tos::validator::prepare_pending_finality_ingress(nullptr, 0);
  if (missing_local_measurement.admitted() ||
      missing_local_measurement.rejection != tos::validator::PendingFinalityIngressRejection::MissingLocalMeasurement) {
    std::cerr << "PENDING_FINALITY_INGRESS_ACCOUNTING_FAILURE: local evidence without a measurement was admitted\n";
    return 1;
  }
  auto local = tos::validator::prepare_pending_finality_ingress(nullptr, 0, 6789);
  if (!local.admitted() || !local.sender.local || local.accounted_bytes != 6789) {
    std::cerr << "PENDING_FINALITY_INGRESS_SENDER_FAILURE: local evidence did not retain its local attribution\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> policy_rejection_check;
  if (!policy_rejection_check.admit(0, 0, 0, 1, ValidatorCapacity, true, true, NoExpiry).admitted() ||
      policy_rejection_check.admit(0, 1, 1, 1, SharedCapacity, false, true, NoExpiry).rejection !=
          tos::validator::PendingFinalityRejection::Policy) {
    std::cerr << "PENDING_FINALITY_POLICY_REJECTION_FAILURE: unverified evidence displaced verified finality\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> sender_budget_check;
  if (!sender_budget_check
           .admit(1, 7, 1, tos::validator::pending_finality_sender_per_block_budget_bytes, SharedCapacity, false, true,
                  NoExpiry)
           .admitted() ||
      !sender_budget_check
           .admit(2, 7, 2, tos::validator::pending_finality_sender_per_block_budget_bytes, SharedCapacity, false, true,
                  NoExpiry)
           .admitted()) {
    std::cerr << "PENDING_FINALITY_PER_BLOCK_SENDER_FAILURE: one sender could not retain maximum-size evidence for two "
                 "blocks\n";
    return 1;
  }
  if (sender_budget_check
          .admit(3, 7, 3, tos::validator::pending_finality_sender_per_block_budget_bytes + 1, SharedCapacity, false,
                 true, NoExpiry)
          .rejection != tos::validator::PendingFinalityRejection::SenderBudget) {
    std::cerr << "PENDING_FINALITY_SENDER_BUDGET_FAILURE: one block exceeded the measured maximum carrier size\n";
    return 1;
  }
  static_assert(tos::validator::pending_finality_sender_global_budget_bytes ==
                tos::validator::pending_finality_sender_global_carrier_shares *
                    block::pq::pq_block_finality_broadcast_max_bytes);
  auto check_sender_monopoly = [](PendingFinalityCapacity capacity, const char *pool_name) {
    tos::validator::PendingFinalityStore<int, int, int> store;
    constexpr int flooding_sender = 700;
    constexpr int honest_sender = 701;
    std::size_t admitted = 0;
    tos::validator::PendingFinalityRejection first_rejection = tos::validator::PendingFinalityRejection::None;
    for (std::size_t block = 0; block <= tos::validator::pending_finality_max_validator_senders; ++block) {
      auto result =
          store.admit(static_cast<int>(block), flooding_sender, static_cast<int>(block),
                      tos::validator::pending_finality_sender_per_block_budget_bytes, capacity, false, true, NoExpiry);
      if (!result.admitted()) {
        first_rejection = result.rejection;
        break;
      }
      ++admitted;
    }

    bool ok = true;
    if (admitted != tos::validator::pending_finality_sender_global_carrier_shares ||
        first_rejection != tos::validator::PendingFinalityRejection::SenderBudget ||
        store.sender_bytes(flooding_sender) != tos::validator::pending_finality_sender_global_budget_bytes) {
      std::cerr << "PENDING_FINALITY_GLOBAL_SENDER_BUDGET_FAILURE: " << pool_name << " sender admitted=" << admitted
                << " rejection=" << tos::validator::pending_finality_rejection_name(first_rejection)
                << " held=" << store.sender_bytes(flooding_sender)
                << " expected_slots=" << tos::validator::pending_finality_sender_global_carrier_shares << "\n";
      ok = false;
    }
    auto honest =
        store.admit(10000, honest_sender, 10000, tos::validator::pending_finality_sender_per_block_budget_bytes,
                    capacity, false, true, NoExpiry);
    if (!honest.admitted()) {
      std::cerr << "PENDING_FINALITY_POOL_MONOPOLY_FAILURE: " << pool_name
                << " sender prevented honest sender after reaching its global share; rejection="
                << tos::validator::pending_finality_rejection_name(honest.rejection) << "\n";
      ok = false;
    }
    return ok;
  };
  const bool public_monopoly_blocked = check_sender_monopoly(SharedCapacity, "public");
  const bool validator_monopoly_blocked = check_sender_monopoly(ValidatorCapacity, "validator");
  if (!public_monopoly_blocked || !validator_monopoly_blocked) {
    return 1;
  }
  tos::validator::PendingFinalityStore<int, int, int> total_budget_check;
  static_assert(tos::validator::pending_finality_public_budget_bytes ==
                tos::validator::pending_finality_public_candidate_slots *
                    block::pq::pq_block_finality_broadcast_max_bytes);
  static_assert(tos::validator::pending_finality_validator_reserved_budget_bytes ==
                tos::validator::pending_finality_max_validator_senders *
                    block::pq::pq_block_finality_broadcast_max_bytes);
  constexpr auto public_sender_shares = tos::validator::pending_finality_public_candidate_slots;
  for (std::size_t i = 0; i < public_sender_shares; ++i) {
    if (!total_budget_check
             .admit(static_cast<int>(i), static_cast<int>(i), static_cast<int>(i),
                    tos::validator::pending_finality_sender_per_block_budget_bytes, SharedCapacity, false, true,
                    NoExpiry)
             .admitted()) {
      std::cerr << "PENDING_FINALITY_TOTAL_BUDGET_FAILURE: a public peer lost its shared-pool allowance\n";
      return 1;
    }
  }
  if (total_budget_check
          .admit(1000, 1000, 1000, tos::validator::pending_finality_minimum_charge_bytes, SharedCapacity, false, true,
                 NoExpiry)
          .rejection != tos::validator::PendingFinalityRejection::SharedBudget) {
    std::cerr << "PENDING_FINALITY_PUBLIC_BUDGET_FAILURE: public peers exceeded their 16777216-byte shared pool\n";
    return 1;
  }
  if (!total_budget_check
           .admit(2000, 2000, 1, tos::validator::pending_finality_sender_per_block_budget_bytes, ValidatorCapacity,
                  false, true, NoExpiry)
           .admitted()) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_RESERVATION_FAILURE: non-validator peers exhausted validator reserved "
                 "capacity\n";
    return 1;
  }
  tos::validator::PendingFinalityStore<int, int, int> reserved_budget_check;
  for (std::size_t i = 0; i < tos::validator::pending_finality_max_validator_senders; ++i) {
    if (!reserved_budget_check
             .admit(static_cast<int>(i), static_cast<int>(i), static_cast<int>(i),
                    tos::validator::pending_finality_sender_per_block_budget_bytes, ValidatorCapacity, false, true,
                    NoExpiry)
             .admitted()) {
      std::cerr << "PENDING_FINALITY_VALIDATOR_BUDGET_FAILURE: a committee authority lost its reserved share\n";
      return 1;
    }
  }
  if (reserved_budget_check
          .admit(1001, 1001, 1001, tos::validator::pending_finality_minimum_charge_bytes, ValidatorCapacity, false,
                 true, NoExpiry)
          .rejection != tos::validator::PendingFinalityRejection::ValidatorReservedBudget) {
    std::cerr << "PENDING_FINALITY_VALIDATOR_BUDGET_FAILURE: committee evidence exceeded its exact 400-carrier pool\n";
    return 1;
  }

  Fixture fixture;
  auto validator_descriptors = fixture.validator_set->export_vector();
  auto validator_peer = tos::validator::validator_transport_root(validator_descriptors.front());
  auto unrelated_peer = tos::PublicKeyHash{pq_block_signature_test::hash_of("unrelated-public-overlay-peer")};
  if (!tos::validator::pending_finality_sender_is_validator(
          tos::validator::PendingBlockFinalitySender::remote(validator_peer), validator_descriptors) ||
      tos::validator::pending_finality_sender_is_validator(
          tos::validator::PendingBlockFinalitySender::remote(unrelated_peer), validator_descriptors)) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_CLASSIFICATION_FAILURE: transport sender was assigned to the wrong pool\n";
    return 1;
  }
  tos::validator::PendingFinalityAuthorityMemo authority_memo;
  const auto current_catchain_seqno = fixture.validator_set->get_catchain_seqno();
  const auto validator_set_hash = fixture.validator_set->get_validator_set_hash();
  tos::validator::PendingFinalityAuthorityMemo classical_authority_memo;
  std::size_t classical_authority_computations = 0;
  auto classical_loader = [&] {
    ++classical_authority_computations;
    return std::vector<tos::validator::PendingFinalityAuthoritySet>{
        {validator_set_hash, {validator_peer}, fixture.validator_set}};
  };
  const auto &classical_sets =
      classical_authority_memo.get({fixture.id.shard_full(), current_catchain_seqno}, classical_loader);
  if (classical_sets.size() != 1 || classical_sets.front().validator_set != fixture.validator_set ||
      !classical_authority_memo.contains({fixture.id.shard_full(), current_catchain_seqno}, validator_set_hash,
                                         validator_peer, classical_loader) ||
      classical_authority_computations != 1) {
    std::cerr << "PENDING_FINALITY_CLASSICAL_MEMO_FAILURE: authority and classical verification did not share one "
                 "validator-set computation\n";
    return 1;
  }

  tos::ShardIdFull real_shard;
  tos::ShardIdFull deeper_shard;
  auto split_shards = make_split_shard_config(current_catchain_seqno, real_shard, deeper_shard);
  auto inherited_catchain_seqno = split_shards.get_shard_cc_seqno(deeper_shard);
  auto exact_deeper_shard = split_shards.get_shard_hash(deeper_shard, true);
  if (inherited_catchain_seqno != current_catchain_seqno || exact_deeper_shard.not_null()) {
    std::cerr << "PENDING_FINALITY_SHARD_WINDOW_FIXTURE_FAILURE: deeper non-existent shard did not inherit only the "
                 "containing shard's catchain coordinate\n";
    return 1;
  }
  if (tos::validator::pending_finality_coordinate_is_admissible(exact_deeper_shard.not_null(), inherited_catchain_seqno,
                                                                current_catchain_seqno)) {
    std::cerr << "PENDING_FINALITY_DEEP_SHARD_WINDOW_FAILURE: non-existent descendant shard reached validator-set "
                 "computation\n";
    return 1;
  }
  std::size_t authority_computations = 0;
  for (int i = 0; i < 64; ++i) {
    auto claimed_catchain_seqno = static_cast<tos::CatchainSeqno>(current_catchain_seqno + (i % 3));
    auto claimed_validator_set_hash = static_cast<td::uint32>(validator_set_hash + i);
    bool classified = tos::validator::pending_finality_sender_is_validator(
        authority_memo, fixture.id.shard_full(), current_catchain_seqno, claimed_catchain_seqno,
        claimed_validator_set_hash, validator_peer, [&] {
          ++authority_computations;
          return std::vector<tos::validator::PendingFinalityAuthoritySet>{{validator_set_hash, {validator_peer}, {}}};
        });
    if (classified != (i == 0)) {
      std::cerr << "PENDING_FINALITY_AUTHORITY_MEMO_FAILURE: attacker-controlled coordinates changed authority\n";
      return 1;
    }
  }
  if (authority_computations != 2 || authority_memo.size() != 2) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_MEMO_FAILURE: 64 cycled claims computed the validator set "
              << authority_computations << " times\n";
    return 1;
  }

  tos::validator::PendingFinalityAuthorityMemo bounded_authority_memo;
  std::size_t bounded_authority_computations = 0;
  constexpr auto cycled_shard_count = tos::validator::pending_finality_authority_memo_max_entries + 4;
  for (std::size_t i = 0; i < cycled_shard_count; ++i) {
    auto shard = tos::ShardIdFull{tos::basechainId, tos::shardIdAll - static_cast<tos::ShardId>(i * 2)};
    for (int repeat = 0; repeat < 2; ++repeat) {
      tos::validator::pending_finality_sender_is_validator(
          bounded_authority_memo, shard, current_catchain_seqno, current_catchain_seqno, validator_set_hash,
          validator_peer, [&] {
            ++bounded_authority_computations;
            return std::vector<tos::validator::PendingFinalityAuthoritySet>{{validator_set_hash, {validator_peer}, {}}};
          });
    }
  }
  if (bounded_authority_computations != cycled_shard_count ||
      bounded_authority_memo.size() > tos::validator::pending_finality_authority_memo_max_entries) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_MEMO_BOUND_FAILURE: cycled " << cycled_shard_count
              << " shard coordinates caused computations=" << bounded_authority_computations
              << " entries=" << bounded_authority_memo.size()
              << " cap=" << tos::validator::pending_finality_authority_memo_max_entries << "\n";
    return 1;
  }
  authority_memo.clear();
  tos::validator::pending_finality_sender_is_validator(
      authority_memo, fixture.id.shard_full(), current_catchain_seqno, current_catchain_seqno, validator_set_hash,
      validator_peer, [&] {
        ++authority_computations;
        return std::vector<tos::validator::PendingFinalityAuthoritySet>{{validator_set_hash, {validator_peer}, {}}};
      });
  if (authority_computations != 3) {
    std::cerr
        << "PENDING_FINALITY_AUTHORITY_MEMO_FAILURE: trusted-state invalidation retained a stale classification\n";
    return 1;
  }

  constexpr std::size_t measured_validator_count = 400;
  block::TotalValidatorSet measured_set(0, 1, measured_validator_count, measured_validator_count);
  measured_set.list.reserve(measured_validator_count);
  for (std::size_t i = 0; i < measured_validator_count; ++i) {
    auto identity = pq_block_signature_test::hash_of("classification-validator-" + std::to_string(i));
    auto key_id = pq_block_signature_test::hash_of("classification-key-" + std::to_string(i));
    auto adnl = pq_block_signature_test::hash_of("classification-adnl-" + std::to_string(i));
    measured_set.list.emplace_back(tos::ValidatorId{identity}, 1, tos::ConsensusKeyId{key_id},
                                   std::string(tos::pq::mldsa44_public_key_bytes, static_cast<char>(i)), 1, i, adnl);
  }
  measured_set.total_weight = measured_validator_count;
  block::CatchainValidatorsConfig measured_config(0, 0, 0, measured_validator_count);
  constexpr std::size_t measurement_iterations = 20;
  std::size_t measured_outputs = 0;
  auto measurement_started = std::chrono::steady_clock::now();
  for (std::size_t i = 0; i < measurement_iterations; ++i) {
    measured_outputs +=
        block::Config::do_compute_validator_set(measured_config, tos::ShardIdFull{tos::basechainId, tos::shardIdAll},
                                                measured_set, static_cast<tos::CatchainSeqno>(i))
            .size();
  }
  auto measurement_elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - measurement_started);
  if (measured_outputs != measured_validator_count * measurement_iterations) {
    std::cerr
        << "PENDING_FINALITY_CLASSIFICATION_MEASUREMENT_FAILURE: validator-set computation returned the wrong size\n";
    return 1;
  }
  auto measured_microseconds = measurement_elapsed.count() / measurement_iterations;
  auto candidate_data = candidate(fixture.id);
  const std::vector<std::size_t> quorum_signers{0, 1};
  auto valid_pairs = fixture.sign(quorum_signers, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto weight = fixture.weight_of(quorum_signers);
  auto valid = require_ok(fixture.persisted_final(valid_pairs, fixture.session, Fixture::slot, candidate_data, weight,
                                                  fixture.validator_set->get_validator_set_hash(),
                                                  fixture.validator_set->get_catchain_seqno(), fixture.validator_set),
                          "valid-final");
  auto invalid_pairs = clone_pairs(valid_pairs);
  invalid_pairs.front().signature.data()[0] ^= 1;
  auto invalid = require_ok(fixture.persisted_final(invalid_pairs, fixture.session, Fixture::slot, candidate_data,
                                                    weight, fixture.validator_set->get_validator_set_hash(),
                                                    fixture.validator_set->get_catchain_seqno(), fixture.validator_set),
                            "invalid-final");
  auto valid_transport_id = tos::validator::fullnode::block_finality_broadcast_transport_id({fixture.id, valid});
  auto invalid_transport_id = tos::validator::fullnode::block_finality_broadcast_transport_id({fixture.id, invalid});
  if (valid_transport_id == invalid_transport_id) {
    std::cerr
        << "PENDING_FINALITY_TRANSPORT_DEDUP_FAILURE: invalid finality occupied the honest finality transport id\n";
    return 1;
  }
  const block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};

  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> authority_reservation_gate;
  for (std::size_t i = 0; i < public_sender_shares; ++i) {
    if (!authority_reservation_gate
             .admit(static_cast<int>(i), static_cast<int>(i), invalid,
                    tos::validator::pending_finality_sender_per_block_budget_bytes, SharedCapacity, false, true,
                    NoExpiry)
             .admitted()) {
      std::cerr << "PENDING_FINALITY_AUTHORITY_RESERVATION_FAILURE: public peers did not fill their shared pool\n";
      return 1;
    }
  }
  if (!authority_reservation_gate
           .admit(100, 100, valid, tos::validator::pending_finality_sender_per_block_budget_bytes, ValidatorCapacity,
                  false, true, NoExpiry)
           .admitted()) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_RESERVATION_FAILURE: non-validator peers exhausted validator reserved "
                 "capacity\n";
    return 1;
  }
  auto reserved_candidate = authority_reservation_gate.get_if_exists(100)->begin_processing(0);
  if (reserved_candidate == nullptr ||
      block::verify_pq_finality(context, *reserved_candidate->evidence, block::FinalityRole::Final).is_error()) {
    std::cerr << "PENDING_FINALITY_AUTHORITY_RESERVATION_FAILURE: admitted validator evidence was not accepted\n";
    return 1;
  }
  authority_reservation_gate.get_if_exists(100)->complete_front(reserved_candidate.token, true);

  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> retry_then_accept;
  if (!retry_then_accept.admit(0, 0, valid, 4096, ValidatorCapacity, false, true, NoExpiry).admitted()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: valid certificate was not admitted\n";
    return 1;
  }
  auto *retry_candidates = retry_then_accept.get_if_exists(0);
  auto first_retry_attempt = retry_candidates->begin_processing(0);
  if (!first_retry_attempt ||
      retry_candidates->resolve_front_failure(first_retry_attempt.token, tos::ErrorCode::notready, 0).action !=
          tos::validator::PendingFinalityFailureAction::Retry ||
      retry_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: valid evidence was discarded while required state was not ready\n";
    return 1;
  }
  if (retry_candidates->begin_processing(tos::validator::pending_finality_initial_retry_seconds / 2) != nullptr) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: retained evidence retried before its backoff elapsed\n";
    return 1;
  }
  auto retried = retry_candidates->begin_processing(tos::validator::pending_finality_initial_retry_seconds);
  if (retried == nullptr ||
      block::verify_pq_finality(context, *retried->evidence, block::FinalityRole::Final).is_error()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: retained evidence was not valid on the later attempt\n";
    return 1;
  }
  retry_candidates->complete_front(retried.token, true);
  if (!retry_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: a later successful attempt did not accept the evidence\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> isolated_store;
  auto invalid_bytes = serialize_tl_object(invalid->tl(), true).size();
  auto valid_bytes = serialize_tl_object(valid->tl(), true).size();
  constexpr int old_candidate_limit = 4;
  for (int i = 0; i < old_candidate_limit; ++i) {
    auto admission = isolated_store.admit(0, 1, invalid, invalid_bytes, ValidatorCapacity, false, true, NoExpiry);
    if ((i == 0 && !admission.admitted()) ||
        (i != 0 && admission.rejection != tos::validator::PendingFinalityRejection::SenderAlreadyPending)) {
      std::cerr << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: one sender occupied more than one block candidate\n";
      return 1;
    }
  }
  if (!isolated_store.admit(0, 2, valid, valid_bytes, ValidatorCapacity, false, true, NoExpiry).admitted() ||
      isolated_store.get_if_exists(0)->size() != 2) {
    std::cerr << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: honest sender was excluded by a Byzantine sender\n";
    return 1;
  }
  bool isolated_accepted = false;
  auto *isolated_candidates = isolated_store.get_if_exists(0);
  while (auto pending = isolated_candidates->begin_processing(0)) {
    bool accepted = block::verify_pq_finality(context, *pending->evidence, block::FinalityRole::Final).is_ok();
    isolated_candidates->complete_front(pending.token, accepted);
    if (accepted) {
      isolated_accepted = true;
      break;
    }
  }
  if (!isolated_accepted) {
    std::cerr
        << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: honest finality was not accepted after Byzantine evidence\n";
    return 1;
  }
  auto positive_control = block::verify_pq_finality(context, *valid, block::FinalityRole::Final);
  if (positive_control.is_error()) {
    std::cerr << "PENDING_FINALITY_POSITIVE_CONTROL_FAILURE: " << positive_control.error().message().str() << "\n";
    return 1;
  }
  auto negative_control = block::verify_pq_finality(context, *invalid, block::FinalityRole::Final);
  if (negative_control.is_ok() ||
      negative_control.error().message().str().find("pq signatures: invalid signature") == std::string::npos) {
    std::cerr
        << "PENDING_FINALITY_NEGATIVE_CONTROL_FAILURE: corrupted final was not rejected as an invalid signature\n";
    return 1;
  }

  // Check the good-first ordering first. Reversing candidate processing must
  // fail this assertion before the bad-first retry assertion can shadow it.
  auto good_then_bad = process_finality_candidates({valid, invalid}, context);
  if (!good_then_bad.accepted || good_then_bad.attempted.size() != 1 || good_then_bad.attempted[0] != valid.get()) {
    std::cerr << "PENDING_FINALITY_ORDER_FAILURE: later bad final ran before the earlier valid final\n";
    return 1;
  }
  auto bad_then_good = process_finality_candidates({invalid, valid}, context);
  if (!bad_then_good.accepted || bad_then_good.attempted.size() != 2 || bad_then_good.attempted[0] != invalid.get() ||
      bad_then_good.attempted[1] != valid.get()) {
    std::cerr << "PENDING_FINALITY_ORDER_FAILURE: bad final displaced the later valid final\n";
    return 1;
  }
  std::cout << "PENDING_FINALITY_ORDER_OK: first cryptographically valid final accepted in both arrival orders\n";
  std::cout << "PENDING_FINALITY_REJECTION_NAME_OK: ingress and store refusals have stable textual names\n";
  std::cout << "PENDING_FINALITY_RETRY_OK: notready retained valid evidence and a later attempt accepted it\n";
  std::cout << "PENDING_FINALITY_TIMEOUT_CLASSIFICATION_OK: verification timeout remains transient\n";
  std::cout << "PENDING_FINALITY_PERMANENT_OK: protocol violation was discarded without retry\n";
  std::cout << "PENDING_FINALITY_RETRY_DEADLINE_OK: transient evidence freed its slot after "
            << tos::validator::pending_finality_retention_seconds << " seconds\n";
  std::cout
      << "PENDING_FINALITY_STALE_ATTEMPT_OK: late failure and success tokens could not mutate the replacement front\n";
  std::cout
      << "PENDING_FINALITY_QUEUE_REUSE_OK: destroyed and recreated block queues use distinct attempt namespaces\n";
  std::cout
      << "PENDING_FINALITY_INGRESS_OK: missing accounting fails closed and authenticated senders retain attribution\n";
  std::cout << "PENDING_FINALITY_TRANSPORT_DEDUP_OK: evidence-distinct finalities have distinct transport ids\n";
  std::cout
      << "PENDING_FINALITY_SENDER_ISOLATION_OK: four bad arrivals from one sender did not exclude another sender\n";
  std::cout << "PENDING_FINALITY_BYTE_BUDGET_OK: total=" << tos::validator::pending_finality_total_budget_bytes
            << " public_shared=" << tos::validator::pending_finality_public_budget_bytes
            << " validator_reserved=" << tos::validator::pending_finality_validator_reserved_budget_bytes
            << " per_sender_per_block=" << tos::validator::pending_finality_sender_per_block_budget_bytes
            << " per_sender_global=" << tos::validator::pending_finality_sender_global_budget_bytes
            << " minimum_charge=4096 validator_shares=" << tos::validator::pending_finality_max_validator_senders
            << "\n";
  std::cout << "PENDING_FINALITY_AUTHORITY_MEMO_OK: cycled_claims=64 computations=2 entries=2"
               " global_cycled_shards="
            << cycled_shard_count << " global_computations=" << bounded_authority_computations
            << " global_entries=" << bounded_authority_memo.size()
            << " global_cap=" << tos::validator::pending_finality_authority_memo_max_entries << "\n";
  std::cout << "PENDING_FINALITY_CLASSICAL_MEMO_OK: authority classification and classical verification share one "
               "computation\n";
  std::cout << "PENDING_FINALITY_DEEP_SHARD_WINDOW_OK: containing_cc_seqno=" << inherited_catchain_seqno
            << " exact_descendant=absent validator_set_computation=blocked\n";
  std::cout << "PENDING_FINALITY_CLASSIFICATION_COST: validators=400 average_us=" << measured_microseconds
            << " copied_pq_key_bytes_per_set=" << measured_validator_count * tos::pq::mldsa44_public_key_bytes
            << " iterations=" << measurement_iterations << "\n";
  return 0;
}
