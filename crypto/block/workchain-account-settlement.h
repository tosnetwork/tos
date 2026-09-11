#pragma once

#include <algorithm>
#include <exception>
#include <memory>
#include <type_traits>

#include "block/workchain-account-effects.h"
#include "block/workchain-payout-overlay.h"
#include "block/workchain-allocation-overlay.h"
#include "block/workchain-native-materialization.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-registration-settlement.h"
#include "block/workchain-deposit-rejection-settlement.h"
#include "block/workchain-closure-settlement.h"
#include "block/workchain-budget-backing.h"
#include "block/workchain-operation-fees.h"
#include "vm/cells/UsageCell.h"

namespace block {

struct WorkchainAccountSettlement {
  td::Ref<vm::Cell> input, effects;
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
  WorkchainFinalImportEvidence imports;
  // Disposal exports derived from transactions, not queue-ready envelopes.
  std::vector<NewOutMsg> exports;
  // Private continuation of the output content union. It is absent for the
  // retained prototype and is never trusted from claimed replay artifacts.
  // Queue/shard updates must extend this meter before live authorization;
  // carrying it is not evidence that those remaining outputs were admitted.
  // A later stage copies this immutable snapshot before extending it; copied
  // settlement/claim objects cannot charge or reset one another's meter.
  std::shared_ptr<const NativeStateReadMeter> output_admission;
  // Continue the same authenticated state union without extending a temporary
  // proof tree's lifetime. A complete host owns the tree across all stages.
  std::shared_ptr<const NativeStateReadMeter> state_admission;
  vm::CellUsageTree::NodePtr state_usage_node;
};

// Candidate-only comparison after independent execution/settlement. Extracted
// from the validator's final boundary so controls exercise its actual verdict,
// not a test-only approximation. Rebuilt data never comes from these claims.
inline td::Status compare_workchain_account_replay_artifacts(
    const WorkchainAccountSettlement& rebuilt, const td::Ref<vm::Cell>& effects,
    const td::Ref<vm::Cell>& accounts, const td::Ref<vm::Cell>& account_blocks,
    const td::Ref<vm::Cell>& imports, std::uint64_t end_lt) {
  if (rebuilt.effects.is_null() || rebuilt.state.accounts.is_null() ||
      rebuilt.state.account_blocks.is_null() || rebuilt.imports.in_msg_descr.is_null())
    return td::Status::Error(-7201, "account replay rebuilt artifacts unavailable");
  if (effects.is_null() || accounts.is_null() || account_blocks.is_null() || imports.is_null() ||
      rebuilt.effects->get_hash() != effects->get_hash() ||
      rebuilt.state.accounts->get_hash() != accounts->get_hash() ||
      rebuilt.state.account_blocks->get_hash() != account_blocks->get_hash() ||
      rebuilt.imports.in_msg_descr->get_hash() != imports->get_hash() || rebuilt.state.end_lt != end_lt)
    return td::Status::Error(-7200, "account replay artifacts differ from independently rebuilt settlement");
  return td::Status::OK();
}

// One engine invocation followed by private Native materialization. No caller
// supplies the input/effects hashes or a second set of account data updates.
// This post-admission operation does not authenticate roles, resource policy,
// old state or withdrawal authorization. The resolved engine must derive its
// payout request from verified obligations, not forward an unverified request.
// Registration needs additional Native record shapes. The explicit disposal
// runner preserves foreign destinations; the strict runner rejects them.
// Live integration of joint disposal and custody payout settlement remains open.
namespace account_settlement_detail {
// Raised only by the authenticated old-state read observer below. It must not
// be used for candidate decoding or translated into candidate invalidity.
struct UnadmittedStateRead {};

// Cheap host-context checks only: no candidate parsing, state loads, allocation
// of usage trees or engine callback. Apply before shape inspection; these
// programming/configuration faults cannot become candidate rejections.
template <class Admission>
inline td::Status validate_batch_context(
    const Admission& input, const td::Ref<vm::Cell>& old_accounts,
    const WorkchainHostIdentity& identity, const td::Bits256& custody,
    const td::Bits256& coordinator, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainDisposalEntryContext* disposal) {
  static_assert(std::is_same_v<Admission, AdmittedBatchInput> ||
                std::is_same_v<Admission, ProofAdmittedBatchInput>);
  if (old_accounts.is_null() || extra_validation_cells <= 0 ||
      (disposal && (disposal->max_inbound != input.policy().resources().input.max_inbound ||
                    identity.shard_id != tos::shardIdAll || coordinator == custody ||
                    cfg.global_version != message_cfg.global_version))) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                             "invalid local batch settlement context");
  }
  return td::Status::OK();
}

// Source-specific helpers: callers must pass only locally rebuilt output or
// engine-effects closures, never a parser for untrusted candidate wire data.
inline td::Status charge_closure(std::optional<NativeStateReadMeter>& meter, td::Ref<vm::Cell> root,
                          const char* limit_message, const char* unavailable_message) {
  if (!meter || root.is_null()) return td::Status::OK();
  std::vector<td::Ref<vm::Cell>> pending{std::move(root)};
  while (!pending.empty()) {
    auto cell = std::move(pending.back());
    pending.pop_back();
    if (meter->charged_hashes().count(cell->get_hash())) continue;
    auto loaded = meter->load_encoded(cell);
    if (std::holds_alternative<NativeClosureLimit>(loaded)) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                               td::Slice(limit_message));
    }
    auto* slice = std::get_if<td::Ref<vm::CellSlice>>(&loaded);
    if (!slice) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               td::Slice(unavailable_message));
    }
    for (unsigned i = 0; i < (*slice)->size_refs(); ++i) {
      pending.push_back((*slice)->prefetch_ref(i));
    }
  }
  return td::Status::OK();
}

template <class Function>
inline auto contain_local_output_failure(const Function& function) -> decltype(function()) {
  // Keep the unrelated Native exception classes aligned with
  // NativeStateReadMeter::load_encoded in workchain-native-materialization.h.
  // Standard exceptions from other own-output construction are local too;
  // do not catch all types and intercept the custom footprint signal.
  const char* cause = nullptr;
  try {
    return function();
  } catch (const vm::VmError&) {
    cause = "rebuilt output admission: VM read/decode failure";
  } catch (const vm::VmVirtError&) {
    cause = "rebuilt output admission: virtual content unavailable";
  } catch (const vm::VmNoGas&) {
    cause = "rebuilt output admission: Native gas exhaustion";
  } catch (const vm::VmFatal&) {
    cause = "rebuilt output admission: Native fatal exception";
  } catch (const vm::CellBuilder::CellCreateError&) {
    cause = "rebuilt output admission: CellCreateError";
  } catch (const vm::CellBuilder::CellWriteError&) {
    cause = "rebuilt output admission: CellWriteError";
  } catch (const std::bad_alloc&) {
    cause = "rebuilt output admission: allocation failure";
  } catch (const std::length_error&) {
    cause = "rebuilt output admission: allocation length failure";
  } catch (const std::exception&) {
    cause = "rebuilt output admission: standard local exception";
  }
  // Returned quota errors remain CandidateInvalid; only exceptions from
  // own-output acquisition/construction are translated here. The custom
  // UnadmittedStateRead signal is left to the enclosing sticky observer.
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                           td::Slice(cause));
}


// Settlement-only continuation. It cannot call an engine: the executed result,
// decoded declarations and original admission/tracking context are explicit.
// The enclosing execute frame owns any private usage tree through this call.
template <class Admission>
inline td::Result<WorkchainAccountSettlement> settle_executed(
    ExecutedWorkchainAccountBatch executed, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const Admission& admitted,
    const WorkchainAccountDeclarations& declarations,
    vm::CellUsageTree::NodePtr state_usage_node,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, std::uint64_t max_transfers,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainDisposalEntryContext* disposal) {
  if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
    if (executed.input.is_null() || executed.input->get_hash() != admitted.root()->get_hash()) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "executed input differs from settlement admission");
    }
  }
  bool unadmitted_read = false;
  std::optional<vm::CellUsageTree::ScopedReadObserver> state_observer;
  if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
    if (!executed.state_admission) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "settlement lacks old-state admission");
    }
    // Observe the existing tree; never nest another UsageCell around its root,
    // cache LoadedCell, or replace its proof callback. Repeated reads are checked
    // too: proof tracking's first-load bit is not this batch's admission evidence.
    // The same synchronous owner must remain live through this second scope.
    state_observer.emplace(state_usage_node, [&](const vm::Cell& cell) {
      if (unadmitted_read || !cell.get_tree_node().empty() ||
          !executed.state_admission->charged_hashes().count(cell.get_hash())) {
        unadmitted_read = true;
        throw UnadmittedStateRead{};
      }
    });
  }
  auto settle = [&]() -> td::Result<WorkchainAccountSettlement> {
    std::optional<WorkchainDepositRejectionMaterial> rejected_material;
    std::optional<WorkchainDisposalEntryContext> rejected_context;
    NativeDisposalProfile rejected_profile{NativeDisposalSource::OriginalDestination,
        {0, -ComputePhase::sk_no_state, {}}, false};
    if (executed.effects.rejected_deposit) {
      if (disposal || executed.effects.registration || executed.effects.closure ||
          executed.effects.payout_request.not_null() || executed.effects.fees ||
          !executed.effects.native_transfers.empty() || executed.effects.events.not_null())
        return td::Status::Error(-7201, "rejected Deposit cannot carry unrelated settlement effects");
      const auto& rejected = *executed.effects.rejected_deposit;
      if (rejected.ingress.executor_address != coordinator || !rejected.ingress.custody_address ||
          *rejected.ingress.custody_address != custody)
        return td::Status::Error(-7201, "rejected Deposit settlement roles unavailable");
      TRY_RESULT(material, prepare_workchain_deposit_rejection_settlement(rejected, old_accounts,
          identity, executed.input, declarations, max_writes, max_inbound, extra_validation_cells, message_cfg));
      bool replaced = false;
      for (auto& update : executed.effects.updates) {
        if (update.account != coordinator) continue;
        if (replaced || update.data.is_null() || rejected.old_coordinator_data != update.data->get_hash().bits())
          return td::Status::Error(-7201, "rejected Deposit coordinator update mismatch");
        update.data = material.coordinator_data;
        replaced = true;
      }
      if (!replaced) return td::Status::Error(-7201, "rejected Deposit lacks coordinator update");
      // Implementation event encoding (not a frozen business-config schema):
      // the block commits rejection/branch and any attribution-loss alarm.
      executed.effects.events = vm::CellBuilder().store_long(0x55445234, 32)
            .store_long(material.plan.native.branch == NativeDisposalBranch::Bounce, 1)
            .store_long(material.plan.sender_attribution_lost, 1)
            .store_long(material.plan.extra_attribution_lost, 1)
            .store_bits(rejected.message.bits(), 256).finalize();
      rejected_material.emplace(std::move(material));
      rejected_context.emplace(WorkchainDisposalEntryContext{custody, message_cfg, rejected.workchains,
          rejected_profile, max_inbound, 1, rejected.message});
      disposal = &*rejected_context;
    }
    std::optional<NativeStateReadMeter> effect_meter;
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
      const auto& bounds = admitted.policy().resources().work_output;
      effect_meter.emplace(bounds.max_effect_cells, bounds.max_effect_bits);
    }
    // This counts an effects-only content union, not old-state or input usage.
    // Every walk has one root plus at most four pending edges per charged Cell.
    // Spliced old-state subtrees are safe to revisit only because account
    // acquisition admitted and usage-tracked each selected account's complete
    // closure. Lazy/partial acquisition would require changing this boundary.
    // The engine has already produced its result: its own allocation/work bound
    // remains an independent pre-execution obligation, not proved by this walk.
    auto charge_effect = [&](td::Ref<vm::Cell> root) {
      return charge_closure(effect_meter, std::move(root), "effects closure exceeds authenticated budget",
                            "engine effects content unavailable");
    };
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
      // execute() already matched updates one-for-one to the bounded write set.
      // Transfers have no such earlier check: bound them before this walk.
      if (executed.effects.native_transfers.size() > max_transfers) {
        return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                 "effects entries exceed authenticated counts");
      }
      for (const auto& update : executed.effects.updates) TRY_STATUS(charge_effect(update.data));
      for (const auto& transfer : executed.effects.native_transfers) TRY_STATUS(charge_effect(transfer.value.extra));
      TRY_STATUS(charge_effect(executed.effects.payout_request));
      TRY_STATUS(charge_effect(executed.effects.receipts));
      TRY_STATUS(charge_effect(executed.effects.events));
    }
    TRY_RESULT(effects_root, encode_workchain_account_effects(executed.effects, max_writes, max_transfers,
        extra_validation_cells));
    // Dictionary construction above is count-bounded, not incrementally charged.
    // dict_set follows one path, decreasing key width each recursion, rebuilds
    // one node per ancestor and finalizes at most three nodes at the insertion.
    // A conservative cumulative bound is 259*U + 36*T + 3 finalized Cells:
    // 256-bit update paths; 32-bit transfer paths plus one entry each; two
    // outer wrappers and at most one fee record. U <= max_writes and
    // T <= max_transfers were checked above.
    // This excludes already-produced engine data and is not zero overshoot of
    // the final union budget. No runtime multiplication relies on this bound.
    TRY_STATUS(charge_effect(effects_root));
    const bool specialized = executed.effects.registration || executed.effects.closure;
    if (specialized) {
      if constexpr (!std::is_same_v<Admission, ProofAdmittedBatchInput>) {
        return td::Status::Error(-7201, "registration/closure require admitted metered execution");
      } else if (!admitted.policy().requires_proof_operation_meter()) {
        return td::Status::Error(-7201, "registration/closure require operation-metered profile");
      }
      if ((executed.effects.registration && executed.effects.closure) || disposal ||
          executed.effects.payout_request.not_null() || !executed.effects.native_transfers.empty())
        return td::Status::Error(-7201, "conflicting locally executed Native settlement kinds");
      WorkchainAccountEffects expected;
      if (executed.effects.registration) {
        const auto& result = executed.effects.registration->registration;
        auto decoded = decode_workchain_confidential_account(result.account_data);
        if (decoded.is_error()) return td::Status::Error(-7201, "engine registration record malformed");
        auto created = decoded.move_as_ok();
        expected.updates = {{created.address.account, result.account_data}, {coordinator, result.coordinator_data}};
      } else {
        const auto& result = *executed.effects.closure;
        expected.updates = {{result.account, result.transition.account_data},
                            {coordinator, result.transition.coordinator_data}};
      }
      std::sort(expected.updates.begin(), expected.updates.end(),
                [](const auto& a, const auto& b) { return a.account < b.account; });
      auto encoded_expected = encode_workchain_account_effects(expected, max_writes, max_transfers,
                                                               extra_validation_cells);
      if (encoded_expected.is_error()) return td::Status::Error(-7201, "engine Native settlement result malformed");
      auto expected_root = encoded_expected.move_as_ok();
      // Specialized materializers reconstruct precisely these effects. Reject
      // extra fees/events/usage or divergent data rather than committing two
      // different effects hashes to the engine result and Native entry.
      if (expected_root->get_hash() != effects_root->get_hash())
        return td::Status::Error(-7201, "Native settlement differs from locally executed effects");
    }
    std::vector<WorkchainStorageWrite> writes;
    writes.reserve(executed.effects.updates.size());
    for (const auto& update : executed.effects.updates) {
      auto read = std::lower_bound(declarations.reads.begin(), declarations.reads.end(), update.account,
          [](const auto& entry, const auto& key) { return entry.account < key; });
      if (read == declarations.reads.end() || read->account != update.account ||
          (!read->old_account_hash && !executed.effects.registration)) {
        return td::Status::Error("account creation requires a registration participant");
      }
      if (read->old_account_hash) writes.push_back({update.account, *read->old_account_hash, update.data});
    }
    const td::Bits256 input_hash(executed.input->get_hash().bits());
    const td::Bits256 effects_hash(effects_root->get_hash().bits());
    WorkchainStorageOverlay state;
    td::Ref<vm::Cell> message;
    WorkchainFinalImportEvidence imports;
    std::vector<NewOutMsg> exports;
    if (specialized) {
      auto materialize = [&]() -> td::Result<WorkchainInboundAllocationOverlay> {
        if (executed.effects.registration)
          return settle_workchain_registration(old_accounts, identity, executed.input,
              *executed.effects.registration, coordinator, custody, max_reads, max_writes, max_inbound,
              extra_validation_cells, cfg);
        return settle_workchain_executed_closure(old_accounts, identity, executed.input,
            *executed.effects.closure, coordinator, custody, max_reads, max_writes,
            extra_validation_cells, cfg, message_cfg);
      };
      TRY_RESULT(allocated, materialize());
      state = std::move(allocated.state);
      imports = std::move(allocated.imports);
      exports = std::move(allocated.exports);
    } else if (executed.effects.payout_request.is_null()) {
      TRY_RESULT(allocated, disposal ? build_workchain_disposal_allocation_overlay(old_accounts, identity, executed.input,
          effects_root, coordinator, max_reads, max_writes, max_transfers, extra_validation_cells, cfg, *disposal) :
          build_workchain_inbound_allocation_overlay(old_accounts, identity, executed.input,
          effects_root, coordinator, custody, max_reads, max_writes, max_transfers, max_inbound,
          extra_validation_cells, cfg));
      state = std::move(allocated.state);
      imports = std::move(allocated.imports);
      exports = std::move(allocated.exports);
    } else {
      // Materialize the complete write set and all outputs without re-executing
      // the engine. Strict callers retain the original recipient policy.
      TRY_RESULT(payout, build_workchain_payout_overlay(old_accounts, identity.workchain_id, identity.gen_utime,
          identity.host_after_lt, input_hash, effects_hash, writes, custody, coordinator,
          executed.effects.payout_request, fee_budget,
          max_reads, max_writes, max_transfers, extra_validation_cells, cfg, message_cfg,
          executed.input, effects_root, max_inbound, disposal, {}, executed.effects.payout_forward_fee,
          executed.effects.payout_principal));
      state = std::move(payout.state);
      message = std::move(payout.message);
      imports = std::move(payout.imports);
      exports = std::move(payout.exports);
    }
    if (executed.effects.protected_coordinator_snapshot) {
      vm::AugmentedDictionary previous(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
      vm::AugmentedDictionary produced(vm::load_cell_slice_ref(state.accounts), 256, tlb::aug_ShardAccounts);
      Account old_budget(identity.workchain_id, coordinator.bits()), new_budget(identity.workchain_id, coordinator.bits());
      if (!old_budget.unpack(previous.lookup(coordinator), identity.gen_utime, false) || old_budget.data.is_null() ||
          *executed.effects.protected_coordinator_snapshot != old_budget.data->get_hash().bits() ||
          !new_budget.unpack(produced.lookup(coordinator), identity.gen_utime, false) || new_budget.data.is_null())
        return td::Status::Error(-7201, "protected coordinator snapshot unavailable");
      TRY_RESULT(before, decode_workchain_coordinator_state(old_budget.data));
      TRY_RESULT(after, decode_workchain_coordinator_state(new_budget.data));
      TRY_RESULT(old_holdings, workchain_budget_bucket_holdings(before, extra_validation_cells));
      TRY_RESULT(new_holdings, workchain_budget_bucket_holdings(after, extra_validation_cells));
      auto refundable_before = workchain_protected_refundable(before.refundable_deposits);
      auto refundable_after = workchain_protected_refundable(after.refundable_deposits);
      if (check_workchain_budget_backing(old_budget.balance, refundable_before, old_holdings).is_error())
        return td::Status::Error(-7201, "authenticated coordinator protected holdings are not fully backed");
      CurrencyCollection expected_refundable = refundable_before, bucket_credit(0);
      // Classification is fixed by independent execution, not candidate events:
      // registration imports are refundable, rejected non-bounced imports are
      // bucket holdings, Deposit slot fees and D32 S are operating income.
      if (executed.effects.registration) {
        if (!CurrencyCollection::add(refundable_before,
                executed.effects.registration->coordinator_flow.imported, expected_refundable))
          return td::Status::Error(-7200, "registration protected credit overflow");
      } else if (executed.effects.closure) {
        // Checked subtraction: only the historically authorized refund may
        // reduce this protected claim, never its forwarding fee.
        if (!CurrencyCollection::sub(refundable_before,
                workchain_protected_refundable(executed.effects.closure->transition.refund.amount), expected_refundable))
          return td::Status::Error(-7200, "closure protected debit exceeds recorded claim");
      } else if (rejected_material &&
                 rejected_material->plan.native.branch == NativeDisposalBranch::UnexpectedCredit) {
        bucket_credit = rejected_material->plan.native.row.imported;
      }
      if (refundable_after != expected_refundable)
        return td::Status::Error(-7200, "refundable classification differs from authenticated event");
      TRY_STATUS(check_workchain_bucket_credit_pair(old_holdings, new_holdings, bucket_credit));
      auto backing = check_workchain_budget_backing(new_budget.balance, refundable_after, new_holdings);
      if (backing.is_error()) return td::Status::Error(-7200, backing.message());
    }
    std::shared_ptr<const NativeStateReadMeter> output_snapshot;
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
      const auto& limits = admitted.policy().resources();
      // Only rebuilt outputs, decoded declaration keys and immutable limits
      // enter this scope. There is no direct engine/candidate-parser capture;
      // engine-produced Cells can still execute load callbacks, which the
      // exception boundary below contains.
      // References spliced from authenticated state are still local sources;
      // the existing read observer keeps its separate footprint enforcement.
      auto admit_output = [&state, &imports, &exports, &declarations, &limits]()
          -> td::Result<std::shared_ptr<const NativeStateReadMeter>> {
        std::optional<NativeStateReadMeter> output_meter;
        output_meter.emplace(limits.work_output.max_output_cells, limits.work_output.max_output_bits);
        // All three dictionary outputs use get_wrapped_dict_root(): even an
        // empty dictionary yields a finalized cell; construction failure throws.
        // Select only the independently rebuilt write set. Walking the whole
        // ShardAccounts root would charge every untouched account as output.
        // Lookup work remains bounded separately by write count and key width;
        // account-dictionary/shard update proofs are a later output root group.
        vm::AugmentedDictionary produced(vm::load_cell_slice_ref(state.accounts), 256, tlb::aug_ShardAccounts);
        for (const auto& key : declarations.writes) {
          auto value = produced.lookup(key);
          tlb::ShardAccount::Record record;
          if (value.is_null() || value->size_ext() != 0x10140 || !record.unpack(value)) {
            return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                     "rebuilt account wrapper malformed");
          }
          // Acquisition validated this same immutable depth value as uint16
          // before calling the engine; no second policy supplies this narrowing.
          auto closure = read_workchain_account_closure(record.account, *output_meter,
              limits.state.max_account_cells, limits.state.max_account_bits,
              static_cast<std::uint16_t>(limits.state.max_account_depth));
          if (std::holds_alternative<NativeClosureLimit>(closure) ||
              std::holds_alternative<WorkchainAccountClosureLimit>(closure)) {
            // This is newly proposed output, not an unreadable persisted account.
            return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                     "rebuilt account exceeds output or per-account budget");
          }
          if (std::holds_alternative<LocalUnavailable>(closure)) {
            return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                     "rebuilt account content unavailable");
          }
        }
        auto charge_output = [&](td::Ref<vm::Cell> root) {
          return charge_closure(output_meter, std::move(root), "output closure exceeds authenticated budget",
                                "rebuilt output content unavailable");
        };
        TRY_STATUS(charge_output(state.account_blocks));
        TRY_STATUS(charge_output(imports.in_msg_descr));
        for (const auto& output : exports) {
          TRY_STATUS(charge_output(output.msg));
          TRY_STATUS(charge_output(output.trans));
        }
        return std::make_shared<const NativeStateReadMeter>(std::move(*output_meter));
      };
      TRY_RESULT(snapshot, contain_local_output_failure(admit_output));
      output_snapshot = std::move(snapshot);
    }
    std::shared_ptr<const NativeStateReadMeter> state_snapshot;
    if (executed.state_admission) {
      TRY_RESULT(snapshot, contain_local_output_failure([&executed]()
          -> td::Result<std::shared_ptr<const NativeStateReadMeter>> {
        return std::make_shared<const NativeStateReadMeter>(*executed.state_admission);
      }));
      state_snapshot = std::move(snapshot);
    }
    return WorkchainAccountSettlement{std::move(executed.input), std::move(effects_root),
                                      std::move(state), std::move(message), std::move(imports), std::move(exports),
                                      std::move(output_snapshot), std::move(state_snapshot), state_usage_node};
  };
  try {
    auto result = settle();
    if (!unadmitted_read) return result;
  } catch (const UnadmittedStateRead&) {
    // This is an incomplete host footprint, not an invalid candidate. No
    // private result may escape, even if an intermediate callee swallowed it.
  }
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                           "settlement read outside admitted old-state footprint");
}

template <class Admission>
inline td::Result<WorkchainAccountSettlement> execute(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const Admission& admitted,
    std::conditional_t<std::is_same_v<Admission, ProofAdmittedBatchInput>, std::nullptr_t,
                       const WorkchainAccountDeclarations&> prototype_declarations,
    const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, std::uint64_t max_transfers,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainDisposalEntryContext* disposal) {
  static_assert(std::is_same_v<Admission, AdmittedInput> || std::is_same_v<Admission, ProofAdmittedBatchInput>);
  if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
    if (!admitted.inspected_by(engine)) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "settlement proof admission belongs to another engine");
    }
  }
  std::shared_ptr<vm::CellUsageTree> state_usage_tree;
  vm::CellUsageTree::NodePtr state_usage_node;
  if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
    if (old_accounts.is_null()) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "authenticated settlement state missing");
    }
    state_usage_node = old_accounts->get_tree_node();
    if (state_usage_node.empty()) {
      // Private-source tree ownership stays in this frame. Returned Native
      // cells may retain weak usage nodes; do not export a strong owner of this
      // tree or those wrappers would remain active in a caller's new proof.
      // Existing caller-owned trees retain their ordinary Native lifetime.
      // An expired wrapper is also empty: its load no longer sets a tree node,
      // so wrapping it in this fresh tree does not create live nested tracking.
      state_usage_tree = std::make_shared<vm::CellUsageTree>();
      old_accounts = vm::UsageCell::create(std::move(old_accounts), state_usage_tree->root_ptr());
      state_usage_node = old_accounts->get_tree_node();
    }
  }
  // Batch callers cannot supply a second declaration cut, even to this private
  // helper. Decode once and use the same object for execution and settlement.
  WorkchainAccountDeclarations batch_declarations;
  gen::UnoV2HostInput::Record batch_input;
  if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
    // The session locally finalizes this ordinary root; it is not a virtualized
    // state root. Structural counts already passed the same authenticated limits.
    if (!tlb::unpack_cell(admitted.root(), batch_input)) {
      return td::Status::Error("invalid admitted settlement input");
    }
    TRY_RESULT(decoded, decode_workchain_account_declarations(batch_input.access, max_reads, max_writes));
    batch_declarations = std::move(decoded);
  }
  const auto& declarations = [&]() -> const WorkchainAccountDeclarations& {
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) return batch_declarations;
    else return prototype_declarations;
  }();
  if (extra_validation_cells <= 0) return td::Status::Error("invalid settlement currency validation budget");
  if (disposal && (identity.shard_id != tos::shardIdAll || coordinator == custody ||
                   cfg.global_version != message_cfg.global_version)) {
    return td::Status::Error("invalid resolved disposal settlement context");
  }
  // Ownership is enforced by type. Queue authentication, aggregate admission
  // and role authorization are still enclosing-host obligations. Check final
  // import destinations before account acquisition or any engine invocation.
  std::vector<td::Bits256> recipients{coordinator, custody};
  std::sort(recipients.begin(), recipients.end());
  TRY_RESULT(inbox, disposal ? plan_workchain_disposal_envelopes(native_cells.roots(), identity.workchain_id,
      identity.host_after_lt, max_inbound) : plan_workchain_native_envelopes(native_cells.roots(),
      identity.workchain_id, recipients, identity.host_after_lt, max_inbound));
  auto run = [&]() -> td::Result<ExecutedWorkchainAccountBatch> {
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
      const auto& input = batch_input;
      TRY_RESULT(expected_identity, encode_workchain_host_identity(identity));
      if (input.identity->get_hash() != expected_identity->get_hash()) {
        return td::Status::Error("settlement context differs from admitted identity");
      }
      td::Ref<vm::Cell> expected_inbox;
      if (!inbox.envelopes.empty()) {
        TRY_RESULT(encoded, encode_workchain_batch_inbound(inbox.envelopes));
        expected_inbox = std::move(encoded);
      }
      auto claimed_inbox = input.inbox->prefetch_ref();
      if (claimed_inbox.is_null() != expected_inbox.is_null() ||
          (expected_inbox.not_null() && claimed_inbox->get_hash() != expected_inbox->get_hash())) {
        return td::Status::Error("settlement inbox differs from admitted input");
      }
      return account_engine_detail::execute(engine, old_accounts, admitted, declarations,
                                             max_reads, max_writes);
    } else {
      return execute_workchain_account_engine(engine, old_accounts, identity, admitted, declarations,
          inbox.envelopes, max_reads, max_writes, max_inbound);
    }
  };
  auto guarded_run = [&]() -> td::Result<ExecutedWorkchainAccountBatch> {
    if constexpr (std::is_same_v<Admission, ProofAdmittedBatchInput>) {
      bool nested_read = false;
      // The private owner above or the synchronous caller owns this live node.
      // Both callbacks are nonempty. Invalid observer construction is therefore
      // a host lifetime/contract violation, not a serialized-input condition.
      // This scope ends before the post-execution observer is installed; their
      // shared exception type has exactly one installing handler at a time.
      vm::CellUsageTree::ScopedReadObserver source_guard(state_usage_node, [&](const vm::Cell& cell) {
        // A bare root says nothing about descendants. Stop an encountered
        // nested UsageCell before its load can reach Native's anti-nesting CHECK.
        if (nested_read || !cell.get_tree_node().empty()) {
          nested_read = true;
          throw UnadmittedStateRead{};
        }
      });
      try {
        auto result = run();
        if (!nested_read) return result;
      } catch (const UnadmittedStateRead&) {
      }
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "authenticated settlement source has nested tracking");
    } else {
      return run();
    }
  };
  TRY_RESULT(executed, guarded_run());
  return settle_executed(std::move(executed), std::move(old_accounts), identity, admitted,
      declarations, state_usage_node, max_reads, max_writes, max_inbound, max_transfers,
      custody, coordinator, std::move(fee_budget), extra_validation_cells, cfg, message_cfg, disposal);
}
}  // namespace account_settlement_detail

// Complete-input path: declaration and resource arguments cannot be supplied
// independently of the admitted cut. Identity and authenticated inbox are
// compared before account reads or engine invocation. Enclosing commitment,
// proof budgets and Native authentication are still required; this is a
// private settlement runner, not live execution authorization.
// Enforced here: input read/write/inbound counts, output transfer count and
// the complete encoded effects cells/bits union.
// The engine's old-account acquisition enforces aggregate state cells/bits and
// per-account cells/bits/depth. Tracked overlay reads must remain in that
// preadmitted content-hash union. New full accounts also obey those per-account
// limits. Their closures, AccountBlocks, final imports and export records share
// a separate output meter, retained for later queue/shard update admission.
// Declared proof work is checked before execution. Backend cost correspondence,
// repeated work, remaining usage paths and complete output still need admission.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_accounts(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const ProofAdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg) {
  TRY_STATUS(account_settlement_detail::validate_batch_context(admitted, old_accounts, identity,
      custody, coordinator, extra_validation_cells, cfg, message_cfg, nullptr));
  const auto& limits = admitted.policy().resources();
  return account_settlement_detail::execute(engine, std::move(old_accounts), identity, admitted,
      nullptr, native_cells, limits.input.max_reads, limits.input.max_writes,
      limits.input.max_inbound, limits.work_output.max_transfers, custody, coordinator,
      std::move(fee_budget), extra_validation_cells, cfg, message_cfg, nullptr);
}

inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_accounts(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations, const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, std::uint64_t max_transfers,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg) {
  return account_settlement_detail::execute(engine, old_accounts, identity, admitted, declarations, native_cells,
      max_reads, max_writes, max_inbound, max_transfers, custody, coordinator, std::move(fee_budget),
      extra_validation_cells, cfg, message_cfg, nullptr);
}

// Convenience entry for structurally admitted input. Inspection precedes any
// semantic inbox processing; replay uses the already-inspected overload.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_accounts(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg) {
  TRY_STATUS(account_settlement_detail::validate_batch_context(admitted, old_accounts, identity,
      custody, coordinator, extra_validation_cells, cfg, message_cfg, nullptr));
  TRY_RESULT(preflight, ProofAdmittedBatchInput::admit(engine, admitted));
  return execute_and_settle_workchain_accounts(engine, std::move(old_accounts), identity, preflight,
      native_cells, custody, coordinator, std::move(fee_budget), extra_validation_cells, cfg, message_cfg);
}

// Explicit post-admission disposal runner. Roles, limits and prices have one
// source in context; native_cells owns the complete detached Native closures.
// It is not registration, return authorization, or a final voting boundary.
// Complete admission supplies every resource argument available in that cut.
// The duplicated inbound count in the Native context must agree, not become
// a second local allowance. Other context authentication remains the host's job.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_disposal(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const ProofAdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context) {
  TRY_STATUS(account_settlement_detail::validate_batch_context(admitted, old_accounts, identity,
      context.custody, coordinator, extra_validation_cells, cfg, context.messages, &context));
  const auto& limits = admitted.policy().resources();
  if (context.max_inbound != limits.input.max_inbound) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                             "disposal context differs from admitted inbound policy");
  }
  return account_settlement_detail::execute(engine, std::move(old_accounts), identity, admitted,
      nullptr, native_cells, limits.input.max_reads, limits.input.max_writes,
      limits.input.max_inbound, limits.work_output.max_transfers, context.custody, coordinator,
      std::move(fee_budget), extra_validation_cells, cfg, context.messages, &context);
}

inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_disposal(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations, const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_transfers,
    const td::Bits256& coordinator, td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context) {
  return account_settlement_detail::execute(engine, old_accounts, identity, admitted, declarations, native_cells,
      max_reads, max_writes, context.max_inbound, max_transfers, context.custody, coordinator, std::move(fee_budget),
      extra_validation_cells, cfg, context.messages, &context);
}

inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_disposal(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context) {
  TRY_STATUS(account_settlement_detail::validate_batch_context(admitted, old_accounts, identity,
      context.custody, coordinator, extra_validation_cells, cfg, context.messages, &context));
  TRY_RESULT(preflight, ProofAdmittedBatchInput::admit(engine, admitted));
  return execute_and_settle_workchain_disposal(engine, std::move(old_accounts), identity, preflight,
      native_cells, coordinator, std::move(fee_budget), extra_validation_cells, cfg, context);
}

}  // namespace block
