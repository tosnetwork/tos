#pragma once

#include <algorithm>
#include <type_traits>

#include "block/workchain-account-effects.h"
#include "block/workchain-payout-overlay.h"
#include "block/workchain-allocation-overlay.h"
#include "block/workchain-native-materialization.h"
#include "block/workchain-native-inbox.h"
#include "vm/cells/UsageCell.h"

namespace block {

struct WorkchainAccountSettlement {
  td::Ref<vm::Cell> input, effects;
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
  WorkchainFinalImportEvidence imports;
  // Disposal exports derived from transactions, not queue-ready envelopes.
  std::vector<NewOutMsg> exports;
};

// One engine invocation followed by private Native materialization. No caller
// supplies the input/effects hashes or a second set of account data updates.
// This post-admission operation does not authenticate roles, resource policy,
// old state or withdrawal authorization. The resolved engine must derive its
// payout request from verified obligations, not forward an unverified request.
// Registration needs additional Native record shapes. The explicit disposal
// runner preserves foreign destinations; the strict runner rejects them.
// Joint disposal and custody payout settlement still needs integration.
namespace account_settlement_detail {
// Raised only by the authenticated old-state read observer below. It must not
// be used for candidate decoding or translated into candidate invalidity.
struct UnadmittedStateRead {};

template <class Admission>
inline td::Result<WorkchainAccountSettlement> execute(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const Admission& admitted,
    std::conditional_t<std::is_same_v<Admission, AdmittedBatchInput>, std::nullptr_t,
                       const WorkchainAccountDeclarations&> prototype_declarations,
    const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, std::uint64_t max_transfers,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainDisposalEntryContext* disposal) {
  static_assert(std::is_same_v<Admission, AdmittedInput> || std::is_same_v<Admission, AdmittedBatchInput>);
  std::shared_ptr<vm::CellUsageTree> state_usage_tree;
  vm::CellUsageTree::NodePtr state_usage_node;
  if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) {
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
  if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) {
    // The session locally finalizes this ordinary root; it is not a virtualized
    // state root. Structural counts already passed the same authenticated limits.
    if (!tlb::unpack_cell(admitted.root(), batch_input)) {
      return td::Status::Error("invalid admitted settlement input");
    }
    TRY_RESULT(decoded, decode_workchain_account_declarations(batch_input.access, max_reads, max_writes));
    batch_declarations = std::move(decoded);
  }
  const auto& declarations = [&]() -> const WorkchainAccountDeclarations& {
    if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) return batch_declarations;
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
    if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) {
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
      return account_engine_detail::execute(engine, old_accounts, admitted.root(), declarations,
                                             max_reads, max_writes, &admitted.policy().resources().state);
    } else {
      return execute_workchain_account_engine(engine, old_accounts, identity, admitted, declarations,
          inbox.envelopes, max_reads, max_writes, max_inbound);
    }
  };
  auto guarded_run = [&]() -> td::Result<ExecutedWorkchainAccountBatch> {
    if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) {
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
  bool unadmitted_read = false;
  std::optional<vm::CellUsageTree::ScopedReadObserver> state_observer;
  if constexpr (std::is_same_v<Admission, AdmittedBatchInput>) {
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
    TRY_RESULT(effects_root, encode_workchain_account_effects(executed.effects, max_writes, max_transfers,
        extra_validation_cells));
    std::vector<WorkchainStorageWrite> writes;
    writes.reserve(executed.effects.updates.size());
    for (const auto& update : executed.effects.updates) {
      auto read = std::lower_bound(declarations.reads.begin(), declarations.reads.end(), update.account,
          [](const auto& entry, const auto& key) { return entry.account < key; });
      if (read == declarations.reads.end() || read->account != update.account || !read->old_account_hash) {
        return td::Status::Error("account creation requires a registration participant");
      }
      writes.push_back({update.account, *read->old_account_hash, update.data});
    }
    const td::Bits256 input_hash(executed.input->get_hash().bits());
    const td::Bits256 effects_hash(effects_root->get_hash().bits());
    WorkchainStorageOverlay state;
    td::Ref<vm::Cell> message;
    WorkchainFinalImportEvidence imports;
    std::vector<NewOutMsg> exports;
    if (executed.effects.payout_request.is_null()) {
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
          executed.effects.payout_request, fee_budget, max_reads, max_writes, max_transfers, extra_validation_cells, cfg, message_cfg,
          executed.input, effects_root, max_inbound, disposal));
      state = std::move(payout.state);
      message = std::move(payout.message);
      imports = std::move(payout.imports);
      exports = std::move(payout.exports);
    }
    return WorkchainAccountSettlement{std::move(executed.input), std::move(effects_root),
                                      std::move(state), std::move(message), std::move(imports), std::move(exports)};
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
}  // namespace account_settlement_detail

// Complete-input path: declaration and resource arguments cannot be supplied
// independently of the admitted cut. Identity and authenticated inbox are
// compared before account reads or engine invocation. Enclosing commitment,
// proof budgets and Native authentication are still required; this is a
// private settlement runner, not live execution authorization.
// Enforced here: input read/write/inbound counts and output transfer count.
// The engine's old-account acquisition enforces aggregate state cells/bits and
// per-account cells/bits/depth. Tracked overlay reads must remain in that
// preadmitted content-hash union. Repeated work, usage paths, proof units,
// effect cells/bits and output cells/bits still need independent admission.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_accounts(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg) {
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

// Explicit post-admission disposal runner. Roles, limits and prices have one
// source in context; native_cells owns the complete detached Native closures.
// It is not registration, return authorization, or a final voting boundary.
// Complete admission supplies every resource argument available in that cut.
// The duplicated inbound count in the Native context must agree, not become
// a second local allowance. Other context authentication remains the host's job.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_disposal(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context) {
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

}  // namespace block
