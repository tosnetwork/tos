#pragma once

#include "block/workchain-account-dictionary.h"
#include "block/workchain-host-input.h"
#include "block/workchain-value-flow.h"
#include "block/workchain-execution-errors.h"

namespace block {

struct WorkchainAccountSnapshot {
  td::Bits256 account;
  // Null is verified absence. Acquisition failures are never encoded as null.
  td::Ref<vm::Cell> state;
};

class WorkchainAccountReadView {
 public:
  explicit WorkchainAccountReadView(std::vector<WorkchainAccountSnapshot> snapshots)
      : snapshots_(std::move(snapshots)) {}
  WorkchainAccountReadView(const WorkchainAccountReadView&) = delete;
  WorkchainAccountReadView& operator=(const WorkchainAccountReadView&) = delete;

  td::Result<td::Ref<vm::Cell>> read(const td::Bits256& account) {
    if (failure_.is_error()) return failure_.clone();
    auto it = std::lower_bound(snapshots_.begin(), snapshots_.end(), account,
        [](const auto& snapshot, const auto& key) { return snapshot.account < key; });
    if (it == snapshots_.end() || it->account != account) {
      failure_ = td::Status::Error("engine attempted an undeclared account read");
      return failure_.clone();
    }
    return it->state;
  }
  td::Status status() const { return failure_.clone(); }

 private:
  const std::vector<WorkchainAccountSnapshot> snapshots_;
  td::Status failure_;
};

struct WorkchainAccountUpdate {
  td::Bits256 account;
  td::Ref<vm::Cell> data;
};

struct WorkchainAccountEffects {
  std::vector<WorkchainAccountUpdate> updates;
  // Canonical directed Native movements; not confidential SEND amounts.
  // Authorization and principal/budget classification remain engine obligations.
  std::vector<WorkchainInternalTransfer> native_transfers;
  // Optional single custody payout request, not a finalized Native message.
  // The settlement host must authenticate its role, amount and authorization.
  td::Ref<vm::Cell> payout_request;
  td::Ref<vm::Cell> receipts, events;
  WorkchainBlockResourceUsage usage;
};

class WorkchainAccountEngine {
 public:
  virtual ~WorkchainAccountEngine() = default;
  // Input is the committed host envelope; no shard dictionary or mutable
  // Account/Transaction/CellDb handle is exposed. Read closures and Native inbox
  // have their own admitted profiles; candidate-only rules do not apply to them.
  virtual td::Result<WorkchainAccountEffects> execute_accounts(
      const td::Ref<vm::Cell>& input, WorkchainAccountReadView& accounts) const = 0;
};

struct ExecutedWorkchainAccountBatch {
  td::Ref<vm::Cell> input;
  WorkchainAccountEffects effects;
  // Retain the old-state content-hash union for private settlement. It does not
  // bound the number of paths to shared content in the Native usage tree.
  // An absent meter belongs only to the retained prototype path.
  std::optional<NativeStateReadMeter> state_admission;
};

namespace account_engine_detail {
// Post-admission execution, not an authentication certificate. The enclosing
// host must bind old_accounts to the authenticated previous shard. Batch calls
// admit lookup paths and account closures with state_policy; prototype callers
// retain their separate admission obligation. The batch acquisition scope below
// contains known source exceptions as local failures; the prototype and engine
// callback retain their existing exception behaviour. This does not authenticate
// the caller's source or contain the whole execution/settlement frame.
// Count bounds alone are not state traversal or execution-work limits.
inline td::Result<ExecutedWorkchainAccountBatch> execute(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    td::Ref<vm::Cell> input,
    const WorkchainAccountDeclarations& declarations,
    std::uint64_t max_reads, std::uint64_t max_writes,
    const gen::UnoV2ResourceState::Record* state_policy = nullptr) {
  TRY_RESULT(access, WorkchainAccountAccess::create(declarations.reads, declarations.writes,
                                                   max_reads, max_writes));
  std::optional<NativeStateReadMeter> state_meter;
  std::optional<vm::AugmentedDictionary> prototype_accounts;
  if (state_policy) {
    if (!state_policy->max_cells || !state_policy->max_bits || !state_policy->max_account_cells ||
        !state_policy->max_account_bits || state_policy->max_account_depth <= 0 ||
        state_policy->max_account_depth > UINT16_MAX) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "installed state policy cannot admit account state");
    }
    state_meter.emplace(state_policy->max_cells, state_policy->max_bits);
  } else {
    // Only the retained singleton prototype uses this unmetered path.
    prototype_accounts.emplace(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  }
  // This closure has no candidate Cell or engine callback capability. Only
  // authenticated old-state reads can raise Native decoding exceptions here;
  // declaration keys and expected hashes are already decoded scalar values.
  // Authentication of old_accounts remains the enclosing host's obligation.
  auto acquire = [&old_accounts, &declarations, &access, &state_meter,
                  &prototype_accounts, state_policy]()
      -> td::Result<std::vector<WorkchainAccountSnapshot>> {
    std::vector<WorkchainAccountSnapshot> snapshots;
    snapshots.reserve(declarations.reads.size());
    for (const auto& read : declarations.reads) {
      auto expected = access.expected_read(read.account);
      if (expected.is_error()) return expected.move_as_error();
      td::Ref<vm::CellSlice> value;
      if (state_meter) {
        const auto mode = std::binary_search(declarations.writes.begin(), declarations.writes.end(), read.account)
            ? WorkchainAccountPathMode::Replace : WorkchainAccountPathMode::Read;
        auto acquired = lookup_workchain_account_metered(old_accounts, read.account, *state_meter, mode);
        if (std::holds_alternative<NativeClosureLimit>(acquired)) {
          return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                   "declared account paths exceed batch state budget");
        }
        if (std::holds_alternative<LocalUnavailable>(acquired)) {
          return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                   "authenticated account path unavailable");
        }
        value = std::get<td::Ref<vm::CellSlice>>(std::move(acquired));
      } else {
        value = prototype_accounts->lookup(read.account);
      }
      td::Ref<vm::Cell> state;
      std::optional<td::Bits256> actual;
      if (value.not_null()) {
        tlb::ShardAccount::Record record;
        if (value->size_ext() != 0x10140 || !record.unpack(value)) {
          if (state_policy) {
            return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::AuthenticatedStateCorrupt),
                                     "invalid authenticated ShardAccount entry");
          }
          throw vm::VmError{vm::Excno::dict_err, "invalid old ShardAccount entry"};
        }
        state = record.account;
        actual = td::Bits256(state->get_hash().bits());
      }
      TRY_STATUS(access.record_old_read(read.account, actual));
      if (state_meter && state.not_null()) {
        auto closure = read_workchain_account_closure(state, *state_meter,
            state_policy->max_account_cells, state_policy->max_account_bits,
            static_cast<std::uint16_t>(state_policy->max_account_depth));
        if (std::holds_alternative<NativeClosureLimit>(closure)) {
          return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                   "declared account closures exceed batch state budget");
        }
        if (std::holds_alternative<WorkchainAccountClosureLimit>(closure)) {
          // A persisted account that cannot fit the installed per-account policy
          // is not a bad candidate. Do not disguise it as candidate invalidity.
          // Liveness requires output admission to enforce these same closure
          // bounds and configuration migration to preserve readability of all
          // persisted accounts. Neither obligation is implemented by this guard.
          return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::AuthenticatedStateCorrupt),
                                   "authenticated account violates installed closure policy");
        }
        if (std::holds_alternative<LocalUnavailable>(closure)) {
          return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                   "authenticated account closure unavailable");
        }
      }
      snapshots.push_back({read.account, std::move(state)});
    }
    return snapshots;
  };
  auto acquire_with_boundary = [&acquire, state_policy]() -> td::Result<std::vector<WorkchainAccountSnapshot>> {
    if (!state_policy) return acquire();  // Retained singleton exception semantics.
    const char* cause = nullptr;
    try {
      return acquire();
    } catch (const WorkchainAccountFormatError& error) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::AuthenticatedStateCorrupt),
                               td::Slice(error.get_msg()));
    } catch (const vm::VmError&) {
      cause = "authenticated account acquisition: VM read/decode failure";
    } catch (const vm::VmVirtError&) {
      cause = "authenticated account acquisition: virtual content unavailable";
    } catch (const vm::VmNoGas&) {
      cause = "authenticated account acquisition: Native gas exhaustion";
    } catch (const vm::VmFatal&) {
      cause = "authenticated account acquisition: Native fatal exception";
    } catch (const vm::CellBuilder::CellCreateError&) {
      cause = "authenticated account acquisition: CellCreateError";
    } catch (const vm::CellBuilder::CellWriteError&) {
      cause = "authenticated account acquisition: CellWriteError";
    } catch (const std::bad_alloc&) {
      cause = "authenticated account acquisition: allocation failure";
    } catch (const std::length_error&) {
      cause = "authenticated account acquisition: allocation length failure";
    }
    // Source failure is never a mismatch with the candidate's declared hash.
    // Preserve ordinary returned policy/mismatch errors; contain only exceptions
    // from this acquisition scope, before the engine receives any read view.
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                             td::Slice(cause));
  };
  TRY_RESULT(snapshots, acquire_with_boundary());
  WorkchainAccountReadView view(std::move(snapshots));
  auto executed = engine.execute_accounts(input, view);
  // The engine cannot suppress an access violation by ignoring its Result.
  TRY_STATUS(view.status());
  TRY_RESULT(effects, std::move(executed));
  if (effects.updates.size() != declarations.writes.size()) {
    return td::Status::Error("engine updates differ from declared write count");
  }
  for (std::size_t i = 0; i < effects.updates.size(); ++i) {
    if (effects.updates[i].account != declarations.writes[i] || effects.updates[i].data.is_null()) {
      return td::Status::Error("engine update key or data differs from declared write set");
    }
  }
  // This checks engine claims only. The settlement overlay must independently
  // check actual Native account differences and physical participant coverage.
  return ExecutedWorkchainAccountBatch{std::move(input), std::move(effects), std::move(state_meter)};
}
}  // namespace account_engine_detail

// Consume the complete structurally admitted input without rebuilding it or
// accepting another policy/declaration cut. This remains a post-admission
// runner: the enclosing host must check commitment, authenticate the complete
// inbox, and admit proof work BEFORE invoking it. This runner admits old-state
// paths/closures before the engine, not later settlement reads. Structural input
// alone does not grant live execution readiness.
inline td::Result<ExecutedWorkchainAccountBatch> execute_workchain_account_engine(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const AdmittedBatchInput& admitted) {
  gen::UnoV2HostInput::Record input;
  if (!tlb::unpack_cell(admitted.root(), input)) {
    return td::Status::Error("structurally admitted host input cannot be decoded");
  }
  const auto& limits = admitted.policy().resources().input;
  TRY_RESULT(declarations, decode_workchain_account_declarations(input.access, limits.max_reads, limits.max_writes));
  return account_engine_detail::execute(engine, std::move(old_accounts), admitted.root(), declarations,
                                        limits.max_reads, limits.max_writes, &admitted.policy().resources().state);
}

// Retained prototype settlement callers only. Do not route the live batch
// profile through this singleton admission interface or synthesize its limits
// from local defaults. It is removed as the settlement/replay chain is converted.
inline td::Result<ExecutedWorkchainAccountBatch> execute_workchain_account_engine(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations,
    const std::vector<td::Ref<vm::Cell>>& authenticated_inbox,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound) {
  TRY_RESULT(input, encode_workchain_host_input(identity, admitted, declarations, authenticated_inbox,
                                                max_reads, max_writes, max_inbound));
  return account_engine_detail::execute(engine, std::move(old_accounts), std::move(input), declarations,
                                        max_reads, max_writes);
}

}  // namespace block
