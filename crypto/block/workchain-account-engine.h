#pragma once

#include "block/workchain-account-dictionary.h"
#include "block/workchain-host-input.h"

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
};

// Post-admission execution, not an authentication certificate. The enclosing
// host must bind old_accounts to the authenticated previous shard and bound its
// read closures before calling. Native source exceptions propagate unchanged;
// this helper never reclassifies missing local data as a candidate mismatch.
// Count bounds alone are not state traversal or execution-work limits.
inline td::Result<ExecutedWorkchainAccountBatch> execute_workchain_account_engine(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations,
    const std::vector<td::Ref<vm::Cell>>& authenticated_inbox,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound) {
  TRY_RESULT(input, encode_workchain_host_input(identity, admitted, declarations, authenticated_inbox,
                                                max_reads, max_writes, max_inbound));
  TRY_RESULT(access, WorkchainAccountAccess::create(declarations.reads, declarations.writes,
                                                   max_reads, max_writes));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(std::move(old_accounts)), 256,
                                  tlb::aug_ShardAccounts);
  std::vector<WorkchainAccountSnapshot> snapshots;
  snapshots.reserve(declarations.reads.size());
  for (const auto& read : declarations.reads) {
    auto expected = access.expected_read(read.account);
    if (expected.is_error()) return expected.move_as_error();
    auto value = accounts.lookup(read.account);
    td::Ref<vm::Cell> state;
    std::optional<td::Bits256> actual;
    if (value.not_null()) {
      tlb::ShardAccount::Record record;
      if (value->size_ext() != 0x10140 || !record.unpack(value)) {
        throw vm::VmError{vm::Excno::dict_err, "invalid old ShardAccount entry"};
      }
      state = record.account;
      actual = td::Bits256(state->get_hash().bits());
    }
    TRY_STATUS(access.record_old_read(read.account, actual));
    snapshots.push_back({read.account, std::move(state)});
  }
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
  return ExecutedWorkchainAccountBatch{std::move(input), std::move(effects)};
}

}  // namespace block
