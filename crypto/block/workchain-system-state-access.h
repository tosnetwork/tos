#pragma once

#include "block/workchain-coordinator-state.h"
#include "block/block.h"
#include "block/block-parse.h"
#include "vm/dict.h"
#include "block/workchain-execution-errors.h"
#include <new>
#include <variant>

namespace block {

// Representation acquisition, not logical ownership. A locally constructed
// proof view must use AcquiredView even when it describes candidate state.
enum class WorkchainSystemStateSource { ReceivedCandidate, AcquiredView };
enum class WorkchainSystemStateReadReason { Unreadable, Malformed, MissingCoordinator, WrongAddress, Allocation };
struct WorkchainSystemStateReadFailure {
  WorkchainExecutionFailure category;
  WorkchainSystemStateReadReason reason;
};
struct WorkchainSystemStateView {
  td::Ref<vm::Cell> coordinator_account;
  td::Ref<vm::Cell> coordinator_data;
  WorkchainCoordinatorState value;
};
using WorkchainSystemStateReadResult = std::variant<WorkchainSystemStateView, WorkchainSystemStateReadFailure>;

// D43 frozen location: ShardAccounts[authenticated coordinator] -> Native
// Account.StateInit.data -> UnoV2CoordinatorState.system. No fallback root.
// This decodes transport/state only; collator and validator must each acquire
// their own authenticated predecessor and independently derive transitions.
// Bitwise comparison of the derived system cells is safe only while D28 is
// deterministic: no local policy/randomness and division truncating toward
// zero. A new locally dependent or unspecified rounding term breaks that rule.
inline WorkchainSystemStateReadResult read_workchain_system_state(
    const td::Ref<vm::Cell>& shard_root, const td::Bits256& authenticated_coordinator,
    WorkchainSystemStateSource source) {
  auto failure = [source](WorkchainSystemStateReadReason reason) -> WorkchainSystemStateReadResult {
    switch (source) {
      case WorkchainSystemStateSource::ReceivedCandidate:
        return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::CandidateInvalid, reason};
      case WorkchainSystemStateSource::AcquiredView:
        return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::LocalUnavailable, reason};
    }
    return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::LocalUnavailable,
                                          WorkchainSystemStateReadReason::Malformed};
  };
  try {
    if (shard_root.is_null()) return failure(WorkchainSystemStateReadReason::Unreadable);
    bool special = false;
    vm::load_cell_slice_special(shard_root, special);
    if (special) return failure(WorkchainSystemStateReadReason::Unreadable);
    gen::ShardStateUnsplit::Record shard;
    gen::ShardIdent::Record shard_id;
    if (!resource_policy_detail::unpack_exact(shard_root, shard) || !tlb::csr_unpack(shard.shard_id, shard_id) ||
        shard_id.workchain_id != 2) return failure(WorkchainSystemStateReadReason::Malformed);
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(shard.accounts), 256, tlb::aug_ShardAccounts);
    auto entry = accounts.lookup(authenticated_coordinator);
    if (entry.is_null()) return failure(WorkchainSystemStateReadReason::MissingCoordinator);
    gen::ShardAccount::Record wrapped;
    gen::Account::Record_account account;
    gen::AccountStorage::Record storage;
    gen::AccountState::Record_account_active active;
    gen::StateInit::Record init;
    if (!tlb::csr_unpack(entry, wrapped) || !resource_policy_detail::unpack_exact(wrapped.account, account) ||
        !tlb::csr_unpack(account.storage, storage) || !tlb::csr_unpack(storage.state, active) ||
        !tlb::csr_unpack(active.x, init) || init.data->size_ext() != 0x10001 || init.data->prefetch_ulong(1) != 1)
      return failure(WorkchainSystemStateReadReason::Malformed);
    tos::WorkchainId wc;
    td::Bits256 address;
    if (!tlb::t_MsgAddressInt.extract_std_address(account.addr, wc, address) || wc != 2 ||
        address != authenticated_coordinator) return failure(WorkchainSystemStateReadReason::WrongAddress);
    auto data = init.data->prefetch_ref();
    // Unlike the outer shard/dictionary, this fixed two-record closure cannot
    // contain unrelated pruned branches. Its complete representation is needed.
    if (data->get_level() != 0) return failure(WorkchainSystemStateReadReason::Unreadable);
    auto decoded = decode_workchain_coordinator_state(data);
    if (decoded.is_error()) return failure(WorkchainSystemStateReadReason::Malformed);
    return WorkchainSystemStateView{wrapped.account, data, decoded.move_as_ok()};
  } catch (const vm::VmVirtError&) {
    return failure(WorkchainSystemStateReadReason::Unreadable);
  } catch (const vm::VmError&) {
    return failure(WorkchainSystemStateReadReason::Malformed);
  } catch (const vm::CellBuilder::CellCreateError&) {
    return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::LocalUnavailable,
                                          WorkchainSystemStateReadReason::Allocation};
  } catch (const vm::CellBuilder::CellWriteError&) {
    return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::LocalUnavailable,
                                          WorkchainSystemStateReadReason::Allocation};
  } catch (const std::bad_alloc&) {
    return WorkchainSystemStateReadFailure{WorkchainExecutionFailure::LocalUnavailable,
                                          WorkchainSystemStateReadReason::Allocation};
  }
}
}  // namespace block
