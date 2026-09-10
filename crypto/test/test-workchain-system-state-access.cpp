#include "block/workchain-system-state-access.h"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
td::Ref<vm::Cell> fixture(td::Ref<vm::Cell> data, bool include_coordinator = true) {
  auto key = td::Bits256::zero();
  vm::CellBuilder account;
  account.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(key.bits(), 256)
      .store_zeroes(42).store_long(2, 64);
  require(block::CurrencyCollection(1000).store(account), "account balance encoding");
  auto root = account.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(data)
      .store_long(0, 1).finalize();
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  if (include_coordinator) {
    vm::CellBuilder wrapped;
    wrapped.store_ref(root).store_zeroes(256).store_long(1, 64);
    require(accounts.set_builder(key, wrapped), "coordinator dictionary insertion");
  }
  vm::CellBuilder aux;
  aux.store_zeroes(128);
  require(block::CurrencyCollection(1000).store(aux), "shard balance encoding");
  auto extra = aux.store_zeroes(7).finalize();
  auto queue = vm::CellBuilder().store_zeroes(3).finalize();
  return vm::CellBuilder().store_long(0x9023afe2, 32).store_long(-23901, 32)
      .store_long(0, 2).store_long(0, 6).store_long(2, 32).store_long(0, 64)
      .store_long(1, 32).store_long(0, 32).store_long(1, 32).store_long(2, 64).store_long(0, 32)
      .store_ref(queue).store_long(0, 1).store_ref(accounts.get_wrapped_dict_root())
      .store_ref(extra).store_long(0, 1).finalize();
}
}
int main() {
  try {
    using namespace block;
    auto encoded = encode_workchain_coordinator_state({1, {1, 1000000, 23, 2}});
    require(encoded.is_ok(), "system record encoding");
    auto root = fixture(encoded.ok());
    auto acquired = read_workchain_system_state(root, td::Bits256::zero(), WorkchainSystemStateSource::AcquiredView);
    auto proposed = read_workchain_system_state(root, td::Bits256::zero(), WorkchainSystemStateSource::ReceivedCandidate);
    for (const auto* result : {&acquired, &proposed}) {
      require(std::holds_alternative<WorkchainSystemStateView>(*result), "valid frozen path must be accepted");
      const auto& view = std::get<WorkchainSystemStateView>(*result);
      require(view.value.system.base_compute == 1000000 && view.value.system.registered_accounts == 23 &&
          view.value.system.system_pending_count == 2, "system values from frozen path");
      require(view.coordinator_data->get_hash() == encoded.ok()->get_hash(), "original system container retained");
    }
    auto bad = fixture(vm::CellBuilder().finalize());
    for (auto source : {WorkchainSystemStateSource::ReceivedCandidate, WorkchainSystemStateSource::AcquiredView}) {
      auto result = read_workchain_system_state(bad, td::Bits256::zero(), source);
      require(std::holds_alternative<WorkchainSystemStateReadFailure>(result), "invalid system container rejected");
      const auto& failed = std::get<WorkchainSystemStateReadFailure>(result);
      require(failed.reason == WorkchainSystemStateReadReason::Malformed, "container failure reason");
      require(failed.category == (source == WorkchainSystemStateSource::ReceivedCandidate
          ? WorkchainExecutionFailure::CandidateInvalid : WorkchainExecutionFailure::LocalUnavailable),
          "failure classification follows acquisition source");
    }
    auto missing = read_workchain_system_state(fixture(encoded.ok(), false), td::Bits256::zero(),
                                               WorkchainSystemStateSource::AcquiredView);
    require(std::holds_alternative<WorkchainSystemStateReadFailure>(missing) &&
        std::get<WorkchainSystemStateReadFailure>(missing).reason == WorkchainSystemStateReadReason::MissingCoordinator,
        "missing coordinator must not initialize defaults");
    auto pruned = fixture(vm::CellBuilder::do_create_pruned_branch(encoded.ok(), 1, 0));
    for (auto source : {WorkchainSystemStateSource::ReceivedCandidate, WorkchainSystemStateSource::AcquiredView}) {
      auto result = read_workchain_system_state(pruned, td::Bits256::zero(), source);
      require(std::holds_alternative<WorkchainSystemStateReadFailure>(result), "pruned system must not decode");
      const auto& failed = std::get<WorkchainSystemStateReadFailure>(result);
      require(failed.reason == WorkchainSystemStateReadReason::Unreadable, "pruning is unreadability, not mismatch");
      require(failed.category == (source == WorkchainSystemStateSource::ReceivedCandidate
          ? WorkchainExecutionFailure::CandidateInvalid : WorkchainExecutionFailure::LocalUnavailable),
          "same pruned representation classified by explicit acquisition source");
    }
    std::cout << "system state frozen-path reads and source classifications passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
