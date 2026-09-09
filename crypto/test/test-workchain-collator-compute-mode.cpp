#include "validator/impl/workchain-collator-compute-mode.h"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* identity) {
  if (!value) throw std::runtime_error(identity);
}
void check(const block::ResolvedScopedWorkchainExecution& execution, bool expected,
           const char* identity) {
  auto result = tos::validator::collator_uses_custom_account_compute(execution);
  require(result.is_ok(), "classification.must_not_authorize_or_refuse_execution");
  require(result.ok() == expected, identity);
}
}

int main() {
  try {
    block::ResolvedWorkchainExecution account;
    account.descriptor.vm_version = static_cast<std::int32_t>(block::tvm_workchain_engine_key().selector);
    require(block::workchain_engine_key_from_descriptor(account.descriptor) == block::tvm_workchain_engine_key(),
            "fixture.tvm_key");
    check(account, false, "tvm.legacy_mode_unchanged");
    account.descriptor.vm_version = 0x434e5431;
    check(account, true, "custom.legacy_mode_unchanged");
    check(block::ResolvedWorkchainBlockExecution{}, false, "singleton.not_account_compute");
    block::WorkchainResourcePolicy resources{2, {1000, 1000000, 3, 2, 2, 1},
        {1000, 1000000, 128, 65536, 64}, {32, 128, 65536, 1000, 1000000, 2}};
    block::InputPolicyIdentity identity{vm::CellHash{}, false, 0x434e5431, 7, 5, 2};
    auto policy = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, identity);
    require(std::holds_alternative<block::ResolvedBatchInputPolicy>(policy), "fixture.policy");
    // Deliberately no executor/configuration: classification must not dereference
    // either, create another adapter, or manufacture an execution permission.
    block::ResolvedWorkchainAccountBinding binding{nullptr, {}, {}, {}, {},
        std::get<block::ResolvedBatchInputPolicy>(policy)};
    check(binding, false, "batch.not_account_compute");
    std::cout << "4 execution classifications passed; no engine invoked\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
