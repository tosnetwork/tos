#pragma once

#include <limits>

#include "block/workchain-execution-dispatch.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

namespace block::test {

// Deterministic test engine only; never registered by production node startup.
inline td::Ref<vm::Cell> counter_number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

class CounterEngine final : public block::RegisteredWorkchainBlockEngine {
 public:
  explicit CounterEngine(block::WorkchainBlockResourceUsage limits = {8, 1, 3}, std::uint64_t verification_units = 1)
      : limits_(limits), verification_units_(verification_units) {
  }

  td::Result<block::WorkchainBlockPolicy> block_policy(
      const block::WorkchainExecutionDescriptor&, const block::WorkchainEngineConfig&) const override {
    return block::WorkchainBlockPolicy{td::Bits256::zero(), limits_};
  }
  block::WorkchainEngineKey engine_key() const override {
    return {block::WorkchainFormat::Basic, 0x434e5431};
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor, const block::Config&) const override {
    if (descriptor.min_split != 0 || descriptor.max_split != 0) {
      return td::Status::Error("counter requires an unsplit workchain");
    }
    if (descriptor.vm_mode != 0) {
      return std::shared_ptr<const block::WorkchainEngineConfig>{};
    }
    return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<block::WorkchainEngineConfig>());
  }

  td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& input) const override {
    TRY_RESULT(engine_state, block::extract_workchain_engine_state(input.previous_shard_state, 2, td::Bits256::zero()));
    auto state = vm::load_cell_slice(engine_state);
    auto candidate = vm::load_cell_slice(input.candidate);
    if (state.size() != 64 || state.size_refs() != 0 || candidate.size() != 64 || candidate.size_refs() != 0) {
      return td::Status::Error("counter input shape");
    }
    const auto value = state.fetch_ulong(64);
    const auto increment = candidate.fetch_ulong(64);
    if (increment > std::numeric_limits<std::uint64_t>::max() - value) {
      return td::Status::Error("counter overflow");
    }
    block::WorkchainBlockResult result;
    result.new_engine_state = counter_number(value + increment);
    result.outbound_messages = vm::CellBuilder().store_long(0, 1).finalize();
    result.actions = input.candidate;
    result.receipts = result.new_engine_state;
    result.events = counter_number(increment);
    result.data_availability = input.candidate;
    result.usage = {8, verification_units_, 3};
    return result;
  }

 private:
  block::WorkchainBlockResourceUsage limits_;
  std::uint64_t verification_units_;
};

}  // namespace block::test

