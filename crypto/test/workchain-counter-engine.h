#pragma once

#include <limits>

#include "block/workchain-execution-dispatch.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace block::test {

// Deterministic test engine only; never registered by production node startup.
inline td::Ref<vm::Cell> counter_number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

// Non-bouncing transfers to an uninitialized native recipient exercise delivery
// without requiring a return-message handler in the test block engine.
inline td::Ref<vm::Cell> counter_message_candidate(std::uint64_t increment, bool to_executor = false,
                                                std::int32_t executor_workchain = 2) {
  auto message = vm::CellBuilder().store_long(4, 4).store_zeroes(2)
      .store_long(4, 3).store_long(to_executor ? executor_workchain : 0, 8)
      .store_zeroes(255).store_long(to_executor ? 0 : 1, 1)
      .store_long(1, 4).store_long(100, 8).store_long(0, 1)
      .store_zeroes(8).store_zeroes(96).store_zeroes(2).finalize();
  vm::Dictionary dict(15);
  for (unsigned index = 0; index < 2; ++index) {
    CHECK(dict.set_ref(td::BitArray<15>(index), message));
  }
  vm::CellBuilder cb;
  CHECK(std::move(dict).append_dict_to_bool(cb));
  return vm::CellBuilder().store_long(increment, 64).store_ref(cb.finalize()).finalize();
}

class CounterEngine final : public block::RegisteredWorkchainBlockEngine {
 public:
  enum class PayloadMode { None, PreserveReference };

  explicit CounterEngine(block::WorkchainBlockResourceUsage limits = {8, 1, 3}, std::uint64_t verification_units = 1,
                         std::int32_t workchain = 2, PayloadMode payload_mode = PayloadMode::None)
      : limits_(limits), verification_units_(verification_units), workchain_(workchain), payload_mode_(payload_mode) {
  }

  td::Result<block::WorkchainBlockPolicy> block_policy(
      const block::WorkchainExecutionDescriptor&, const block::WorkchainEngineConfig&) const override {
    return block::WorkchainBlockPolicy{td::Bits256::zero(), limits_};
  }
  block::WorkchainEngineKey engine_key() const override {
    return {block::WorkchainFormat::Basic, 0x434e5431};
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor, const block::Config&,
      const td::Ref<vm::Cell>& engine_configuration) const override {
    if (engine_configuration.is_null() ||
        engine_configuration->get_hash() != vm::CellBuilder().finalize()->get_hash()) {
      return td::Status::Error("counter requires an empty engine configuration");
    }
    if (descriptor.min_split != 0 || descriptor.max_split != 0) {
      return td::Status::Error("counter requires an unsplit workchain");
    }
    if (descriptor.vm_mode != 0) {
      return std::shared_ptr<const block::WorkchainEngineConfig>{};
    }
    return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<block::WorkchainEngineConfig>());
  }

  td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& input) const override {
    TRY_RESULT(engine_state, block::extract_workchain_engine_state(input.previous_shard_state, workchain_, td::Bits256::zero()));
    auto state = vm::load_cell_slice(engine_state);
    auto candidate = vm::load_cell_slice(input.candidate);
    const unsigned expected_refs = payload_mode_ == PayloadMode::PreserveReference ? 1 : 0;
    if (state.size() != 64 || state.size_refs() != expected_refs || candidate.size() != 64 || candidate.size_refs() > 1) {
      return td::Status::Error("counter input shape");
    }
    const auto value = state.fetch_ulong(64);
    const auto increment = candidate.fetch_ulong(64);
    if (increment > std::numeric_limits<std::uint64_t>::max() - value) {
      return td::Status::Error("counter overflow");
    }
    block::WorkchainBlockResult result;
    vm::CellBuilder next_state;
    next_state.store_long(value + increment, 64);
    if (payload_mode_ == PayloadMode::PreserveReference) {
      next_state.store_ref(state.fetch_ref());
    }
    result.new_engine_state = next_state.finalize();
    result.outbound_messages = candidate.size_refs() ? candidate.fetch_ref()
        : vm::CellBuilder().store_long(0, 1).finalize();
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
  std::int32_t workchain_;
  PayloadMode payload_mode_;
};

}  // namespace block::test
