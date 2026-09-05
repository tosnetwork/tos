#pragma once

#include <cstdint>

#include "td/utils/Status.h"
#include "td/utils/bits.h"
#include "vm/cells/Cell.h"

namespace block {

enum class WorkchainExecutionScope : std::uint8_t { AccountCompute = 0, BlockTransition = 1 };

// The host authenticates configuration and finality before constructing this input.
// Engines receive immutable cells and never own database or message-queue handles.
struct WorkchainBlockInput {
  td::Ref<vm::Cell> previous_shard_state;
  td::Ref<vm::Cell> candidate;
  td::Ref<vm::Cell> configuration;
  td::Ref<vm::Cell> finality_context;
};

struct WorkchainBlockResourceUsage {
  std::uint64_t wire_bytes{0};
  std::uint64_t verification_units{0};
  std::uint64_t written_cells{0};

  bool operator==(const WorkchainBlockResourceUsage&) const = default;
};

struct WorkchainBlockResult {
  // Engine-owned state only. The host constructs the account, transaction and shard afterwards.
  td::Ref<vm::Cell> new_engine_state;
  td::Ref<vm::Cell> outbound_messages;
  td::Ref<vm::Cell> actions;
  td::Ref<vm::Cell> receipts;
  td::Ref<vm::Cell> events;
  td::Ref<vm::Cell> data_availability;
  WorkchainBlockResourceUsage usage;
};

// Neither hash may depend on this transaction or the final shard wrapper.
struct WorkchainBatchDescription {
  td::Bits256 input_hash{td::Bits256::zero()};
  td::Bits256 effects_hash{td::Bits256::zero()};
  WorkchainBlockResourceUsage usage;
};

td::Ref<vm::Cell> encode_workchain_batch_description(const WorkchainBatchDescription& description);
td::Result<WorkchainBatchDescription> decode_workchain_batch_description(const td::Ref<vm::Cell>& root);
td::Result<td::Ref<vm::Cell>> encode_workchain_block_input(const WorkchainBlockInput& input);
// Requires exactly one active executor account in an unsplit, already authenticated shard.
td::Result<td::Ref<vm::Cell>> extract_workchain_engine_state(const td::Ref<vm::Cell>& shard_state,
                                                           std::int32_t workchain_id,
                                                           const td::Bits256& executor_address);
td::Result<WorkchainBatchDescription> make_workchain_batch_description(const WorkchainBlockInput& input,
                                                                     const WorkchainBlockResult& effects);
// Scope check only; callers must separately validate the full transaction encoding.
td::Status validate_transaction_execution_scope(const td::Ref<vm::Cell>& description, WorkchainExecutionScope scope);

class WorkchainBlockEngine {
 public:
  virtual ~WorkchainBlockEngine() = default;
  virtual td::Result<WorkchainBlockResult> execute_block(const WorkchainBlockInput& input) const = 0;
};

// Replay from authenticated input and compare the complete pre-wrapper effect commitment.
td::Result<WorkchainBlockResult> replay_workchain_batch(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const td::Ref<vm::Cell>& description);

// These helpers never commit state. The host may commit only after replay succeeds.
td::Status validate_workchain_block_result(const WorkchainBlockResult& result);
// Canonical TL-B envelope; encoding is not proof of valid execution or authenticated context.
td::Result<td::Ref<vm::Cell>> encode_workchain_block_result(const WorkchainBlockResult& result);
td::Result<WorkchainBlockResult> decode_workchain_block_result(const td::Ref<vm::Cell>& root);
td::Result<WorkchainBlockResult> replay_workchain_block(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const WorkchainBlockResult& claimed);
td::Result<WorkchainBlockResult> replay_workchain_block(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const td::Ref<vm::Cell>& claimed_root);

}  // namespace block
