#pragma once

#include <cstdint>

#include "td/utils/Status.h"
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
  td::Ref<vm::Cell> new_shard_state;
  td::Ref<vm::Cell> batch_transaction;
  td::Ref<vm::Cell> outbound_messages;
  td::Ref<vm::Cell> actions;
  td::Ref<vm::Cell> receipts;
  td::Ref<vm::Cell> events;
  td::Ref<vm::Cell> data_availability;
  WorkchainBlockResourceUsage usage;
};

class WorkchainBlockEngine {
 public:
  virtual ~WorkchainBlockEngine() = default;
  virtual td::Result<WorkchainBlockResult> execute_block(const WorkchainBlockInput& input) const = 0;
};

// Neither function commits state. The host may commit only after replay succeeds.
td::Status validate_workchain_block_result(const WorkchainBlockResult& result);
td::Result<WorkchainBlockResult> replay_workchain_block(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const WorkchainBlockResult& claimed);

}  // namespace block
