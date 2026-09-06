#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "td/utils/Status.h"
#include "td/utils/bits.h"
#include "vm/cells/Cell.h"
#include "block/workchain-execution-errors.h"

namespace block {

struct SerializeConfig;
struct ActionPhaseConfig;

enum class WorkchainExecutionScope : std::uint8_t { AccountCompute = 0, BlockTransition = 1 };

// This host version pays ordinary native message fees from its operating balance.
// Batch execution has no StoragePhase; this flag is not a storage-rent exemption.
inline constexpr bool kWorkchainExecutorIsSpecial = false;

// The host authenticates configuration and finality before constructing this input.
// Engines receive immutable cells and never own database or message-queue handles.
struct WorkchainBlockInput {
  // Commits native queues, processed-up-to and dispatch state as well as accounts.
  td::Ref<vm::Cell> previous_shard_state;
  td::Ref<vm::Cell> candidate;
  td::Ref<vm::Cell> configuration;
  td::Ref<vm::Cell> finality_context;
  // Nonempty canonical envelope list, authenticated by native queue validation.
  td::Ref<vm::Cell> inbound_messages = {};
};

// Read-only view of OutMsgQueueInfo from the committed previous shard header.
// No duplicate queue input: host queue proofs, routing, dequeue/enqueue and
// processed-up-to validation remain mandatory. This does not authenticate cells
// or traverse queue contents, and engines cannot return a replacement queue.
td::Result<td::Ref<vm::Cell>> extract_workchain_native_queue_state(const WorkchainBlockInput& input);

// Optional host-local acceleration. Entries are bound to the storage dictionary
// hash in the authenticated account, never used as an alternative state source.
struct WorkchainReplayStorageCache {
  std::function<td::Ref<vm::Cell>(const td::Bits256&)> lookup;
  // Collect computed indexes locally; the host publishes them only after the
  // enclosing block passes all checks. This callback never commits chain state.
  std::function<void(td::Ref<vm::Cell>, td::uint32)> remember;
};

// Candidate data is recovered from the claimed state, never supplied by a local cache.
struct WorkchainBlockReplayContext {
  td::Ref<vm::Cell> previous_shard_state;
  td::Ref<vm::Cell> configuration;
  td::Ref<vm::Cell> finality_context;
  td::Ref<vm::Cell> inbound_messages = {};
  const WorkchainReplayStorageCache* storage_cache = nullptr;
};

// Select a start LT strictly after host/message events, leaving one LT for end.
// The host remains responsible for authenticating the supplied inbox.
td::Result<std::uint64_t> workchain_batch_start_lt(std::uint64_t host_after_lt,
                                                const td::Ref<vm::Cell>& inbound_messages = {});

// Reconstruct the engine inbox from native imports, not the claimed batch list.
// Queue proofs, dictionary keys and transaction backlinks remain host checks.
// Deferred transit contributes no engine input; an empty result is null.
td::Result<td::Ref<vm::Cell>> workchain_batch_inbound_from_imports(
    const std::vector<td::Ref<vm::Cell>>& imports);

// Decode orders by (emitted LT, message hash), falling back to created LT.
// Engines may apply their own authenticated source-locator order afterwards.
// These helpers do not authenticate message delivery.
td::Result<td::Ref<vm::Cell>> encode_workchain_batch_inbound(const std::vector<td::Ref<vm::Cell>>& envelopes);
td::Result<std::vector<td::Ref<vm::Cell>>> decode_workchain_batch_inbound(const td::Ref<vm::Cell>& root);
// Membership only. The caller separately validates the complete list and transaction.
bool workchain_batch_inbound_contains(const td::Ref<vm::Cell>& root, const td::Ref<vm::Cell>& message);

struct WorkchainBlockResourceUsage {
  std::uint64_t wire_bytes{0};
  std::uint64_t verification_units{0};
  std::uint64_t written_cells{0};

  bool operator==(const WorkchainBlockResourceUsage&) const = default;
};

struct WorkchainBlockResult {
  // Engine-owned state only. The host constructs the account, transaction and shard afterwards.
  td::Ref<vm::Cell> new_engine_state;
  // Host settlement interprets this as ordered HashmapE 15 ^MessageRelaxed
  // requests (internal messages, fixed send mode 1), not finalized messages.
  td::Ref<vm::Cell> outbound_messages;
  td::Ref<vm::Cell> actions;
  td::Ref<vm::Cell> receipts;
  td::Ref<vm::Cell> events;
  td::Ref<vm::Cell> data_availability;
  WorkchainBlockResourceUsage usage;
};

// Only the latest batch is retained here; historical witnesses belong to archived blocks/states.
struct WorkchainExecutorState {
  td::Ref<vm::Cell> engine_state;
  td::Ref<vm::Cell> candidate;
  td::Ref<vm::Cell> effects;
};
td::Result<td::Ref<vm::Cell>> encode_workchain_executor_state(const WorkchainExecutorState& state);
td::Result<WorkchainExecutorState> decode_workchain_executor_state(const td::Ref<vm::Cell>& root);

// Neither hash may depend on this transaction or the final shard wrapper.
struct WorkchainBatchDescription {
  td::Bits256 input_hash{td::Bits256::zero()};
  td::Bits256 effects_hash{td::Bits256::zero()};
  WorkchainBlockResourceUsage usage;
  td::Ref<vm::Cell> inbound_messages = {};
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
td::Status validate_workchain_candidate_scope(const td::Ref<vm::Cell>& candidate, WorkchainExecutionScope scope);

class WorkchainBlockEngine {
 public:
  virtual ~WorkchainBlockEngine() = default;
  // Use load_cell_slice_special with the input's own wire policy, not implicit
  // library resolution. Reject forbidden candidate representations explicitly;
  // authenticated-state corruption and local failures use the reserved codes.
  // Do not apply the candidate's ordinary-only rule to native message bodies.
  virtual td::Result<WorkchainBlockResult> execute_block(const WorkchainBlockInput& input) const = 0;
};

// Replay from authenticated input and compare the complete pre-wrapper effect commitment.
td::Result<WorkchainBlockResult> replay_workchain_batch(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const td::Ref<vm::Cell>& description);

// Returns reconstructed Account state without committing. Identity, time and config come from the host.
td::Result<td::Ref<vm::Cell>> replay_workchain_batch_transaction(
    const WorkchainBlockEngine& engine, const WorkchainBlockInput& input, const td::Ref<vm::Cell>& claimed,
    std::int32_t workchain_id, const td::Bits256& executor_address, std::uint64_t expected_lt,
    std::uint32_t expected_utime, const SerializeConfig& cfg, const ActionPhaseConfig* message_cfg = nullptr,
    const WorkchainReplayStorageCache* storage_cache = nullptr);

// Checks the persisted witness, reconstructed Account and final transaction link.
// The host separately authenticates context and validates shard header/queues/value flow.
td::Result<td::Ref<vm::Cell>> replay_workchain_batch_state(
    const WorkchainBlockEngine& engine, const WorkchainBlockReplayContext& context,
    const td::Ref<vm::Cell>& claimed_shard, const td::Ref<vm::Cell>& claimed_transaction,
    std::int32_t workchain_id, const td::Bits256& executor_address, std::uint64_t expected_lt,
    std::uint32_t expected_utime, const SerializeConfig& cfg, const ActionPhaseConfig* message_cfg = nullptr);

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
