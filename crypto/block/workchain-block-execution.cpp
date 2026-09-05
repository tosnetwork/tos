#include "block/workchain-block-execution.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

namespace block {
namespace {

constexpr std::uint32_t result_tag = 0x57425231;
constexpr std::uint32_t outputs_tag = 0x57424f31;

bool same_cell(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
  return a.not_null() && b.not_null() && a->get_hash() == b->get_hash();
}

}  // namespace

td::Status validate_workchain_block_result(const WorkchainBlockResult& result) {
  if (result.new_shard_state.is_null() || result.batch_transaction.is_null() ||
      result.outbound_messages.is_null() || result.actions.is_null() || result.receipts.is_null() ||
      result.events.is_null() || result.data_availability.is_null()) {
    return td::Status::Error("block execution returned an incomplete result");
  }
  return td::Status::OK();
}

td::Result<td::Ref<vm::Cell>> encode_workchain_block_result(const WorkchainBlockResult& result) {
  TRY_STATUS(validate_workchain_block_result(result));
  auto outputs = vm::CellBuilder().store_long(outputs_tag, 32)
                     .store_ref(result.outbound_messages).store_ref(result.actions)
                     .store_ref(result.receipts).store_ref(result.events).finalize();
  return vm::CellBuilder().store_long(result_tag, 32)
      .store_long(result.usage.wire_bytes, 64).store_long(result.usage.verification_units, 64)
      .store_long(result.usage.written_cells, 64).store_ref(result.new_shard_state)
      .store_ref(result.batch_transaction).store_ref(outputs).store_ref(result.data_availability).finalize();
}

td::Result<WorkchainBlockResult> decode_workchain_block_result(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing block result envelope");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 224 || cs.size_refs() != 4 || cs.fetch_ulong(32) != result_tag) {
    return td::Status::Error("invalid block result envelope");
  }
  WorkchainBlockResult result;
  result.usage = {cs.fetch_ulong(64), cs.fetch_ulong(64), cs.fetch_ulong(64)};
  result.new_shard_state = cs.fetch_ref();
  result.batch_transaction = cs.fetch_ref();
  auto outputs = vm::load_cell_slice_special(cs.fetch_ref(), special);
  result.data_availability = cs.fetch_ref();
  if (special || outputs.size() != 32 || outputs.size_refs() != 4 || outputs.fetch_ulong(32) != outputs_tag) {
    return td::Status::Error("invalid block output envelope");
  }
  result.outbound_messages = outputs.fetch_ref();
  result.actions = outputs.fetch_ref();
  result.receipts = outputs.fetch_ref();
  result.events = outputs.fetch_ref();
  return result;
}

td::Result<WorkchainBlockResult> replay_workchain_block(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const WorkchainBlockResult& claimed) {
  if (input.previous_shard_state.is_null() || input.candidate.is_null() || input.configuration.is_null() ||
      input.finality_context.is_null()) {
    return td::Status::Error("block replay requires state, candidate, configuration and finality");
  }
  TRY_STATUS(validate_workchain_block_result(claimed));
  TRY_RESULT(actual, engine.execute_block(input));
  TRY_STATUS(validate_workchain_block_result(actual));
  if (!same_cell(actual.new_shard_state, claimed.new_shard_state) ||
      !same_cell(actual.batch_transaction, claimed.batch_transaction) ||
      !same_cell(actual.outbound_messages, claimed.outbound_messages) || !same_cell(actual.actions, claimed.actions) ||
      !same_cell(actual.receipts, claimed.receipts) || !same_cell(actual.events, claimed.events) ||
      !same_cell(actual.data_availability, claimed.data_availability) || !(actual.usage == claimed.usage)) {
    return td::Status::Error("block execution replay differs from claimed result");
  }
  return actual;
}

td::Result<WorkchainBlockResult> replay_workchain_block(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const td::Ref<vm::Cell>& claimed_root) {
  TRY_RESULT(claimed, decode_workchain_block_result(claimed_root));
  return replay_workchain_block(engine, input, claimed);
}

}  // namespace block
