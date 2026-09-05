#include "block/workchain-block-execution.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

namespace block {
namespace {

constexpr std::uint32_t result_tag = 0x57425232;
constexpr std::uint32_t outputs_tag = 0x57424f31;

bool same_cell(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
  return a.not_null() && b.not_null() && a->get_hash() == b->get_hash();
}

}  // namespace

td::Ref<vm::Cell> encode_workchain_batch_description(const WorkchainBatchDescription& description) {
  return vm::CellBuilder().store_long(8, 4)
      .store_bits(description.input_hash.bits(), 256).store_bits(description.effects_hash.bits(), 256)
      .store_long(description.usage.wire_bytes, 64).store_long(description.usage.verification_units, 64)
      .store_long(description.usage.written_cells, 64).finalize();
}

td::Result<WorkchainBatchDescription> decode_workchain_batch_description(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing batch transaction description");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 708 || cs.size_refs() != 0 || cs.fetch_ulong(4) != 8) {
    return td::Status::Error("invalid batch transaction description");
  }
  WorkchainBatchDescription description;
  if (!cs.fetch_bits_to(description.input_hash) || !cs.fetch_bits_to(description.effects_hash)) {
    return td::Status::Error("incomplete batch transaction commitments");
  }
  description.usage = {cs.fetch_ulong(64), cs.fetch_ulong(64), cs.fetch_ulong(64)};
  return description;
}

td::Status validate_transaction_execution_scope(const td::Ref<vm::Cell>& description, WorkchainExecutionScope scope) {
  if (description.is_null()) {
    return td::Status::Error("missing transaction description for execution scope");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(description, special);
  if (special || cs.size() < 4) {
    return td::Status::Error("invalid transaction description for execution scope");
  }
  auto tag = cs.fetch_ulong(4);
  if (tag > 8) {
    return td::Status::Error("unknown transaction description for execution scope");
  }
  if (scope == WorkchainExecutionScope::AccountCompute && tag < 8) {
    return td::Status::OK();
  }
  if (scope == WorkchainExecutionScope::BlockTransition && tag == 8) {
    return td::Status::OK();
  }
  return td::Status::Error("transaction description does not match execution scope");
}

td::Status validate_workchain_block_result(const WorkchainBlockResult& result) {
  if (result.new_engine_state.is_null() ||
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
      .store_long(result.usage.written_cells, 64).store_ref(result.new_engine_state)
      .store_ref(outputs).store_ref(result.data_availability).finalize();
}

td::Result<WorkchainBlockResult> decode_workchain_block_result(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing block result envelope");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 224 || cs.size_refs() != 3 || cs.fetch_ulong(32) != result_tag) {
    return td::Status::Error("invalid block result envelope");
  }
  WorkchainBlockResult result;
  result.usage = {cs.fetch_ulong(64), cs.fetch_ulong(64), cs.fetch_ulong(64)};
  result.new_engine_state = cs.fetch_ref();
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
  if (!same_cell(actual.new_engine_state, claimed.new_engine_state) ||
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

td::Result<td::Ref<vm::Cell>> encode_workchain_block_input(const WorkchainBlockInput& input) {
  if (input.previous_shard_state.is_null() || input.candidate.is_null() || input.configuration.is_null() ||
      input.finality_context.is_null()) {
    return td::Status::Error("batch commitment requires state, candidate, configuration and finality");
  }
  return vm::CellBuilder().store_long(0x57424931, 32).store_ref(input.previous_shard_state)
      .store_ref(input.candidate).store_ref(input.configuration).store_ref(input.finality_context).finalize();
}

td::Result<WorkchainBatchDescription> make_workchain_batch_description(const WorkchainBlockInput& input,
                                                                     const WorkchainBlockResult& effects) {
  TRY_RESULT(context, encode_workchain_block_input(input));
  TRY_RESULT(encoded_effects, encode_workchain_block_result(effects));
  WorkchainBatchDescription description;
  description.input_hash = context->get_hash().bits();
  description.effects_hash = encoded_effects->get_hash().bits();
  description.usage = effects.usage;
  return description;
}

td::Result<WorkchainBlockResult> replay_workchain_batch(const WorkchainBlockEngine& engine,
                                                      const WorkchainBlockInput& input,
                                                      const td::Ref<vm::Cell>& description) {
  TRY_RESULT(claimed, decode_workchain_batch_description(description));
  TRY_RESULT(context, encode_workchain_block_input(input));
  if (claimed.input_hash != context->get_hash().bits()) {
    return td::Status::Error("batch transaction input commitment differs from authenticated context");
  }
  TRY_RESULT(effects, engine.execute_block(input));
  TRY_RESULT(actual, make_workchain_batch_description(input, effects));
  if (claimed.input_hash != actual.input_hash || claimed.effects_hash != actual.effects_hash ||
      !(claimed.usage == actual.usage)) {
    return td::Status::Error("batch transaction commitments differ from replay");
  }
  return effects;
}

}  // namespace block
