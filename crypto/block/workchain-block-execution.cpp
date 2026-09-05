#include "block/workchain-block-execution.h"

namespace block {
namespace {

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

}  // namespace block
