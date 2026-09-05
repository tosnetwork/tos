#include "block/workchain-block-execution.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/transaction.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include <algorithm>

namespace block {
namespace {

constexpr std::uint32_t result_tag = 0x57425232;
constexpr std::uint32_t outputs_tag = 0x57424f31;

bool same_cell(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
  return a.not_null() && b.not_null() && a->get_hash() == b->get_hash();
}

}  // namespace

td::Result<std::vector<td::Ref<vm::Cell>>> decode_workchain_batch_inbound(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing batch inbound list");
  }
  try {
    bool special = false;
    auto cs = vm::load_cell_slice_special(root, special);
    if (special || cs.size() != 48 || cs.size_refs() != 1 || cs.fetch_ulong(32) != 0x57494e31) {
      return td::Status::Error("invalid batch inbound list");
    }
    auto count = cs.fetch_ulong(15);
    if (!count || cs.prefetch_ulong(1) != 1) {
      return td::Status::Error("batch inbound list must be nonempty");
    }
    vm::Dictionary dict(cs, 256);
    using Order = std::pair<std::uint64_t, td::Bits256>;
    std::vector<std::pair<Order, td::Ref<vm::Cell>>> ordered;
    if (!dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int bits) {
          if (bits != 256 || ordered.size() >= count ||
              value->size_ext() != 0x10000) {
            return false;
          }
          auto cell = value->prefetch_ref();
          block::tlb::MsgEnvelope::Record_std envelope;
          gen::CommonMsgInfo::Record_int_msg_info info;
          if (!gen::t_MsgEnvelope.validate_ref(4096, cell) || !tlb::unpack_cell(cell, envelope) ||
              !tlb::unpack_cell_inexact(envelope.msg, info)) {
            return false;
          }
          td::Bits256 hash = envelope.msg->get_hash().bits();
          if (hash != td::Bits256(key)) {
            return false;
          }
          ordered.emplace_back(Order{envelope.emitted_lt ? envelope.emitted_lt.value() : info.created_lt, hash},
                               std::move(cell));
          return true;
        }) || ordered.size() != count) {
      return td::Status::Error("invalid or noncanonical batch inbound entries");
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<td::Ref<vm::Cell>> envelopes;
    envelopes.reserve(ordered.size());
    for (auto& item : ordered) {
      envelopes.push_back(std::move(item.second));
    }
    return envelopes;
  } catch (vm::VmError&) {
    return td::Status::Error("invalid batch inbound cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("incomplete batch inbound proof");
  }
}

td::Result<td::Ref<vm::Cell>> encode_workchain_batch_inbound(const std::vector<td::Ref<vm::Cell>>& envelopes) {
  if (envelopes.empty() || envelopes.size() > 32767) {
    return td::Status::Error("batch inbound count must be between 1 and 32767");
  }
  vm::Dictionary dict(256);
  for (unsigned index = 0; index < envelopes.size(); ++index) {
    block::tlb::MsgEnvelope::Record_std envelope;
    if (envelopes[index].is_null() || !tlb::unpack_cell(envelopes[index], envelope)) {
      return td::Status::Error("cannot encode batch inbound entry");
    }
    if (!dict.set_ref(envelope.msg->get_hash().bits(), 256, envelopes[index], vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("duplicate batch inbound message");
    }
  }
  vm::CellBuilder cb;
  cb.store_long(0x57494e31, 32).store_long(envelopes.size(), 15);
  if (!std::move(dict).append_dict_to_bool(cb)) {
    return td::Status::Error("cannot encode batch inbound dictionary");
  }
  auto root = cb.finalize();
  TRY_RESULT(checked, decode_workchain_batch_inbound(root));
  return root;
}

bool workchain_batch_inbound_contains(const td::Ref<vm::Cell>& root, const td::Ref<vm::Cell>& message) {
  if (root.is_null() || message.is_null()) {
    return false;
  }
  try {
    gen::WorkchainBatchInbound::Record record;
    if (!tlb::unpack_cell(root, record) || !record.count) {
      return false;
    }
    vm::Dictionary dict(record.envelopes, 256);
    auto cell = dict.lookup_ref(message->get_hash().bits(), 256);
    block::tlb::MsgEnvelope::Record_std envelope;
    return cell.not_null() && tlb::unpack_cell(cell, envelope) && envelope.msg->get_hash() == message->get_hash();
  } catch (vm::VmError&) {
    return false;
  } catch (vm::VmVirtError&) {
    return false;
  }
}

td::Result<td::Ref<vm::Cell>> extract_workchain_engine_state(const td::Ref<vm::Cell>& shard_state,
                                                           std::int32_t workchain_id,
                                                           const td::Bits256& executor_address) {
  if (shard_state.is_null() || workchain_id < 0 || workchain_id == tos::workchainInvalid) {
    return td::Status::Error("missing or invalid block workchain state identity");
  }
  try {
    gen::ShardStateUnsplit::Record state;
    gen::ShardIdent::Record shard;
    if (!tlb::unpack_cell(shard_state, state) || !tlb::csr_unpack(state.shard_id, shard)) {
      return td::Status::Error("invalid block workchain shard state");
    }
    if (shard.workchain_id != workchain_id || shard.shard_pfx_bits != 0 || shard.shard_prefix != 0 ||
        state.before_split) {
      return td::Status::Error("block engine requires its own unsplit shard state");
    }
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    td::Ref<vm::CellSlice> executor;
    if (!accounts.validate_check_extra([&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>,
                                          td::ConstBitPtr key, int bits) {
          if (bits != 256 || td::Bits256(key) != executor_address || executor.not_null()) {
            return false;
          }
          executor = std::move(value);
          return true;
        }) || executor.is_null()) {
      return td::Status::Error("block workchain must contain exactly its executor account");
    }
    Account account(workchain_id, executor_address.bits());
    if (!account.unpack(executor, state.gen_utime, false)) {
      return td::Status::Error("invalid block executor account");
    }
    if (account.status != Account::acc_active || account.data.is_null() || account.addr_rewrite_length != 0) {
      return td::Status::Error("block executor requires active state data without address rewriting");
    }
    TRY_RESULT(executor_state, decode_workchain_executor_state(account.data));
    return executor_state.engine_state;
  } catch (vm::VmError&) {
    return td::Status::Error("invalid block workchain state cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("incomplete block workchain state proof");
  }
}

td::Ref<vm::Cell> encode_workchain_batch_description(const WorkchainBatchDescription& description) {
  vm::CellBuilder cb;
  cb.store_long(description.inbound_messages.not_null() ? 9 : 8, 4)
      .store_bits(description.input_hash.bits(), 256).store_bits(description.effects_hash.bits(), 256)
      .store_long(description.usage.wire_bytes, 64).store_long(description.usage.verification_units, 64)
      .store_long(description.usage.written_cells, 64);
  if (description.inbound_messages.not_null()) {
    cb.store_ref(description.inbound_messages);
  }
  return cb.finalize();
}

td::Result<WorkchainBatchDescription> decode_workchain_batch_description(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing batch transaction description");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 708) {
    return td::Status::Error("invalid batch transaction description");
  }
  auto tag = cs.fetch_ulong(4);
  if ((tag != 8 && tag != 9) || cs.size_refs() != (tag == 9 ? 1u : 0u)) {
    return td::Status::Error("invalid batch transaction description");
  }
  WorkchainBatchDescription description;
  if (!cs.fetch_bits_to(description.input_hash) || !cs.fetch_bits_to(description.effects_hash)) {
    return td::Status::Error("incomplete batch transaction commitments");
  }
  description.usage = {cs.fetch_ulong(64), cs.fetch_ulong(64), cs.fetch_ulong(64)};
  if (tag == 9) {
    description.inbound_messages = cs.fetch_ref();
    TRY_RESULT(checked, decode_workchain_batch_inbound(description.inbound_messages));
  }
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
  if (tag > 9) {
    return td::Status::Error("unknown transaction description for execution scope");
  }
  if (scope == WorkchainExecutionScope::AccountCompute && tag < 8) {
    return td::Status::OK();
  }
  if (scope == WorkchainExecutionScope::BlockTransition && (tag == 8 || tag == 9)) {
    return td::Status::OK();
  }
  return td::Status::Error("transaction description does not match execution scope");
}

td::Status validate_workchain_candidate_scope(const td::Ref<vm::Cell>& candidate, WorkchainExecutionScope scope) {
  if ((scope == WorkchainExecutionScope::BlockTransition && candidate.not_null()) ||
      (scope == WorkchainExecutionScope::AccountCompute && candidate.is_null())) {
    return td::Status::OK();
  }
  return td::Status::Error("workchain candidate does not match configured execution scope");
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
  if (input.inbound_messages.not_null()) {
    TRY_RESULT(checked, decode_workchain_batch_inbound(input.inbound_messages));
    auto context = vm::CellBuilder().store_long(0x57424332, 32)
        .store_ref(input.configuration).store_ref(input.finality_context).finalize();
    return vm::CellBuilder().store_long(0x57424932, 32).store_ref(input.previous_shard_state)
        .store_ref(input.candidate).store_ref(context).store_ref(input.inbound_messages).finalize();
  }
  return vm::CellBuilder().store_long(0x57424931, 32).store_ref(input.previous_shard_state)
      .store_ref(input.candidate).store_ref(input.configuration).store_ref(input.finality_context).finalize();
}

namespace {
td::Status validate_executor_state(const WorkchainExecutorState& state) {
  if (state.engine_state.is_null() || state.candidate.is_null() != state.effects.is_null()) {
    return td::Status::Error("incomplete workchain executor state");
  }
  if (state.effects.not_null()) {
    TRY_RESULT(effects, decode_workchain_block_result(state.effects));
    if (effects.new_engine_state->get_hash() != state.engine_state->get_hash()) {
      return td::Status::Error("executor state differs from stored batch effects");
    }
  }
  return td::Status::OK();
}
}  // namespace

td::Result<td::Ref<vm::Cell>> encode_workchain_executor_state(const WorkchainExecutorState& state) {
  TRY_STATUS(validate_executor_state(state));
  vm::CellBuilder cb;
  cb.store_long(0x57424531, 32).store_ref(state.engine_state).store_long(state.effects.not_null(), 1);
  if (state.effects.not_null()) {
    cb.store_ref(vm::CellBuilder().store_long(0x57425731, 32).store_ref(state.candidate)
                     .store_ref(state.effects).finalize());
  }
  return cb.finalize();
}

td::Result<WorkchainExecutorState> decode_workchain_executor_state(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) {
    return td::Status::Error("missing workchain executor state");
  }
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 33 || cs.fetch_ulong(32) != 0x57424531) {
    return td::Status::Error("invalid workchain executor state");
  }
  bool have_batch = cs.fetch_ulong(1) != 0;
  if (cs.size_refs() != (have_batch ? 2u : 1u)) {
    return td::Status::Error("invalid workchain executor state references");
  }
  WorkchainExecutorState state;
  state.engine_state = cs.fetch_ref();
  if (have_batch) {
    auto witness = vm::load_cell_slice_special(cs.fetch_ref(), special);
    if (special || witness.size() != 32 || witness.size_refs() != 2 || witness.fetch_ulong(32) != 0x57425731) {
      return td::Status::Error("invalid stored workchain batch witness");
    }
    state.candidate = witness.fetch_ref();
    state.effects = witness.fetch_ref();
  }
  TRY_STATUS(validate_executor_state(state));
  return state;
}

td::Result<WorkchainBatchDescription> make_workchain_batch_description(const WorkchainBlockInput& input,
                                                                     const WorkchainBlockResult& effects) {
  TRY_RESULT(context, encode_workchain_block_input(input));
  TRY_RESULT(encoded_effects, encode_workchain_block_result(effects));
  WorkchainBatchDescription description;
  description.input_hash = context->get_hash().bits();
  description.effects_hash = encoded_effects->get_hash().bits();
  description.usage = effects.usage;
  description.inbound_messages = input.inbound_messages;
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
      !(claimed.usage == actual.usage) ||
      (!(claimed.inbound_messages.is_null() && actual.inbound_messages.is_null()) &&
       !same_cell(claimed.inbound_messages, actual.inbound_messages))) {
    return td::Status::Error("batch transaction commitments differ from replay");
  }
  return effects;
}

td::Result<td::Ref<vm::Cell>> replay_workchain_batch_transaction(
    const WorkchainBlockEngine& engine, const WorkchainBlockInput& input, const td::Ref<vm::Cell>& claimed,
    std::int32_t workchain_id, const td::Bits256& executor_address, std::uint64_t expected_lt,
    std::uint32_t expected_utime, const SerializeConfig& cfg, const ActionPhaseConfig* message_cfg) {
  if (claimed.is_null()) {
    return td::Status::Error("missing batch transaction");
  }
  try {
    gen::Transaction::Record record;
    if (!gen::t_Transaction.validate_ref(4096, claimed) || !tlb::unpack_cell(claimed, record)) {
      return td::Status::Error("invalid batch transaction encoding");
    }
    TRY_STATUS(validate_transaction_execution_scope(record.description, WorkchainExecutionScope::BlockTransition));
    if (record.account_addr != executor_address || record.lt != expected_lt || record.now != expected_utime) {
      return td::Status::Error("batch transaction identity or time differs from host context");
    }
    TRY_RESULT(previous_data, extract_workchain_engine_state(input.previous_shard_state, workchain_id, executor_address));
    gen::ShardStateUnsplit::Record previous;
    if (!tlb::unpack_cell(input.previous_shard_state, previous)) {
      return td::Status::Error("invalid batch replay shard state");
    }
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(previous.accounts), 256, block::tlb::aug_ShardAccounts);
    Account account(workchain_id, executor_address.bits());
    if (!account.unpack(accounts.lookup(executor_address), expected_utime, false)) {
      return td::Status::Error("invalid batch replay account");
    }
    TRY_RESULT(effects, replay_workchain_batch(engine, input, record.description));
    transaction::Transaction actual(account, transaction::Transaction::tr_workchain_batch, expected_lt, expected_utime);
    TRY_STATUS(actual.prepare_workchain_batch(input, effects, cfg, message_cfg));
    if (actual.start_lt != expected_lt || !actual.serialize(cfg)) {
      return td::Status::Error("cannot reconstruct batch transaction");
    }
    if (actual.root->get_hash() != claimed->get_hash()) {
      return td::Status::Error("batch transaction wrapper differs from replay");
    }
    return actual.new_total_state;
  } catch (vm::VmError&) {
    return td::Status::Error("invalid batch transaction replay cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("incomplete batch transaction replay proof");
  }
}

td::Result<td::Ref<vm::Cell>> replay_workchain_batch_state(
    const WorkchainBlockEngine& engine, const WorkchainBlockReplayContext& context,
    const td::Ref<vm::Cell>& claimed_shard, const td::Ref<vm::Cell>& claimed_transaction,
    std::int32_t workchain_id, const td::Bits256& executor_address, std::uint64_t expected_lt,
    std::uint32_t expected_utime, const SerializeConfig& cfg, const ActionPhaseConfig* message_cfg) {
  if (claimed_transaction.is_null()) {
    return td::Status::Error("missing batch transaction");
  }
  try {
    TRY_RESULT(engine_state, extract_workchain_engine_state(claimed_shard, workchain_id, executor_address));
    gen::ShardStateUnsplit::Record state;
    if (!tlb::unpack_cell(claimed_shard, state)) {
      return td::Status::Error("invalid claimed batch shard state");
    }
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    Account account(workchain_id, executor_address.bits());
    if (!account.unpack(accounts.lookup(executor_address), expected_utime, false)) {
      return td::Status::Error("invalid claimed batch executor account");
    }
    if (account.last_trans_hash_ != claimed_transaction->get_hash().bits() || account.last_trans_lt_ != expected_lt) {
      return td::Status::Error("claimed executor transaction link differs from batch");
    }
    TRY_RESULT(witness, decode_workchain_executor_state(account.data));
    if (witness.candidate.is_null()) {
      return td::Status::Error("claimed executor state is missing batch witness");
    }
    WorkchainBlockInput input{context.previous_shard_state, witness.candidate,
                              context.configuration, context.finality_context, context.inbound_messages};
    TRY_RESULT(reconstructed, replay_workchain_batch_transaction(
        engine, input, claimed_transaction, workchain_id, executor_address, expected_lt, expected_utime, cfg, message_cfg));
    if (!same_cell(reconstructed, account.total_state)) {
      return td::Status::Error("claimed executor account differs from batch replay");
    }
    return reconstructed;
  } catch (vm::VmError&) {
    return td::Status::Error("invalid batch state replay cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("incomplete batch state replay proof");
  }
}

}  // namespace block
