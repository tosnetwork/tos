// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// get_method harness: one read-only get-method the way the liteserver runs runSmcMethod
// (schema/harness/get_method-v1.schema.json). The configuration, libraries and previous-block context
// come from the masterchain state through block::ConfigInfo; the account is decoded as the liteserver
// decodes it; c7 and the library list come from block::prepare_get_method_c7 and
// block::get_method_libraries, the functions the liteserver and the control getter call.
//
// The libemulator get-method entry points are not used: they build c7 with a zero logical time, a zero
// due payment and a 64-bit balance, and run with an unbounded gas maximum and their own data-depth and
// library-load limits, so their results differ from what a node answers for the same account.
#include <string>
#include <utility>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/get-method-context.h"
#include "block/mc-config.h"
#include "td/utils/misc.h"
#include "vm/cellslice.h"
#include "vm/vm.h"

#include "common.h"

namespace {

constexpr std::size_t kMaxStackItems = 255;

td::Result<td::Bits256> parse_hash(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.size() != 64 || text.find_first_not_of("0123456789ABCDEF") != std::string::npos) {
    return td::Status::Error(PSLICE() << field << " must be 64 uppercase hex digits");
  }
  td::Bits256 bits;
  if (bits.from_hex(text) != 256) {
    return td::Status::Error(PSLICE() << field << " is not a 256-bit hash");
  }
  return bits;
}

td::Result<td::Bits256> parse_seed(td::JsonObject &ctx) {
  TRY_RESULT(text, ctx.get_required_string_field("rand_seed"));
  if (text.size() != 64 || text.find_first_not_of("0123456789abcdef") != std::string::npos) {
    return td::Status::Error("rand_seed must be 64 lowercase hex digits");
  }
  td::Bits256 bits;
  if (bits.from_hex(text) != 256) {
    return td::Status::Error("rand_seed is not 256 bits");
  }
  return bits;
}

td::Result<tos::BlockIdExt> parse_block_id(td::JsonObject &ctx) {
  TRY_RESULT(value, ctx.extract_required_field("mc_block", td::JsonValue::Type::Object));
  auto &obj = value.get_object();
  TRY_RESULT(seqno, obj.get_required_long_field("seqno"));
  if (seqno < 0 || seqno > 0xffffffffLL) {
    return td::Status::Error("mc_block.seqno must fit 32 bits");
  }
  TRY_RESULT(root_hash, parse_hash(obj, "root_hash"));
  TRY_RESULT(file_hash, parse_hash(obj, "file_hash"));
  return tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, static_cast<tos::BlockSeqno>(seqno), root_hash,
                         file_hash};
}

std::string no_state() {
  return "{\"outcome\":\"no_state\"}";
}

// The masterchain state does not yield a configuration (for example a history without a valid
// zerostate entry): there is no context to run in.
std::string context_unavailable() {
  return "{\"outcome\":\"context_unavailable\"}";
}

td::Result<std::string> run_get_method_checked(td::JsonObject &ctx) {
  TRY_RESULT(mc_state, conformance::required_boc(ctx, "mc_state"));
  TRY_RESULT(block_id, parse_block_id(ctx));
  TRY_RESULT(account_cell, conformance::required_boc(ctx, "account"));
  // Both roots may be partial (pruned) snapshots; only the cells a run reads must be present.
  auto account_root = account_cell->virtualize(0);
  TRY_RESULT(now, ctx.get_required_long_field("now"));
  TRY_RESULT(lt, ctx.get_required_long_field("lt"));
  TRY_RESULT(seed, parse_seed(ctx));
  TRY_RESULT(method_text, ctx.get_required_string_field("method_id"));
  TRY_RESULT(gas_limit, ctx.get_required_long_field("gas_limit"));
  if (now < 0 || now > 0xffffffffLL || lt < 0) {
    return td::Status::Error("now must fit 32 bits and lt must be non-negative");
  }
  if (gas_limit < 0) {
    return td::Status::Error("gas_limit must be non-negative");
  }
  // The liteserver method id is a signed 64-bit integer; it travels as text so JSON keeps every bit.
  auto method_id = td::to_integer_safe<td::int64>(method_text);
  if (method_id.is_error() || std::to_string(method_id.ok()) != method_text) {
    return td::Status::Error("method_id must be a canonical signed 64-bit decimal");
  }
  TRY_RESULT(stack_value, ctx.extract_required_field("stack", td::JsonValue::Type::Array));
  auto &items = stack_value.get_array();
  if (items.size() > kMaxStackItems) {
    return td::Status::Error("initial stack too deep");
  }
  td::Ref<vm::Stack> stack{true};
  for (auto &item : items) {
    TRY_RESULT(parsed, conformance::parse_stack_item(item));
    stack.write().push(std::move(parsed));
  }
  stack.write().push_smallint(method_id.ok());

  auto r_config = block::ConfigInfo::extract_config(
      mc_state->virtualize(0), block_id,
      block::ConfigInfo::needLibraries | block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks);
  if (r_config.is_error()) {
    // The liteserver answers such a query with an error and runs nothing.
    return context_unavailable();
  }
  auto config = r_config.move_as_ok();

  // Account decoding as the liteserver does it: an uninitialized, frozen or undecodable account has no
  // state to run, and the liteserver answers without executing.
  block::gen::Account::Record_account acc;
  block::gen::StorageInfo::Record storage_info;
  block::gen::AccountStorage::Record store;
  block::CurrencyCollection balance;
  block::gen::StateInit::Record state_init;
  if (!(tlb::unpack_cell(account_root, acc) && tlb::csr_unpack(std::move(acc.storage), store) &&
        balance.validate_unpack(store.balance) && store.state->prefetch_ulong(1) == 1 &&
        store.state.write().advance(1) && tlb::csr_unpack(std::move(store.state), state_init) &&
        tlb::csr_unpack(std::move(acc.storage_stat), storage_info))) {
    return no_state();
  }
  auto code = state_init.code->prefetch_ref();
  auto data = state_init.data->prefetch_ref();
  auto account_libraries = state_init.library->prefetch_ref();
  td::RefInt256 due_payment;
  if (storage_info.due_payment.write().fetch_long(1)) {
    due_payment = block::tlb::t_Tomis.as_integer(storage_info.due_payment);
  } else {
    due_payment = td::zero_refint();
  }
  if (due_payment.is_null()) {
    return no_state();
  }

  vm::VmState vm{code,
                 config->get_global_version(),
                 std::move(stack),
                 vm::GasLimits{gas_limit, gas_limit},
                 1,
                 std::move(data),
                 vm::VmLog::Null(),
                 block::get_method_libraries(*config, account_libraries)};
  auto c7 = block::prepare_get_method_c7(static_cast<tos::UnixTime>(now), static_cast<tos::LogicalTime>(lt),
                                         td::make_ref<vm::CellSlice>(acc.addr->clone()), balance, config.get(),
                                         std::move(code), due_payment, seed);
  if (c7.is_null()) {
    return context_unavailable();
  }
  vm.set_c7(std::move(c7));
  const int exit_code = ~vm.run();
  const auto missing = vm.get_missing_library();
  return "{\"outcome\":\"executed\",\"exit_code\":" + std::to_string(exit_code) +
         ",\"gas_used\":" + std::to_string(vm.gas_consumed()) +
         ",\"stack\":" + conformance::stack_json(vm.get_stack()) +
         ",\"missing_library\":" + (missing ? conformance::json_quote(missing.value().to_hex()) : std::string("null")) +
         "}";
}

td::Result<std::string> run_get_method(td::JsonObject &ctx) {
  try {
    return run_get_method_checked(ctx);
  } catch (const vm::VmVirtError &) {
    // A partial snapshot that lacks a cell the configuration or the context reads is an incomplete
    // context, not a node answer.
    return td::Status::Error("a cell the get-method context reads is pruned from the supplied state");
  }
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(get_method, run_get_method);
