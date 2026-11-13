// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// txn harness: one transaction through the transaction emulator's C interface, the same native path the
// existing transaction fixtures use (schema/harness/txn-v1.schema.json).
#include <cstdint>
#include <memory>
#include <string>

#include "vm/cellslice.h"

#include "common.h"
#include "emulator-extern.h"

namespace {

struct EmulatorDeleter {
  void operator()(void *emulator) const {
    transaction_emulator_destroy(emulator);
  }
};

td::Result<std::string> checked_boc_field(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(text, ctx.get_required_string_field(field));
  auto cell = conformance::boc_from_base64(text);
  if (cell.is_error()) {
    return td::Status::Error(PSLICE() << field << ": " << cell.error().message());
  }
  return text;
}

td::Result<std::string> run_txn(td::JsonObject &ctx) {
  TRY_RESULT(config, checked_boc_field(ctx, "config"));
  TRY_RESULT(shard_account, checked_boc_field(ctx, "shard_account"));
  TRY_RESULT(now, ctx.get_required_long_field("now"));
  TRY_RESULT(lt, ctx.get_required_long_field("lt"));
  TRY_RESULT(rand_seed, ctx.get_required_string_field("rand_seed"));
  const bool has_message = ctx.has_field("message");
  const bool has_tick_tock = ctx.has_field("tick_tock");
  if (has_message == has_tick_tock) {
    return td::Status::Error("exactly one of message and tick_tock is required");
  }
  if (now <= 0 || now > 0xffffffffLL || lt <= 0) {
    return td::Status::Error("now and lt must be positive, now must fit 32 bits");
  }
  if (rand_seed.size() != 64 || rand_seed.find_first_not_of("0123456789abcdef") != std::string::npos) {
    return td::Status::Error("rand_seed must be 64 lowercase hex digits");
  }
  std::string message;
  bool is_tock = false;
  if (has_message) {
    TRY_RESULT_ASSIGN(message, checked_boc_field(ctx, "message"));
  } else {
    TRY_RESULT(kind, ctx.get_required_string_field("tick_tock"));
    if (kind != "tick" && kind != "tock") {
      return td::Status::Error("tick_tock must be tick or tock");
    }
    is_tock = kind == "tock";
  }
  std::string libraries;
  if (ctx.has_field("libraries")) {
    TRY_RESULT_ASSIGN(libraries, checked_boc_field(ctx, "libraries"));
  }
  std::string prev_blocks;
  if (ctx.has_field("prev_blocks")) {
    TRY_RESULT_ASSIGN(prev_blocks, checked_boc_field(ctx, "prev_blocks"));
  }

  // A fresh emulator per context, so no setting of one context leaks into the next.
  std::unique_ptr<void, EmulatorDeleter> emulator{transaction_emulator_create(config.c_str(), 0)};
  if (!emulator) {
    return td::Status::Error("config refused by the transaction emulator");
  }
  if (!transaction_emulator_set_unixtime(emulator.get(), static_cast<std::uint32_t>(now)) ||
      !transaction_emulator_set_lt(emulator.get(), static_cast<std::uint64_t>(lt)) ||
      !transaction_emulator_set_rand_seed(emulator.get(), rand_seed.c_str()) ||
      !transaction_emulator_set_ignore_chksig(emulator.get(), false)) {
    return td::Status::Error("transaction emulator refused a context parameter");
  }
  if (!libraries.empty() && !transaction_emulator_set_libs(emulator.get(), libraries.c_str())) {
    return td::Status::Error("transaction emulator refused the libraries");
  }
  if (!prev_blocks.empty() && !transaction_emulator_set_prev_blocks_info(emulator.get(), prev_blocks.c_str())) {
    return td::Status::Error("transaction emulator refused the previous blocks");
  }

  const char *raw =
      has_message ? transaction_emulator_emulate_transaction(emulator.get(), shard_account.c_str(), message.c_str())
                  : transaction_emulator_emulate_tick_tock_transaction(emulator.get(), shard_account.c_str(), is_tock);
  if (raw == nullptr) {
    return td::Status::Error("transaction emulator returned no response");
  }
  std::string response{raw};
  string_destroy(raw);

  TRY_RESULT(parsed, td::json_decode(td::MutableSlice(response)));
  if (parsed.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("transaction emulator response is not an object");
  }
  auto &obj = parsed.get_object();
  TRY_RESULT(success, obj.get_required_bool_field("success"));
  if (success) {
    TRY_RESULT(transaction_cell, conformance::required_boc(obj, "transaction"));
    TRY_RESULT(shard_account_cell, conformance::required_boc(obj, "shard_account"));
    if (vm::load_cell_slice(shard_account_cell).size_refs() < 1) {
      return td::Status::Error("ShardAccount without an account reference");
    }
    const auto account_cell = vm::load_cell_slice(shard_account_cell).prefetch_ref(0);
    return "{\"outcome\":\"accepted\",\"transaction_hash\":" +
           conformance::json_quote(conformance::hash_hex(transaction_cell)) +
           ",\"account_hash\":" + conformance::json_quote(conformance::hash_hex(account_cell)) +
           ",\"shard_account_hash\":" + conformance::json_quote(conformance::hash_hex(shard_account_cell)) + "}";
  }
  TRY_RESULT(not_accepted, obj.get_optional_bool_field("external_not_accepted", false));
  if (not_accepted) {
    TRY_RESULT(exit_code, obj.get_required_int_field("vm_exit_code"));
    return "{\"outcome\":\"rejected\",\"vm_exit_code\":" + std::to_string(exit_code) + "}";
  }
  return std::string("{\"outcome\":\"error\"}");
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(txn, run_txn);
