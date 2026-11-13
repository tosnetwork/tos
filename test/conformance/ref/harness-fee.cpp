// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// fee harness: fee and gas arithmetic the node computes from explicit prices (schema/harness/fee-v1.schema.json).
//
// Each kind calls the node's own function on prices and inputs taken from the context:
//   storage       block::StoragePrices::compute_storage_fees
//   gas_purchase  block::ComputePhaseConfig::compute_threshold, gas_bought_for, compute_gas_price
//   forward       block::MsgPrices::compute_fwd_fees, compute_fwd_ihr_fees, get_first_part, get_next_part
#include <string>
#include <vector>

#include "block/mc-config.h"
#include "block/transaction.h"
#include "common/refint.h"

#include "common.h"

namespace {

constexpr std::size_t kMaxPeriods = 64;

// Unsigned 64-bit context values travel as decimal strings: JSON numbers cannot hold all of them.
td::Result<td::uint64> u64_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string::npos) {
    return td::Status::Error(PSLICE() << field << ": unsigned decimal required");
  }
  auto value = td::dec_string_to_int256(text);
  if (value.is_null() || !value->unsigned_fits_bits(64)) {
    return td::Status::Error(PSLICE() << field << ": does not fit 64 bits");
  }
  return static_cast<td::uint64>(std::stoull(text));
}

td::Result<td::uint32> u32_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(value, obj.get_required_long_field(field));
  if (value < 0 || value > 0xffffffffLL) {
    return td::Status::Error(PSLICE() << field << ": 32-bit unsigned required");
  }
  return static_cast<td::uint32>(value);
}

std::string dec(const td::RefInt256 &value) {
  return value.is_null() ? std::string("null") : conformance::json_quote(value->to_dec_string());
}

std::string dec(td::uint64 value) {
  return conformance::json_quote(std::to_string(value));
}

td::Result<std::string> run_storage(td::JsonObject &ctx) {
  TRY_RESULT(now, u32_field(ctx, "now"));
  TRY_RESULT(last_paid, u32_field(ctx, "last_paid"));
  block::StorageUsed used;
  TRY_RESULT_ASSIGN(used.cells, u64_field(ctx, "cells"));
  TRY_RESULT_ASSIGN(used.bits, u64_field(ctx, "bits"));
  TRY_RESULT(special, ctx.get_required_bool_field("special"));
  TRY_RESULT(masterchain, ctx.get_required_bool_field("masterchain"));
  TRY_RESULT(periods_value, ctx.extract_required_field("periods", td::JsonValue::Type::Array));
  auto &list = periods_value.get_array();
  if (list.size() > kMaxPeriods) {
    return td::Status::Error("too many storage price periods");
  }
  std::vector<block::StoragePrices> periods;
  for (auto &item : list) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("a storage price period must be an object");
    }
    auto &period = item.get_object();
    TRY_RESULT(since, u32_field(period, "since"));
    TRY_RESULT(bit_price, u64_field(period, "bit_price"));
    TRY_RESULT(cell_price, u64_field(period, "cell_price"));
    TRY_RESULT(mc_bit_price, u64_field(period, "mc_bit_price"));
    TRY_RESULT(mc_cell_price, u64_field(period, "mc_cell_price"));
    periods.emplace_back(since, bit_price, cell_price, mc_bit_price, mc_cell_price);
  }
  auto fee = block::StoragePrices::compute_storage_fees(now, periods, used, last_paid, special, masterchain);
  return "{\"outcome\":\"storage\",\"fee\":" + dec(fee) + "}";
}

td::Result<std::string> run_gas_purchase(td::JsonObject &ctx) {
  block::ComputePhaseConfig config{};
  TRY_RESULT_ASSIGN(config.gas_price, u64_field(ctx, "gas_price"));
  TRY_RESULT_ASSIGN(config.gas_limit, u64_field(ctx, "gas_limit"));
  TRY_RESULT_ASSIGN(config.flat_gas_limit, u64_field(ctx, "flat_gas_limit"));
  TRY_RESULT_ASSIGN(config.flat_gas_price, u64_field(ctx, "flat_gas_price"));
  TRY_RESULT(balance_text, ctx.get_required_string_field("balance"));
  if (balance_text.empty() || balance_text.size() > 39 ||
      balance_text.find_first_not_of("0123456789") != std::string::npos) {
    return td::Status::Error("balance: unsigned decimal required");
  }
  auto balance = td::dec_string_to_int256(balance_text);
  if (balance.is_null() || balance->bit_size(false) > 128) {
    return td::Status::Error("balance: more than 128 bits");
  }
  config.compute_threshold();
  // The fee functions take the gas amount as uint64: the balance's low 64 bits, as
  // emulator/test/gas-purchase.cpp passes them, independently of the signed scalar conversions above.
  auto low = td::mod(balance, td::make_refint(1) << 64);
  const td::uint64 gas_used = std::stoull(low->to_dec_string());
  // The variable-price fee without the flat part, as GETGASFEESIMPLE computes it.
  auto simple = td::rshift(td::make_refint(config.gas_price) * gas_used, 16, 1);
  return "{\"outcome\":\"gas_purchase\",\"threshold\":" + dec(config.max_gas_threshold) +
         ",\"gas_bought\":" + dec(config.gas_bought_for(balance)) +
         ",\"fee\":" + dec(config.compute_gas_price(gas_used)) + ",\"simple_fee\":" + dec(simple) + "}";
}

td::Result<std::string> run_forward(td::JsonObject &ctx) {
  TRY_RESULT(lump, u64_field(ctx, "lump_price"));
  TRY_RESULT(bit_price, u64_field(ctx, "bit_price"));
  TRY_RESULT(cell_price, u64_field(ctx, "cell_price"));
  TRY_RESULT(ihr_factor, u32_field(ctx, "ihr_factor"));
  TRY_RESULT(first_frac, u32_field(ctx, "first_frac"));
  TRY_RESULT(next_frac, u32_field(ctx, "next_frac"));
  TRY_RESULT(cells, u64_field(ctx, "cells"));
  TRY_RESULT(bits, u64_field(ctx, "bits"));
  TRY_RESULT(ihr_disabled, ctx.get_optional_bool_field("ihr_disabled", false));
  const block::MsgPrices prices(lump, bit_price, cell_price, ihr_factor, first_frac, next_frac);
  const auto fwd = prices.compute_fwd_fees(cells, bits);
  const auto fwd256 = prices.compute_fwd_fees256(cells, bits);
  const auto fwd_ihr = prices.compute_fwd_ihr_fees(cells, bits, ihr_disabled);
  return "{\"outcome\":\"forward\",\"fwd_fee\":" + dec(fwd) + ",\"fwd_fee_256\":" + dec(fwd256) +
         ",\"ihr_fwd_fee\":" + dec(fwd_ihr.first) + ",\"ihr_fee\":" + dec(fwd_ihr.second) +
         ",\"first_part\":" + dec(prices.get_first_part(fwd)) +
         ",\"first_part_256\":" + dec(prices.get_first_part(fwd256)) +
         ",\"next_part_256\":" + dec(prices.get_next_part(fwd256)) + "}";
}

td::Result<std::string> run_fee(td::JsonObject &ctx) {
  TRY_RESULT(kind, ctx.get_required_string_field("kind"));
  if (kind == "storage") {
    return run_storage(ctx);
  }
  if (kind == "gas_purchase") {
    return run_gas_purchase(ctx);
  }
  if (kind == "forward") {
    return run_forward(ctx);
  }
  return td::Status::Error("unknown fee kind");
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(fee, run_fee);
