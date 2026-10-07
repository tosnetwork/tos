/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The JSON-RPC server parses account data and get-method results that a
// contract author fully controls. Every parser below used to reach a bare
// cell or dictionary loader that throws vm::VmError on hostile input, and an
// exception escaping an actor event terminates the validator. These tests
// feed each parser the inputs that used to throw and require a td::Status
// instead. Remove the guards in json-rpc-server-parse.cpp and the process
// aborts here.

#include <limits>

#include "auto/tl/lite_api.hpp"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/dict.h"
#include "vm/stack.hpp"

#include "json-rpc-server-parse.h"
#include "json-rpc-server-runresult.h"

namespace {

td::Ref<vm::Cell> make_library_cell() {
  // library#02 hash:bits256, a level-0 exotic cell that std_boc_deserialize
  // accepts as a root but load_cell_slice() refuses to open.
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(static_cast<int>(vm::Cell::SpecialType::Library), 8));
  cb.store_zeroes(256);
  return cb.finalize(true);
}

td::BufferSlice serialize_stack(const vm::Stack& stack) {
  vm::CellBuilder cb;
  CHECK(stack.serialize(cb));
  return vm::std_boc_serialize(cb.finalize()).move_as_ok();
}

// vm_stack#_ depth:(## 24) stack:(VmStackList depth) with one vm_stk_slice
// entry whose cell is the given (exotic) cell.
td::BufferSlice serialize_slice_stack_over(td::Ref<vm::Cell> cell) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(1, 24));                             // depth
  CHECK(cb.store_ref_bool(vm::CellBuilder().finalize()));       // rest: VmStackList 0
  CHECK(cb.store_long_bool(4, 8));                              // vm_stk_slice#04
  CHECK(cb.store_ref_bool(std::move(cell)));                    // cell:^Cell
  CHECK(cb.store_long_bool(0, 10) && cb.store_long_bool(0, 10)); // st_bits, end_bits
  CHECK(cb.store_long_bool(0, 3) && cb.store_long_bool(0, 3));   // st_ref, end_ref
  return vm::std_boc_serialize(cb.finalize()).move_as_ok();
}

td::Ref<vm::Cell> make_key_dict(const std::vector<td::Ref<vm::Cell>>& entries) {
  vm::Dictionary dict{8};
  int i = 0;
  for (const auto& entry : entries) {
    td::BitArray<8> key;
    key.store_ulong(static_cast<unsigned long long>(i++));
    CHECK(dict.set(key.cbits(), 8, vm::load_cell_slice_ref(entry)));
  }
  return dict.get_root_cell();
}

// Reply rendering shared by runGetMethod (Legacy) and runGetMethodStd (Std). The
// expected bodies and messages were captured from the handlers' own rendering
// code before it moved into render_run_method_result, so the move is pinned
// byte for byte. These test the reply both endpoints send, not the HTTP
// transport or the handler lambdas.
td::BufferSlice serialize_full_stack() {
  vm::Stack st;
  st.push_smallint(42);
  st.push_cell(vm::CellBuilder().finalize());
  vm::CellBuilder sb;
  sb.store_long(0xabcd, 16);
  sb.store_ref(vm::CellBuilder().finalize());
  st.push_cellslice(td::make_ref<vm::CellSlice>(vm::load_cell_slice(sb.finalize())));
  std::vector<vm::StackEntry> inner{vm::StackEntry{}};
  std::vector<vm::StackEntry> outer{td::make_refint(-7), vm::StackEntry{std::move(inner)}};
  st.push(vm::StackEntry{std::move(outer)});
  st.push(vm::StackEntry{});
  return serialize_stack(st);
}

tos::lite_api::object_ptr<tos::lite_api::tosNode_blockIdExt> fixed_block() {
  return tos::lite_api::make_object<tos::lite_api::tosNode_blockIdExt>(
      -1, std::numeric_limits<td::int64>::min(), 12345, td::Bits256(td::Slice(std::string(32, '\x11')).ubegin()),
      td::Bits256(td::Slice(std::string(32, '\x22')).ubegin()));
}

tos::lite_api::liteServer_runMethodResult run_answer(td::int32 exit_code, td::BufferSlice result, bool with_block) {
  return tos::lite_api::liteServer_runMethodResult(4, with_block ? fixed_block() : nullptr, nullptr, td::BufferSlice(),
                                                   td::BufferSlice(), td::BufferSlice(), td::BufferSlice(),
                                                   td::BufferSlice(), exit_code, std::move(result));
}

void expect_body(const tos::lite_api::liteServer_runMethodResult& answer, tos::RunResultFormat format,
                 const char* expected) {
  auto body = tos::render_run_method_result(answer, format);
  ASSERT_TRUE(body.is_ok());
  ASSERT_STREQ(expected, body.ok());
}

void expect_error(const tos::lite_api::liteServer_runMethodResult& answer, tos::RunResultFormat format,
                  const char* expected) {
  auto body = tos::render_run_method_result(answer, format);
  ASSERT_TRUE(body.is_error());
  ASSERT_EQ(-32603, body.error().code());
  ASSERT_STREQ(expected, body.error().message().str());
}

}  // namespace

TEST(JsonRpcParse, result_stack_round_trip) {
  vm::Stack stack;
  stack.push_smallint(42);
  stack.push_cell(vm::CellBuilder().finalize());
  auto parsed = tos::parse_get_method_result_stack(serialize_stack(stack).as_slice());
  ASSERT_TRUE(parsed.is_ok());
  auto stk = parsed.move_as_ok();
  ASSERT_EQ(2, stk->depth());
  ASSERT_TRUE(stk->at(1).is_int());
  ASSERT_EQ(42, stk->at(1).as_int()->to_long());
  ASSERT_TRUE(stk->at(0).is_cell());
}

TEST(JsonRpcParse, pq_block_signatures_fail_loudly) {
  auto signatures = tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplexPq>();
  auto rendered = tos::render_masterchain_block_signatures_json(signatures.get(), td::Slice("{}"));
  ASSERT_TRUE(rendered.is_error());
  ASSERT_STREQ("post-quantum block signatures are not supported by JSON-RPC yet", rendered.error().message().c_str());
}

TEST(JsonRpcParse, absent_block_signatures_remain_an_empty_ordinary_set) {
  auto rendered = tos::render_masterchain_block_signatures_json(nullptr, td::Slice("{\"seqno\":1}"));
  ASSERT_TRUE(rendered.is_ok());
  ASSERT_STREQ("{\"@type\":\"blocks.blockSignatures\",\"id\":{\"seqno\":1},\"signatures\":[]}", rendered.ok().c_str());
}

TEST(JsonRpcParse, result_stack_rejects_garbage_boc) {
  auto parsed = tos::parse_get_method_result_stack(td::Slice("\xff\xff\xff\xff\x00\x01"));
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, result_stack_rejects_exotic_root) {
  auto boc = vm::std_boc_serialize(make_library_cell()).move_as_ok();
  auto parsed = tos::parse_get_method_result_stack(boc.as_slice());
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, result_stack_rejects_slice_over_exotic_cell) {
  // Deserializing this entry loads the referenced cell as a slice, which
  // throws cell_und on a library cell without the guard.
  auto parsed = tos::parse_get_method_result_stack(serialize_slice_stack_over(make_library_cell()).as_slice());
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, run_method_inactive_account_resolves_to_an_empty_stack) {
  // The liteserver's own value, pinned independently of the production constant.
  ASSERT_EQ(-256, tos::kInactiveAccountExitCode);
  auto resolved = tos::resolve_run_method_result_stack(-256, td::Slice());
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(0, resolved.ok()->depth());
}

TEST(JsonRpcParse, run_method_missing_result_is_an_error_for_any_other_exit_code) {
  for (td::int32 exit_code : {0, 11}) {
    auto resolved = tos::resolve_run_method_result_stack(exit_code, td::Slice());
    ASSERT_TRUE(resolved.is_error());
    ASSERT_STREQ(PSTRING() << "liteserver returned no result stack for exit code " << exit_code,
                 resolved.error().message().str());
  }
}

TEST(JsonRpcParse, run_method_zero_depth_stack_is_a_result_not_a_missing_one) {
  auto resolved = tos::resolve_run_method_result_stack(0, serialize_stack(vm::Stack{}).as_slice());
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(0, resolved.ok()->depth());
}

TEST(JsonRpcParse, run_method_returned_stack_round_trips_for_success_and_failure_exits) {
  vm::Stack stack;
  stack.push_smallint(42);
  stack.push_cell(vm::CellBuilder().finalize());
  auto boc = serialize_stack(stack);
  for (td::int32 exit_code : {0, 11}) {
    auto resolved = tos::resolve_run_method_result_stack(exit_code, boc.as_slice());
    ASSERT_TRUE(resolved.is_ok());
    auto stk = resolved.move_as_ok();
    ASSERT_EQ(2, stk->depth());
    ASSERT_TRUE(stk->at(1).is_int());
    ASSERT_EQ(42, stk->at(1).as_int()->to_long());
    ASSERT_TRUE(stk->at(0).is_cell());
  }
}

TEST(JsonRpcParse, run_method_unparsable_result_keeps_the_parser_error) {
  td::Slice garbage("\xff\xff\xff\xff\x00\x01");
  auto library = vm::std_boc_serialize(make_library_cell()).move_as_ok();
  for (td::Slice result : {garbage, td::Slice(library.as_slice())}) {
    auto expected = tos::parse_get_method_result_stack(result);
    ASSERT_TRUE(expected.is_error());
    auto resolved = tos::resolve_run_method_result_stack(0, result);
    ASSERT_TRUE(resolved.is_error());
    ASSERT_EQ(expected.error().code(), resolved.error().code());
    ASSERT_STREQ(expected.error().message().str(), resolved.error().message().str());
  }
}

TEST(JsonRpcParse, run_method_inactive_exit_code_does_not_excuse_unparsable_bytes) {
  auto resolved = tos::resolve_run_method_result_stack(-256, td::Slice("\xff\xff\xff\xff\x00\x01"));
  ASSERT_TRUE(resolved.is_error());
}

TEST(JsonRpcParse, multisig_keys_happy_path) {
  vm::CellBuilder key1;
  key1.store_ones(256);
  vm::CellBuilder key2;
  key2.store_zeroes(256);
  auto parsed = tos::parse_multisig_public_keys(make_key_dict({key1.finalize(), key2.finalize()}));
  ASSERT_TRUE(parsed.is_ok());
  auto keys = parsed.move_as_ok();
  ASSERT_EQ(2u, keys.size());
  ASSERT_EQ("ed25519:" + std::string(64, 'f'), keys[0]);
  ASSERT_EQ("ed25519:" + std::string(64, '0'), keys[1]);
}

TEST(JsonRpcParse, multisig_keys_empty_dictionary) {
  auto parsed = tos::parse_multisig_public_keys({});
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(parsed.ok().empty());
}

TEST(JsonRpcParse, multisig_keys_rejects_short_entry) {
  vm::CellBuilder short_key;
  short_key.store_zeroes(8);
  auto parsed = tos::parse_multisig_public_keys(make_key_dict({short_key.finalize()}));
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, multisig_keys_rejects_malformed_dictionary) {
  // A dictionary root whose label is not a valid HmLabel: the traversal
  // throws dict_err without the guard.
  vm::CellBuilder cb;
  cb.store_ones(8);
  auto parsed = tos::parse_multisig_public_keys(cb.finalize());
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, multisig_keys_rejects_exotic_root) {
  auto parsed = tos::parse_multisig_public_keys(make_library_cell());
  ASSERT_TRUE(parsed.is_error());
}

TEST(JsonRpcParse, restricted_wallet_start_at) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(7, 32));    // seqno
  CHECK(cb.store_long_bool(698983191, 32));  // subwallet_id
  cb.store_zeroes(256);                // public_key
  CHECK(cb.store_long_bool(1789434000, 32));  // start_at
  auto parsed = tos::parse_restricted_wallet_start_at(cb.finalize());
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_EQ(1789434000u, parsed.ok());
}

TEST(JsonRpcParse, restricted_wallet_start_at_short_cell_is_zero) {
  vm::CellBuilder cb;
  cb.store_zeroes(64);
  auto parsed = tos::parse_restricted_wallet_start_at(cb.finalize());
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_EQ(0u, parsed.ok());
}

TEST(JsonRpcParse, restricted_wallet_start_at_rejects_null_and_exotic) {
  ASSERT_TRUE(tos::parse_restricted_wallet_start_at({}).is_error());
  ASSERT_TRUE(tos::parse_restricted_wallet_start_at(make_library_cell()).is_error());
}

// A request id of type Number is echoed into the reply unquoted, so it has
// to satisfy the grammar the client's parser applies. The scanner that
// produced it is more permissive than that grammar.
TEST(JsonRpcParse, json_number_grammar_accepts_valid) {
  for (const char* s : {"0", "-0", "1", "-1", "42", "1.5", "-1.5", "1e10", "1E10",
                        "1e+10", "1e-10", "0.5", "-0.5", "123456789012345678901234567890",
                        "1.5e-10"}) {
    ASSERT_TRUE(tos::is_valid_json_number(s));
  }
}

TEST(JsonRpcParse, json_number_grammar_rejects_malformed) {
  // Every one of these is accepted by the scanner as a Number and would be
  // spliced into the reply as-is.
  for (const char* s : {".", "--", "1e+-.3", "", "-", "+1", "1.", ".5", "1e", "1e+",
                        "01", "-01", "1..2", "1e1e1", "1 2", " 1", "1 ", "0x1", "nan"}) {
    ASSERT_TRUE(!tos::is_valid_json_number(s));
  }
}

namespace {
td::Result<std::string> reflect(std::string json) {
  auto parsed = td::json_decode(td::MutableSlice(json));
  CHECK(parsed.is_ok());
  auto value = parsed.move_as_ok();
  return tos::reflected_request_id(value);
}
}  // namespace

TEST(JsonRpcParse, reflected_id_is_bounded_on_its_serialized_form) {
  ASSERT_EQ(reflect("null").move_as_ok(), "null");
  ASSERT_EQ(reflect("\"abc\"").move_as_ok(), "\"abc\"");
  ASSERT_EQ(reflect("-12.5e3").move_as_ok(), "-12.5e3");

  // Plain string: 254 characters serialize to exactly 256 bytes.
  std::string at_bound = "\"" + std::string(254, 'a') + "\"";
  ASSERT_EQ(reflect(at_bound).move_as_ok(), at_bound);
  ASSERT_TRUE(reflect("\"" + std::string(255, 'a') + "\"").is_error());

  // Escaping counts: 127 quotes serialize to 2 + 2 * 127 = 256 bytes, 128 do
  // not fit although the raw string is only 128 bytes.
  std::string quotes_127, quotes_128;
  for (int i = 0; i < 127; i++) {
    quotes_127 += "\\\"";
  }
  quotes_128 = quotes_127 + "\\\"";
  auto r127 = reflect("\"" + quotes_127 + "\"");
  ASSERT_TRUE(r127.is_ok());
  ASSERT_EQ(r127.ok().size(), tos::kMaxReflectedIdBytes);
  ASSERT_TRUE(reflect("\"" + quotes_128 + "\"").is_error());

  // Numbers: 256 digits fit, 257 do not.
  ASSERT_EQ(reflect("1" + std::string(255, '0')).move_as_ok().size(), tos::kMaxReflectedIdBytes);
  ASSERT_TRUE(reflect("1" + std::string(256, '0')).is_error());

  // Not a string, number or null, or a number outside the JSON grammar.
  for (auto bad : {"true", "false", "[1]", "{\"a\":1}", "1e+-.3"}) {
    ASSERT_TRUE(reflect(bad).is_error());
  }
}

TEST(JsonRpcRunResult, full_stack_with_block_id_renders_both_formats) {
  auto answer = run_answer(11, serialize_full_stack(), true);
  expect_body(
      answer, tos::RunResultFormat::Legacy,
      "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[[\"list\",{\"elements\":[]}],[\"tuple\",{\"elements\":[["
      "\"num\",\"-7\"],[\"tuple\",{\"elements\":[[\"list\",{\"elements\":[]}]]}]]}],[\"slice\",{\"bytes\":"
      "\"te6ccgEBAgEABwABBKvNAQAA\"}],[\"cell\",{\"bytes\":\"te6ccgEBAQEAAgAAAA==\"}],[\"num\",\"42\"]],\"exit_code\":"
      "11,\"last_transaction_id\":null,\"block_id\":{\"@type\":\"tos.blockIdExt\",\"workchain\":-1,\"shard\":\"-"
      "9223372036854775808\",\"seqno\":12345,\"root_hash\":\"ERERERERERERERERERERERERERERERERERERERERERE=\",\"file_"
      "hash\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"}}");
  expect_body(
      answer, tos::RunResultFormat::Std,
      "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[{\"@type\":\"tvm.stackEntryList\",\"list\":{\"@type\":"
      "\"tvm.list\",\"elements\":[]}},{\"@type\":\"tvm.stackEntryTuple\",\"tuple\":{\"@type\":\"tvm.tuple\","
      "\"elements\":[{\"@type\":\"tvm.stackEntryNumber\",\"number\":{\"@type\":\"tvm.numberDecimal\",\"number\":\"-7\"}"
      "},{\"@type\":\"tvm.stackEntryTuple\",\"tuple\":{\"@type\":\"tvm.tuple\",\"elements\":[{\"@type\":\"tvm."
      "stackEntryList\",\"list\":{\"@type\":\"tvm.list\",\"elements\":[]}}]}}]}},{\"@type\":\"tvm.stackEntrySlice\","
      "\"slice\":{\"@type\":\"tvm.slice\",\"bytes\":\"te6ccgEBAgEABwABBKvNAQAA\"}},{\"@type\":\"tvm.stackEntryCell\","
      "\"cell\":{\"@type\":\"tvm.cell\",\"bytes\":\"te6ccgEBAQEAAgAAAA==\"}},{\"@type\":\"tvm.stackEntryNumber\","
      "\"number\":{\"@type\":\"tvm.numberDecimal\",\"number\":\"42\"}}],\"exit_code\":11,\"last_transaction_id\":null,"
      "\"block_id\":{\"@type\":\"tos.blockIdExt\",\"workchain\":-1,\"shard\":\"-9223372036854775808\",\"seqno\":12345,"
      "\"root_hash\":\"ERERERERERERERERERERERERERERERERERERERERERE=\",\"file_hash\":"
      "\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"}}");
}

TEST(JsonRpcRunResult, inactive_account_renders_an_empty_stack) {
  auto answer = run_answer(-256, td::BufferSlice(), false);
  expect_body(answer, tos::RunResultFormat::Legacy,
              "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[],\"exit_code\":-256,\"last_transaction_id\":"
              "null,\"block_id\":null}");
  expect_body(answer, tos::RunResultFormat::Std,
              "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[],\"exit_code\":-256,\"last_transaction_id\":"
              "null,\"block_id\":null}");
}

TEST(JsonRpcRunResult, zero_depth_stack_is_a_result) {
  vm::Stack empty;
  auto answer = run_answer(0, serialize_stack(empty), false);
  expect_body(answer, tos::RunResultFormat::Legacy,
              "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[],\"exit_code\":0,\"last_transaction_id\":null,"
              "\"block_id\":null}");
  expect_body(answer, tos::RunResultFormat::Std,
              "{\"@type\":\"smc.runResult\",\"gas_used\":0,\"stack\":[],\"exit_code\":0,\"last_transaction_id\":null,"
              "\"block_id\":null}");
}

TEST(JsonRpcRunResult, missing_result_answers_internal_error) {
  auto answer = run_answer(0, td::BufferSlice(), false);
  expect_error(
      answer, tos::RunResultFormat::Legacy,
      "result stack (exit_code 0, result_bytes 0): [Error : 0 : liteserver returned no result stack for exit code 0]");
  expect_error(
      answer, tos::RunResultFormat::Std,
      "result stack (exit_code 0, result_bytes 0): [Error : 0 : liteserver returned no result stack for exit code 0]");
}

TEST(JsonRpcRunResult, unreadable_result_answers_internal_error) {
  auto answer = run_answer(0, td::BufferSlice(td::Slice("\xff\xff\xff\xff\x00\x01", 6)), false);
  expect_error(answer, tos::RunResultFormat::Legacy,
               "result stack (exit_code 0, result_bytes 6): [Error : 0 : result BOC parse error: cannot deserialize "
               "bag-of-cells: invalid header, error 0]");
  expect_error(answer, tos::RunResultFormat::Std,
               "result stack (exit_code 0, result_bytes 6): [Error : 0 : result BOC parse error: cannot deserialize "
               "bag-of-cells: invalid header, error 0]");
}

TEST(JsonRpcRunResult, inactive_exit_code_does_not_excuse_unreadable_bytes) {
  auto answer = run_answer(-256, td::BufferSlice(td::Slice("\xff\xff\xff\xff\x00\x01", 6)), false);
  expect_error(answer, tos::RunResultFormat::Legacy,
               "result stack (exit_code -256, result_bytes 6): [Error : 0 : result BOC parse error: cannot deserialize "
               "bag-of-cells: invalid header, error 0]");
  expect_error(answer, tos::RunResultFormat::Std,
               "result stack (exit_code -256, result_bytes 6): [Error : 0 : result BOC parse error: cannot deserialize "
               "bag-of-cells: invalid header, error 0]");
}
