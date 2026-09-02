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

#include "json-rpc-server-parse.h"

#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/dict.h"
#include "vm/stack.hpp"

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

}  // namespace

TEST(JsonRpcParse, result_stack_round_trip) {
  vm::Stack stack;
  stack.push_smallint(42);
  stack.push_cell(vm::CellBuilder().finalize());
  auto parsed = tos::parse_get_method_result_stack(serialize_stack(stack).as_slice());
  ASSERT_TRUE(parsed.is_ok());
  auto stk = parsed.move_as_ok();
  ASSERT_EQ(2u, stk->depth());
  ASSERT_TRUE(stk->at(1).is_int());
  ASSERT_EQ(42, stk->at(1).as_int()->to_long());
  ASSERT_TRUE(stk->at(0).is_cell());
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
