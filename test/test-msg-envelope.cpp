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

#include "block/block-parse.h"
#include "td/utils/tests.h"

namespace {

td::Ref<vm::Cell> make_msg_envelope(int tag, bool with_emitted_lt, bool with_metadata) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(tag, 4));
  CHECK(cb.store_long_bool(0, 8));  // cur_addr
  CHECK(cb.store_long_bool(0, 8));  // next_addr
  CHECK(cb.store_long_bool(0, 4));  // zero Tomis
  CHECK(cb.store_ref_bool(vm::CellBuilder().finalize()));
  if (tag == 5) {
    CHECK(cb.store_bool_bool(with_emitted_lt));
    if (with_emitted_lt) {
      CHECK(cb.store_long_bool(123, 64));
    }
    CHECK(cb.store_bool_bool(with_metadata));
    if (with_metadata) {
      CHECK(cb.store_long_bool(0, 4));   // msg_metadata#0
      CHECK(cb.store_long_bool(1, 32));  // depth
      CHECK(cb.store_long_bool(2, 2));   // addr_std$10
      CHECK(cb.store_long_bool(0, 1));   // no anycast
      CHECK(cb.store_long_bool(0, 8));   // workchain_id
      cb.store_zeroes(256);              // address
      CHECK(cb.store_long_bool(100, 64));
    }
  }
  return cb.finalize();
}

bool unpack_record(const td::Ref<vm::Cell>& cell) {
  auto cs = vm::load_cell_slice(cell);
  block::tlb::MsgEnvelope::Record record;
  return block::tlb::t_MsgEnvelope.unpack(cs, record) && cs.empty_ext();
}

bool unpack_record_std(const td::Ref<vm::Cell>& cell) {
  auto cs = vm::load_cell_slice(cell);
  block::tlb::MsgEnvelope::Record_std record;
  return block::tlb::t_MsgEnvelope.unpack(cs, record) && cs.empty_ext();
}

void expect_unpack_result(const td::Ref<vm::Cell>& cell, bool expected) {
  EXPECT_EQ(unpack_record(cell), expected);
  EXPECT_EQ(unpack_record_std(cell), expected);
}

TEST(MsgEnvelope, RequiresCanonicalV2) {
  expect_unpack_result(make_msg_envelope(4, false, false), true);
  expect_unpack_result(make_msg_envelope(5, false, false), false);
  expect_unpack_result(make_msg_envelope(5, true, false), true);
  expect_unpack_result(make_msg_envelope(5, false, true), true);
  expect_unpack_result(make_msg_envelope(5, true, true), true);
}

}  // namespace
