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

#include <stdexcept>

#include "block/block-parse.h"
#include "td/utils/tests.h"
#include "tl/tlblib.hpp"
#include "validator/impl/shard.hpp"
#include "vm/excno.hpp"

namespace {

void expect_error(td::Status status, td::Slice message) {
  ASSERT_TRUE(status.is_error());
  EXPECT_EQ(status.message(), message);
}

struct EmptyRecord {
  struct type_class {
    bool unpack(vm::CellSlice&, EmptyRecord& record) {
      record.unpack_called = true;
      return true;
    }
  };

  bool unpack_called{false};
};

struct EmptyType {
  bool unpack(vm::CellSlice&, EmptyRecord& record) const {
    record.unpack_called = true;
    return true;
  }
};

td::Ref<vm::Cell> make_masterchain_state_with_malformed_extra() {
  vm::CellBuilder aux;
  CHECK(aux.store_zeroes_bool(128));
  CHECK(block::tlb::t_CurrencyCollection.null_value(aux));
  CHECK(block::tlb::t_CurrencyCollection.null_value(aux));
  CHECK(aux.store_zeroes_bool(2));  // Empty libraries and no master_ref.

  auto empty = vm::CellBuilder().finalize();
  auto malformed_extra = vm::CellBuilder().finalize();

  vm::CellBuilder state;
  CHECK(state.store_long_bool(0x9023afe2, 32));
  CHECK(state.store_long_bool(-1, 32));  // A non-zero global_id.
  CHECK(block::ShardId(tos::masterchainId, tos::shardIdAll).serialize(state));
  CHECK(state.store_zeroes_bool(32 + 32 + 32 + 64 + 32));
  CHECK(state.store_ref_bool(empty));  // out_msg_queue_info
  CHECK(state.store_bool_bool(false));  // before_split
  CHECK(state.store_ref_bool(empty));  // accounts
  CHECK(state.store_ref_bool(aux.finalize()));
  CHECK(state.store_bool_bool(true));  // custom is present
  CHECK(state.store_ref_bool(std::move(malformed_extra)));
  return state.finalize();
}

TEST(VmExceptionHardening, ConvertsEverySupportedExceptionToStatus) {
  auto ok = TRY_VM(td::Status::OK());
  EXPECT(ok.is_ok());

  expect_error(TRY_VM(([]() -> td::Status { throw vm::VmError(vm::Excno::cell_und, "test vm error"); })()),
               "Got a vm exception: test vm error");
  expect_error(TRY_VM(([]() -> td::Status { throw vm::VmVirtError(1); })()),
               "Got a vm virtualization exception: prunned branch");
  expect_error(TRY_VM(([]() -> td::Status { throw vm::VmNoGas(); })()),
               "Got a vm no gas exception: out of gas");
  expect_error(TRY_VM(([]() -> td::Status { throw vm::CellBuilder::CellCreateError(); })()),
               "Got cell create error");
  expect_error(TRY_VM(([]() -> td::Status { throw vm::CellBuilder::CellWriteError(); })()),
               "Got cell write error");
  expect_error(TRY_VM(([]() -> td::Status { throw std::runtime_error("test standard exception"); })()),
               "Got exception: test standard exception");
  expect_error(TRY_VM(([]() -> td::Status { throw vm::VmFatal(); })()), "Got unknown exception");
}

TEST(TlbNullCellHardening, RejectsNullCellsBeforeUnpacking) {
  td::Ref<vm::Cell> null_cell;

  EmptyRecord exact_record;
  EXPECT(!tlb::unpack_cell(null_cell, exact_record));
  EXPECT(!exact_record.unpack_called);

  EmptyRecord inexact_record;
  EXPECT(!tlb::unpack_cell_inexact(null_cell, inexact_record));
  EXPECT(!inexact_record.unpack_called);

  EmptyRecord typed_record;
  EXPECT(!tlb::type_unpack_cell(null_cell, EmptyType{}, typed_record));
  EXPECT(!typed_record.unpack_called);
}

TEST(TlbNullCellHardening, PreservesNonNullUnpacking) {
  auto empty = vm::CellBuilder().finalize();

  EmptyRecord exact_record;
  EXPECT(tlb::unpack_cell(empty, exact_record));
  EXPECT(exact_record.unpack_called);

  EmptyRecord inexact_record;
  EXPECT(tlb::unpack_cell_inexact(empty, inexact_record));
  EXPECT(inexact_record.unpack_called);

  EmptyRecord typed_record;
  EXPECT(tlb::type_unpack_cell(empty, EmptyType{}, typed_record));
  EXPECT(typed_record.unpack_called);
}

TEST(MasterchainStateHardening, RejectsMalformedExtraAfterHeaderInitialization) {
  auto block_id =
      tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, 0, tos::RootHash::zero(), tos::FileHash::zero()};
  auto result =
      tos::validator::MasterchainStateQ::fetch(block_id, td::BufferSlice{}, make_masterchain_state_with_malformed_extra());

  ASSERT_TRUE(result.is_error());
  EXPECT_EQ(result.error().message(), "state extra information is invalid");
}

}  // namespace
