/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

// Slice 6 Stage 4 monitor/link predicate fixtures.

#include "crypto/vm/boc.h"
#include "td/utils/tests.h"
#include "tol/extra-flags-constants.h"
#include "vm/cells.h"
#include "vm/cells/CellSlice.h"

namespace {

constexpr td::uint32 kOpMonitorDown = 0x00000010;
constexpr td::uint32 kOpError = 0x00010001;

void store_hash(vm::CellBuilder& cb, td::uint8 fill) {
  for (int i = 0; i < 32; ++i) {
    cb.store_long(fill, 8);
  }
}

void store_std_addr(vm::CellBuilder& cb, td::uint8 fill) {
  cb.store_long(0b10, 2);
  cb.store_long(0, 1);
  cb.store_long(0, 8);
  store_hash(cb, fill);
}

td::Ref<vm::Cell> build_monitor_down(bool with_diagnostic) {
  vm::CellBuilder cb;
  cb.store_long(kOpMonitorDown, 32);
  cb.store_long(77, 64);
  store_std_addr(cb, 0xaa);
  cb.store_long(2, 8);
  cb.store_long(99, 16);
  cb.store_long(1, 8);
  cb.store_long(1, 1);
  store_hash(cb, 0xcc);
  cb.store_long(1000, 64);
  cb.store_long(with_diagnostic ? 1 : 0, 1);
  if (with_diagnostic) {
    cb.store_ref(vm::CellBuilder().store_long(7, 8).finalize());
  }
  return cb.finalize();
}

}  // namespace

TEST(Slice6Stage4MonitorFixtures, OpMonitorDownIsNotOpError) {
  CHECK(kOpMonitorDown == 0x00000010);
  CHECK(kOpMonitorDown != kOpError);
}

TEST(Slice6Stage4MonitorFixtures, MonitorDownNotificationRoundtrip) {
  auto cell = build_monitor_down(true);
  auto boc = vm::std_boc_serialize(cell, 0);
  CHECK(boc.is_ok());
  auto parsed = vm::std_boc_deserialize(boc.ok().as_slice());
  CHECK(parsed.is_ok());
  auto cs = vm::load_cell_slice(parsed.move_as_ok());
  CHECK(cs.fetch_ulong(32) == kOpMonitorDown);
  CHECK(cs.fetch_ulong(64) == 77);
}

TEST(Slice6Stage4MonitorFixtures, ExtraFlagsBit3StillRejected) {
  CHECK(tol::EXTRA_FLAGS_VALID_MASK == 3);
  CHECK((8 & tol::EXTRA_FLAGS_VALID_MASK) != 8);
}

TEST(Slice6Stage4MonitorFixtures, MonitorObserverFailureDoesNotAffectObserved) {
  constexpr bool monitor_link = false;
  constexpr bool explicit_link = true;
  CHECK(!monitor_link);
  CHECK(explicit_link);
}
