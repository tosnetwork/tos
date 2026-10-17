/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Bag-of-cells deserialization: every untrusted cell tree the node accepts -- messages,
// blocks, proofs, states -- enters through these parsers.
//
// Each input goes to the multi-root parser and to the single-root entry, and whatever is
// accepted must survive a round trip: serialized again in the canonical layout, with and
// without index and checksum, it must parse back to the same roots.
//
// Run:
//   build-fuzz/fuzz/fuzz-boc -max_total_time=300 -max_len=65536 fuzz-work/fuzz-boc test/fuzz/corpus/fuzz-boc

#include <vector>

#include "vm/boc.h"
#include "vm/cells.h"

#include "fuzz-common.h"

namespace {

void check_round_trip(const std::vector<td::Ref<vm::Cell>> &roots) {
  for (int mode : {0, vm::BagOfCells::Mode::WithIndex | vm::BagOfCells::Mode::WithCRC32C,
                   static_cast<int>(vm::BagOfCells::Mode::max)}) {
    auto r_serialized = vm::std_boc_serialize_multi(roots, mode);
    TOS_FUZZ_INVARIANT(r_serialized.is_ok());
    auto r_again = vm::std_boc_deserialize_multi(r_serialized.ok().as_slice());
    TOS_FUZZ_INVARIANT(r_again.is_ok());
    auto again = r_again.move_as_ok();
    TOS_FUZZ_INVARIANT(again.size() == roots.size());
    for (std::size_t i = 0; i < roots.size(); i++) {
      TOS_FUZZ_INVARIANT(again[i]->get_hash() == roots[i]->get_hash());
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  td::Slice input(reinterpret_cast<const char *>(data), size);

  auto r_roots = vm::std_boc_deserialize_multi(input);
  if (r_roots.is_ok() && !r_roots.ok().empty()) {
    check_round_trip(r_roots.ok());
  }

  auto r_root = vm::std_boc_deserialize(input);
  if (r_root.is_ok()) {
    // A bag the single-root entry accepts is one the multi-root parser accepts too, with
    // that same root.
    TOS_FUZZ_INVARIANT(r_roots.is_ok());
    TOS_FUZZ_INVARIANT(r_roots.ok().size() == 1);
    TOS_FUZZ_INVARIANT(r_roots.ok()[0]->get_hash() == r_root.ok()->get_hash());
  }

  vm::BagOfCells boc;
  auto r_size = boc.deserialize(input);
  if (r_size.is_ok()) {
    // The parser consumes no more than it was given.
    TOS_FUZZ_INVARIANT(r_size.ok() >= 0);
    TOS_FUZZ_INVARIANT(static_cast<std::size_t>(r_size.ok()) <= size);
  }
  return 0;
}
