/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// State import: the bounded streaming importer a node uses to read a persistent state
// downloaded from a peer out of its spool file and into the cell database
// (std_boc_deserialize_from_file_bounded). The bytes are the peer's; the file is ours.
//
// The input is written to an anonymous in-memory file and imported through a sink that
// checks the importer's lifecycle promises: begin once before any cell, every cell after
// begin, finish once on success with the root's hash, abort exactly once on any failure
// after begin and never otherwise. A state both the streaming importer and the in-memory
// parser accept must have the same root.
//
// Run:
//   build-fuzz/fuzz/fuzz-state-import -max_total_time=300 -max_len=65536 fuzz-work/fuzz-state-import test/fuzz/corpus/fuzz-state-import

#include <sys/mman.h>
#include <unistd.h>

#include "td/utils/port/FileFd.h"
#include "vm/boc.h"
#include "vm/cells.h"

#include "fuzz-common.h"

namespace {

class CheckingSink final : public vm::StreamingCellSink {
 public:
  td::Status begin() override {
    TOS_FUZZ_INVARIANT(begun == 0);
    TOS_FUZZ_INVARIANT(persisted == 0);
    begun++;
    return td::Status::OK();
  }
  td::Status persist(td::Ref<vm::Cell> cell) override {
    TOS_FUZZ_INVARIANT(begun == 1);
    TOS_FUZZ_INVARIANT(finished == 0);
    TOS_FUZZ_INVARIANT(aborted == 0);
    TOS_FUZZ_INVARIANT(cell.not_null());
    persisted++;
    return td::Status::OK();
  }
  td::Status finish(const vm::Cell::Hash &hash) override {
    TOS_FUZZ_INVARIANT(begun == 1);
    TOS_FUZZ_INVARIANT(finished == 0);
    TOS_FUZZ_INVARIANT(persisted > 0);
    finished++;
    root_hash = hash;
    return td::Status::OK();
  }
  void abort() override {
    TOS_FUZZ_INVARIANT(finished == 0);
    TOS_FUZZ_INVARIANT(begun == 1);
    TOS_FUZZ_INVARIANT(aborted == 0);
    aborted++;
  }

  int begun = 0;
  int finished = 0;
  int aborted = 0;
  std::size_t persisted = 0;
  vm::Cell::Hash root_hash;
};

// The fuzzer's limits, kept far below the node's so a run spends its time on parsing and
// not on allocating budgets an input could never fill.
vm::StreamingBocImportOptions fuzz_options() {
  vm::StreamingBocImportOptions options;
  options.max_cells = 1 << 16;
  options.max_roots = 1;
  options.max_total_cell_bytes = 1 << 22;
  options.max_resident_bytes = 1 << 24;
  options.max_scaffolding_bytes = 1 << 24;
  return options;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  int native = ::memfd_create("fuzz-state-import", MFD_CLOEXEC);
  if (native < 0) {
    tos::fuzz::invariant_failed("memfd_create failed");
  }
  std::size_t written = 0;
  while (written < size) {
    auto n = ::write(native, data + written, size - written);
    if (n <= 0) {
      tos::fuzz::invariant_failed("writing the spool file failed");
    }
    written += static_cast<std::size_t>(n);
  }
  if (::lseek(native, 0, SEEK_SET) != 0) {
    tos::fuzz::invariant_failed("rewinding the spool file failed");
  }
  auto file = td::FileFd::from_native_fd(td::NativeFd(native));

  CheckingSink sink;
  auto r_root = vm::std_boc_deserialize_from_file_bounded(file, size, fuzz_options(), &sink);
  file.close();

  if (r_root.is_ok()) {
    auto root = r_root.move_as_ok();
    TOS_FUZZ_INVARIANT(root.not_null());
    TOS_FUZZ_INVARIANT(sink.begun == 1 && sink.finished == 1 && sink.aborted == 0);
    TOS_FUZZ_INVARIANT(sink.root_hash == root->get_hash());
    auto r_in_memory = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char *>(data), size), false, true);
    if (r_in_memory.is_ok()) {
      TOS_FUZZ_INVARIANT(r_in_memory.ok()->get_hash() == root->get_hash());
    }
  } else {
    // Refused before the cell loop: no callback at all. Refused after: abort, once.
    TOS_FUZZ_INVARIANT(sink.finished == 0);
    TOS_FUZZ_INVARIANT(sink.aborted == sink.begun);
  }
  return 0;
}
