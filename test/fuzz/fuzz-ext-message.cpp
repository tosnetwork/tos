/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// External message admission: the structural parse every validator applies to an inbound
// external message from the network, before any gas is paid (ExtMessageQ::create_ext_message
// with the default ConfigParam 43 limits).
//
// What it accepts must hold to the limits it enforces, and the parse from the cell alone
// (the path a message already in a block takes) must agree with it on the destination and
// on both hashes.
//
// Run:
//   build-fuzz/fuzz/fuzz-ext-message -max_total_time=300 -max_len=65536 fuzz-work/fuzz-ext-message test/fuzz/corpus/fuzz-ext-message

#include "validator/impl/external-message.hpp"
#include "vm/boc.h"

#include "fuzz-common.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  td::Slice input(reinterpret_cast<const char *>(data), size);
  block::SizeLimitsConfig::ExtMsgLimits limits;
  auto r_message = tos::validator::ExtMessageQ::create_ext_message(td::BufferSlice(input), limits);
  if (r_message.is_error()) {
    return 0;
  }
  auto message = r_message.move_as_ok();
  auto root = message->root_cell();
  TOS_FUZZ_INVARIANT(root.not_null());
  TOS_FUZZ_INVARIANT(size <= limits.max_size);
  TOS_FUZZ_INVARIANT(root->get_level() == 0);
  TOS_FUZZ_INVARIANT(root->get_depth() < limits.max_depth);
  TOS_FUZZ_INVARIANT(message->serialize().as_slice() == input);
  TOS_FUZZ_INVARIANT(message->hash() == tos::Bits256{root->get_hash().bits()});

  auto r_from_cell = tos::validator::ExtMessageQ::create_ext_message(root);
  TOS_FUZZ_INVARIANT(r_from_cell.is_ok());
  auto from_cell = r_from_cell.move_as_ok();
  TOS_FUZZ_INVARIANT(from_cell->wc() == message->wc());
  TOS_FUZZ_INVARIANT(from_cell->addr() == message->addr());
  TOS_FUZZ_INVARIANT(from_cell->hash() == message->hash());
  TOS_FUZZ_INVARIANT(from_cell->hash_norm() == message->hash_norm());

  auto r_norm = tos::validator::get_ext_in_msg_hash_norm(root);
  TOS_FUZZ_INVARIANT(r_norm.is_ok());
  TOS_FUZZ_INVARIANT(r_norm.ok() == message->hash_norm());
  return 0;
}
