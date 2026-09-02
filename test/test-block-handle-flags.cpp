/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "validator/block-handle.hpp"

#include <cstdio>

int main() {
  tos::BlockIdExt block_id{tos::BlockId{0, 0x8000000000000000ULL, 123}, tos::RootHash::zero(),
                           tos::FileHash::zero()};
  auto handle = tos::validator::BlockHandleImpl::create_empty(block_id);

  if (handle->applied_stored()) {
    std::fprintf(stderr, "fresh handle must not report applied_stored\n");
    return 1;
  }

  handle->set_applied();
  handle->set_applied_stored();
  handle->set_processed();
  handle->set_handle_moved_to_archive();
  if (!handle->is_applied() || !handle->applied_stored() || !handle->processed() ||
      !handle->handle_moved_to_archive()) {
    std::fprintf(stderr, "in-memory flags were not set\n");
    return 1;
  }

  // applied_stored, processed and handle_moved_to_archive describe what this
  // process has verified about durable state; persisting any of them would
  // let a crash-torn database claim work that never completed.
  auto reloaded = tos::validator::BlockHandleImpl::create(handle->serialize().as_slice());
  if (!reloaded->is_applied()) {
    std::fprintf(stderr, "applied flag must survive serialization\n");
    return 1;
  }
  if (reloaded->applied_stored()) {
    std::fprintf(stderr, "applied_stored must not survive serialization\n");
    return 1;
  }
  if (reloaded->processed()) {
    std::fprintf(stderr, "processed must not survive serialization\n");
    return 1;
  }
  if (reloaded->handle_moved_to_archive()) {
    std::fprintf(stderr, "handle_moved_to_archive must not survive serialization\n");
    return 1;
  }

  // The flush contract: mutations make the handle dirty, and only an
  // explicit flushed_upto acknowledgment for the observed version clears it.
  auto dirty = tos::validator::BlockHandleImpl::create_empty(block_id);
  dirty->set_applied();
  if (!dirty->need_flush()) {
    std::fprintf(stderr, "setting a persistent flag must mark the handle dirty\n");
    return 1;
  }
  auto version = dirty->version();
  dirty->set_is_key_block(true);
  dirty->flushed_upto(version);
  if (!dirty->need_flush()) {
    std::fprintf(stderr, "acknowledging an old version must keep the handle dirty\n");
    return 1;
  }
  dirty->flushed_upto(dirty->version());
  if (dirty->need_flush()) {
    std::fprintf(stderr, "acknowledging the latest version must clear the dirty state\n");
    return 1;
  }
  if (dirty->applied_stored()) {
    std::fprintf(stderr, "flush acknowledgment must not imply applied_stored\n");
    return 1;
  }

  // Handles assert on destruction that every mutation was flushed.
  handle->flushed_upto(handle->version());
  return 0;
}
