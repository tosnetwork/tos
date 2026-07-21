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

// Regression for DownloadNextBlocks::validate_next_blocks_full (Codex
// review finding, 2026-07-21): a malicious protocol-3.2 peer could pack
// more than MAX_BLOCKS (10) small DataFull entries into a single
// nextBlocksFull response within the byte-size cap, amplifying
// TL-deserialization/allocation cost per round trip. Also pins the
// pre-existing empty-block-mixed-with-real-blocks rejection.

#include "validator/net/download-next-blocks.hpp"

#include "auto/tl/tos_api.h"
#include "common/errorcode.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

#define EXPECT_TRUE(cond)                                                                              \
  do {                                                                                                  \
    if (!(cond)) {                                                                                      \
      std::fprintf(stderr, "FAIL %s:%d  expected true: %s\n", __FILE__, __LINE__, #cond);               \
      std::exit(1);                                                                                     \
    }                                                                                                    \
  } while (0)

#define EXPECT_FALSE(cond)                                                                              \
  do {                                                                                                  \
    if (cond) {                                                                                          \
      std::fprintf(stderr, "FAIL %s:%d  expected false: %s\n", __FILE__, __LINE__, #cond);               \
      std::exit(1);                                                                                     \
    }                                                                                                    \
  } while (0)

using tos::validator::fullnode::validate_next_blocks_full;

std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_DataFull>> make_nonempty_blocks(size_t n) {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_DataFull>> v;
  v.reserve(n);
  for (size_t i = 0; i < n; i++) {
    v.push_back(tos::create_tl_object<tos::tos_api::tosNode_dataFullCompressedV2>());
  }
  return v;
}

void test_rejects_response_exceeding_max_blocks() {
  // 11 entries against a cap of 10 -- the exact amplification scenario
  // Codex flagged: a peer stuffing more DataFull entries into one response
  // than the server-side NextBlocksFullSender is supposed to ever send.
  auto blocks = make_nonempty_blocks(11);
  auto status = validate_next_blocks_full(blocks, 10);
  EXPECT_TRUE(status.is_error());
  EXPECT_TRUE(status.code() == tos::ErrorCode::protoviolation);
}

void test_allows_response_exactly_at_max_blocks() {
  // Boundary: exactly MAX_BLOCKS non-empty entries must be accepted --
  // the size check is size() > max_blocks, not >=.
  auto blocks = make_nonempty_blocks(10);
  auto status = validate_next_blocks_full(blocks, 10);
  EXPECT_TRUE(status.is_ok());
}

void test_allows_small_nonempty_response_within_limit() {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_DataFull>> blocks;
  blocks.push_back(tos::create_tl_object<tos::tos_api::tosNode_dataFullCompressedV2>());
  blocks.push_back(tos::create_tl_object<tos::tos_api::tosNode_dataFullCompressedV2>());
  auto status = validate_next_blocks_full(blocks, 10);
  EXPECT_TRUE(status.is_ok());
}

void test_rejects_empty_block_mixed_with_real_blocks() {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_DataFull>> blocks;
  blocks.push_back(tos::create_tl_object<tos::tos_api::tosNode_dataFullCompressedV2>());
  blocks.push_back(tos::create_tl_object<tos::tos_api::tosNode_dataFullEmpty>());
  auto status = validate_next_blocks_full(blocks, 10);
  EXPECT_TRUE(status.is_error());
  EXPECT_TRUE(status.code() == tos::ErrorCode::protoviolation);
}

void test_empty_vector_is_accepted_by_this_check() {
  // validate_next_blocks_full only guards batch shape; an empty batch is
  // handled by the caller's separate "node doesn't have next blocks" path.
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_DataFull>> blocks;
  auto status = validate_next_blocks_full(blocks, 10);
  EXPECT_TRUE(status.is_ok());
}

}  // namespace

int main() {
  std::printf("test-download-next-blocks-validation: nextBlocksFull batch-shape regression\n");
  test_rejects_response_exceeding_max_blocks();
  test_allows_response_exactly_at_max_blocks();
  test_allows_small_nonempty_response_within_limit();
  test_rejects_empty_block_mixed_with_real_blocks();
  test_empty_vector_is_accepted_by_this_check();
  std::printf("test-download-next-blocks-validation: OK\n");
  return 0;
}
