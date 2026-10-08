// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include "td/utils/tests.h"
#include "validator/impl/external-message.hpp"
#include "vm/boc.h"

namespace tos::validator {
namespace {

td::BufferSlice make_valid_external_message() {
  // ext_in_msg_info$10, addr_none$00 source, addr_std$10 destination with no
  // anycast in workchain 0, zero address/import fee, no StateInit, empty inline body.
  auto root = vm::CellBuilder()
                  .store_long(2, 2)
                  .store_zeroes(2)
                  .store_long(2, 2)
                  .store_zeroes(1 + 8 + 256 + 4 + 1 + 1)
                  .finalize();
  return vm::std_boc_serialize(std::move(root)).move_as_ok();
}

td::BufferSlice make_deep_external_message(unsigned depth) {
  CHECK(depth > 0);
  auto body = vm::CellBuilder().finalize();
  for (unsigned i = 1; i < depth; ++i) {
    body = vm::CellBuilder().store_ref(body).finalize();
  }
  auto root = vm::CellBuilder()
                  .store_long(2, 2)
                  .store_zeroes(2)
                  .store_long(2, 2)
                  .store_zeroes(1 + 8 + 256 + 4 + 1)
                  .store_long(1, 1)
                  .store_ref(body)
                  .finalize();
  CHECK(root->get_depth() == depth);
  return vm::std_boc_serialize(std::move(root)).move_as_ok();
}

TEST(ExtMessageIngress, SerializedSizeBoundary) {
  auto data = make_valid_external_message();
  block::SizeLimitsConfig::ExtMsgLimits limits;
  limits.max_size = static_cast<td::uint32>(data.size());
  EXPECT(ExtMessageQ::create_ext_message(data.clone(), limits).is_ok());
  --limits.max_size;
  auto rejected = ExtMessageQ::create_ext_message(data.clone(), limits);
  ASSERT_TRUE(rejected.is_error());
  EXPECT_EQ(rejected.error().message(), "external message too large, rejecting");
  limits.max_size += 2;
  EXPECT(ExtMessageQ::create_ext_message(data.clone(), limits).is_ok());
}

TEST(ExtMessageIngress, DepthBoundary) {
  block::SizeLimitsConfig::ExtMsgLimits limits;
  ASSERT_TRUE(limits.max_depth == 512);
  EXPECT(ExtMessageQ::create_ext_message(make_deep_external_message(511), limits).is_ok());
  for (auto depth : {512u, 513u}) {
    auto rejected = ExtMessageQ::create_ext_message(make_deep_external_message(depth), limits);
    ASSERT_TRUE(rejected.is_error());
    EXPECT_EQ(rejected.error().message(), "external message is too deep");
  }
}

}  // namespace
}  // namespace tos::validator
