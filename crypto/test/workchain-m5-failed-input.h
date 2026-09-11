#pragma once
// TEST ONLY: selects an authenticated custody import and its predecessor owner.
// Not a Withdrawal wire operation, a balance declaration, or a production tag.
#include "block/workchain-confidential-state.h"

namespace block::m3_test {
struct M5TestFailedInput {
  WorkchainConfidentialAddress owner;
  td::Bits256 inbound_message;
};
constexpr unsigned m5_test_failed_tag = 0x54465231; // TFR1
inline bool is_m5_test_failed(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return false;
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  return !special && slice.have(32) && slice.prefetch_ulong(32) == m5_test_failed_tag;
}
inline td::Result<M5TestFailedInput> decode_m5_test_failed(const td::Ref<vm::Cell>& root) {
  if (!is_m5_test_failed(root)) return td::Status::Error(-7200, "missing test Failed selector");
  auto slice = vm::load_cell_slice(root);
  if (slice.size() != 832 || slice.size_refs())
    return td::Status::Error(-7200, "malformed test Failed selector");
  slice.advance(32);
  M5TestFailedInput result;
  result.owner.workchain_id = static_cast<int>(slice.fetch_long(32));
  if (!slice.fetch_bits_to(result.owner.account) || !slice.fetch_bits_to(result.owner.instance) ||
      !slice.fetch_bits_to(result.inbound_message))
    return td::Status::Error(-7200, "incomplete test Failed selector");
  return result;
}
inline td::Ref<vm::Cell> encode_m5_test_failed(const M5TestFailedInput& input) {
  return vm::CellBuilder().store_long(m5_test_failed_tag, 32).store_long(input.owner.workchain_id, 32)
      .store_bits(input.owner.account.bits(), 256).store_bits(input.owner.instance.bits(), 256)
      .store_bits(input.inbound_message.bits(), 256).finalize();
}
} // namespace block::m3_test
