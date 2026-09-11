#pragma once
// TEST-SCOPE Native Deposit body/candidate adapter. Shape NOT frozen; this is
// not the production business-config codec. Value comes from the real inbox,
// never from a detached test balance or a candidate effects declaration.
#include "block/workchain-confidential-state.h"

namespace block::m3_test {
struct M4TestDepositInput {
  WorkchainConfidentialAddress destination;
  std::uint64_t principal;
};
constexpr unsigned m4_test_deposit_tag = 0x54445031;
inline bool is_m4_test_deposit(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return false;
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  return !special && slice.prefetch_ulong(32) == m4_test_deposit_tag;
}
inline td::Result<M4TestDepositInput> decode_m4_test_deposit(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return td::Status::Error(-7200, "missing test Deposit body");
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  if (special || slice.size() != 640 || slice.size_refs() || slice.fetch_ulong(32) != m4_test_deposit_tag)
    return td::Status::Error(-7200, "malformed test Deposit body");
  M4TestDepositInput result;
  result.destination.workchain_id = static_cast<int>(slice.fetch_long(32));
  if (!slice.fetch_bits_to(result.destination.account) || !slice.fetch_bits_to(result.destination.instance))
    return td::Status::Error(-7200, "incomplete test Deposit address");
  result.principal = slice.fetch_ulong(64);
  return result;
}
inline td::Ref<vm::Cell> encode_m4_test_deposit(const M4TestDepositInput& input) {
  return vm::CellBuilder().store_long(m4_test_deposit_tag, 32)
      .store_long(input.destination.workchain_id, 32).store_bits(input.destination.account.bits(), 256)
      .store_bits(input.destination.instance.bits(), 256).store_long(input.principal, 64).finalize();
}
}  // namespace block::m3_test
