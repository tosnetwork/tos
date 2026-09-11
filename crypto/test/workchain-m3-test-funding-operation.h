#pragma once
// TEST ONLY, shape NOT frozen. This block-contained state transition creates
// assumed test balances, NOT M4 Deposit. Never a production replay constructor.
#include "block/workchain-confidential-state.h"

namespace block::m3_test {
struct M3TestFundingOperation {
  td::Bits256 account;
  WorkchainCiphertext available;
};
constexpr unsigned m3_test_funding_tag = 0x54465531;
inline bool is_m3_test_funding(const td::Ref<vm::Cell>& root) {
  return root.not_null() && vm::load_cell_slice(root).prefetch_ulong(32) == m3_test_funding_tag;
}
inline td::Result<M3TestFundingOperation> decode_m3_test_funding(const td::Ref<vm::Cell>& root) {
  auto cs = vm::load_cell_slice(root);
  M3TestFundingOperation result;
  if (cs.size() != 800 || cs.size_refs() != 0 || cs.fetch_ulong(32) != m3_test_funding_tag ||
      !cs.fetch_bits_to(result.account) || !cs.fetch_bits_to(result.available.commitment) ||
      !cs.fetch_bits_to(result.available.handle) || result.available.handle.is_zero() ||
      !confidential_state_detail::canonical_ciphertext(result.available))
    return td::Status::Error(-7200, "malformed test-only funding operation");
  return result;
}
inline td::Ref<vm::Cell> encode_m3_test_funding(const M3TestFundingOperation& value) {
  return vm::CellBuilder().store_long(m3_test_funding_tag, 32).store_bits(value.account.bits(), 256)
      .store_bits(value.available.commitment.bits(), 256).store_bits(value.available.handle.bits(), 256).finalize();
}
inline td::Result<td::Ref<vm::Cell>> apply_m3_test_funding(
    const td::Ref<vm::Cell>& prior_data, const M3TestFundingOperation& operation) {
  TRY_RESULT(account, decode_workchain_confidential_account(prior_data));
  if (account.address.workchain_id != 2 || account.address.account != operation.account ||
      !std::holds_alternative<WorkchainAccountActive>(account.lifecycle) || account.auth_nonce != 0 ||
      account.available_revision != 0 || !account.pending.empty() ||
      !account.available.commitment.is_zero() || !account.available.handle.is_zero())
    return td::Status::Error(-7200, "test funding requires an unused registered account");
  // One-time synchronous write: no transfer, asynchronous association, claim or
  // settlement obligation is created. Both actors derive this from prior state.
  account.available = operation.available;
  // Checked initial revision == 0 above; assigning 1 cannot wrap and prevents
  // repeating the test operation, even if a later ciphertext represented zero.
  account.available_revision = 1;
  return encode_workchain_confidential_account(account);
}
}  // namespace block::m3_test
