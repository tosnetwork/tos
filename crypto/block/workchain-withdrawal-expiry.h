#pragma once

#include "block/workchain-withdrawal-account.h"

namespace block {

struct WorkchainWithdrawalExpiry {
  WorkchainWithdrawalAccount account;
  // Ephemeral event inputs only; never a permanent per-payout history.
  std::vector<WorkchainWithdrawalRecord> closed;
};

// D74/D78 row 4. The caller must obtain this account and height from its
// authenticated predecessor/host context and authorize the owner's triggering
// operation before publishing. This is NOT an independent settlement operation.
// Phase 1's Q must already have been established by D73 queue observation;
// neither caller nor this helper may manufacture Q from a phase-0 zero.
// Only obligations are removed: no receipt, currency or sequence is produced.
inline td::Result<WorkchainWithdrawalExpiry> expire_workchain_withdrawals(
    WorkchainWithdrawalAccount account, std::uint32_t authenticated_height) {
  WorkchainWithdrawalExpiry result{std::move(account), {}};
  LOG(INFO) << "WORKCHAIN_RETURN_CALLEE lazy_owner_settlement owner=" << result.account.account.address.account.to_hex();
  auto& records = result.account.control.withdrawals;
  for (auto it = records.begin(); it != records.end();) {
    TRY_STATUS(check_workchain_withdrawal_record(*it));
    if (it->timing.phase == 0) {
      ++it;
      continue;
    }
    // Two uint32 fields fit their sum in uint64. The record validator above
    // separately enforces the encoded uint32 deadline bound.
    const auto deadline = std::uint64_t{it->timing.queue_removed_height} +
                          it->timing.settlement_blocks;
    if (authenticated_height <= deadline) {
      ++it;
      continue;
    }
    result.closed.push_back(*it);
    it = records.erase(it);
  }
  return result;
}

}  // namespace block
