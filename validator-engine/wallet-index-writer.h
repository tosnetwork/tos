#pragma once

#include <algorithm>

#include "vm/cells.h"
#include "vm/vm.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"

namespace tos_wallet_index {

constexpr long long kWalletIndexGetMethodGasLimit = 1'000'000;
constexpr long long kWalletIndexBlockVerificationGasLimit = 10'000'000;

enum class WalletIndexGetMethodStatus { Success, ContractFailure, Indeterminate };

// A failed get-method is indeterminate only when the node, rather than the
// contract, prevented a conclusive answer. In particular, preserve an old
// ownership claim when the fair-share scheduler supplied less than the normal
// per-method limit and that reduced share was exhausted. A contract that burns
// the full normal limit still fails verification, otherwise it could pin stale
// ownership forever by deliberately running out of gas.
inline WalletIndexGetMethodStatus wallet_index_classify_get_method_failure(long long reserved_gas, td::int32 exit_code,
                                                                           long long gas_used) {
  auto out_of_gas = ~static_cast<td::int32>(vm::Excno::out_of_gas);
  auto virtualization_error = ~static_cast<td::int32>(vm::Excno::virt_err);
  if (exit_code == virtualization_error || (reserved_gas > 0 && reserved_gas < kWalletIndexGetMethodGasLimit &&
                                            exit_code == out_of_gas && gas_used >= reserved_gas)) {
    return WalletIndexGetMethodStatus::Indeterminate;
  }
  return WalletIndexGetMethodStatus::ContractFailure;
}

// Both limit and max must be bounded. A hostile get-method may execute ACCEPT,
// which raises the current limit up to gas_max.
inline vm::GasLimits wallet_index_get_method_gas_limits(
    long long remaining = kWalletIndexGetMethodGasLimit) {
  auto limit = std::min(kWalletIndexGetMethodGasLimit, std::max(0LL, remaining));
  return vm::GasLimits{limit, limit};
}

inline bool wallet_index_state_contains(tos::ShardIdFull shard, const td::Bits256& address) {
  return tos::shard_contains(shard, tos::AccountIdPrefixFull{0, tos::extract_top64(address)});
}

class WalletIndexVerificationBudget {
 public:
  void begin_candidate(size_t remaining_candidates) {
    candidate_remaining_ = remaining_candidates == 0 ? 0 : remaining_ / static_cast<long long>(remaining_candidates);
  }

  long long acquire() {
    auto limit = std::min({kWalletIndexGetMethodGasLimit, remaining_, candidate_remaining_});
    remaining_ -= limit;
    candidate_remaining_ -= limit;
    return limit;
  }

  void refund_unused(long long reserved, long long used) {
    auto refund = reserved - std::clamp(used, 0LL, reserved);
    remaining_ += refund;
    candidate_remaining_ += refund;
  }

 private:
  long long remaining_{kWalletIndexBlockVerificationGasLimit};
  long long candidate_remaining_{kWalletIndexGetMethodGasLimit};
};

// Index every wc=0 transaction in an applied block into the wallet index, and
// (re)index token ownership verified against the post-apply shard state.
// Installed as tos::validator::g_wc0_block_index_hook by validator-engine.
// Best-effort: swallows parse errors so it never affects block application.
// `state_root` may be null; token indexing is then skipped (fail-closed).
// `block_id` must be the full BlockIdExt (not just workchain+seqno): the
// crash-recovery marker is keyed off it, and workchain+seqno alone is not
// unique across a shard split/merge.
void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id);

}  // namespace tos_wallet_index
