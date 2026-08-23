#pragma once

#include <algorithm>

#include "vm/cells.h"
#include "vm/vm.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"

namespace tos_wallet_index {

constexpr long long kWalletIndexGetMethodGasLimit = 1'000'000;
constexpr long long kWalletIndexBlockVerificationGasLimit = 10'000'000;

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
