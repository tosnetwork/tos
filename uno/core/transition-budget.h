#pragma once

#include "uno/core/accounting.h"
#include "uno/core/leaf-budget.h"

namespace uno_workchain {

// A joint calculation, not a complete state transition. The caller must commit
// this result with verified bundles, withdrawal records, tree and message state.
struct TransitionBudget {
  Accounting accounting;
  LeafBudget leaves;

  td::Result<TransitionBudget> checked_prepare_withdrawal(const Amount& principal, const Amount& fee,
                                                        td::uint64 main_leaves, td::uint64 refund_leaves) const {
    TRY_RESULT(next_accounting, accounting.checked_prepare_withdrawal(principal, fee));
    TRY_RESULT(next_leaves, leaves.checked_prepare(main_leaves, refund_leaves));
    return TransitionBudget{next_accounting, next_leaves};
  }
  td::Result<TransitionBudget> checked_paid_ack(const Amount& principal, td::uint64 refund_leaves) const {
    TRY_RESULT(next_accounting, accounting.checked_paid_ack(principal));
    TRY_RESULT(next_leaves, leaves.checked_release(refund_leaves));
    return TransitionBudget{next_accounting, next_leaves};
  }
  td::Result<TransitionBudget> checked_refund(const Amount& principal, td::uint64 refund_leaves) const {
    TRY_RESULT(next_accounting, accounting.checked_refund(principal));
    TRY_RESULT(next_leaves, leaves.checked_refund_append(refund_leaves));
    return TransitionBudget{next_accounting, next_leaves};
  }
};

}  // namespace uno_workchain
