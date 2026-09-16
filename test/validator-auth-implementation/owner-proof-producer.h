#pragma once

// Extracts an owner approval from an execution that already happened. This is
// fixture tooling and lives with the tests: a validator verifies approvals and
// has no use for building them, so no production target compiles this.
//
// It cannot forge one. Building a proof re-runs the same execution check the
// verifier runs, on the same cells, so a transaction that did not execute
// yields no proof -- which is what the negative cases here rely on.

#include "validator/auth/owner-proof.h"

namespace tos::auth {
Result<OwnerAuth> make_owner_execution_proof(td::Ref<vm::Cell> masterchain_state, td::Ref<vm::Cell> owner_block,
                                             const Anchor&, const ChainContext&, const Update&, const Identity&,
                                             std::uint64_t transaction_lt, std::uint16_t message_index,
                                             ObjectPublisher = {});
}  // namespace tos::auth
