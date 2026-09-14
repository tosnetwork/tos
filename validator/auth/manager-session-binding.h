#pragma once
#include "crypto/block/validator-set.h"
#include "tos/tos-types.h"
#include "vm/cells/Cell.h"

#include "native-session-id.h"
namespace tos::auth {
// The manager builds a session identity of its own, and the producer builds the
// same identity from the validator set. Two derivations of one fact is the shape
// this repository keeps producing, so they are bound here: the manager may not
// run a session under an identity the producer does not confirm.
//
// Replacing the manager's construction was not available. A frozen file admits
// insertions only, and inserting an early return would have left the original
// construction in place as unreachable code -- still two implementations, with
// one of them hidden. Binding them with a check that fails on disagreement is
// the alternative the repository's own guidance names.
//
// Nothing here runs unless the chain has activated P0. The gate is deliberately
// the same one native committee derivation uses, so a chain cannot be subject to
// this refusal while native derivation would have admitted it.

// True when this masterchain state has activated validator authentication.
// A state that cannot be read reports false: an unreadable state must not turn
// into an enforcement that stops an otherwise healthy node from validating.
bool native_session_binding_active(td::Ref<vm::Cell> masterchain_state);

// Inputs the manager owns, restated here so the producer receives exactly the
// values the manager's own identity was built from rather than re-deriving them.
struct ManagerSessionInputs {
  Hash options_hash{};
  std::uint32_t vertical_seqno{};
  std::uint32_t key_block_seqno{};
  bool new_catchain_ids{};
};

// Confirms the manager's identity against the producer's. An error is a refusal
// to proceed, never a silent pass: a caller that cannot establish agreement must
// decline the session rather than run it unconfirmed.
Result<bool> native_session_identity_confirms(td::Ref<block::ValidatorSet> validator_set, tos::ShardIdFull shard,
                                              const ManagerSessionInputs&, const Hash& manager_identity);
}  // namespace tos::auth
