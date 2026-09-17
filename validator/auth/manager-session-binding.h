#pragma once
#include <tuple>

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
// this refusal while native derivation would have admitted it. The admission
// rules are derivation's own for the same reason: applied from a copy here they
// would be a second set of rules the moment one of them moved, and the manager
// would build a group whose roster derivation refuses.

// The manager copies a session id and an options hash into these fixed-size
// fields byte for byte. That copy is exactly sized only because both sources are
// 256-bit, which is declared somewhere else entirely and would fail silently by
// overrunning the destination if it ever changed. Bind the two widths here so
// the build refuses instead.
static_assert(sizeof(td::Bits256) == std::tuple_size_v<Hash>,
              "a session identity no longer fits the fixed-size hash the manager copies it into");

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

// Confirms the manager's identity against the producer's, and confirms that the
// state and the roster are ones committee derivation admits. An error is a
// refusal to proceed, never a silent pass: a caller that cannot establish
// agreement must decline the session rather than run it unconfirmed.
//
// The masterchain state is the one the manager built its set from. It is passed
// rather than re-fetched so that what is admitted here is what the session will
// actually run under, and so that the admission rules can be derivation's own
// rather than a smaller set restated here.
Result<bool> native_session_identity_confirms(td::Ref<vm::Cell> masterchain_state,
                                              td::Ref<block::ValidatorSet> validator_set, tos::ShardIdFull shard,
                                              const ManagerSessionInputs&, const Hash& manager_identity);
}  // namespace tos::auth
