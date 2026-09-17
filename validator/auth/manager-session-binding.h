#pragma once
#include <tuple>

#include "crypto/block/validator-set.h"
#include "tos/tos-types.h"
#include "vm/cells/Cell.h"

#include "native-committee.h"
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
// this refusal while native derivation would have admitted it. The admission is
// derivation itself, called here, rather than any subset restated: a subset was
// the failure this exists to prevent, and for a while it was the actual state of
// this file -- the state rules were applied and the registry rules were not, so
// a roster carrying a binding the registry never issued passed here and could
// not be derived at all. The chain would not have run unauthenticated; it would
// have stalled, with two admissions giving opposite answers about one set.

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
// committee this session would run under derives at all. An error is a refusal
// to proceed, never a silent pass: a caller that cannot establish agreement must
// decline the session rather than run it unconfirmed.
//
// The masterchain state is the one the manager built its set from, passed rather
// than re-fetched so that what is admitted is what the session will actually run
// under. The anchor names that same state and must be one the caller established
// itself -- the node's own applied masterchain block, never a value a peer
// offered -- because it is what the registry read is filed under. The chain
// context is the node's own, established from the zero state it was configured
// with; derivation checks the registry's domain against it, and a context taken
// from the registry being checked would make that check confirm its own name.
//
// The roster is compared against the one derivation selects, which is the whole
// of what binds a state to a set here: every other rule is about the state and
// reaches the roster only through it, so a roster that did not come from this
// state would otherwise be carried by an admissible state that says nothing
// about it. It is also what makes this a use of the derived committee rather
// than a second opinion beside it.
Result<bool> native_session_identity_confirms(td::Ref<vm::Cell> masterchain_state, const Anchor& anchor,
                                              const ChainContext& chain, td::Ref<block::ValidatorSet> validator_set,
                                              tos::ShardIdFull shard, const ManagerSessionInputs&,
                                              const Hash& manager_identity, StateReadBudget budget = {});
}  // namespace tos::auth
