#pragma once
#include "tos/tos-types.h"

#include "session-birth.h"
#include "state.h"
namespace block {
class ConfigInfo;
}
namespace tos::auth {
// Inputs the node owns rather than the chain: the vertical sequence this build
// runs at, and whether the consensus options select the newer catchain identity
// form. Both already decide the node's own session identity, so the epoch a
// history observation reports has to be derived from the same two values or it
// would name a session no actor ever created.
struct NativeSessionContext {
  std::uint32_t vertical_seqno{};
  bool new_catchain_ids{};
  // The node already hashes its consensus options to decide its own session
  // identity. Recomputing that hash here would be a second implementation of
  // it, free to drift from the one the identity is actually built from.
  Hash options_hash{};
};

// Derive the session a masterchain state establishes for one shard.
//
// This computes the identity the node computes, from the same authenticated
// inputs, so that walking history names the same sessions the manager named
// while it was live. It is the single derivation: the manager call site is
// expected to delegate here rather than keep a second copy that could drift.
//
// An empty result means the state positively establishes no session for this
// shard -- the shard is absent from the current set -- which the selector
// treats as a boundary. A read failure is an error, never an empty result.
// The anchor names the block this state belongs to. Extraction is bound to it
// rather than to a bare state, so an epoch is always attributed to the block a
// caller authenticated rather than to whatever cell it happened to hold.
Result<std::optional<SessionBirthEpoch>> native_session_epoch(td::Ref<vm::Cell> masterchain_state, const Anchor&,
                                                              tos::ShardIdFull shard, const NativeSessionContext&,
                                                              StateReadBudget = {});

// The same derivation against an already-extracted configuration, for callers
// that hold one. The configuration must come from the state whose session is
// being named.
Result<std::optional<SessionBirthEpoch>> native_session_epoch(const block::ConfigInfo&, tos::ShardIdFull,
                                                              const NativeSessionContext&);
}  // namespace tos::auth
