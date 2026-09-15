#pragma once
#include "tos/tos-types.h"
#include "vm/cells/Cell.h"

#include "context.h"
namespace tos::auth {
// Establish this node's own chain context from the zero state.
//
// Every native path takes a ChainContext and trusts it, and nothing produced
// one: a caller could pass a context assembled from the registry it is about to
// check, which makes the domain check vacuous -- the registry would be
// confirming its own name.
//
// The zero block id is the node's independent anchor: it is configuration the
// operator supplied, not a value any peer offered. The genesis coordinates come
// from it directly, the network is checked against the zero state's own global
// id, and the chain domain is read from the registry the zero state committed.
// That is not circular, because what binds the registry is the zero block id
// the node already held.
//
// This establishes a name, not authority. A context says which chain this node
// believes it is on; it grants nothing and proves nothing about any other node.
Result<ChainContext> establish_chain_context(td::Ref<vm::Cell> zero_state, const tos::BlockIdExt& zero_block_id,
                                             std::int32_t expected_network);
}  // namespace tos::auth
