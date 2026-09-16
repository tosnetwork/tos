#pragma once

#include "block/mc-config.h"

#include "native-config-transaction.h"
#include "native-election-binding-transaction.h"

namespace tos::auth {

// Everything the registry authority for one transaction is derived from. All of
// it is chain state or the message itself, so anyone holding the same block and
// the same finalized history derives the same authority.
//
// That is the point of naming the inputs instead of reading them from whoever
// is assembling: a block is produced once and re-executed by every validator,
// and the authority a validator rebuilds has to be the one the producer used.
// If they were assembled from different readings, a transaction that succeeded
// for the producer would fail for everyone else, and the candidate would be
// rejected for a difference neither side could see.
struct CollationAuthorityInputs {
  td::Ref<vm::Cell> message;
  const block::ConfigInfo* config = nullptr;
  td::Ref<vm::Cell> masterchain_state;
  tos::BlockIdExt masterchain_state_block;
  tos::BlockIdExt parent_block;
  ChainContext chain;
  tos::ShardIdFull shard;
  tos::CatchainSeqno set_catchain = 0;
  std::uint32_t now = 0;
  std::uint32_t inclusion = 0;
};

// Assembles the authority for a registry update, or refuses. A refusal is the
// ordinary answer: almost every message reaching here is not a registry update.
//
// There is nothing for a caller to do about a refusal and nothing to report.
// An update either carries the finality its approval relies on, in which case
// every node holding the block reaches the same authority, or it does not, in
// which case it is not executable for anyone and a later block changes nothing.
// Refusals name the layer that refused -- the witness surface, the history
// index, the declared anchor -- so a diagnosis does not have to guess.
// The block's native prefix, opened once from the parent it extends.
//
// Every caller that executes the configuration account needs one, and each of
// them opening its own would be three readings of a single fact -- the shape
// this design has repeatedly had to undo. The collator opens it for the block
// it produces, validation opens it for the block it re-executes, and the two
// must agree because they read the same parent through the same function.
//
// `message` is not read; a sequence belongs to a block, not to a message.
Result<NativeConfigSequence> open_configuration_sequence(const CollationAuthorityInputs&, StateReadBudget = {});

// The sequence carries what the transactions before this one in the same block
// actually committed. Both assemblers take it rather than deriving a prefix
// from the parent state: a second update in one block, and an elected set bound
// after one, must see the registry their predecessor committed.
Result<std::unique_ptr<NativeConfigTransaction>> assemble_registry_authority(const CollationAuthorityInputs&,
                                                                            const NativeConfigSequence&);


// Assembles the authority for one elected validator set, or refuses.
//
// The same inputs the registry assembler takes, because the caller holds one
// set of facts and should not have to know which message it is looking at
// before it asks. Which authority comes back is decided by the message's own
// shape: an external message carrying an update is not this, and an internal
// message from the elector is not the other.
//
// A refusal is the ordinary answer. Almost every message reaching here is
// neither, and on a chain that has not activated validator authentication this
// refuses every message, because there is no binding authority to give.
Result<std::unique_ptr<NativeElectionBindingTransaction>> assemble_election_binding_authority(
    const CollationAuthorityInputs&, const NativeConfigSequence&);

}  // namespace tos::auth
