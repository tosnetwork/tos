#pragma once

#include "block/mc-config.h"

#include "native-anchor-cache.h"
#include "native-config-transaction.h"

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
  const NativeAnchorCache* anchors = nullptr;
  tos::ShardIdFull shard;
  tos::CatchainSeqno set_catchain = 0;
  std::uint32_t now = 0;
  std::uint32_t inclusion = 0;
};

// Assembles the authority for a registry update, or refuses. A refusal is the
// ordinary answer: almost every message reaching here is not a registry update.
//
// "registry-admission-deferred" is the one refusal that says something, and it
// says which finalized history is missing. A producer reports those coordinates
// so a later block can admit the update; a validator has nothing to report,
// because a producer that deferred did not execute the update either.
Result<std::unique_ptr<NativeConfigTransaction>> assemble_registry_authority(const CollationAuthorityInputs&);

}  // namespace tos::auth
