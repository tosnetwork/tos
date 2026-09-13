#pragma once
#include "native-committee.h"
#include "native-proof.h"
namespace tos::auth {
Result<Proofref> make_committee_proof(td::Ref<vm::Cell>, const Anchor&, const ChainContext&, tos::ShardIdFull,
                                      std::uint32_t catchain, ObjectPublisher = {});
// The caller pins the full anchor, chain and native selection coordinate. The
// returned owned snapshot is derived from the proof, never a supplied roster.
Result<NativeCommittee> verify_committee_proof(const Proofref&, const Anchor&, const ChainContext&, tos::ShardIdFull,
                                               std::uint32_t catchain, ObjectReader&);
}  // namespace tos::auth
