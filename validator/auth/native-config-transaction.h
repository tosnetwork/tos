#pragma once
#include "native-committee.h"
#include "native-config-host.h"
#include "native-evidence.h"
namespace tos::auth {
// Assemble the authority a native configuration transaction executes under.
//
// Everything this needs is available where a block is collated except one
// thing: authenticating an owner approval requires the original bytes of a past
// masterchain block, and that is an archive read. It is therefore the only
// injected seam here. Every other input -- the registry to advance, the
// committee that governs it, the chain this node believes it is on, and the
// evidence the transaction carries -- is derived synchronously from values the
// collator already holds.
//
// The owner path is also the only consumer of that seam, and it refuses any
// anchor at or after the block being built, so a transaction cannot authorise
// itself with state it is in the middle of producing.
struct NativeConfigTransactionInputs {
  td::Ref<vm::Cell> masterchain_state;  // the parent state this block extends
  Anchor parent;                        // its anchor, bound to that state
  ChainContext chain;                   // established from the zero state
  tos::ShardIdFull shard;
  std::uint32_t catchain{};
  std::uint32_t inclusion{};  // coordinate of the block being built
};

// Owns the pieces the host borrows, because the host holds references to them
// and outliving the assembler would be a dangling read rather than an error.
class NativeConfigTransaction {
  NativeCommittee committee_;
  NativeEvidence evidence_;
  const FinalizedAnchorSource& history_;
  NativeIdentityContext context_;
  ObjectReader reader_;
  NativeConfigHost host_;
  NativeConfigTransaction(NativeCommittee, NativeEvidence, const FinalizedAnchorSource&, NativeRegistryBlock,
                          ChainContext, std::uint32_t inclusion);

 public:
  static Result<std::unique_ptr<NativeConfigTransaction>> open(const NativeConfigTransactionInputs&,
                                                               td::Ref<vm::Cell> transaction_evidence,
                                                               const FinalizedAnchorSource&, const EvidenceCharge&,
                                                               StateReadBudget = {});
  NativeConfigHost& host() {
    return host_;
  }
  const Authorizations& authorizations() const {
    return evidence_.authorizations();
  }
};
}  // namespace tos::auth
