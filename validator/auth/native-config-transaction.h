#pragma once
#include <memory>

#include "native-committee.h"
#include "native-config-host.h"
#include "native-config-sequence.h"
#include "native-evidence.h"
namespace tos::auth {
// Assemble the authority a native configuration transaction executes under.
//
// The finalized history is injected rather than read here, because what may be
// served differs by caller: consensus admission supplies only the anchors the
// message itself witnessed, so that a producer and a validator holding the same
// block reach the same answer. Every other input -- the registry to advance,
// the committee that governs it, the chain this node believes it is on, and the
// evidence the transaction carries -- is derived synchronously from values the
// collator already holds.
//
// The owner path is the only consumer of that source, and it refuses any anchor
// at or after the block being built, so a transaction cannot authorise itself
// with state it is in the middle of producing.
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
  std::shared_ptr<const FinalizedAnchorSource> history_;
  NativeIdentityContext context_;
  ObjectReader reader_;
  NativeConfigHost host_;
  NativeConfigTransaction(NativeCommittee, NativeEvidence, std::shared_ptr<const FinalizedAnchorSource>,
                          NativeRegistryBlock, ChainContext, std::uint32_t inclusion);

 public:
  // The prefix comes from the sequence, never from the parent state. A second
  // registry update in one block must start from what the first one committed;
  // re-deriving the registry here would hand it the prefix that update already
  // replaced, and both transactions would look correct on their own.
  static Result<std::unique_ptr<NativeConfigTransaction>> open(const NativeConfigTransactionInputs&,
                                                               const NativeConfigSequence&,
                                                               td::Ref<vm::Cell> transaction_evidence,
                                                               std::shared_ptr<const FinalizedAnchorSource>,
                                                               const EvidenceCharge&, StateReadBudget = {});
  NativeConfigHost& host() {
    return host_;
  }
  // The history the authority executes against. Owner verification reads it
  // during VM execution, long after the call that assembled this returned, so
  // it is exposed here for one reason: a test can read it after that return and
  // find out whether it is still there.
  const FinalizedAnchorSource& history() const {
    return *history_;
  }
  const Authorizations& authorizations() const {
    return evidence_.authorizations();
  }
};
}  // namespace tos::auth
