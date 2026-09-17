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

// Owns one execution host while sharing the immutable material that admission
// established. A diagnostic retry needs a fresh host and fresh work allowance,
// but it must not parse the arriving evidence again: the cell is immutable and
// admission already bounded and authenticated that interpretation.
class NativeConfigTransaction {
  struct Material;
  std::shared_ptr<const Material> material_;
  NativeIdentityContext context_;
  ObjectReader reader_;
  NativeConfigHost host_;
  explicit NativeConfigTransaction(std::shared_ptr<const Material>);

 public:
  // The prefix comes from the sequence, never from the parent state. A second
  // registry update in one block must start from what the first one committed;
  // re-deriving the registry here would hand it the prefix that update already
  // replaced, and both transactions would look correct on their own.
  // `admitted_proposal` is the configuration proposal the message carried, or
  // nothing. It reaches the host from the message that was recognised, never
  // from a caller that supplies one afterwards: the point of binding it here is
  // that the authority and the attachment come from one reading.
  static Result<std::unique_ptr<NativeConfigTransaction>> open(const NativeConfigTransactionInputs&,
                                                               const NativeConfigSequence&,
                                                               td::Ref<vm::Cell> transaction_evidence,
                                                               td::Ref<vm::Cell> admitted_proposal,
                                                               std::shared_ptr<const FinalizedAnchorSource>,
                                                               const EvidenceCharge&, StateReadBudget = {});

  // Admission has already opened and bounded the evidence before it can
  // authenticate owner history. Passing that exact value onward keeps one
  // interpretation of the unauthenticated container: reopening its root here
  // would repeat the expansion and create a second parser decision for the same
  // transaction. Other callers that only hold a cell use open() above.
  static Result<std::unique_ptr<NativeConfigTransaction>> open_admitted(
      const NativeConfigTransactionInputs&, const NativeConfigSequence&, NativeEvidence transaction_evidence,
      td::Ref<vm::Cell> admitted_proposal, std::shared_ptr<const FinalizedAnchorSource>, StateReadBudget = {});

  // Construct another execution over exactly the material this transaction was
  // admitted with. The parsed evidence, committee, witnessed history, proposal
  // and accepted prefix are shared immutably; the context, object reader and
  // host are new. In particular, work settled by one host is not inherited by
  // the next one, while no attacker-controlled bytes are expanded again.
  std::unique_ptr<NativeConfigTransaction> clone_for_execution() const;

  NativeConfigHost& host() {
    return host_;
  }
  // The history the authority executes against. Owner verification reads it
  // during VM execution, long after the call that assembled this returned, so
  // it is exposed here for one reason: a test can read it after that return and
  // find out whether it is still there.
  const FinalizedAnchorSource& history() const;
  const Authorizations& authorizations() const;
};
}  // namespace tos::auth
