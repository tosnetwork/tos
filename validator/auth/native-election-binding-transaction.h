#pragma once
#include <memory>

#include "native-config-sequence.h"
#include "native-election-binding-host.h"
namespace tos::auth {
// Everything the authority for one elected-set transaction is derived from.
//
// Less than a registry update needs, because binding needs less: there is no
// evidence to open, no committee to derive and no history to read. What remains
// is the parent state the set is bound against and the coordinate it is bound
// at, which is what decides whether a registry policy is yet effective.
struct NativeElectionBindingTransactionInputs {
  td::Ref<vm::Cell> masterchain_state;  // the parent state this block extends
  Anchor parent;                        // its anchor, bound to that state
  ChainContext chain;                   // established from the zero state
  std::uint32_t inclusion = 0;          // coordinate of the block being built
};

// Owns the host the instruction borrows, for the same reason the update
// transaction does: the host holds the registry block it reads from, and
// outliving the assembler would be a dangling read rather than an error.
class NativeElectionBindingTransaction {
  NativeElectionBindingHost host_;
  explicit NativeElectionBindingTransaction(NativeRegistryBlock accepted, std::uint32_t inclusion)
      : host_(std::move(accepted), inclusion) {
  }

 public:
  // Refuses unless the chain has activated validator authentication. A chain
  // that has not must not be able to reach the instruction at all, and the
  // contract on such a chain never asks: both sides read the same parameter.
  // The prefix comes from the sequence, so a set elected in the same block as a
  // registry update is bound against the registry that update committed rather
  // than the one it replaced.
  static Result<std::unique_ptr<NativeElectionBindingTransaction>> open(
      const NativeElectionBindingTransactionInputs&, const NativeConfigSequence&);

  vm::ValidatorAuthHost& host() {
    return host_;
  }
  unsigned bindings() const {
    return host_.bindings();
  }
  const NativeElectionBindingHost& host_state() const {
    return host_;
  }
};
}  // namespace tos::auth
