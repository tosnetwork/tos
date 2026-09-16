#pragma once
#include <optional>

#include "native-config-context.h"
namespace tos::auth {
// What one transaction's privileged host authorized, carried out of the
// transaction so the sequence can compare it against what the configuration
// account actually committed.
//
// A claim installs nothing. The host stages a candidate prefix; the
// configuration contract alone produces persistent c4. The claim is what lets
// the sequence tell a c4 the host authorized from one that reached the account
// by another path -- a legacy proposal, a stale parameter, or a contract that
// wrote something other than what it was handed.
class NativeCommitClaim {
  bool authorized_ = false;
  std::optional<NativeRegistryBlock> candidate_;
  Hash registry_{};    // the candidate's parameter-46 encoding
  Hash checkpoint_{};  // the candidate's account checkpoint
  NativeCommitClaim(NativeRegistryBlock candidate, Hash registry, Hash checkpoint)
      : authorized_(true)
      , candidate_(std::move(candidate))
      , registry_(registry)
      , checkpoint_(checkpoint) {
  }

 public:
  // A transaction whose host refused, or was never offered one. It authorizes
  // nothing, which is not the same as authorizing the prefix that was already
  // accepted: a transaction with no claim may not change parameter 46 at all.
  NativeCommitClaim() = default;
  // Derived from the prefix a host staged, not from a value the caller chose.
  // The two hashes are the ones the commit is compared against, so computing
  // them anywhere else would be the second description again.
  static Result<NativeCommitClaim> staged(const NativeRegistryBlock&);

  bool authorized() const {
    return authorized_;
  }
  const Hash& registry() const {
    return registry_;
  }
  const Hash& checkpoint() const {
    return checkpoint_;
  }
  // Only meaningful when authorized(); the sequence checks that first.
  const NativeRegistryBlock& candidate() const {
    return *candidate_;
  }
};

// The configuration account's native prefix across one block.
//
// The account is executed in sequence, and every transaction after the first
// needs what its predecessors committed rather than what the parent state held.
// Opening each transaction from the parent would mean a second registry update
// in one block starting from a prefix that the first one has already replaced,
// and an elected set bound against a registry that no longer exists.
//
// It installs nothing. The host authorizes and stages a candidate; the
// configuration contract alone produces persistent c4; the sequence accepts
// that candidate only when the real transaction commits and the committed c4
// binds exactly to it.
class NativeConfigSequence {
  ChainContext chain_;
  Anchor parent_;
  Hash address_{};
  std::uint32_t inclusion_ = 0;
  // The prefix later transactions open from. At block start it is the parent
  // registry with this coordinate's due transitions already materialized, which
  // is why a block with no registry message still has something to persist.
  NativeRegistryBlock accepted_;
  // The account data that produced the accepted prefix. Null until a
  // transaction in this block commits one; the parent's is not it, because the
  // parent's belongs to a coordinate whose due transitions had not fallen due.
  td::Ref<vm::Cell> accepted_data_;
  unsigned promoted_ = 0;
  NativeConfigSequence(ChainContext chain, Anchor parent, Hash address, std::uint32_t inclusion,
                       NativeRegistryBlock accepted)
      : chain_(chain), parent_(parent), address_(address), inclusion_(inclusion), accepted_(std::move(accepted)) {
  }

 public:
  // Begun at the coordinate being built, not at the parent's: a transition
  // effective at this block is part of what every transaction in it reads.
  static Result<NativeConfigSequence> begin(const NativeConfigContext&, std::uint32_t inclusion,
                                            StateReadBudget = {});

  const NativeRegistryBlock& accepted() const {
    return accepted_;
  }
  const ChainContext& chain() const {
    return chain_;
  }
  const Anchor& parent() const {
    return parent_;
  }
  const Hash& address() const {
    return address_;
  }
  std::uint32_t inclusion() const {
    return inclusion_;
  }
  // How many transactions have been promoted. A test reads it to tell "the
  // prefix did not move because nothing committed" from "the prefix did not
  // move because what committed matched what was already there".
  unsigned promoted() const {
    return promoted_;
  }
  td::Ref<vm::Cell> accepted_data() const {
    return accepted_data_;
  }

  // Bind what the configuration account actually committed to what this
  // transaction's host authorized, and advance the prefix only if they agree.
  //
  // `committed_data` is the account's persistent data after a real transaction
  // commit, never a value a host produced. The rules, in the order they can
  // fail:
  //
  //   parameter 46 unchanged  -> nothing to install; a claim that named a
  //                              different prefix means the host accepted an
  //                              update the contract then did not write.
  //   parameter 46 changed    -> there must be a claim, the committed
  //                              parameter must be exactly the candidate's,
  //                              and the committed checkpoint must be the
  //                              candidate's checkpoint.
  //
  // Refusal leaves the sequence exactly where it was, so a transaction that
  // could not be bound does not move the prefix for the ones after it.
  Result<bool> promote(const NativeCommitClaim&, td::Ref<vm::Cell> committed_data);
};
}  // namespace tos::auth
