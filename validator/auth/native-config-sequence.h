#pragma once
#include <optional>

#include "native-config-context.h"
namespace tos::auth {
// What a governance operation changed about the configuration itself: the
// parameter it names, the hash that parameter had to hold before, and the hash
// it must hold after.
//
// The proposal is not a virtual machine operand, so nothing in the instruction
// stream ties the value the contract installed to the one the host authorized.
// This is what ties them, at the commit: the contract could otherwise be
// authorized for one proposal and install another.
struct ConfigurationDelta {
  bool present = false;
  long long index = 0;
  Hash previous{};  // zero means the parameter was absent
  Hash proposed{};  // zero means the proposal deletes it
};

// Tie a governance operation to the exact proposal the message carried.
//
// The operation names a parameter index, the hash the parameter must currently
// hold and the hash it must hold afterwards. The proposal is the object those
// hashes describe: it carries the same index, the compare-and-swap the vote was
// taken under, and the value to install. Every one of the three has to agree,
// or the operation was authorized for something other than what would be
// installed.
//
// Two zero hashes have meanings rather than being absences. A previous hash of
// zero says the parameter is currently absent, which is how the contract itself
// encodes a missing value; the proposal must still state that condition rather
// than omit it, or "no compare-and-swap was asked for" and "the parameter must
// be absent" would be one encoding for two different demands. A proposed hash
// of zero says the proposal deletes the parameter.
//
// An operation that takes no proposal must not carry one: a message whose extra
// cell nobody examined is a message whose shape nobody checked.
Result<ConfigurationDelta> bind_configuration_proposal(const Update&, const td::Ref<vm::Cell>& proposal);

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
  // The elected set the instruction returned, when this transaction bound one.
  bool binds_ = false;
  Hash validators_{};
  ConfigurationDelta delta_;
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
  static Result<NativeCommitClaim> staged(const NativeRegistryBlock&, ConfigurationDelta = {});
  // The same, for a transaction that also bound an elected set. The registry
  // does not move -- binding reads it and changes nothing -- but the set the
  // instruction returned is what the contract must install, and a contract
  // that was handed one set and wrote another is the join this catches.
  static Result<NativeCommitClaim> bound(const NativeRegistryBlock&, td::Ref<vm::Cell> validators);

  bool authorized() const {
    return authorized_;
  }
  const Hash& registry() const {
    return registry_;
  }
  const Hash& checkpoint() const {
    return checkpoint_;
  }
  bool binds() const {
    return binds_;
  }
  const ConfigurationDelta& delta() const {
    return delta_;
  }
  const Hash& validators() const {
    return validators_;
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
  // Begun from the parent's installed registry parameter, at the coordinate
  // being built: a transition effective at this block is part of what every
  // transaction in it reads.
  //
  // The parameter, not the account's checkpoint. The two are the registry's two
  // homes and the account is where it persists, but requiring a coordinate-
  // current checkpoint to *begin* would be a stronger precondition than the
  // chain meets: a block whose configuration account has not yet re-stored its
  // checkpoint would have no sequence at all, and so no way to store one. The
  // account is bound to the candidate where that binding belongs -- at commit,
  // in promote().
  static Result<NativeConfigSequence> begin(td::Ref<vm::Cell> registry_parameter, const Hash& address,
                                            const Anchor& parent, const ChainContext& chain,
                                            std::uint32_t inclusion, StateReadBudget = {});

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
  //   a set was bound          -> the committed parameter 36 must be exactly
  //                              the set the instruction returned.
  //   a parameter was changed  -> it held exactly the hash the operation named
  //                              before this transaction and holds exactly the
  //                              proposed one after. The proposal is not a
  //                              virtual machine operand, so this is the only
  //                              place a contract authorized for one proposal
  //                              and installing another is caught.
  //
  // `before` is the account as it stood before this transaction. It is supplied
  // rather than remembered: the first transaction of a block follows the
  // parent's account, which the sequence never held, and inventing a second
  // notion of "before" is the shape this whole arrangement removes.
  //
  // Refusal leaves the sequence exactly where it was, so a transaction that
  // could not be bound does not move the prefix for the ones after it.
  Result<bool> promote(const NativeCommitClaim&, td::Ref<vm::Cell> before, td::Ref<vm::Cell> committed_data);
};
}  // namespace tos::auth
