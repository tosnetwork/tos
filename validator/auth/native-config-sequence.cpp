#include "vm/dict.h"

#include "native-config-sequence.h"
namespace tos::auth {
namespace {
Hash hash(td::Ref<vm::Cell> cell) {
  Hash result{};
  if (cell.not_null()) {
    auto owned = cell->get_hash();
    std::copy_n(owned.as_slice().ubegin(), result.size(), result.begin());
  }
  return result;
}

// One configuration parameter as the account currently holds it, by the same
// lookup every consumer of that parameter performs. A missing parameter is not
// an error here: a chain whose registry has never been installed has none, and
// a chain between elections has no pending set, so both are reported as the
// zero hash rather than refusing to read the account.
Hash committed_parameter(td::Ref<vm::Cell> configuration, long long index) {
  if (configuration.is_null())
    return Hash{};
  vm::Dictionary parameters{std::move(configuration), 32};
  return hash(parameters.lookup_ref(td::BitArray<32>{index}));
}
}  // namespace

Result<ConfigurationDelta> bind_configuration_proposal(const Update& update, const td::Ref<vm::Cell>& proposal) {
  if (update.operation_ != 6) {
    if (proposal.not_null())
      return Error{"proposal-unexpected"};
    return ConfigurationDelta{};
  }
  if (proposal.is_null())
    return Error{"proposal-absent"};
  // The operation's own statement of what it changes.
  if (update.operation_data_.size() != 4 + 32 + 32)
    return Error{"proposal-operand"};
  Reader r{update.operation_data_};
  std::int32_t index = 0;
  Hash previous{}, proposed{};
  r.integer(index);
  r.hash(previous);
  r.hash(proposed);
  if (!r.ok())
    return Error{"proposal-operand"};

  try {
    // cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell)
    //                 if_hash_equal:(Maybe uint256)
    vm::CellSlice cs{vm::NoVm{}, proposal};
    if (cs.is_special() || cs.fetch_ulong(8) != 0xf3)
      return Error{"proposal-shape"};
    std::int32_t declared = 0;
    if (!cs.fetch_int_to(32, declared) || declared != index)
      return Error{"proposal-parameter"};
    td::Ref<vm::Cell> value;
    if (cs.fetch_ulong(1) == 1) {
      if (cs.size_refs() == 0)
        return Error{"proposal-shape"};
      value = cs.fetch_ref();
    }
    // The compare-and-swap the vote was taken under has to be stated. A
    // proposal that asked for none was voted on under a different condition
    // than the one this operation authorizes.
    if (cs.fetch_ulong(1) != 1)
      return Error{"proposal-compare"};
    Hash condition{};
    if (!cs.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(condition.data()), condition.size())))
      return Error{"proposal-shape"};
    if (cs.size() != 0 || cs.size_refs() != 0)
      return Error{"proposal-shape"};
    if (condition != previous)
      return Error{"proposal-precondition"};
    if (hash(value) != proposed)
      return Error{"proposal-value"};
    ConfigurationDelta delta;
    delta.present = true;
    delta.index = index;
    delta.previous = previous;
    delta.proposed = proposed;
    return delta;
  } catch (const vm::VmError&) {
    return Error{"proposal-shape"};
  } catch (const vm::VmVirtError&) {
    return Error{"proposal-pruned"};
  }
}

Result<NativeCommitClaim> NativeCommitClaim::bound(const NativeRegistryBlock& candidate,
                                                   td::Ref<vm::Cell> validators) {
  auto claim = staged(candidate);
  if (!claim.ok())
    return claim.error();
  if (validators.is_null())
    return Error{"commit-claim-validators"};
  claim.value().binds_ = true;
  claim.value().validators_ = hash(std::move(validators));
  return claim;
}

Result<NativeCommitClaim> NativeCommitClaim::staged(const NativeRegistryBlock& candidate,
                                                   ConfigurationDelta delta) {
  auto registry = candidate.state().encode_cell();
  if (!registry.ok())
    return registry.error();
  auto checkpoint = candidate.state().checkpoint();
  if (!checkpoint.ok())
    return checkpoint.error();
  auto claim = NativeCommitClaim(candidate, hash(registry.value()), hash(checkpoint.value()));
  claim.delta_ = delta;
  return claim;
}

Result<NativeConfigSequence> NativeConfigSequence::begin(td::Ref<vm::Cell> registry_parameter, const Hash& address,
                                                         const Anchor& parent, const ChainContext& chain,
                                                         std::uint32_t inclusion, StateReadBudget budget) {
  auto registry = NativeRegistry::bootstrap(std::move(registry_parameter), parent.seqno_, budget);
  if (!registry.ok())
    return registry.error();
  // The chain domain the registry names must be the one this node established
  // from its own zero state, or the registry would be confirming its own name.
  if (registry.value().chain_domain() != chain.chain_domain)
    return Error{"config-sequence-domain"};
  // No coordinate check here. A gathered coordinate is refused, but by the
  // registry itself: begin() replays the parent onto `inclusion`, and a
  // successor that is not the parent's next one has no transitions to select.
  // Restating it here would be a second guard for one rule, and a mutation
  // proved this copy could be deleted without any case noticing -- which is
  // what a guard that protects nothing looks like.
  auto accepted = NativeRegistryBlock::begin(registry.value(), inclusion, budget);
  if (!accepted.ok())
    return accepted.error();
  return NativeConfigSequence(chain, parent, address, inclusion, std::move(accepted.value()));
}

Result<bool> NativeConfigSequence::promote(const NativeCommitClaim& claim, td::Ref<vm::Cell> before,
                                           td::Ref<vm::Cell> committed_data) {
  auto committed = read_configuration_account(committed_data);
  if (!committed.ok())
    return committed.error();
  // A configuration parameter the operation named. Checked first and on its own
  // account: a governance operation moves the registry like any other, so every
  // check below would pass for one that installed a different proposal.
  if (claim.delta().present) {
    auto earlier = read_configuration_account(std::move(before));
    if (!earlier.ok())
      return earlier.error();
    if (committed_parameter(earlier.value().configuration, claim.delta().index) != claim.delta().previous)
      return Error{"config-sequence-parameter-before"};
    if (committed_parameter(committed.value().configuration, claim.delta().index) != claim.delta().proposed)
      return Error{"config-sequence-parameter-after"};
  }
  // A bound set is checked before anything about the registry, because a
  // binding transaction does not move the registry at all: the whole of what it
  // changed is parameter 36, so a check placed after the "nothing to install"
  // return would never run for the transaction it is about.
  if (claim.binds() && claim.validators() != committed_parameter(committed.value().configuration, 36))
    return Error{"config-sequence-validators"};
  auto accepted_registry = accepted_.state().encode_cell();
  if (!accepted_registry.ok())
    return accepted_registry.error();

  const auto installed = committed_parameter(committed.value().configuration, 46);
  const auto standing = hash(accepted_registry.value());
  if (installed == standing) {
    // Nothing to install. A host that accepted a different prefix and a
    // contract that did not write it is not a transaction that merely changed
    // nothing -- it is the two coming apart, which is the case this exists for.
    if (claim.authorized() && claim.registry() != standing)
      return Error{"config-sequence-uninstalled"};
    // The account still moved, even though the registry did not: this is what
    // it holds now, and the next transaction reads it from here.
    accepted_data_ = std::move(committed_data);
    return false;
  }
  // Parameter 46 moved. Only a host can move it, and only to what it accepted.
  if (!claim.authorized())
    return Error{"config-sequence-unauthorized"};
  if (claim.registry() != installed)
    return Error{"config-sequence-registry"};
  if (claim.checkpoint() != hash(committed.value().checkpoint))
    return Error{"config-sequence-checkpoint"};

  accepted_ = claim.candidate();
  accepted_data_ = std::move(committed_data);
  ++promoted_;
  return true;
}
}  // namespace tos::auth
