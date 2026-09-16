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

// Parameter 46 as the account currently holds it, by the same lookup every
// consumer of the parameter performs. A missing parameter is not an error here:
// a chain whose registry has never been installed has none, and the sequence
// reports that as the zero hash rather than refusing to read the account.
Hash committed_registry(td::Ref<vm::Cell> configuration) {
  if (configuration.is_null())
    return Hash{};
  vm::Dictionary parameters{std::move(configuration), 32};
  return hash(parameters.lookup_ref(td::BitArray<32>{(long long)46}));
}
}  // namespace

Result<NativeCommitClaim> NativeCommitClaim::staged(const NativeRegistryBlock& candidate) {
  auto registry = candidate.state().encode_cell();
  if (!registry.ok())
    return registry.error();
  auto checkpoint = candidate.state().checkpoint();
  if (!checkpoint.ok())
    return checkpoint.error();
  return NativeCommitClaim(candidate, hash(registry.value()), hash(checkpoint.value()));
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

Result<bool> NativeConfigSequence::promote(const NativeCommitClaim& claim, td::Ref<vm::Cell> committed_data) {
  auto committed = read_configuration_account(committed_data);
  if (!committed.ok())
    return committed.error();
  auto accepted_registry = accepted_.state().encode_cell();
  if (!accepted_registry.ok())
    return accepted_registry.error();

  const auto installed = committed_registry(committed.value().configuration);
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
