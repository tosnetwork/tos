#include <limits>

#include "block/mc-config.h"
#include "vm/authops.h"

#include "native-election-binding-transaction.h"
#include "native-history.h"
#include "native-registry.h"
namespace tos::auth {

Result<std::unique_ptr<NativeElectionBindingTransaction>> NativeElectionBindingTransaction::open(
    const NativeElectionBindingTransactionInputs& inputs, StateReadBudget budget) {
  if (inputs.masterchain_state.is_null())
    return Error{"native-binding-transaction-input"};
  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||
      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)
    return Error{"native-binding-transaction-chain"};
  // A masterchain successor has exactly one coordinate, for the same reason the
  // update transaction requires it: a gathered +2 coordinate would select due
  // transitions for a block that is not being built.
  if (inputs.parent.seqno_ == std::numeric_limits<std::uint32_t>::max() ||
      inputs.inclusion != inputs.parent.seqno_ + 1)
    return Error{"native-binding-transaction-coordinate"};

  // Opening the history validates that this state really is the parent it
  // claims to be, on the network and genesis this node established. The reader
  // refuses, and the budget is not what stops it: nothing here resolves a
  // coordinate, so a reader that could reach an archive would simply never be
  // asked -- which is precisely why it must not be able to.
  auto reader = [](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> {
    return Error{"native-binding-archive-read"};
  };
  auto history = NativeFinalizedHistory::open(inputs.masterchain_state, inputs.parent, inputs.chain, reader,
                                              HistoryReadBudget{});
  if (!history.ok())
    return history.error();

  // Extracted asking for the capability block, because the activation test
  // below reads it: a configuration taken without it reports version zero and
  // no capabilities, and every chain would look inactive.
  auto config = block::Config::extract_from_state(inputs.masterchain_state, block::Config::needCapabilities);
  if (config.is_error())
    return Error{"native-binding-transaction-config"};
  // The same parameter the contract reads and the machine gates on. A chain
  // that has not activated has no binding authority to give, so there is no
  // host for a message that asks for one.
  if (config.ok()->get_global_version() < vm::validator_auth_min_version ||
      (config.ok()->get_capabilities() & vm::validator_auth_capability) == 0)
    return Error{"native-binding-transaction-inactive"};

  auto registry = NativeRegistry::bootstrap(config.ok()->get_config_param(46), inputs.parent.seqno_, budget);
  if (!registry.ok())
    return registry.error();
  // The chain domain the registry names must be the one this node established
  // from its own zero state. Without this the registry would be confirming its
  // own name, which is the whole reason the context is established elsewhere.
  if (registry.value().chain_domain() != inputs.chain.chain_domain)
    return Error{"native-binding-transaction-domain"};

  // Begun at the coordinate being built, not merely read at the parent's: due
  // transitions effective at this block are part of what the set is bound
  // against.
  auto accepted = NativeRegistryBlock::begin(registry.value(), inputs.inclusion, budget);
  if (!accepted.ok())
    return accepted.error();

  return std::unique_ptr<NativeElectionBindingTransaction>(
      new NativeElectionBindingTransaction(std::move(accepted.value()), inputs.inclusion));
}
}  // namespace tos::auth
