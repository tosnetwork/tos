#pragma once
#include "native-anchor-cache.h"
#include "native-config-transaction.h"
#include "native-history.h"
namespace tos::auth {
// Deciding whether a block may admit a registry update, separated from the
// collation that asks.
//
// Every input being wrong produces the same non-symptom: the answer is simply
// always "no", and a node that never admits an update looks exactly like a node
// on a chain that has none. So the decision lives here, where an input can be
// constructed and the answer made to fail, and the collator is left with
// gathering values it already holds.
//
// Parent block identity and catchain have two representations at this boundary:
// the values the collator actually holds, and the copies placed in the native
// transaction inputs. Keeping both would be two authorities unless admission
// binds them. They are therefore carried together and compared before an
// authority can be assembled.
struct RegistryAdmissionInputs {
  td::Ref<vm::Cell> message;     // the external message, as received
  Hash configuration_account{};  // as declared by the parent state
  tos::BlockIdExt parent_block;  // exact parent block identity held by the collator
  std::uint32_t catchain_source{};  // catchain held by the collator's validator set
  NativeConfigTransactionInputs transaction;
};

// Gather the values the collator already holds into the one admission object.
// The authoritative parent BlockIdExt and catchain remain beside the copies
// assembled for NativeConfigTransaction, so admission can detect any drift.
Result<RegistryAdmissionInputs> gather_registry_admission_inputs(
    td::Ref<vm::Cell> message, const Hash& configuration_account, td::Ref<vm::Cell> masterchain_state,
    const tos::BlockIdExt& parent_block, const ChainContext& chain, tos::ShardIdFull shard,
    std::uint32_t catchain, std::uint32_t inclusion);

// Assembles the authority for one registry update, or refuses.
//
// A refusal is never an error to report upward: it means this block does not
// admit this message, and a later one may. The distinction the caller needs is
// only whether an authority came back.
Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs&,
                                                                        const NativeAnchorCache&);

// What the update declares it will read, so a caller that deferred for missing
// history knows what to resolve before trying again. This reads nothing from
// the chain: the declaration is carried by the message.
Result<std::vector<std::uint32_t>> registry_message_requirements(td::Ref<vm::Cell> message, std::uint32_t inclusion);
}  // namespace tos::auth
