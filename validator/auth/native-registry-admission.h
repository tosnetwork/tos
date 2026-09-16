#pragma once
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
// Parent block identity and catchain have two representations after gathering:
// independently established sources and the copies used by the transaction.
// The production caller obtains the established parent from the loaded
// masterchain state and the established catchain from that state's validator
// configuration; the values it intends to use remain separate claims.
// Admission binds the transaction copies back to the established sources so a
// later mutation of the admission object cannot create a second authority.
struct RegistryAdmissionInputs {
  td::Ref<vm::Cell> message;     // the external message, as received
  Hash configuration_account{};  // as declared by the parent state
  tos::BlockIdExt parent_block;  // parent identity established by the loaded state
  std::uint32_t catchain_source{};  // catchain independently derived from parent config
  NativeConfigTransactionInputs transaction;
};

// Gather the values the collator already holds into the one admission object.
//
// `parent_block` and `catchain` are the values the collator intends to use.
// They are not authorities by themselves. The corresponding established values
// come from the loaded masterchain state and its configuration. A mismatch is
// refused before the transaction inputs are assembled, so a caller cannot make
// two equally-wrong copies and pass a self-comparison.
Result<RegistryAdmissionInputs> gather_registry_admission_inputs(
    td::Ref<vm::Cell> message, const Hash& configuration_account, td::Ref<vm::Cell> masterchain_state,
    const tos::BlockIdExt& established_parent_block, const tos::BlockIdExt& parent_block,
    const ChainContext& chain, tos::ShardIdFull shard, std::uint32_t established_catchain,
    std::uint32_t catchain, std::uint32_t inclusion);

// Assembles the authority for one registry update, or refuses.
//
// A refusal is never an error to report upward: it means this block does not
// admit this message, and a later one may. The distinction the caller needs is
// only whether an authority came back.
// Admits a registry update, or refuses. Everything it decides from is the
// parent state and the message: the finality an approval relies on is carried
// by that message and authenticated against this state's own history index.
//
// There is deliberately no archive, cache or resolver in this signature. A
// producer and a validator holding the same block must reach the same answer,
// and anything node-local here would make that depend on what one of them
// happened to have resolved.
Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs&);
}  // namespace tos::auth
