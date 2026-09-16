#include "block/block-auto.h"
#include "block/block-parse.h"

#include "native-collation-authority.h"

#include "native-config-context.h"
#include "native-config-message.h"
#include "native-history.h"
#include "native-registry-admission.h"

namespace tos::auth {

Result<NativeConfigSequence> open_configuration_sequence(const CollationAuthorityInputs& inputs,
                                                         StateReadBudget budget) {
  if (inputs.config == nullptr || inputs.masterchain_state.is_null())
    return Error{"collation-sequence-input"};
  // Which account is the configuration account is read the same way the
  // authority inputs read it, bound to this state.
  auto configuration = declared_configuration_account(*inputs.config, inputs.masterchain_state);
  if (!configuration.ok())
    return configuration.error();
  return NativeConfigSequence::begin(inputs.config->get_config_param(46), configuration.value(),
                                     anchor_of(inputs.parent_block, inputs.masterchain_state), inputs.chain,
                                     inputs.inclusion, budget);
}

Result<std::unique_ptr<NativeConfigTransaction>> assemble_registry_authority(
    const CollationAuthorityInputs& inputs, const NativeConfigSequence& sequence) {
  if (inputs.config == nullptr || inputs.message.is_null() || inputs.masterchain_state.is_null()) {
    return Error{"collation-authority-input"};
  }

  // Which account is the configuration account is read the same way the
  // authority inputs read it, bound to this state; a second reading would be a
  // second source that nothing compares.
  auto configuration = declared_configuration_account(*inputs.config, inputs.masterchain_state);
  if (!configuration.ok()) {
    return configuration.error();
  }

  // The catchain the established set answers for, taken from the same config
  // the account was read from rather than from whoever is calling.
  tos::CatchainSeqno established_catchain = 0;
  auto established = inputs.config->compute_validator_set_cc(inputs.shard, inputs.now, &established_catchain);
  if (established.empty()) {
    return Error{"collation-authority-validator-set"};
  }

  auto gathered = gather_registry_admission_inputs(
      inputs.message, configuration.value(), inputs.masterchain_state, inputs.masterchain_state_block,
      inputs.parent_block, inputs.chain, inputs.shard, established_catchain, inputs.set_catchain, inputs.inclusion);
  if (!gathered.ok()) {
    return gathered.error();
  }
  return admit_registry_message(gathered.value(), sequence);
}


Result<std::unique_ptr<NativeElectionBindingTransaction>> assemble_election_binding_authority(
    const CollationAuthorityInputs& inputs, const NativeConfigSequence& sequence) {
  if (inputs.config == nullptr || inputs.message.is_null() || inputs.masterchain_state.is_null()) {
    return Error{"election-binding-input"};
  }

  // Internal, from the masterchain, and not a bounce. The contract refuses all
  // three, and an authority assembled for a message the contract would drop
  // would be an authority for nothing.
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  vm::CellSlice cs;
  try {
    cs = vm::load_cell_slice(inputs.message);
    if (!tlb::unpack(cs, info)) {
      return Error{"election-binding-not-internal"};
    }
  } catch (const vm::VmError&) {
    return Error{"election-binding-not-internal"};
  }
  if (info.bounced) {
    return Error{"election-binding-bounced"};
  }

  auto address = [](vm::CellSlice source, Hash& account) {
    return source.fetch_ulong(2) == 2 && source.fetch_ulong(1) == 0 &&
           source.fetch_long(8) == tos::masterchainId &&
           source.fetch_bytes(td::MutableSlice(account.data(), account.size()));
  };
  Hash source{}, destination{};
  if (!address(info.src.write(), source) || !address(info.dest.write(), destination)) {
    return Error{"election-binding-not-masterchain"};
  }

  // The elector this chain names, and the configuration account this state
  // declares. Both come from the same parent config the set will be bound
  // against, so neither is a value the caller supplied.
  auto elector = inputs.config->get_config_param(1);
  if (elector.is_null()) {
    return Error{"election-binding-no-elector"};
  }
  Hash expected_source{};
  try {
    vm::CellSlice named{vm::NoVm{}, elector};
    if (named.size() < 256 || !named.fetch_bytes(td::MutableSlice(expected_source.data(), expected_source.size()))) {
      return Error{"election-binding-no-elector"};
    }
  } catch (const vm::VmError&) {
    return Error{"election-binding-no-elector"};
  }
  if (source != expected_source) {
    return Error{"election-binding-not-elector"};
  }
  auto configuration = declared_configuration_account(*inputs.config, inputs.masterchain_state);
  if (!configuration.ok()) {
    return configuration.error();
  }
  if (destination != configuration.value()) {
    return Error{"election-binding-not-configuration"};
  }

  if (cs.size_refs() != 1) {
    return Error{"election-binding-not-validator-set"};
  }
  auto recognized = recognize_validator_set_message(cs.fetch_ref());
  if (!recognized.ok()) {
    return Error{"election-binding-not-validator-set"};
  }
  // A set arriving without bindings on an active chain is refused by the
  // contract, so there is nothing for an authority to do with one. Assembling
  // here would produce a host no instruction ever reaches.
  if (recognized.value().bindings.is_null()) {
    return Error{"election-binding-absent"};
  }

  return NativeElectionBindingTransaction::open(
      {inputs.masterchain_state, anchor_of(inputs.parent_block, inputs.masterchain_state), inputs.chain,
       inputs.inclusion},
      sequence);
}

}  // namespace tos::auth
