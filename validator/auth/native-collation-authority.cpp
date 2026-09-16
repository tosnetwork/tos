#include "native-collation-authority.h"

#include "native-config-context.h"
#include "native-registry-admission.h"

namespace tos::auth {

Result<std::unique_ptr<NativeConfigTransaction>> assemble_registry_authority(
    const CollationAuthorityInputs& inputs) {
  if (inputs.config == nullptr || inputs.anchors == nullptr || inputs.message.is_null() ||
      inputs.masterchain_state.is_null()) {
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
  return admit_registry_message(gathered.value(), *inputs.anchors);
}

}  // namespace tos::auth
