// Manual compile probe, deliberately outside the default build.
// The required path must preserve the resolved business configuration at the
// proof-admission seam. The raw registered engine must not convert to an
// unconfigured execution engine. Neither branch opens the live execution gate.
#include "block/workchain-execution-dispatch.h"
#include "block/workchain-account-replay.h"

void probe_resolved_account_configuration(
    const block::ResolvedWorkchainAccountBinding& binding,
    const block::AdmittedBatchInput& input) {
#if defined(UNO_CONNECTIVITY_DROP_CONFIG_CONTROL)
  // Negative compiler control: configuration cannot be dropped implicitly.
  auto result = block::ProofAdmittedBatchInput::admit(*binding.executor, input);
#else
  auto configured = block::ConfiguredWorkchainAccountEngine::bind(binding);
  if (configured.is_error()) return;
  auto result = block::ProofAdmittedBatchInput::admit(*configured.ok(), input);
#endif
  (void)result;
}
