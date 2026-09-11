#pragma once
// Shape NOT frozen. Test-scope only. The production business-config codec is a
// separate, undecided unit; do not treat this layout as a precedent.
#include "workchain-m3-business-config.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-execution-dispatch.h"

namespace block::m3_test {
struct M3TestGenesisCells {
  td::Ref<vm::Cell> business_parameters, engine_configuration, param84, coordinator_data;
};

// Single-workchain TEST fixture, not a deployment parser or configuration
// installer. Every value comes from the caller; no environment or production
// defaults. The caller installs param84 in its authenticated configuration and
// coordinator_data in the Native account, then derives configuration identity
// from that actual enclosing configuration through the normal host path.
// This function supplies neither an authentication verdict nor a statement.
inline td::Result<M3TestGenesisCells> make_m3_test_genesis_cells(
    const M3TestBusinessParameters& business, const WorkchainResourcePolicy& resources,
    std::uint32_t accepted_cadence_ms, const td::Bits256& workchain_instance,
    std::uint64_t registration_deposit, WorkchainNativeIngressPolicy ingress_identity,
    const WorkchainCoordinatorState& initial_coordinator) {
  if (ingress_identity.engine_configuration.not_null())
    return td::Status::Error("M3 test fixture refuses to replace an existing engine configuration");
  TRY_RESULT(parameters, encode_m3_test_business_parameters(business));
  TRY_RESULT(configuration, encode_workchain_engine_parameters(
      {accepted_cadence_ms, workchain_instance, resources, parameters, registration_deposit}));
  ingress_identity.engine_configuration = configuration;
  TRY_RESULT(param84, encode_workchain_native_ingress_table({ingress_identity}));
  TRY_RESULT(coordinator, encode_workchain_coordinator_state(initial_coordinator));
  return M3TestGenesisCells{parameters, configuration, param84, coordinator};
}
}  // namespace block::m3_test
