/*
    JVM workchain initialization (Phase 2 scaffold).
*/
#include "jvm/core/init.h"

#include "block/workchain-execution-dispatch.h"
#include "jvm/core/dispatch-engine.h"

namespace jvm_workchain {

bool init_jvm_workchain(const char* /*db_root*/) {
    // Phase 2 stub: register engine stub.
    // TODO(Phase 2): initialize Avata Machine, load rt.jar from zerostate.
    // TODO(Phase 2): call avata_set_opcode_gas_costs() / avata_set_contract_helper_gas_costs()
    //   from ConfigParam 85 via avata_begin_contract_transaction_with_limits().
    register_jvm_workchain_engine(block::default_workchain_execution_registry());
    return true;
}

}  // namespace jvm_workchain
