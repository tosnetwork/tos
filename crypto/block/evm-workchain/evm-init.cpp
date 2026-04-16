/*
    EVM Workchain — module initialisation implementation.

    Registers the EVM compute phase handler with the host-chain dispatch
    mechanism defined in evm-workchain-dispatch.h.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-init.h"
#include "evm-workchain.h"

#include "block/evm-workchain-dispatch.h"
#include "evm-compute-phase.h"
#include "evm-state.h"

#include "td/utils/logging.h"

namespace evm_workchain {

/// Global EVM workchain state — first-slice in-memory implementation.
/// In later phases this will be backed by persistent storage.
static EvmState g_evm_state;

EvmState& global_evm_state() {
    return g_evm_state;
}

void init_evm_workchain() {
    LOG(WARNING) << "evm-workchain: initialising EVM workchain (workchain_id=2, chain_id="
                 << kEvmChainId << ")";

    evm_workchain_dispatch::set_evm_compute_handler(
        [](block::ComputePhase& cp,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            return run_evm_compute_phase(
                cp, in_msg_body, gas_limit,
                g_evm_state,
                block_seqno, timestamp, rand_seed);
        });

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
