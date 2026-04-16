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
#include "evm-persistent-state.h"

#include "td/utils/logging.h"

namespace evm_workchain {

static std::unique_ptr<EvmState> g_evm_state;

EvmState& global_evm_state() {
    return *g_evm_state;
}

void init_evm_workchain(const std::string& db_root) {
    LOG(WARNING) << "evm-workchain: initialising (workchain_id=2, chain_id="
                 << kEvmChainId << ")";

    if (!db_root.empty()) {
        std::string evm_db_path = db_root + "/evm-state";
        auto persistent = PersistentEvmState::open(evm_db_path);
        if (persistent) {
            g_evm_state = std::make_unique<EvmState>(std::move(persistent));
            LOG(WARNING) << "evm-workchain: using persistent state at " << evm_db_path;
        } else {
            LOG(ERROR) << "evm-workchain: failed to open persistent state, falling back to in-memory";
            g_evm_state = std::make_unique<EvmState>();
        }
    } else {
        g_evm_state = std::make_unique<EvmState>();
        LOG(WARNING) << "evm-workchain: using in-memory state (volatile)";
    }

    evm_workchain_dispatch::set_evm_compute_handler(
        [](block::ComputePhase& cp,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            return run_evm_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_evm_state,
                block_seqno, timestamp, rand_seed);
        });

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
