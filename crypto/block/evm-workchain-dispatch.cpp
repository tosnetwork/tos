/*
    EVM Workchain dispatch — callback registry implementation.
    Source: TOS-specific integration point.
*/
#include "evm-workchain-dispatch.h"

namespace evm_workchain_dispatch {

static EvmComputeHandler g_handler;

void set_evm_compute_handler(EvmComputeHandler handler) {
    g_handler = std::move(handler);
}

bool has_evm_compute_handler() noexcept {
    return static_cast<bool>(g_handler);
}

bool invoke_evm_compute(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {
    return g_handler(cp, in_msg_body, gas_limit, block_seqno, timestamp, rand_seed);
}

}  // namespace evm_workchain_dispatch
