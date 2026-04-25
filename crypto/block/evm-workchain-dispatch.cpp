/*
    EVM Workchain dispatch — callback registry implementation.
    Source: TOS-specific integration point.
*/
#include "evm-workchain-dispatch.h"

#include "vm/cells/CellBuilder.h"

namespace evm_workchain_dispatch {

static EvmComputeHandler g_handler;

td::Ref<vm::Cell> get_evm_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x45, 8);  // 'E' — EVM activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

void set_evm_compute_handler(EvmComputeHandler handler) {
    g_handler = std::move(handler);
}

bool has_evm_compute_handler() noexcept {
    return static_cast<bool>(g_handler);
}

bool invoke_evm_compute(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {
    return g_handler(cp, std::move(account_data), in_msg_body, gas_limit,
                     block_seqno, timestamp, rand_seed);
}

}  // namespace evm_workchain_dispatch
