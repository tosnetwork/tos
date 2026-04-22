/*
    Uno Workchain dispatch — callback registry implementation.
    Mirrors evm-workchain-dispatch.cpp. Source: TOS-specific integration point.
*/
#include "uno-workchain-dispatch.h"

#include "vm/cells/CellBuilder.h"

namespace uno_workchain_dispatch {

static UnoComputeHandler g_handler;

td::Ref<vm::Cell> get_uno_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x55, 8);  // 'U' — Uno activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

void set_uno_compute_handler(UnoComputeHandler handler) {
    g_handler = std::move(handler);
}

bool has_uno_compute_handler() noexcept {
    return static_cast<bool>(g_handler);
}

bool invoke_uno_compute(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> state_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {
    return g_handler(cp, std::move(state_data), in_msg_body, gas_limit,
                     block_seqno, timestamp, rand_seed);
}

}  // namespace uno_workchain_dispatch
