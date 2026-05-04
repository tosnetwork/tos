/*
    EVM Workchain dispatch — canonical account marker cell implementation.
    Source: TOS-specific integration point.
*/
#include "evm-workchain-dispatch.h"

#include "vm/cells/CellBuilder.h"

namespace evm_workchain_dispatch {

td::Ref<vm::Cell> get_evm_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x45, 8);  // 'E' — EVM activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

}  // namespace evm_workchain_dispatch
