/*
    EVM Workchain — external message builder implementation.

    Builds a TLB-compliant ext_in_msg cell that passes:
      - block::gen::t_Message_Any.validate_ref()
      - block::tlb::t_Message.validate_ref()

    TLB schema (block.tlb):
      message$_ {X:Type} info:CommonMsgInfo
        init:(Maybe (Either StateInit ^StateInit))
        body:(Either X ^X) = Message X;

      ext_in_msg_info$10 src:MsgAddressExt dest:MsgAddressInt
        import_fee:Grams = CommonMsgInfo;

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/external-message.h"
#include "evm/core/cell-codec.h"
#include "evm/core/workchain.h"

#include "vm/cellslice.h"
#include "block/block.h"

namespace evm_workchain {

namespace {

bool fits_addr_std_workchain_id(tos::WorkchainId workchain_id) {
    return workchain_id >= -128 && workchain_id <= 127;
}

}  // namespace

td::Bits256 eth_addr_to_internal(const evmc::address& addr) {
    td::Bits256 result;
    result.set_zero();
    // Place 20-byte Ethereum address in the lower 160 bits (bytes 12..31)
    std::memcpy(result.data() + 12, addr.bytes, 20);
    return result;
}

td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& sender_addr) {
    return build_evm_external_message(raw_rlp, rlp_size, sender_addr, kWorkchainId);
}

td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& sender_addr,
    tos::WorkchainId workchain_id) {
    tos::StdSmcAddress executor_addr;
    executor_addr.bits().copy_from(td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
    return build_evm_external_message(raw_rlp, rlp_size, sender_addr, workchain_id, executor_addr);
}

td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& /*sender_addr*/,
    tos::WorkchainId workchain_id,
    const tos::StdSmcAddress& executor_addr) {

    if (!raw_rlp || rlp_size == 0) return {};
    if (!fits_addr_std_workchain_id(workchain_id)) return {};

    // --- Build body cell ---
    //
    // A single cell holds at most 1023 bits (~127 bytes). Ethereum raw
    // transactions routinely exceed that — a dynamic-fee / access-list /
    // blob tx is 200+ bytes. We chunk the bytes across a cell chain
    // using the same `EvmBytecodeChunk` encoding defined in
    // `evm-cell-codec.h` (127 bytes inline + Maybe ^next).
    //
    // The reader (`extract_evm_payload`) walks the chain via
    // `decode_evm_bytecode`.
    auto body_cell = encode_evm_bytecode(
        td::Slice(reinterpret_cast<const char*>(raw_rlp), rlp_size));
    if (body_cell.is_null()) return {};

    // --- Build the message cell ---
    vm::CellBuilder cb;

    // CommonMsgInfo: ext_in_msg_info$10
    cb.store_long(0b10, 2);

    // src: addr_none$00
    cb.store_long(0b00, 2);

    // dest: addr_std$10, anycast=Nothing$0
    cb.store_long(0b100, 3);  // addr_std$10 + anycast=0

    // workchain_id: int8
    cb.store_long(workchain_id, 8);

    // address: bits256 — singleton executor account resolved from the active
    // EVM engine policy. The sender_addr is unused at the outer TLB layer; it
    // is recovered from the RLP body at compute time.
    cb.store_bits(executor_addr.cbits(), 256);

    // import_fee: Grams = 0  (VarUInteger 16: 4-bit length = 0)
    cb.store_long(0, 4);

    // init: Maybe (Either StateInit ^StateInit) = nothing$0
    cb.store_long(0, 1);

    // body: Either X ^X = right$1 (body as reference cell)
    cb.store_long(1, 1);
    cb.store_ref(body_cell);

    return cb.finalize();
}

}  // namespace evm_workchain
