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
#include "evm-external-message.h"
#include "evm-workchain.h"

#include "vm/cellslice.h"
#include "block/block.h"

namespace evm_workchain {

td::Bits256 eth_addr_to_internal(const evmc::address& addr) {
    td::Bits256 result;
    result.set_zero();
    // Place 20-byte Ethereum address in the lower 160 bits (bytes 12..31)
    std::memcpy(result.data() + 12, addr.bytes, 20);
    return result;
}

td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& /*sender_addr*/) {

    if (!raw_rlp || rlp_size == 0) return {};

    // --- Build body cell first (raw RLP bytes) ---
    vm::CellBuilder body_cb;
    for (size_t i = 0; i < rlp_size; ++i) {
        body_cb.store_long(raw_rlp[i], 8);
    }
    auto body_cell = body_cb.finalize();

    // --- Build the message cell ---
    vm::CellBuilder cb;

    // CommonMsgInfo: ext_in_msg_info$10
    cb.store_long(0b10, 2);

    // src: addr_none$00
    cb.store_long(0b00, 2);

    // dest: addr_std$10, anycast=Nothing$0
    cb.store_long(0b100, 3);  // addr_std$10 + anycast=0

    // workchain_id: int8
    cb.store_long(kWorkchainId, 8);

    // address: bits256 — fixed executor account. Every EVM ext-message
    // routes to the same wc=1 account whose StateInit.data carries the
    // entire EVM world state. sender_addr is unused at the outer TLB
    // layer; it is recovered from the RLP body at compute time.
    cb.store_bytes(reinterpret_cast<const char*>(kEvmExecutorAddressBytes), 32);

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
