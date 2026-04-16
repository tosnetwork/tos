/*
    EVM Workchain — external message builder implementation.
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
    const evmc::address& sender_addr) {

    if (!raw_rlp || rlp_size == 0) return {};

    // Build the external message cell:
    //   ext_in_msg_info$10
    //     src:addr_none$00
    //     dest:addr_std$10 anycast:(Maybe Anycast) = Nothing$0
    //          workchain_id:int8 address:bits256
    //     import_fee:Grams = 0
    //   body: raw RLP bytes

    vm::CellBuilder cb;

    // CommonMsgInfo tag: ext_in_msg_info$10
    cb.store_long(0b10, 2);

    // src: addr_none$00
    cb.store_long(0b00, 2);

    // dest: addr_std$10, anycast=Nothing$0
    cb.store_long(0b100, 3);  // addr_std$10 + anycast=0

    // workchain_id: int8
    cb.store_long(kWorkchainId, 8);

    // address: bits256 (Ethereum address zero-padded to 256 bits)
    td::Bits256 internal_addr = eth_addr_to_internal(sender_addr);
    cb.store_bits(internal_addr.as_bitslice());

    // import_fee: Grams (var_uint 4 bits length prefix + value)
    // 0 Grams = 0b0000 (length=0)
    cb.store_long(0, 4);

    // Body: raw RLP bytes
    // Store as a reference cell to handle large transactions
    vm::CellBuilder body_cb;
    for (size_t i = 0; i < rlp_size; ++i) {
        body_cb.store_long(raw_rlp[i], 8);
    }

    // If body fits in the remaining bits, store inline; otherwise as reference
    if (cb.remaining_bits() >= rlp_size * 8) {
        // Store body bits inline
        for (size_t i = 0; i < rlp_size; ++i) {
            cb.store_long(raw_rlp[i], 8);
        }
    } else {
        // Store body as a reference
        cb.store_long(0, 1);  // either$0 — body in reference (bit=0 means in ref)
        cb.store_ref(body_cb.finalize());
    }

    return cb.finalize();
}

}  // namespace evm_workchain
