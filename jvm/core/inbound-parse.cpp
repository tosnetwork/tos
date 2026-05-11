/*
    JVM Workchain — inbound message parsing helper.

    Shared between dispatch-engine.cpp (first-activation auth) and
    avata-runtime.cpp (Context plumbing). Centralizing the unpack logic
    prevents the two paths from drifting apart and keeps a single
    canonical pattern for "what counts as a valid addr_std caller".
*/
#include "jvm/core/inbound-parse.h"

#include <cstring>

#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/cellslice.h"

namespace jvm_workchain {

td::Result<ParsedInboundMessage> parse_jvm_inbound_message(
    const td::Ref<vm::Cell>& inbound_message) {
    ParsedInboundMessage parsed;
    if (inbound_message.is_null()) {
        return parsed;
    }
    parsed.present = true;

    bool special = false;
    vm::CellSlice msg_cs;
    try {
        msg_cs = vm::load_cell_slice_special(inbound_message, special);
    } catch (const vm::VmError&) {
        return parsed;
    } catch (const vm::VmVirtError&) {
        return parsed;
    }
    if (special) {
        // Special cells (e.g. libraries) cannot carry a normal inbound msg.
        return parsed;
    }

    const int tag = block::gen::t_CommonMsgInfo.get_tag(msg_cs);
    if (tag != block::gen::CommonMsgInfo::int_msg_info) {
        // External inbound — Context.callerPresent() will be false.
        parsed.is_internal = false;
        return parsed;
    }
    parsed.is_internal = true;

    block::gen::CommonMsgInfo::Record_int_msg_info info;
    if (!tlb::unpack(msg_cs, info)) {
        return parsed;
    }

    // Parse `src` as addr_std with anycast=Nothing; anything else leaves
    // src_present=false and the engine surfaces "no caller" to Java code.
    block::gen::MsgAddressInt::Record_addr_std src;
    if (block::gen::csr_unpack(info.src, src)
        && src.anycast.not_null()
        && src.anycast->size() == 1) {
        parsed.src_present = true;
        parsed.src_workchain = src.workchain_id;
        std::memcpy(parsed.src_addr.data(), src.address.data(), 32);
    }

    // Parse attached value as a 32-byte big-endian Uint256.  On failure
    // value_be stays all-zero, which is the safe default; contracts that
    // care about non-zero attached value should compare to Uint256.ZERO
    // explicitly.
    block::CurrencyCollection cc;
    if (cc.unpack(info.value) && cc.tomis.not_null()) {
        (void)cc.tomis->export_bytes(parsed.value_be.data(),
                                     parsed.value_be.size(),
                                     /*sgnd=*/false);
    }

    return parsed;
}

}  // namespace jvm_workchain
