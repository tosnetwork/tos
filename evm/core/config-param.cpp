/*
    EVM Workchain — ConfigParam 12 workchain descriptor implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/config-param.h"
#include "evm/core/workchain.h"

#include "vm/cellslice.h"
#include "vm/cells/CellSlice.h"
#include "vm/boc.h"
#include "block/block-auto.h"
#include "td/utils/logging.h"
#include "td/utils/crypto.h"

namespace evm_workchain {

td::Ref<vm::Cell> build_evm_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    uint32_t enabled_since) {

    // Build workchain#a6 (v1) descriptor:
    //   tag(8)=0xa6
    //   enabled_since(32)
    //   monitor_min_split(8) min_split(8) max_split(8)
    //   basic(1)=1 active(1)=1 accept_msgs(1)=1 flags(13)=0
    //   zerostate_root_hash(256)
    //   zerostate_file_hash(256)
    //   version(32)=0
    //   wfmt_basic#1: tag(1)=1 vm_version(32) vm_mode(64)

    vm::CellBuilder cb;

    // Tag
    cb.store_long(0xa6, 8);

    // enabled_since
    cb.store_long(enabled_since, 32);

    // monitor_min_split=0, min_split=0, max_split=8
    cb.store_long(0, 8);    // monitor_min_split
    cb.store_long(0, 8);    // min_split
    cb.store_long(8, 8);    // max_split (up to 256 shards)

    // basic=1, active=1, accept_msgs=1, flags=0 (13 bits)
    // binary: 1 1 1 0000000000000 = 0xe000 (16 bits)
    cb.store_long(0xe000, 16);

    // zerostate_root_hash (256 bits)
    cb.store_bits(zerostate_root_hash.as_bitslice());

    // zerostate_file_hash (256 bits)
    cb.store_bits(zerostate_file_hash.as_bitslice());

    // version = 0
    cb.store_long(0, 32);

    // WorkchainFormat basic=1 → wfmt_basic#1:
    //   tag(4 bits)=0x1, vm_version(32 bits signed), vm_mode(64 bits)
    //
    // Audit #5 follow-up: vm_mode is the on-chain EVM chain id. It is part
    // of ConfigParam 12, hence part of the masterchain config proof, and
    // collator/validator code rejects wc=1 if it differs from the runtime
    // chain id.
    // Matches Fift: x{1} s, -1 32 i, 0 64 u,
    cb.store_long(0x1, 4);          // wfmt_basic tag (4 bits, matches x{1} in Fift)
    cb.store_long(kVmVersion, 32);  // vm_version = 0x45564D ("EVM"), signed int32
    cb.store_long(current_evm_chain_id(), 64);

    auto cell = cb.finalize();

    // Validate against the TLB schema
    if (!block::gen::t_WorkchainDescr.validate_ref(cell)) {
        LOG(ERROR) << "evm-workchain: built WorkchainDescr failed TLB validation";
        return {};
    }

    LOG(WARNING) << "evm-workchain: built WorkchainDescr for workchain " << kWorkchainId
                 << " (vm_version=0x" << std::hex << kVmVersion
                 << ", evm_chain_id=0x" << current_evm_chain_id()
                 << std::dec << ")";
    return cell;
}

td::Ref<vm::Cell> build_evm_zerostate(
    tos::RootHash& root_hash,
    tos::FileHash& file_hash) {

    // Build a minimal zerostate cell.
    // A real zerostate would contain a full ShardState with empty account
    // dictionaries, initial config, etc. For the first slice, we create
    // a minimal cell that serves as a unique identifier for the workchain.
    //
    // The cell contains:
    //   magic(32) = 0x9023afe2 (shard_state#9023afe2 tag from block.tlb)
    //   global_id(32) = host global id placeholder
    //   workchain_id(32) = 2

    vm::CellBuilder cb;
    cb.store_long(0x9023afe2, 32);            // shard_state tag
    cb.store_long(0, 32);                     // global_id placeholder
    cb.store_long(kWorkchainId, 32);          // shard_ident.workchain_id (simplified)
    // Pad with zeros for the remaining required fields (simplified zerostate)
    cb.store_long(0, 64);               // shard_ident.shard_pfx_bits + shard_prefix
    cb.store_long(0, 32);               // seq_no
    cb.store_long(0, 32);               // vert_seqno
    cb.store_long(0, 32);               // gen_utime
    cb.store_long(0, 64);               // gen_lt
    cb.store_long(0, 32);               // min_ref_mc_seqno

    auto cell = cb.finalize();

    // Compute root_hash = cell hash
    auto hash = cell->get_hash();
    root_hash = hash.bits();

    // Compute file_hash = sha256 of BoC serialization
    auto boc_r = vm::std_boc_serialize(cell);
    if (boc_r.is_error()) {
        LOG(ERROR) << "evm-workchain: failed to serialize zerostate BoC";
        return {};
    }
    auto boc = boc_r.move_as_ok();
    unsigned char sha256_buf[32];
    td::sha256(boc.as_slice(), td::MutableSlice(sha256_buf, 32));
    file_hash = tos::FileHash(td::ConstBitPtr(sha256_buf));

    LOG(WARNING) << "evm-workchain: built zerostate, root_hash=" << root_hash.to_hex()
                 << ", file_hash=" << file_hash.to_hex();

    return cell;
}

std::optional<uint64_t> extract_evm_chain_id_from_workchain_descr(
    td::Ref<vm::Cell> cell) noexcept {
    if (cell.is_null()) return std::nullopt;
    try {
        if (!block::gen::t_WorkchainDescr.validate_ref(cell)) {
            return std::nullopt;
        }
        bool special = false;
        auto cs = vm::load_cell_slice_special(cell, special);
        if (special) return std::nullopt;

        if (cs.size() < 8) return std::nullopt;
        auto tag = cs.fetch_ulong(8);
        if (tag != 0xa6 && tag != 0xa7) return std::nullopt;

        if (!cs.advance(32 + 8 + 8 + 8)) return std::nullopt;
        if (cs.size() < 16) return std::nullopt;
        auto basic = cs.fetch_ulong(1);
        if (!basic) return std::nullopt;
        if (!cs.advance(1 + 1 + 13)) return std::nullopt;
        if (!cs.advance(256 + 256 + 32)) return std::nullopt;

        if (cs.size() < 4 + 32 + 64) return std::nullopt;
        auto fmt_tag = cs.fetch_ulong(4);
        if (fmt_tag != 0x1) return std::nullopt;
        auto vm_version = static_cast<int32_t>(cs.fetch_long(32));
        auto vm_mode = static_cast<uint64_t>(cs.fetch_ulong(64));
        if (vm_version != kVmVersion || vm_mode == kLegacyVmMode) {
            return std::nullopt;
        }
        return vm_mode;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace evm_workchain
