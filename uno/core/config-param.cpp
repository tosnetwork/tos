/*
    Uno Workchain — ConfigParam 12 + 84 builders.

    Mirrors `evm/core/config-param.cpp` in style. The WorkchainDescr
    TLB layout is reused as-is (workchain#a6, v1) because it is a
    masterchain-wide registry format that every non-masterchain workchain
    shares, including wc=1 (EVM) and wc=2 (Uno). We plug our own
    vm_version, vm_mode, and split/flag fields into that common envelope.

    Decision #4 (§16): UnoConfig lives in ConfigParam 84, not 26.

    Source: TOS-specific adapter; see doc/uno-workchain.md §10.1, §10.2.
*/
#include "uno/core/config-param.h"
#include "uno/core/workchain.h"

#include "block/block-auto.h"   // block::gen::t_WorkchainDescr
#include "vm/cellslice.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include "td/utils/logging.h"

#include <atomic>
#include <mutex>

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Process-scope config storage
// ---------------------------------------------------------------------------
namespace {

// Using a pointer + mutex keeps the accessor path lock-free *after* install;
// the install path is one-shot so a simple atomic swap is sufficient in
// practice. For v1 we use a plain mutex since install is called exactly
// once before any consumer thread reads the value.
std::mutex g_config_mutex;
UnoConfig g_uno_config{};       // default-constructed = testnet defaults
bool      g_uno_config_installed{false};

// Runtime chain-id override (declared in workchain.h). Centralised here
// to avoid a separate translation unit; mirrors evm's `set_evm_chain_id`.
std::atomic<uint32_t> g_uno_chain_id{kDefaultTestnetChainId};

}  // namespace

// ---------------------------------------------------------------------------
// workchain.h accessors
// ---------------------------------------------------------------------------

uint32_t current_uno_chain_id() noexcept {
    return g_uno_chain_id.load(std::memory_order_relaxed);
}

void set_uno_chain_id(uint32_t chain_id) noexcept {
    g_uno_chain_id.store(chain_id, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Accessors for UnoConfig
// ---------------------------------------------------------------------------

const UnoConfig& current_uno_config() noexcept {
    // Reads after `install_uno_config` are data-race-free because install
    // is one-shot (see doc); before install, the caller sees the default
    // value which is fine for testnet-default boot.
    return g_uno_config;
}

void install_uno_config(UnoConfig cfg) noexcept {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    if (g_uno_config_installed) {
        LOG(WARNING) << "uno/config: install_uno_config called twice; ignoring "
                     << "replacement (chain_id=0x" << std::hex << cfg.chain_id
                     << std::dec << ")";
        return;
    }
    g_uno_config = std::move(cfg);
    g_uno_config_installed = true;
    g_uno_chain_id.store(g_uno_config.chain_id, std::memory_order_relaxed);
    LOG(WARNING) << "uno/config: installed chain_id=0x" << std::hex
                 << g_uno_config.chain_id << std::dec
                 << ", min_fee=" << g_uno_config.min_fee_nano
                 << ", max_spends=" << int(g_uno_config.max_spends_per_tx)
                 << ", anchor_window=" << g_uno_config.anchor_window_size;
}

// ---------------------------------------------------------------------------
// UnoConfig cell codec
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> build_uno_config_cell(const UnoConfig& cfg) {
    if (cfg.version != kConfigParamVersion) {
        LOG(ERROR) << "uno/config: refusing to build cell with version "
                   << int(cfg.version) << " (this build expects "
                   << int(kConfigParamVersion) << ")";
        return {};
    }
    vm::CellBuilder cb;
    cb.store_long(kUnoConfigMagic, kUnoConfigMagicBits);
    cb.store_long(cfg.version, 8);
    cb.store_long(cfg.chain_id, 32);
    cb.store_long(static_cast<long long>(cfg.min_fee_nano),         64);
    cb.store_long(static_cast<long long>(cfg.fee_per_byte_nano),    64);
    cb.store_long(static_cast<long long>(cfg.fee_per_spend_nano),   64);
    cb.store_long(static_cast<long long>(cfg.fee_per_output_nano),  64);
    cb.store_long(cfg.max_spends_per_tx,    8);
    cb.store_long(cfg.max_outputs_per_tx,   8);
    cb.store_long(cfg.anchor_window_size,  16);
    cb.store_long(cfg.tree_depth,           8);
    cb.store_long(cfg.expiry_window_blocks, 32);
    return cb.finalize();
}

bool parse_uno_config_cell(td::Ref<vm::Cell> cell, UnoConfig& out) {
    if (cell.is_null()) {
        LOG(ERROR) << "uno/config: parse_uno_config_cell on null cell";
        return false;
    }
    auto cs = vm::load_cell_slice(cell);
    long long v = 0;
    if (!cs.fetch_long_bool(kUnoConfigMagicBits, v) ||
        static_cast<uint32_t>(v) != kUnoConfigMagic) {
        LOG(ERROR) << "uno/config: wrong/missing magic on ConfigParam 84";
        return false;
    }
    if (!cs.fetch_long_bool(8, v)) return false;
    out.version = static_cast<uint8_t>(v);
    if (out.version != kConfigParamVersion) {
        LOG(ERROR) << "uno/config: unknown ConfigParam 84 version "
                   << int(out.version);
        return false;
    }
    if (!cs.fetch_long_bool(32, v)) return false;
    out.chain_id = static_cast<uint32_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.min_fee_nano = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.fee_per_byte_nano = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.fee_per_spend_nano = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.fee_per_output_nano = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(8, v)) return false;
    out.max_spends_per_tx = static_cast<uint8_t>(v);
    if (!cs.fetch_long_bool(8, v)) return false;
    out.max_outputs_per_tx = static_cast<uint8_t>(v);
    if (!cs.fetch_long_bool(16, v)) return false;
    out.anchor_window_size = static_cast<uint16_t>(v);
    if (!cs.fetch_long_bool(8, v)) return false;
    out.tree_depth = static_cast<uint8_t>(v);
    if (!cs.fetch_long_bool(32, v)) return false;
    out.expiry_window_blocks = static_cast<uint32_t>(v);

    // Minimal sanity checks so a malformed config does not wedge consensus.
    if (out.max_spends_per_tx == 0 || out.max_outputs_per_tx == 0) {
        LOG(ERROR) << "uno/config: invalid zero spend/output limits";
        return false;
    }
    if (out.tree_depth != kTreeDepth) {
        LOG(ERROR) << "uno/config: tree_depth=" << int(out.tree_depth)
                   << " disagrees with compile-time kTreeDepth="
                   << kTreeDepth;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// ConfigParam 12 — wc=2 workchain descriptor
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> build_uno_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    uint32_t enabled_since) {
    // Reuse the same workchain#a6 (v1) TL-B the masterchain registry expects
    // for every non-TVM workchain; see block.tlb. Only the trailing
    // `wfmt_basic` payload differs from a TVM workchain.
    vm::CellBuilder cb;
    cb.store_long(0xa6, 8);                 // workchain#a6 tag
    cb.store_long(enabled_since, 32);       // enabled_since

    // monitor_min_split / min_split / max_split.
    // §10.1: min_split=0, max_split=0 (single-shard). No sharding for v1 —
    // the commitment tree is global.
    cb.store_long(0, 8);                    // monitor_min_split
    cb.store_long(0, 8);                    // min_split
    cb.store_long(0, 8);                    // max_split

    // basic (1 bit) + active (1 bit) + accept_msgs (1 bit) + flags (13 bits)
    // §10.1 + decision #8: basic=true (non-TVM workchains still set this bit
    // — it distinguishes "first-class workchain" from the legacy extension
    // format, not "is-TVM"), active=true, accept_msgs=true, flags=0. The
    // TLB schema enforces `flags = 0` on WorkchainDescr; identity is carried
    // by vm_version ("UNO1") only, not by a flag bit.
    // Packed: 1 1 1 <flags:13=0>
    uint16_t flags13 = 0;
    uint16_t packed = static_cast<uint16_t>((1u << 15) | (1u << 14) |
                                            (1u << 13) | flags13);
    cb.store_long(packed, 16);

    cb.store_bits(zerostate_root_hash.as_bitslice());  // zerostate_root_hash
    cb.store_bits(zerostate_file_hash.as_bitslice());  // zerostate_file_hash

    cb.store_long(0, 32);                   // version = 0

    // WorkchainFormat. basic=0 → wfmt_ext#0 tag (4 bits)=0x0 + min_addr_len
    // + max_addr_len + addr_len_step + workchain_type_id. For Uno we do
    // not run a TVM, so the format is `wfmt_ext`, not `wfmt_basic`.
    //
    // TL-B reference from crypto/block/block.tlb:
    //   wfmt_basic#1 vm_version:int32 vm_mode:uint64
    //     = WorkchainFormat 1;
    //   wfmt_ext#0   min_addr_len:(## 12) max_addr_len:(## 12)
    //                addr_len_step:(## 12)
    //                workchain_type_id:(## 32) { workchain_type_id >= 1 }
    //     = WorkchainFormat 0;
    //
    // We choose wfmt_basic with our own vm_version = "UNO1" so that the
    // routing switch in `crypto/block/transaction.cpp` can tell "wc=2 with
    // Uno's VM marker" apart from an accidentally-TVM descriptor.
    //
    // This matches the choice evm_workchain makes (wfmt_basic with
    // vm_version="EVM"); Agent 5 will pick up the routing in
    // `prepare_compute_phase`.
    cb.store_long(0x1, 4);                  // wfmt_basic tag (4 bits)
    cb.store_long(kVmVersion, 32);          // vm_version = 0x554E4F31 "UNO1"
    cb.store_long(kVmMode, 64);             // vm_mode = 0

    auto cell = cb.finalize();
    if (!block::gen::t_WorkchainDescr.validate_ref(cell)) {
        LOG(ERROR) << "uno/config: built WorkchainDescr failed TLB validation";
        return {};
    }
    LOG(WARNING) << "uno/config: built WorkchainDescr for workchain "
                 << kWorkchainId << " (vm_version=0x" << std::hex
                 << kVmVersion << std::dec << ", flags=0 per decision #8)";
    (void)flags13;
    return cell;
}

}  // namespace uno_workchain
