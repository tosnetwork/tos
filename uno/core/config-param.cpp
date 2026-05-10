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

// Round 130 HIGH fix: store the active UnoConfig as an
// atomic<shared_ptr> so reads on RPC / collator / ext-message-pool
// threads never tear and writes from validate_and_resolve_config
// always become visible.  Pre-fix the global was a plain
// non-atomic struct; round 129 dropped the one-shot install guard
// without strengthening the read side, leaving the per-block
// install path with a C++ data-race UB hazard against concurrent
// readers (parallel-verify, mine_uno, RPC accessors).  The
// shared_ptr backing also lets readers grab a stable snapshot
// for the duration of one block's compute even if a later
// install swaps the pointer mid-block.
//
// The per-block "RPC sees a different snapshot than the collator"
// concern that codex round 129/130 flagged is acknowledged: the
// proper architectural fix is to plumb the parsed UnoConfig
// through the WorkchainEngineConfig (matching JVM/EVM).  That is
// a larger refactor (≈10 current_uno_config_view callers in
// init.cpp) and is tracked as a follow-up; this round closes
// the data-race UB and the present-to-absent transition without
// changing the public accessor signature.
std::atomic<std::shared_ptr<const UnoConfig>> g_uno_config_ptr;

// Runtime chain-id override (declared in workchain.h). Centralised here
// to avoid a separate translation unit; mirrors evm's `set_evm_chain_id`.
std::atomic<uint32_t> g_uno_chain_id{kDefaultTestnetChainId};

// Held only by install_uno_config to log a warning when the new
// config differs from the previous one — the actual config storage
// uses g_uno_config_ptr's atomic operations.
std::mutex g_config_log_mutex;

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

UnoConfig current_uno_config() noexcept {
    // Round 130 HIGH fix: return by value via an atomic shared_ptr
    // load so concurrent installers (round-129 wiring) never tear a
    // read.  Pre-fix this returned a const-ref to the non-atomic
    // global, which is C++ data-race UB once install_uno_config
    // can be called more than once.
    auto p = g_uno_config_ptr.load(std::memory_order_acquire);
    return p ? *p : UnoConfig{};
}

// Forward-declared in init.cpp — a minimal POD projection of UnoConfig to
// let that TU consult chain config without including config-param.h (which
// would pull in workchain.h and conflict with transaction.h on
// `kSchemeIdV1` / `kTransferVersion`).
struct UnoConfigView {
    uint32_t chain_id;
    uint64_t min_fee_nano;
    uint64_t fee_per_byte_nano;
    uint64_t fee_per_spend_nano;
    uint64_t fee_per_output_nano;
    uint8_t  max_spends_per_tx;
    uint8_t  max_outputs_per_tx;
    uint16_t anchor_window_size;
    uint32_t expiry_window_blocks;
};

UnoConfigView current_uno_config_view() noexcept {
    // Round 130 HIGH fix: copy via atomic load (see current_uno_
    // config above for the rationale).  The local `c` is a
    // by-value snapshot taken once per call; a concurrent
    // install_uno_config that swaps the pointer afterwards does
    // not affect the view this caller sees.
    const auto c = current_uno_config();
    return UnoConfigView{
        c.chain_id,
        c.min_fee_nano,
        c.fee_per_byte_nano,
        c.fee_per_spend_nano,
        c.fee_per_output_nano,
        c.max_spends_per_tx,
        c.max_outputs_per_tx,
        c.anchor_window_size,
        c.expiry_window_blocks,
    };
}

void install_uno_config(UnoConfig cfg) noexcept {
    // Round 129 HIGH fix: removed the one-shot guard.  Round 130
    // HIGH fix: switched the storage from a plain global struct to
    // std::atomic<std::shared_ptr<const UnoConfig>> so concurrent
    // readers always see a non-torn snapshot.  Pre-fix the install
    // path was racy against any caller of current_uno_config_view
    // running in parallel (RPC, ext-message admission).  Now writes
    // are an atomic store of a freshly-allocated shared_ptr;
    // readers atomic-load and grab a stable snapshot.
    auto new_ptr =
        std::make_shared<const UnoConfig>(std::move(cfg));
    auto old_ptr = g_uno_config_ptr.exchange(
        new_ptr, std::memory_order_acq_rel);
    g_uno_chain_id.store(new_ptr->chain_id, std::memory_order_release);
    // Log only when the value actually changed, under a separate
    // mutex (the LOG macro can take a long time and we don't want
    // it to serialise the atomic install fast-path).
    bool changed = !old_ptr
                || old_ptr->chain_id != new_ptr->chain_id
                || old_ptr->min_fee_nano != new_ptr->min_fee_nano
                || old_ptr->fee_per_byte_nano != new_ptr->fee_per_byte_nano
                || old_ptr->fee_per_spend_nano != new_ptr->fee_per_spend_nano
                || old_ptr->fee_per_output_nano != new_ptr->fee_per_output_nano
                || old_ptr->max_spends_per_tx != new_ptr->max_spends_per_tx
                || old_ptr->max_outputs_per_tx != new_ptr->max_outputs_per_tx
                || old_ptr->anchor_window_size != new_ptr->anchor_window_size
                || old_ptr->expiry_window_blocks != new_ptr->expiry_window_blocks;
    if (changed) {
        std::lock_guard<std::mutex> lock(g_config_log_mutex);
        LOG(INFO) << "uno/config: installed chain_id=0x" << std::hex
                  << new_ptr->chain_id << std::dec
                  << ", min_fee=" << new_ptr->min_fee_nano
                  << ", max_spends=" << int(new_ptr->max_spends_per_tx)
                  << ", anchor_window=" << new_ptr->anchor_window_size;
    }
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
