/*
    Uno Workchain — module initialisation implementation.

    Mirrors evm/core/init.cpp: wires up the dispatcher handler, loads state,
    pre-loads the Plonky3 verifier, warms LRU, installs end-of-block hook.

    Phase P.5 (N-P5) responsibilities added on top of the earlier skeleton:
      * Concrete `LiveUnoState` backed by A2's CommitmentTree / NullifierSet
        / AnchorWindow / BlockFilterBuilder.  Implements the consensus
        `UnoState` contract declared in `uno/core/compute-phase.h`.
      * 12 setter-DI bindings (§9 RPC facade, A6 contract): every
        `set_*_fn(...)` declared in uno/rpc/handlers.h + filter-service.h is
        wired to a concrete accessor that reads through the live state.
      * End-of-block subscription notify hooks: a hook function is installed
        via `set_end_of_block_hook()` (consumed by compute-phase.cpp).  After
        each accepted tx the hook fires `notify_included_tx(...)`; once per
        block the `notify_new_head` + `notify_new_anchor` fire.

    Source: TOS-specific adapter.
*/
#include "uno/core/init.h"
#include "uno/core/compute-phase.h"
// genesis.h transitively pulls workchain.h (defines UNO_WORKCHAIN_H_), which
// must come before transaction.h so transaction.h's guarded redefinition of
// kTransferVersion / kSchemeIdV1 is suppressed. Reorder is load-bearing.
#include "uno/core/genesis.h"         // try_load_env_mine_target
#include "uno/core/transaction.h"
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"
#include "uno/core/block-filter.h"
#include "uno/core/mine_constants.h"  // kInitMineTargetBE, kMineSupplyNano

#include "uno/rpc/handlers.h"
#include "uno/rpc/filter-service.h"
#include "uno/rpc/metrics.h"
#include "uno/rpc/subscriptions.h"

// `config-param.h` would pull in `workchain.h` which redeclares `kSchemeIdV1`
// and `kTransferVersion` that `transaction.h` also declares — a preexisting
// header-layering wart that other TUs avoid by including exactly one of the
// two. We mirror that: keep `transaction.h` (needed for Transfer decode) and
// forward-declare the three config-param entry points we actually call.
namespace uno_workchain {
struct UnoConfig;  // full type lives in config-param.h
const UnoConfig& current_uno_config() noexcept;
// The handful of UnoConfig fields we consult. Kept locally as an opaque
// view into the process-global config to avoid the header conflict.
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
UnoConfigView current_uno_config_view() noexcept;
}  // namespace uno_workchain

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "block/uno-workchain-dispatch.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace uno_workchain {

// NOTE: The consensus `UnoState` interface is declared in compute-phase.h.
// A1 also authored a concrete `UnoStateFacade` class in state.h (originally
// also named `UnoState`, renamed to resolve the ODR collision — see task #14)
// that wraps an `UnoShardState` value type and targets a RPC-facade role.
// `UnoStateFacade` does NOT inherit from compute-phase's abstract UnoState;
// it is a parallel value-type surface for RPC handlers that want a lockable
// snapshot. This TU implements a concrete `LiveUnoState` that inherits from
// compute-phase's abstract UnoState and holds A2's data structures directly,
// so init.cpp + compute-phase.cpp share a single coherent contract.

namespace {

constexpr uint32_t kLiveUnoShardStateMagic = 0x554E4F53;  // "UNOS"
constexpr unsigned kLiveUnoShardStateMagicBits = 32;
constexpr uint8_t  kLiveShardStateVersion = 1;
constexpr size_t   kLiveHashBytes = 32;
constexpr unsigned kLiveStateRefCommitmentTree = 0;
constexpr unsigned kLiveStateRefNullifierSet = 1;
constexpr unsigned kLiveStateRefMeta = 2;
constexpr unsigned kLiveMetaRefAnchorWindow = 0;
constexpr unsigned kLiveMetaRefStats = 1;
constexpr unsigned kLiveMetaRefMiningState = 2;

td::Ref<vm::Cell> encode_live_stats_cell(uint64_t burned_fees,
                                         uint64_t tx_count,
                                         uint64_t note_count) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(burned_fees), 64);
    cb.store_long(static_cast<long long>(tx_count), 64);
    cb.store_long(static_cast<long long>(note_count), 64);
    return cb.finalize();
}

// Serialize the MineUno consensus fields (mine_remaining, mine_epoch,
// mine_target, halving_era) into a single cell. Byte-identical to the
// canonical block-producer format in `uno/core/cell-state.cpp::
// encode_mining_state_cell` — keep the two in sync so persisted LiveUno
// and zerostate-loader cells decode interchangeably. Without this,
// mine_epoch / mine_remaining / mine_target reset to construction
// defaults on every validator restart, letting an attacker replay a
// fresh-chain mint flood.
td::Ref<vm::Cell> encode_live_mining_state_cell(uint64_t mine_remaining,
                                                uint32_t mine_epoch,
                                                const std::array<uint8_t, 32>& mine_target) {
    vm::CellBuilder cb;
    // Inline: 64 + 32 + 256 + 32 = 384 bits; no refs.
    cb.store_long(static_cast<long long>(mine_remaining), 64);
    cb.store_long(static_cast<long long>(mine_epoch), 32);
    cb.store_bytes(mine_target.data(), 32);
    // halving_era is a deterministic function of mine_epoch, but we
    // store it explicitly to match cell-state.cpp's canonical format.
    const uint32_t halving_era =
        mine_epoch / uno_workchain::kEraSize;
    cb.store_long(static_cast<long long>(halving_era), 32);
    return cb.finalize();
}

td::Ref<vm::Cell> build_live_meta_cell(td::Ref<vm::Cell> anchor_window_cell,
                                       td::Ref<vm::Cell> stats_cell,
                                       td::Ref<vm::Cell> mining_state_cell) {
    if (anchor_window_cell.is_null() || stats_cell.is_null() ||
        mining_state_cell.is_null()) {
        LOG(ERROR) << "uno-workchain: cannot serialize live meta cell with null refs";
        return {};
    }
    vm::CellBuilder cb;
    if (!cb.store_ref_bool(std::move(anchor_window_cell))) return {};
    if (!cb.store_ref_bool(std::move(stats_cell))) return {};
    if (!cb.store_ref_bool(std::move(mining_state_cell))) return {};
    return cb.finalize();
}

bool fetch_live_u64(vm::CellSlice& cs, uint64_t& out) {
    long long v = 0;
    if (!cs.fetch_long_bool(64, v)) return false;
    out = static_cast<uint64_t>(v);
    return true;
}

td::Bits256 cell_hash_bits(const td::Ref<vm::Cell>& cell) {
    return td::Bits256{cell->get_hash().bits()};
}

// ---------------------------------------------------------------------------
// LiveUnoState — A6 consensus UnoState backed by A2 primitives.
// ---------------------------------------------------------------------------

// Per-tx record kept in the current block for RPC surfacing:
//   - status lookup (uno_getTransactionStatus)
//   - end-of-block included-tx notify
//   - paginated outputs fetch
struct IncludedTxRecord {
    std::array<uint8_t, 32> tx_hash{};
    uint64_t                fee_nano{0};
    uint64_t                block_seqno{0};
    // Output wire bytes (concatenated raw OutputDescription) captured at
    // apply-time. Keyed by global_index so uno_getOutputsAtBlock can page
    // without re-serializing.
    std::vector<OutputRecord> outputs;
};

struct BlockOutputsSlab {
    uint64_t                  block_seqno{0};
    std::vector<OutputRecord> outputs;  // indexed by global_index - base
    uint64_t                  base_index{0};
};

class LiveUnoState : public UnoState {
  public:
    LiveUnoState();

    // --- UnoState (compute-phase.h) contract ---------------------------------
    bool anchor_window_contains(const td::Bits256& anchor) const override;
    bool nullifier_is_spent(const td::Bits256& nf) const override;
    void append_commitment(const td::Bits256& cm) override;
    void insert_nullifier(const td::Bits256& nf) override;
    void accumulate_filter_tag(uint16_t filter_tag) override;
    void bump_stats(uint64_t fee, uint64_t note_count_delta) override;
    td::Ref<vm::Cell> serialize_to_cell() const override;
    bool hydrate_from_cell_if_needed(td::Ref<vm::Cell> root);

    uint32_t expected_chain_id() const override;
    uint64_t current_block_seqno() const override;
    uint32_t expiry_window_blocks() const override;
    uint64_t min_fee_nano() const override;
    uint64_t fee_per_byte_nano() const override;
    uint64_t fee_per_spend_nano() const override;
    uint64_t fee_per_output_nano() const override;

    // MineUno state accessors (uno-mine-v1). Read / write the three
    // consensus `mine_*` fields held on this live shard state. Serves both
    // the compute-phase `apply_mine_uno` path and the `uno_getMineState`
    // RPC accessor (via `mine_state_snapshot()` below).
    uint32_t mine_epoch() const noexcept override;
    uint64_t mine_remaining() const noexcept override;
    std::array<uint8_t, 32> mine_target() const noexcept override;
    void advance_mine_state(uint64_t new_remaining) noexcept override;

    /// Snapshot of the three mining fields, taken under the state mutex.
    /// Used by `rpc_mine_state_fn` to feed `uno_getMineState`.
    MineStateSnapshot mine_state_snapshot() const;

    // --- Mutable accessors (bound by init_uno_workchain) ---------------------
    CommitmentTree&     commitment_tree()     { return *commitment_tree_; }
    NullifierSet&       nullifier_set()       { return *nullifier_set_; }
    AnchorWindow&       anchor_window()       { return *anchor_window_; }
    BlockFilterBuilder& current_block_filter(){ return *current_block_filter_; }

    // Snapshot of the current commitment tree root (set at last append).
    std::array<uint8_t, 32> commitment_tree_root() const;

    // --- Stats ---------------------------------------------------------------
    uint64_t tx_count()   const { return stats_tx_count_; }
    uint64_t note_count() const { return stats_note_count_; }
    uint64_t burned_fees()const { return stats_burned_fees_; }

    // --- Config override (boot time) -----------------------------------------
    void set_block_seqno(uint64_t s);

    // --- Per-block staging ---------------------------------------------------
    // Called by compute-phase at end-of-tx (after apply_transfer returns Ok).
    // Moves staged per-tx output records into the included_txs_ queue and
    // rotates the block-level output slab.
    void record_included_tx(const std::array<uint8_t, 32>& tx_hash,
                             uint64_t fee_nano,
                             const std::vector<OutputRecord>& tx_outputs);

    // Called once at end-of-block by compute-phase. Rotates the block filter,
    // pushes the current commitment_tree_root into the anchor window, archives
    // the per-block outputs slab + per-tx status records, and bumps block_seqno.
    // Returns the finalized block's state for hook consumption.
    struct EndOfBlockSnapshot {
        uint64_t                  block_seqno{0};
        std::array<uint8_t, 32>   commitment_tree_root{};
        std::vector<std::array<uint8_t, 32>> tx_hashes;
        std::vector<uint64_t>                tx_fees;
        uint64_t                  tx_count{0};
        uint64_t                  note_count{0};
        std::vector<uint8_t>      gcs_blob;
    };
    EndOfBlockSnapshot finalize_block();

    // --- Per-block scratch (populated during apply_transfer) -----------------
    // Called immediately after each Output is applied to `accumulate_filter_tag`.
    // We buffer the serialized output bytes so record_included_tx() can hand
    // them off to the block-outputs slab.
    void stage_output_bytes(uint64_t global_index, std::string bytes);

    // --- RPC-visible per-block indices ---------------------------------------
    std::optional<BlockFilterBlob>
        fetch_filter_for_seqno(uint64_t seqno) const;

    std::optional<OutputsPage>
        fetch_outputs(uint64_t seqno, uint64_t from_index, uint64_t limit) const;

    std::optional<std::array<uint8_t, 32>>
        anchor_at_seqno(uint64_t seqno) const;

    TxStatusResult tx_status(const uint8_t tx_hash[32]) const;

    std::vector<OutputRecord>
        outputs_for_ivk(const uint8_t ivk[32]) const;

    // --- Snapshot builder for uno_chainInfo / uno_getAnchor ------------------
    HeadStateSnapshot head_snapshot() const;

    // --- Cached head frontier for uno_getCommitmentTreeFrontier --------------
    std::vector<std::array<uint8_t, 32>> frontier_snapshot() const;

    // --- Subscriber-side scan opt-in (server-assisted; §9.2) -----------------
    // When enabled via UNO_ALLOW_SERVER_SCAN=1, we retain the raw
    // OutputDescription bytes in server memory. When disabled (default),
    // outputs_for_ivk always returns an empty list and logs the privacy
    // warning (handlers.cpp already does the logging).
    bool server_scan_enabled() const { return server_scan_enabled_; }

    // --- Thread-safety -------------------------------------------------------
    mutable std::mutex mutex_;

  private:
    std::unique_ptr<CommitmentTree>     commitment_tree_;
    std::unique_ptr<NullifierSet>       nullifier_set_;
    std::unique_ptr<AnchorWindow>       anchor_window_;
    std::unique_ptr<BlockFilterBuilder> current_block_filter_;

    std::array<uint8_t, 32> current_root_{};
    uint64_t next_output_global_index_{0};

    // Stats (consensus-observable; mirrors UnoShardState.stats)
    uint64_t stats_burned_fees_{0};
    uint64_t stats_tx_count_{0};
    uint64_t stats_note_count_{0};

    // Block bookkeeping
    uint64_t block_seqno_{0};

    // MineUno consensus state (uno-mine-v1; mirrors UnoShardState.mine_*).
    // Initialised at construction to genesis defaults (mainnet/testnet
    // `kInitMineTargetBE = 2^219`, full 21 M supply, epoch 0). The dev-mode
    // gate on `global_id == kDevGlobalId` is applied separately by the
    // genesis loader (uno-difficulty task #29); this TU unconditionally
    // seeds the mainnet default so `uno_getMineState` returns a sensible
    // value before the zero-state hydrate path lands the per-network gate.
    mutable uint32_t                mine_epoch_{0};
    mutable uint64_t                mine_remaining_{0};
    mutable std::array<uint8_t, 32> mine_target_{};

    // Per-block scratch: outputs produced by the tx currently being applied.
    std::vector<OutputRecord> pending_tx_outputs_;

    // End-of-block indices keyed by committed block seqno.
    std::unordered_map<uint64_t, BlockFilterBlob>   filter_by_seqno_;
    std::unordered_map<uint64_t, BlockOutputsSlab>  outputs_by_seqno_;
    std::unordered_map<uint64_t, std::array<uint8_t,32>> anchor_by_seqno_;

    // Per-tx status index (updated at end-of-block).
    struct TxStatusEntry {
        uint64_t block_seqno{0};
        bool     included{false};
    };
    std::unordered_map<std::string, TxStatusEntry> tx_status_index_;

    bool server_scan_enabled_{false};
    mutable bool has_live_state_cell_hash_{false};
    mutable td::Bits256 live_state_cell_hash_{};

    void reset_consensus_state_to_empty_locked();
};

LiveUnoState::LiveUnoState()
    : commitment_tree_(std::make_unique<CommitmentTree>()),
      nullifier_set_(std::make_unique<NullifierSet>()),
      anchor_window_(std::make_unique<AnchorWindow>()),
      current_block_filter_(std::make_unique<BlockFilterBuilder>()) {
    // Seed current_root_ with the empty-tree root so anchor queries see a
    // canonical value before the first append.
    const NoteHash& empty_root = commitment_tree_->get_root();
    std::copy(empty_root.begin(), empty_root.end(), current_root_.begin());
    // Push the empty-tree root so the zerostate path's `anchor_window_contains`
    // returns true for the genesis anchor. Real boot replaces this via the
    // zerostate loader.
    anchor_window_->push(empty_root);
    anchor_by_seqno_[0] = current_root_;

    const char* env = std::getenv("UNO_ALLOW_SERVER_SCAN");
    server_scan_enabled_ = (env && std::string(env) == "1");

    // Seed MineUno consensus state with genesis defaults. Resolution
    // order matches `build_zerostate_state()` in uno/core/genesis.cpp so
    // `uno_getMineState` returns a snapshot consistent with what would
    // be baked into a freshly-built unostate2 BoC:
    //   1. `UNO_INIT_MINE_TARGET_HEX` env var (operator override; logged
    //      at WARNING). Used by local testnets to drop difficulty to
    //      something a single CPU box can solve. Set in the systemd unit.
    //   2. Otherwise `kInitMineTargetBE` (2^219, mainnet / public testnet).
    // The global_id-gated `kDevMineTargetBE` (2^40) selection lives in
    // `build_zerostate_state` and applies when a real zerostate BoC is
    // produced via `build_zerostate_state_cell`; LiveUnoState's defaults
    // are reached on the empty-shardstate path (tostester, mkemptyShardState)
    // and so rely on the env-var hook to escape the mainnet target.
    mine_epoch_ = 0;
    mine_remaining_ = kMineSupplyNano;
    if (const auto* override_target = try_load_env_mine_target()) {
        std::copy(override_target->begin(), override_target->end(),
                  mine_target_.begin());
    } else {
        std::copy(std::begin(kInitMineTargetBE), std::end(kInitMineTargetBE),
                  mine_target_.begin());
    }
}

// ----- UnoState contract implementation ------------------------------------

void LiveUnoState::reset_consensus_state_to_empty_locked() {
    commitment_tree_ = std::make_unique<CommitmentTree>();
    nullifier_set_ = std::make_unique<NullifierSet>();
    anchor_window_ = std::make_unique<AnchorWindow>();

    const NoteHash& empty_root = commitment_tree_->get_root();
    std::copy(empty_root.begin(), empty_root.end(), current_root_.begin());
    anchor_window_->push(empty_root);

    next_output_global_index_ = 0;
    stats_burned_fees_ = 0;
    stats_tx_count_ = 0;
    stats_note_count_ = 0;
    has_live_state_cell_hash_ = false;
    live_state_cell_hash_.set_zero();

    // Reset mining fields back to genesis-time defaults so a "hydrate
    // from null" (equivalent to re-entering genesis state) leaves the
    // chain at epoch=0 / full supply / initial target. Without this, a
    // same-process re-hydrate to empty can leave stale mine_epoch_ /
    // mine_remaining_ / mine_target_ from a prior hydrate session.
    // Respect the UNO_INIT_MINE_TARGET_HEX env-override path for
    // parity with the constructor defaults.
    mine_epoch_     = 0;
    mine_remaining_ = kMineSupplyNano;
    if (const auto* override_target = try_load_env_mine_target()) {
        std::copy(override_target->begin(), override_target->end(),
                  mine_target_.begin());
    } else {
        std::copy(std::begin(kInitMineTargetBE), std::end(kInitMineTargetBE),
                  mine_target_.begin());
    }
}

bool LiveUnoState::anchor_window_contains(const td::Bits256& anchor) const {
    NoteHash h{};
    std::memcpy(h.data(), anchor.data(), 32);
    std::lock_guard<std::mutex> lk(mutex_);
    return anchor_window_->contains(h);
}

bool LiveUnoState::nullifier_is_spent(const td::Bits256& nf) const {
    Nullifier n{};
    std::memcpy(n.data(), nf.data(), 32);
    std::lock_guard<std::mutex> lk(mutex_);
    return nullifier_set_->contains(n);
}

void LiveUnoState::append_commitment(const td::Bits256& cm) {
    NoteHash h{};
    std::memcpy(h.data(), cm.data(), 32);
    std::lock_guard<std::mutex> lk(mutex_);
    NoteHash new_root = commitment_tree_->append(h);
    std::copy(new_root.begin(), new_root.end(), current_root_.begin());
    ++next_output_global_index_;
}

void LiveUnoState::insert_nullifier(const td::Bits256& nf) {
    Nullifier n{};
    std::memcpy(n.data(), nf.data(), 32);
    std::lock_guard<std::mutex> lk(mutex_);
    nullifier_set_->insert(n);
}

void LiveUnoState::accumulate_filter_tag(uint16_t filter_tag) {
    std::lock_guard<std::mutex> lk(mutex_);
    current_block_filter_->add(filter_tag);
}

void LiveUnoState::bump_stats(uint64_t fee, uint64_t note_count_delta) {
    std::lock_guard<std::mutex> lk(mutex_);
    stats_burned_fees_ += fee;
    stats_tx_count_    += 1;
    stats_note_count_  += note_count_delta;
}

td::Ref<vm::Cell> LiveUnoState::serialize_to_cell() const {
    std::lock_guard<std::mutex> lk(mutex_);

    auto tree_cell = commitment_tree_->serialize_to_cell();
    vm::CellBuilder nf_cb;
    if (!nullifier_set_->append_to_builder(nf_cb)) {
        LOG(ERROR) << "uno-workchain: failed to serialize nullifier wrapper";
        return {};
    }
    auto nullifier_cell = nf_cb.finalize();
    auto anchor_cell = anchor_window_->serialize_to_cell();
    if (anchor_cell.is_null()) {
        vm::CellBuilder empty_anchor;
        anchor_cell = empty_anchor.finalize();
    }

    if (tree_cell.is_null() || nullifier_cell.is_null() || anchor_cell.is_null()) {
        LOG(ERROR) << "uno-workchain: live state sub-object serialization failed";
        return {};
    }

    auto stats_cell = encode_live_stats_cell(
        stats_burned_fees_, stats_tx_count_, stats_note_count_);
    auto mining_state_cell = encode_live_mining_state_cell(
        mine_remaining_, mine_epoch_, mine_target_);
    auto meta_cell = build_live_meta_cell(std::move(anchor_cell),
                                          std::move(stats_cell),
                                          std::move(mining_state_cell));
    if (meta_cell.is_null()) return {};

    std::array<uint8_t, kLiveHashBytes> config_hash{};

    vm::CellBuilder cb;
    cb.store_long(kLiveUnoShardStateMagic, kLiveUnoShardStateMagicBits);
    cb.store_long(kLiveShardStateVersion, 8);
    cb.store_long(kSchemeIdV1, 8);
    cb.store_long(static_cast<long long>(next_output_global_index_), 64);
    cb.store_bytes(config_hash.data(), kLiveHashBytes);
    cb.store_bytes(current_root_.data(), kLiveHashBytes);
    if (!cb.store_ref_bool(std::move(tree_cell))) return {};
    if (!cb.store_ref_bool(std::move(nullifier_cell))) return {};
    if (!cb.store_ref_bool(std::move(meta_cell))) return {};
    auto out = cb.finalize();
    if (out.not_null()) {
        live_state_cell_hash_ = cell_hash_bits(out);
        has_live_state_cell_hash_ = true;
    }
    return out;
}

bool LiveUnoState::hydrate_from_cell_if_needed(td::Ref<vm::Cell> root) try {
    if (root.is_null()) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (has_live_state_cell_hash_ || next_output_global_index_ != 0 ||
            stats_burned_fees_ != 0 || stats_tx_count_ != 0 ||
            stats_note_count_ != 0) {
            reset_consensus_state_to_empty_locked();
        }
        return true;
    }

    const td::Bits256 incoming_hash = cell_hash_bits(root);
    std::lock_guard<std::mutex> lk(mutex_);
    if (has_live_state_cell_hash_ && live_state_cell_hash_ == incoming_hash) {
        return true;
    }

    // Codex audit (round 4, finding #6): use the special-cell-aware loader
    // for the root and refuse to hydrate from PrunedBranch/MerkleProof/
    // MerkleUpdate/Library cells. The bare `vm::load_cell_slice` throws on
    // those (and on Library cells outside a VM context) — without the
    // `try`/catch wrapper around this whole function, an attacker who can
    // inject a malformed prior UnoShardState into the execution context
    // (e.g. via a forged collation) would crash the validator daemon
    // instead of getting `sk_bad_state`. The function-try-block at the
    // bottom catches anything missed by per-site checks.
    bool root_is_special = false;
    auto cs = vm::load_cell_slice_special(root, root_is_special);
    if (root_is_special) {
        LOG(ERROR) << "uno-workchain: persisted state root is a special cell";
        return false;
    }
    long long v = 0;
    if (!cs.fetch_long_bool(kLiveUnoShardStateMagicBits, v) ||
        static_cast<uint32_t>(v) != kLiveUnoShardStateMagic) {
        LOG(ERROR) << "uno-workchain: persisted state has bad magic";
        return false;
    }
    if (!cs.fetch_long_bool(8, v) || v != kLiveShardStateVersion) {
        LOG(ERROR) << "uno-workchain: persisted state has bad version";
        return false;
    }
    if (!cs.fetch_long_bool(8, v) || v != kSchemeIdV1) {
        LOG(ERROR) << "uno-workchain: persisted state has bad scheme_id";
        return false;
    }

    uint64_t next_position = 0;
    if (!fetch_live_u64(cs, next_position)) {
        LOG(ERROR) << "uno-workchain: persisted state missing next_position";
        return false;
    }
    unsigned char config_hash[kLiveHashBytes];
    std::array<uint8_t, kLiveHashBytes> commitment_root{};
    if (!cs.fetch_bytes(config_hash, kLiveHashBytes) ||
        !cs.fetch_bytes(commitment_root.data(), kLiveHashBytes)) {
        LOG(ERROR) << "uno-workchain: persisted state missing hash fields";
        return false;
    }
    if (cs.size_refs() != 3) {
        LOG(ERROR) << "uno-workchain: persisted state refs=" << cs.size_refs()
                   << " expected=3";
        return false;
    }

    auto tree_cell = cs.prefetch_ref(kLiveStateRefCommitmentTree);
    auto nullifier_cell = cs.prefetch_ref(kLiveStateRefNullifierSet);
    auto meta_cell = cs.prefetch_ref(kLiveStateRefMeta);
    if (tree_cell.is_null() || nullifier_cell.is_null() || meta_cell.is_null()) {
        LOG(ERROR) << "uno-workchain: persisted state has null sub-object ref";
        return false;
    }

    auto tree = std::make_unique<CommitmentTree>();
    NoteHash expected_root{};
    std::copy(commitment_root.begin(), commitment_root.end(),
              expected_root.begin());
    if (!tree->deserialize_from_cell(std::move(tree_cell),
                                     next_position,
                                     expected_root)) {
        LOG(ERROR) << "uno-workchain: persisted commitment tree rejected";
        return false;
    }

    auto nf = std::make_unique<NullifierSet>();
    {
        auto nf_cs = vm::load_cell_slice(nullifier_cell);
        long long has_root = 0;
        if (!nf_cs.fetch_long_bool(1, has_root)) {
            LOG(ERROR) << "uno-workchain: persisted nullifier wrapper missing tag";
            return false;
        }
        td::Ref<vm::Cell> dict_root;
        if (has_root) {
            if (!nf_cs.fetch_ref_to(dict_root)) {
                LOG(ERROR) << "uno-workchain: persisted nullifier wrapper missing root";
                return false;
            }
        }
        nf->load_from_cell(std::move(dict_root));
    }

    auto meta_cs = vm::load_cell_slice(meta_cell);
    // Accept 2 refs (legacy: anchor + stats) OR 3 refs (current:
    // anchor + stats + mining_state). Legacy states pre-date the
    // K-mining-state-persist fix and keep the in-memory mining state
    // at construction defaults on hydrate. Reject any other arity.
    const unsigned meta_refs = meta_cs.size_refs();
    if (meta_refs != 2 && meta_refs != 3) {
        LOG(ERROR) << "uno-workchain: persisted meta refs=" << meta_refs
                   << " expected=2 or 3";
        return false;
    }

    auto win = std::make_unique<AnchorWindow>();
    auto anchor_cell = meta_cs.prefetch_ref(kLiveMetaRefAnchorWindow);
    auto anchor_probe = vm::load_cell_slice(anchor_cell);
    if (!(anchor_probe.size() == 0 && anchor_probe.size_refs() == 0) &&
        !win->deserialize_from_cell(std::move(anchor_cell),
                                    current_uno_config_view().anchor_window_size)) {
        LOG(ERROR) << "uno-workchain: persisted anchor window rejected";
        return false;
    }

    auto stats_cell = meta_cs.prefetch_ref(kLiveMetaRefStats);
    auto stats_cs = vm::load_cell_slice(stats_cell);
    uint64_t burned_fees = 0, tx_count = 0, note_count = 0;
    if (!fetch_live_u64(stats_cs, burned_fees) ||
        !fetch_live_u64(stats_cs, tx_count) ||
        !fetch_live_u64(stats_cs, note_count)) {
        LOG(ERROR) << "uno-workchain: persisted stats cell malformed";
        return false;
    }
    // Codex audit (round 6, finding #5): require canonical exact-shape.
    // Without trailing-payload checks, an attacker who can inject a
    // malformed prior persisted UnoShardState could carry ignored
    // bytes/refs that change the cell hash without changing the
    // semantic state — divergent state hash across validators that all
    // believe they observe the same logical state.
    if (stats_cs.size() != 0 || stats_cs.size_refs() != 0) {
        LOG(ERROR) << "uno-workchain: persisted stats cell has trailing payload"
                   << " bits=" << stats_cs.size() << " refs=" << stats_cs.size_refs();
        return false;
    }

    // MineUno consensus fields — only present in 3-ref meta cells. On
    // legacy 2-ref states, keep the in-memory defaults seeded by the
    // constructor (kMineSupplyNano, epoch=0, env-override-or-mainnet
    // target). Without this persist/hydrate loop, a validator restart
    // would reset mine_epoch=0/mine_remaining=full-cap and allow a
    // fresh mining run from genesis on an already-mined chain.
    uint64_t persisted_mine_remaining = mine_remaining_;
    uint32_t persisted_mine_epoch = mine_epoch_;
    std::array<uint8_t, 32> persisted_mine_target = mine_target_;
    if (meta_refs == 3) {
        auto mining_cell = meta_cs.prefetch_ref(kLiveMetaRefMiningState);
        auto mining_cs = vm::load_cell_slice(mining_cell);
        long long v = 0;
        if (!mining_cs.fetch_long_bool(64, v)) {
            LOG(ERROR) << "uno-workchain: persisted mining_state missing remaining";
            return false;
        }
        persisted_mine_remaining = static_cast<uint64_t>(v);
        if (!mining_cs.fetch_long_bool(32, v)) {
            LOG(ERROR) << "uno-workchain: persisted mining_state missing epoch";
            return false;
        }
        persisted_mine_epoch = static_cast<uint32_t>(v);
        if (!mining_cs.fetch_bytes(persisted_mine_target.data(), 32)) {
            LOG(ERROR) << "uno-workchain: persisted mining_state missing target";
            return false;
        }
        // halving_era is stored but derived from mine_epoch; we ignore
        // the persisted value and recompute to avoid drift on reload.
        if (!mining_cs.fetch_long_bool(32, v)) {
            LOG(ERROR) << "uno-workchain: persisted mining_state missing halving_era";
            return false;
        }
        // Codex audit (round 6, finding #5): canonical exact-shape check.
        if (mining_cs.size() != 0 || mining_cs.size_refs() != 0) {
            LOG(ERROR) << "uno-workchain: persisted mining_state has trailing payload"
                       << " bits=" << mining_cs.size() << " refs=" << mining_cs.size_refs();
            return false;
        }
    }
    // Codex audit (round 6, finding #5): canonical exact-shape on meta_cs
    // itself — meta has no inline data, only refs. We already validated
    // refs count (==2 or ==3) above. Reject any trailing data bits.
    if (meta_cs.size() != 0) {
        LOG(ERROR) << "uno-workchain: persisted meta cell has trailing data bits"
                   << " bits=" << meta_cs.size();
        return false;
    }
    // Codex audit (round 6, finding #5): canonical exact-shape on the
    // root cs. We've consumed magic+version+scheme+next_position+
    // 2×hash_bytes (=80 bits) and 3 refs (already enforced above).
    if (cs.size() != 0) {
        LOG(ERROR) << "uno-workchain: persisted state root has trailing data bits"
                   << " bits=" << cs.size();
        return false;
    }

    commitment_tree_ = std::move(tree);
    nullifier_set_ = std::move(nf);
    anchor_window_ = std::move(win);
    current_root_ = commitment_root;
    next_output_global_index_ = next_position;
    stats_burned_fees_ = burned_fees;
    stats_tx_count_ = tx_count;
    stats_note_count_ = note_count;
    mine_remaining_ = persisted_mine_remaining;
    mine_epoch_ = persisted_mine_epoch;
    mine_target_ = persisted_mine_target;
    live_state_cell_hash_ = incoming_hash;
    has_live_state_cell_hash_ = true;
    return true;
} catch (const std::exception& e) {
    // Codex audit (round 4, finding #6): function-try-block. The remaining
    // `vm::load_cell_slice(X)` calls below the root check (nullifier wrapper,
    // meta wrapper, anchor probe, stats, mining_state) all walk caller-
    // controlled refs and throw on special cells. Catch here so a malformed
    // persisted state returns `false` (→ sk_bad_state at the dispatch
    // layer) rather than crashing the validator daemon.
    LOG(ERROR) << "uno-workchain: persisted state hydrate threw: " << e.what();
    return false;
} catch (...) {
    LOG(ERROR) << "uno-workchain: persisted state hydrate threw (non-std)";
    return false;
}

void LiveUnoState::set_block_seqno(uint64_t s) {
    std::lock_guard<std::mutex> lk(mutex_);
    block_seqno_ = s;
}

uint32_t LiveUnoState::expected_chain_id() const {
    return current_uno_config_view().chain_id;
}

uint64_t LiveUnoState::current_block_seqno() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return block_seqno_;
}

uint32_t LiveUnoState::expiry_window_blocks() const {
    return current_uno_config_view().expiry_window_blocks;
}

uint64_t LiveUnoState::min_fee_nano() const {
    return current_uno_config_view().min_fee_nano;
}
uint64_t LiveUnoState::fee_per_byte_nano() const {
    return current_uno_config_view().fee_per_byte_nano;
}
uint64_t LiveUnoState::fee_per_spend_nano() const {
    return current_uno_config_view().fee_per_spend_nano;
}
uint64_t LiveUnoState::fee_per_output_nano() const {
    return current_uno_config_view().fee_per_output_nano;
}

// ----- MineUno state accessors ---------------------------------------------

uint32_t LiveUnoState::mine_epoch() const noexcept {
    std::lock_guard<std::mutex> lk(mutex_);
    return mine_epoch_;
}

uint64_t LiveUnoState::mine_remaining() const noexcept {
    std::lock_guard<std::mutex> lk(mutex_);
    return mine_remaining_;
}

std::array<uint8_t, 32> LiveUnoState::mine_target() const noexcept {
    std::lock_guard<std::mutex> lk(mutex_);
    return mine_target_;
}

void LiveUnoState::advance_mine_state(uint64_t new_remaining) noexcept {
    std::lock_guard<std::mutex> lk(mutex_);
    ++mine_epoch_;
    mine_remaining_ = new_remaining;
    // `mine_target_` is rewritten by the retarget step driven from
    // `apply_mine_uno` (uno-mine-v1 Phase 2). This accessor only advances
    // epoch + remaining; the target-retarget mutator is a separate method
    // landed alongside the retarget algorithm.
}

MineStateSnapshot LiveUnoState::mine_state_snapshot() const {
    std::lock_guard<std::mutex> lk(mutex_);
    MineStateSnapshot s;
    s.epoch     = mine_epoch_;
    s.remaining = mine_remaining_;
    s.target    = mine_target_;
    // hydrated == true once the LiveUnoState has been hydrated from a
    // real persisted ShardState cell, OR the in-memory snapshot is at
    // genesis defaults (epoch=0, full supply) which IS the canonical
    // chain state for any validator that hasn't yet processed a wc=2
    // tx. The latter case lets miners fetch RPC state at genesis
    // (chicken-and-egg break: without it, the first MineUno can never
    // be built because the RPC always errors). After ANY mutation in
    // this process, the snapshot is no longer "fresh defaults" and the
    // strict `has_live_state_cell_hash_` flag is required.
    //
    // Known operational risk: post-restart, between cold boot and the
    // first wc=2 tx, the in-memory defaults may lag the real chain
    // state (e.g. epoch=0 reported while chain is at epoch=N). Miners
    // submit a tx with stale (epoch, remaining) which then gets
    // rejected as EpochRaceDetected when the validator hydrates from
    // disk during compute-phase. The fail-closed signal lives in the
    // verify_mine_uno_chain_checks reject path, not at the RPC layer.
    s.hydrated  = has_live_state_cell_hash_ ||
                  (mine_epoch_ == 0 && mine_remaining_ == kMineSupplyNano);
    return s;
}

std::array<uint8_t, 32> LiveUnoState::commitment_tree_root() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return current_root_;
}

// ----- Per-block staging ---------------------------------------------------

void LiveUnoState::stage_output_bytes(uint64_t global_index, std::string bytes) {
    std::lock_guard<std::mutex> lk(mutex_);
    OutputRecord r;
    r.global_index = global_index;
    r.bytes        = std::move(bytes);
    pending_tx_outputs_.push_back(std::move(r));
}

void LiveUnoState::record_included_tx(const std::array<uint8_t, 32>& tx_hash,
                                       uint64_t fee_nano,
                                       const std::vector<OutputRecord>& tx_outputs) {
    std::lock_guard<std::mutex> lk(mutex_);

    // Persist tx status as "included at block_seqno_".
    std::string key(reinterpret_cast<const char*>(tx_hash.data()), 32);
    tx_status_index_[key] = {block_seqno_, true};

    // Feed the block outputs slab. Prefer `tx_outputs` (explicit arg from the
    // compute hook / test harness) if non-empty; otherwise drain the
    // pending_tx_outputs_ buffer that `stage_output_bytes` has been filling.
    auto& slab = outputs_by_seqno_[block_seqno_];
    if (slab.outputs.empty()) {
        slab.block_seqno = block_seqno_;
        slab.base_index  = tx_outputs.empty()
            ? (pending_tx_outputs_.empty() ? next_output_global_index_
                                           : pending_tx_outputs_.front().global_index)
            : tx_outputs.front().global_index;
    }
    if (!tx_outputs.empty()) {
        for (const auto& o : tx_outputs) slab.outputs.push_back(o);
    } else {
        for (auto& o : pending_tx_outputs_) slab.outputs.push_back(std::move(o));
    }

    pending_tx_outputs_.clear();
    (void)fee_nano;
}

LiveUnoState::EndOfBlockSnapshot LiveUnoState::finalize_block() {
    std::lock_guard<std::mutex> lk(mutex_);
    EndOfBlockSnapshot snap;
    snap.block_seqno           = block_seqno_;
    snap.commitment_tree_root  = current_root_;
    snap.tx_count              = stats_tx_count_;
    snap.note_count            = stats_note_count_;

    // Rotate the block filter.
    auto gcs = current_block_filter_->compile();
    snap.gcs_blob = gcs;

    BlockFilterBlob blob;
    blob.block_seqno     = block_seqno_;
    blob.filter_tag_bits = static_cast<uint8_t>(kFilterTagBits);
    blob.p_param         = gcs.empty() ? 0u : kGcsP;
    blob.gcs_bytes.assign(reinterpret_cast<const char*>(gcs.data()),
                          gcs.size());
    filter_by_seqno_[block_seqno_] = std::move(blob);
    current_block_filter_->reset();

    // Push current root into the anchor ring.
    NoteHash h{};
    std::copy(current_root_.begin(), current_root_.end(), h.begin());
    anchor_window_->push(h);
    anchor_by_seqno_[block_seqno_] = current_root_;

    // Advance block counter.
    ++block_seqno_;
    return snap;
}

// ----- RPC accessors -------------------------------------------------------

std::optional<BlockFilterBlob> LiveUnoState::fetch_filter_for_seqno(uint64_t seqno) const {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = filter_by_seqno_.find(seqno);
    if (it == filter_by_seqno_.end()) return std::nullopt;
    return it->second;
}

std::optional<OutputsPage> LiveUnoState::fetch_outputs(uint64_t seqno,
                                                        uint64_t from_index,
                                                        uint64_t limit) const {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = outputs_by_seqno_.find(seqno);
    if (it == outputs_by_seqno_.end()) return std::nullopt;
    const auto& slab = it->second;
    OutputsPage page;
    page.block_seqno    = seqno;
    page.from_index     = from_index;
    page.total_in_block = slab.outputs.size();
    for (uint64_t i = from_index;
         i < slab.outputs.size() && page.outputs.size() < limit;
         ++i) {
        page.outputs.push_back(slab.outputs[i]);
    }
    return page;
}

std::optional<std::array<uint8_t, 32>>
LiveUnoState::anchor_at_seqno(uint64_t seqno) const {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = anchor_by_seqno_.find(seqno);
    if (it == anchor_by_seqno_.end()) return std::nullopt;
    return it->second;
}

TxStatusResult LiveUnoState::tx_status(const uint8_t tx_hash[32]) const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::string key(reinterpret_cast<const char*>(tx_hash), 32);
    auto it = tx_status_index_.find(key);
    TxStatusResult r;
    if (it == tx_status_index_.end()) {
        r.kind = TxStatusKind::Unknown;
    } else if (it->second.included) {
        r.kind = TxStatusKind::Included;
        r.block_seqno = it->second.block_seqno;
    } else {
        r.kind = TxStatusKind::Pending;
    }
    return r;
}

std::vector<OutputRecord>
LiveUnoState::outputs_for_ivk(const uint8_t /*ivk*/[32]) const {
    // Opt-in server-assisted scan (§9.2). When disabled, we refuse to emit
    // anything — the RPC handler already logs the privacy warning on its own,
    // and the caller gets an empty result (NOT an error: the privacy-weakening
    // is silent to avoid leaking ivk-set membership).
    if (!server_scan_enabled_) {
        return {};
    }
    // Enabled: hand back all outputs across all blocks. Real trial-decrypt
    // happens on the wallet side — this server just forwards the slab. For
    // P.5 scope, "slab of every output" is acceptable (the RPC already carries
    // the privacy warning).
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<OutputRecord> out;
    for (const auto& [seqno, slab] : outputs_by_seqno_) {
        (void)seqno;
        for (const auto& r : slab.outputs) out.push_back(r);
    }
    return out;
}

HeadStateSnapshot LiveUnoState::head_snapshot() const {
    HeadStateSnapshot s;
    auto cfg = current_uno_config_view();
    s.chain_id             = cfg.chain_id;
    s.workchain_id         = 2;
    s.anchor_window_size   = cfg.anchor_window_size;
    s.min_fee_nano         = cfg.min_fee_nano;
    s.fee_per_byte_nano    = cfg.fee_per_byte_nano;
    s.fee_per_spend_nano   = cfg.fee_per_spend_nano;
    s.fee_per_output_nano  = cfg.fee_per_output_nano;
    s.max_spends_per_tx    = cfg.max_spends_per_tx;
    s.max_outputs_per_tx   = cfg.max_outputs_per_tx;
    s.scheme_id            = kSchemeIdV1;
    // Executor address = (wc=2, account_id = 0x…01). Mirrors
    // `kUnoExecutorAddressBytes` in workchain.h; reproduced locally to keep
    // init.cpp from including workchain.h (see header-conflict comment above).
    static constexpr uint8_t kExecutorAddrBytes[32] = {
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,
    };
    std::memcpy(s.executor_address.data(), kExecutorAddrBytes, 32);

    std::lock_guard<std::mutex> lk(mutex_);
    s.head_seqno = block_seqno_;
    s.current_anchor_root = current_root_;
    // snapshot() from AnchorWindow returns oldest-to-newest; the RPC contract
    // asks for newest-first, so we reverse.
    auto snap = anchor_window_->snapshot();
    s.anchor_window.reserve(snap.size());
    for (auto it = snap.rbegin(); it != snap.rend(); ++it) {
        std::array<uint8_t, 32> a{};
        std::copy(it->begin(), it->end(), a.begin());
        s.anchor_window.push_back(a);
    }
    return s;
}

std::vector<std::array<uint8_t, 32>> LiveUnoState::frontier_snapshot() const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<std::array<uint8_t, 32>> out;
    const auto& levels = commitment_tree_->get_frontier();
    out.reserve(levels.size());
    for (const auto& lvl : levels) {
        std::array<uint8_t, 32> a{};
        if (lvl.filled) {
            std::copy(lvl.hash.begin(), lvl.hash.end(), a.begin());
        }
        out.push_back(a);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Module globals & setter shims
// ---------------------------------------------------------------------------

std::unique_ptr<LiveUnoState> g_live;

// RPC setter shims. They route through the global singleton.
HeadStateSnapshot rpc_head_state_fn() {
    return g_live ? g_live->head_snapshot() : HeadStateSnapshot{};
}
MineStateSnapshot rpc_mine_state_fn() {
    return g_live ? g_live->mine_state_snapshot() : MineStateSnapshot{};
}
std::optional<std::array<uint8_t, 32>> rpc_anchor_at_seqno_fn(uint64_t seqno) {
    if (!g_live) return std::nullopt;
    return g_live->anchor_at_seqno(seqno);
}
std::vector<std::array<uint8_t, 32>> rpc_frontier_fn() {
    if (!g_live) return {};
    return g_live->frontier_snapshot();
}
NullifierStatusResult rpc_nullifier_lookup_fn(const uint8_t nf[32]) {
    NullifierStatusResult r;
    if (!g_live) {
        r.state = NullifierState::Unknown;
        return r;
    }
    Nullifier n{};
    std::memcpy(n.data(), nf, 32);
    // NullifierSet::contains() is non-const on the LRU; protect via the
    // state's mutex by going through nullifier_is_spent.
    td::Bits256 b;
    std::memcpy(b.data(), nf, 32);
    bool spent = g_live->nullifier_is_spent(b);
    r.state = spent ? NullifierState::Spent : NullifierState::Unknown;
    return r;
}

AdmissionResult rpc_admission_check_fn(const uint8_t* tx_bytes, size_t tx_len);
uint64_t        rpc_estimate_fee_fn(uint32_t n_spends, uint32_t n_outputs);
TxStatusResult  rpc_tx_status_fn(const uint8_t tx_hash[32]);
std::vector<OutputRecord> rpc_outputs_for_ivk_fn(const uint8_t ivk[32]);
std::optional<BlockFilterBlob> rpc_filter_fetch_fn(uint64_t seqno);
std::optional<OutputsPage>     rpc_outputs_fetch_fn(uint64_t seqno,
                                                     uint64_t from_index,
                                                     uint64_t limit);
bool rpc_submit_external_message_fn(const std::string& tx_bytes,
                                     const uint8_t tx_hash[32]);

bool checked_add_u64(uint64_t a, uint64_t b, uint64_t& out) noexcept {
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool checked_mul_u64(uint64_t a, uint64_t b, uint64_t& out) noexcept {
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool add_fee_component(uint64_t& total, uint64_t rate, uint64_t units) noexcept {
    uint64_t part = 0;
    if (!checked_mul_u64(rate, units, part)) return false;
    return checked_add_u64(total, part, total);
}

bool compute_required_fee(uint64_t min_fee,
                          uint64_t fee_per_byte,
                          uint64_t fee_per_spend,
                          uint64_t fee_per_output,
                          uint64_t size_bytes,
                          uint64_t n_spends,
                          uint64_t n_outputs,
                          uint64_t& out) noexcept {
    uint64_t total = min_fee;
    if (!add_fee_component(total, fee_per_byte, size_bytes)) return false;
    if (!add_fee_component(total, fee_per_spend, n_spends)) return false;
    if (!add_fee_component(total, fee_per_output, n_outputs)) return false;
    out = total;
    return true;
}

uint64_t rpc_estimate_fee_fn(uint32_t n_spends, uint32_t n_outputs) {
    auto cfg = current_uno_config_view();
    // Rough tx-size estimate; mirrors handlers.cpp's fallback branch.
    uint64_t est_bytes = 128ULL + (uint64_t)n_spends * 150 + (uint64_t)n_outputs * 1200;
    uint64_t fee = 0;
    if (!compute_required_fee(cfg.min_fee_nano,
                              cfg.fee_per_byte_nano,
                              cfg.fee_per_spend_nano,
                              cfg.fee_per_output_nano,
                              est_bytes,
                              n_spends,
                              n_outputs,
                              fee)) {
        return std::numeric_limits<uint64_t>::max();
    }
    return fee;
}

TxStatusResult rpc_tx_status_fn(const uint8_t tx_hash[32]) {
    if (!g_live) return TxStatusResult{};
    return g_live->tx_status(tx_hash);
}

std::vector<OutputRecord> rpc_outputs_for_ivk_fn(const uint8_t ivk[32]) {
    if (!g_live) return {};
    return g_live->outputs_for_ivk(ivk);
}

std::optional<BlockFilterBlob> rpc_filter_fetch_fn(uint64_t seqno) {
    if (!g_live) return std::nullopt;
    return g_live->fetch_filter_for_seqno(seqno);
}
std::optional<OutputsPage> rpc_outputs_fetch_fn(uint64_t seqno,
                                                  uint64_t from_index,
                                                  uint64_t limit) {
    if (!g_live) return std::nullopt;
    return g_live->fetch_outputs(seqno, from_index, limit);
}

// ---------------------------------------------------------------------------
// Admission: runs the §4.3a subset (syntax, anchor, LRU, sigs) deterministically.
// ---------------------------------------------------------------------------

AdmissionResult rpc_admission_check_fn(const uint8_t* tx_bytes, size_t tx_len) {
    // K-uno-metrics: scoped timer for the §4.3a admission chain. A helper
    // fires at each rejection site below so the rejected counter gets the
    // correct reason label — the scoped timer handles the histogram.
    ScopedVerifyTimer _vt(global_metrics_registry(), VerifyPhase::Admission);
    auto bump_reject = [](AdmissionRejectReason reason) noexcept {
        global_metrics_registry().inc_transfers_rejected(
            reject_reason_from_admission(static_cast<int>(reason)));
    };

    AdmissionResult r;
    if (!g_live) {
        r.ok = false;
        r.reason = AdmissionRejectReason::UnavailableState;
        bump_reject(r.reason);
        return r;
    }
    auto decoded = decode_transfer_bytes(td::Slice(
        reinterpret_cast<const char*>(tx_bytes), tx_len));
    if (auto* err = std::get_if<TransferDecodeError>(&decoded)) {
        (void)err;
        r.ok = false;
        r.reason = AdmissionRejectReason::Malformed;
        bump_reject(r.reason);
        return r;
    }
    const Transfer& tx = std::get<Transfer>(decoded);
    std::memcpy(r.tx_hash.data(), tx.tx_hash.data(), 32);

    auto cfg = current_uno_config_view();
    if (tx.version   != kTransferVersion)            { r.reason = AdmissionRejectReason::BadVersion;    r.ok = false; bump_reject(r.reason); return r; }
    if (tx.scheme_id != kSchemeIdV1)                 { r.reason = AdmissionRejectReason::BadVersion;    r.ok = false; bump_reject(r.reason); return r; }
    if (tx.chain_id  != cfg.chain_id)                { r.reason = AdmissionRejectReason::WrongChainId;  r.ok = false; bump_reject(r.reason); return r; }
    if (tx.spends.empty()  || tx.spends.size()  > cfg.max_spends_per_tx)  { r.reason = AdmissionRejectReason::TooManySpends;  r.ok = false; bump_reject(r.reason); return r; }
    if (tx.outputs.empty() || tx.outputs.size() > cfg.max_outputs_per_tx) { r.reason = AdmissionRejectReason::TooManyOutputs; r.ok = false; bump_reject(r.reason); return r; }
    if (!public_input_scalars_fit_field(tx))         { r.reason = AdmissionRejectReason::Malformed;     r.ok = false; bump_reject(r.reason); return r; }

    uint64_t required = 0;
    if (!compute_required_fee(cfg.min_fee_nano,
                              cfg.fee_per_byte_nano,
                              cfg.fee_per_spend_nano,
                              cfg.fee_per_output_nano,
                              tx.wire_size_bytes,
                              tx.spends.size(),
                              tx.outputs.size(),
                              required)) {
        r.reason = AdmissionRejectReason::FeeBelowMin;
        r.ok = false;
        bump_reject(r.reason);
        return r;
    }
    if (tx.fee < required) { r.reason = AdmissionRejectReason::FeeBelowMin; r.ok = false; bump_reject(r.reason); return r; }

    if (!g_live->anchor_window_contains(tx.anchor)) {
        r.reason = AdmissionRejectReason::StaleAnchor;
        r.ok = false;
        bump_reject(r.reason);
        return r;
    }

    // LRU-only nf-seen check (§4.3a step 3: advisory).
    for (const auto& s : tx.spends) {
        if (g_live->nullifier_is_spent(s.nullifier)) {
            r.reason = AdmissionRejectReason::NullifierSeen;
            r.ok = false;
            bump_reject(r.reason);
            return r;
        }
    }

    // Within-tx dedup.
    {
        std::unordered_map<std::string,int> seen_nf, seen_cm;
        for (const auto& s : tx.spends) {
            std::string k(reinterpret_cast<const char*>(s.nullifier.data()), 32);
            if (++seen_nf[k] > 1) { r.reason = AdmissionRejectReason::DuplicateNf; r.ok = false; bump_reject(r.reason); return r; }
        }
        for (const auto& o : tx.outputs) {
            std::string k(reinterpret_cast<const char*>(o.cm.data()), 32);
            if (++seen_cm[k] > 1) { r.reason = AdmissionRejectReason::DuplicateCm; r.ok = false; bump_reject(r.reason); return r; }
        }
    }

    // Ristretto point decompression: delegated to A3.  We intentionally skip
    // the off-circuit decompression here — admission's cost envelope (§4.3a)
    // calls it "cheap"; the compute phase (§4.3 step 1.7) does the real check.
    // Schnorr verify is likewise owned by the compute phase in v1; A6 trades
    // a small admission-FP risk for a tight mempool budget.

    r.ok = true;
    return r;
}

// External-message submit hook. In production this goes through the
// validator-engine liteServer_sendMessage path; see validator-engine.cpp. For
// standalone boot / tests we allow an override via a process-global callback.
//
// Codex audit (round 2, finding #3): in the current builds NOTHING in the
// validator-engine installs a production override here — only the test
// harness does, via `install_uno_submit_hook`. Result: `uno_sendTransfer`
// always returns the structured `kErrSubmitUnavailable` error to clients in
// production. This is a feature gap (not a vulnerability — admission still
// runs and the failure is loud). Wiring it up requires mirroring the
// `uno_sendMineUno` pipeline (intercept in `JsonRpcServer::process_single_
// object_request`, wrap raw bytes in a TVM cell, build a wc=2 `ext_in_msg`,
// submit via `send_liteserver_query`) because the actor-sync gap means the
// process-global callback shape here cannot reach `send_liteserver_query`.
// Until that refactor lands, the handler will continue to surface
// kErrSubmitUnavailable, which clients treat as "use raw sendBoc".
std::atomic<bool(*)(const std::string&, const uint8_t[32])> g_submit_override{nullptr};
bool rpc_submit_external_message_fn(const std::string& tx_bytes,
                                     const uint8_t tx_hash[32]) {
    auto fn = g_submit_override.load(std::memory_order_acquire);
    if (fn) return fn(tx_bytes, tx_hash);
    // No validator-engine hook installed — fail gracefully. The test harness
    // overrides this via `install_uno_submit_hook(...)`. See the codex-2
    // comment block above for why this is the production path today.
    LOG(WARNING) << "uno-workchain: sendTransfer submit attempted without an "
                 << "installed validator-engine hook (tx_bytes=" << tx_bytes.size()
                 << " B). Clients should fall back to raw sendBoc until the "
                 << "JSON-RPC intercept lands; see init.cpp comment for "
                 << "rpc_submit_external_message_fn.";
    (void)tx_hash;
    return false;
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Module-private hooks consumed by compute-phase.cpp
// ---------------------------------------------------------------------------
//
// These are exposed at namespace scope (not in the anon namespace) so
// compute-phase.cpp can call them via an extern-style forward declaration
// without including init.h (which is a thin public surface).

void on_included_tx_from_compute(const uint8_t tx_hash[32],
                                  uint64_t fee_nano,
                                  uint64_t n_outputs) {
    if (!g_live) return;
    std::array<uint8_t, 32> h{};
    std::memcpy(h.data(), tx_hash, 32);
    char hex[65];
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[2*i]   = H[(tx_hash[i] >> 4) & 0xf];
        hex[2*i+1] = H[tx_hash[i] & 0xf];
    }
    hex[64] = '\0';
    std::string hex_str(hex, 64);

    // P.5 scope: compute-phase does not stage per-tx output wire bytes here
    // (that path is driven explicitly by the two-wallet demo via
    // stage_output_wire_bytes_for_test). We still record the tx and fire the
    // included-tx subscription.
    g_live->record_included_tx(h, fee_nano, /*tx_outputs=*/{});
    (void)n_outputs;
    global_uno_subscription_manager().notify_included_tx(hex_str,
        g_live->current_block_seqno(), fee_nano);
}

void on_end_of_block_from_compute() {
    if (!g_live) return;
    auto snap = g_live->finalize_block();
    char hex[65];
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[2*i]   = H[(snap.commitment_tree_root[i] >> 4) & 0xf];
        hex[2*i+1] = H[snap.commitment_tree_root[i] & 0xf];
    }
    hex[64] = '\0';
    std::string hex_str(hex, 64);
    global_uno_subscription_manager().notify_new_head(
        snap.block_seqno, hex_str, snap.tx_count, snap.note_count);
    global_uno_subscription_manager().notify_new_anchor(
        snap.block_seqno, hex_str);

    // K-uno-metrics: refresh gauges + bump block-produced counter.
    // End-of-block is the single natural cadence for gauge updates — every
    // scrape after this fires will see the post-block state.
    auto& mreg = global_metrics_registry();
    mreg.inc_blocks_produced();
    {
        std::lock_guard<std::mutex> lk(g_live->mutex_);
        mreg.set_anchor_window_size(
            static_cast<uint64_t>(g_live->anchor_window().size()));
        mreg.set_commitment_tree_next_position(
            static_cast<uint64_t>(g_live->commitment_tree().next_position()));
        mreg.set_nullifier_set_size(
            static_cast<uint64_t>(g_live->nullifier_set().size()));
    }
    // Observe the compiled block-filter size. `snap.gcs_blob` is moved into
    // the per-seqno index inside `finalize_block`, but we captured its size
    // before rotation.
    mreg.observe_block_filter_gcs_bytes(
        static_cast<uint64_t>(snap.gcs_blob.size()));
}

// Exposed so tests can drive the hook directly (bypassing compute-phase).
UnoState& global_uno_state() {
    return *g_live;
}

// Exposed so the test harness can stage the output wire bytes captured at
// encode time. Keeps the codec decoupled from the state type.
void stage_output_wire_bytes_for_test(uint64_t global_index, std::string bytes) {
    if (g_live) g_live->stage_output_bytes(global_index, std::move(bytes));
}

// Exposed so the test harness can override the external-message submit hook.
void install_uno_submit_hook(bool(*fn)(const std::string&, const uint8_t[32])) {
    g_submit_override.store(fn, std::memory_order_release);
}

// Exposed so test harnesses can drop + recreate the state between runs.
void reset_uno_state_for_test() {
    g_live.reset();
    g_live = std::make_unique<LiveUnoState>();
}

td::Ref<vm::Cell> serialize_live_uno_state_for_test() {
    return g_live ? g_live->serialize_to_cell() : td::Ref<vm::Cell>{};
}

bool hydrate_live_uno_state_from_cell_for_test(td::Ref<vm::Cell> root) {
    return g_live && g_live->hydrate_from_cell_if_needed(std::move(root));
}

// ---------------------------------------------------------------------------
// init_uno_workchain
// ---------------------------------------------------------------------------

void init_uno_workchain(const std::string& db_root) {
    LOG(WARNING) << "uno-workchain: initialising (workchain_id=2, db_root='"
                 << db_root << "')";

    // Consensus warning: UNO_INIT_MINE_TARGET_HEX is honored at
    // LiveUnoState construction and on the lazy-activate first-MineUno
    // path (acc_uninit executor → hydrate(null) → use construction
    // default). All validators in a network MUST agree on whether the
    // env var is set, and on its value if set, or they will disagree
    // on whether the first MineUno meets `state.mine_target()` →
    // consensus split at bootstrap. Mainnet deployments must leave it
    // unset; local-dev networks must set it identically across every
    // validator (setup-testnet.sh propagates a single value via the
    // generated systemd unit).
    //
    // Tracked followup: encode the canonical mining target into the
    // wc=2 zerostate executor's StateInit.data via
    // `build_uno_zerostate_accounts_cell` so chain-state — not env —
    // is the single source of truth.
    if (const char* env = std::getenv("UNO_INIT_MINE_TARGET_HEX"); env != nullptr) {
        LOG(WARNING) << "uno-workchain: UNO_INIT_MINE_TARGET_HEX="
                     << env
                     << " — operator override active. Every validator in this"
                        " network must use the SAME value or you will get a"
                        " consensus split on the first MineUno tx. Unset on"
                        " mainnet.";
    }

    // Step 1. State. Live state with A2-backed sub-objects.
    g_live = std::make_unique<LiveUnoState>();

    // Step 2. Pre-load Plonky3 verifier state. The singleton inside
    // compute-phase.cpp performs lazy init on first verify; we intentionally
    // don't force it here because v1 tests that never call verify shouldn't
    // pay the FRI-param materialization cost.

    // Step 3. Warm the nullifier LRU (M2, §5.3 / §5.9). Pre-populate the
    // LRU with up to K recently-inserted nullifiers so the first blocks
    // after cold start don't pay the ~24-level cell-dict walk for every
    // nullifier-miss path (§4.3 step 2).
    //
    // K source of truth: §10.2 pins `nullifier_lru_capacity = 1_000_000`
    // in ConfigParam 84, but the current `UnoConfig` struct does not yet
    // expose that field (it's documented but not wired through to the
    // builder/parser). We therefore use a compile-time default here —
    // 1 << 20 = 1,048,576 entries per §5.9 — and leave a follow-up to
    // route it through `current_uno_config_view()` once the config-param
    // schema bump lands. Behaviour is identical at launch defaults
    // (doc value is 1,000,000; our default is 1,048,576 — both well
    // under the worst-case ~100 MB RAM budget).
    static constexpr std::size_t kNullifierLruWarmSize = std::size_t{1} << 20;
    if (g_live) {
        g_live->nullifier_set().warm_lru(kNullifierLruWarmSize);
        LOG(INFO) << "uno-workchain: nullifier LRU warm-up requested k="
                  << kNullifierLruWarmSize
                  << " (snapshot now "
                  << g_live->nullifier_set().warm_snapshot_size()
                  << " entries)";
    }

    // Step 5. Register the real compute handler with the dispatcher.
    uno_workchain_dispatch::set_uno_compute_handler(
        [](block::ComputePhase& cp,
           td::Ref<vm::Cell> state_data,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            if (g_live && !g_live->hydrate_from_cell_if_needed(std::move(state_data))) {
                cp.skip_reason = block::ComputePhase::sk_bad_state;
                cp.success = false;
                cp.accepted = true;
                cp.gas_used = 0;
                cp.gas_limit = gas_limit;
                cp.vm_steps = 1;
                cp.vm_init_state_hash.set_zero();
                cp.vm_final_state_hash.set_zero();
                cp.vm_log = "uno: persisted state rejected";
                return true;
            }
            if (g_live) {
                g_live->set_block_seqno(block_seqno);
            }
            return run_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_live,
                block_seqno, timestamp, rand_seed);
        });

    // Step 5. Bind A6 RPC setter-DI. Every handler in uno/rpc/handlers.cpp
    // consults an atomic<fn*> that defaults to nullptr ("unavailable"). These
    // calls flip every pointer to a concrete accessor routed through g_live.
    set_head_state_fn(rpc_head_state_fn);
    set_mine_state_fn(rpc_mine_state_fn);
    set_anchor_at_seqno_fn(rpc_anchor_at_seqno_fn);
    set_frontier_fn(rpc_frontier_fn);
    set_nullifier_lookup_fn(rpc_nullifier_lookup_fn);
    set_admission_check_fn(rpc_admission_check_fn);
    set_estimate_fee_fn(rpc_estimate_fee_fn);
    set_tx_status_fn(rpc_tx_status_fn);
    set_outputs_for_ivk_fn(rpc_outputs_for_ivk_fn);
    set_submit_external_message_hook(rpc_submit_external_message_fn);

    // filter-service setters live in their own TU.
    set_filter_fetch_backend(rpc_filter_fetch_fn);
    set_outputs_fetch_backend(rpc_outputs_fetch_fn);

    LOG(WARNING) << "uno-workchain: handler registered, RPC setter-DI bound "
                 << "(12/12: head_state, anchor_at_seqno, frontier, "
                 << "nullifier_lookup, admission_check, estimate_fee, "
                 << "tx_status, outputs_for_ivk, submit_external_message, "
                 << "filter_fetch, outputs_fetch)";
}

// ---------------------------------------------------------------------------
// Zerostate ShardAccounts builder — mirror of evm_workchain's equivalent.
// ---------------------------------------------------------------------------
//
// Schema (block.tlb §270–292):
//   _ (HashmapAugE 256 ShardAccount DepthBalanceInfo) = ShardAccounts;
//   account_descr$_ account:^Account last_trans_hash:bits256
//                   last_trans_lt:uint64 = ShardAccount;
//   account$1 addr:MsgAddressInt storage_stat:StorageInfo
//             storage:AccountStorage = Account;
//   account_storage$_ last_trans_lt:uint64
//                     balance:CurrencyCollection state:AccountState
//                                                         = AccountStorage;
//   account_uninit$00 = AccountState;
//
// The wc=2 shard contains exactly one entry: the executor account at
// key = kUnoExecutorAddressBytes (0x00…01). It is seeded as `acc_uninit`
// (no StateInit) — the first MineUno ext_in_msg activates it via the
// wc=2 branch in transaction.cpp (see lines 1938-1980): acc_uninit →
// acc_active with the canonical 0x55 'U' code marker cell installed,
// and cp.new_data holding the serialised UnoShardState as StateInit.data.
//
// Determinism: all field stores are in fixed order with literal values;
// cell hash is a pure function of kUnoExecutorAddressBytes + workchain_id.
td::Ref<vm::Cell> build_uno_zerostate_accounts_cell() {
    using td::make_refint;

    // 1. AccountStorage = last_trans_lt:0 balance:zero state:account_uninit$00
    vm::CellBuilder as_cb;
    as_cb.store_long_bool(0, 64);                                 // last_trans_lt
    bool ok = block::CurrencyCollection{make_refint(0)}.store(as_cb);  // balance
    CHECK(ok);
    as_cb.store_long_bool(0, 2);                                  // account_uninit$00
    auto storage_cell = as_cb.finalize();

    // 2. StorageInfo.used = computed from the storage cell (deterministic).
    vm::CellStorageStat stats;
    auto stat_status = stats.compute_used_storage(td::Ref<vm::Cell>(storage_cell));
    CHECK(stat_status.is_ok());

    // 3. Account = account$1 addr:addr_std$10 wc=2 addr storage_stat storage
    vm::CellBuilder acc_cb;
    acc_cb.store_long_bool(1, 1);                                 // account$1
    acc_cb.store_long_bool(2, 2);                                 // addr_std$10
    acc_cb.store_long_bool(0, 1);                                 // anycast: nothing
    acc_cb.store_long_rchk_bool(/*kWorkchainId=*/2, 8);           // workchain_id
    acc_cb.store_bytes(kUnoExecutorAddressBytes, 32);             // address bits
    // storage_stat:StorageInfo = used:StorageUsed extra:StorageExtraInfo
    //                            last_paid:uint32 due_payment:Maybe(Tomis)
    ok = block::store_UInt7(acc_cb, stats.cells)
         && block::store_UInt7(acc_cb, stats.bits);
    CHECK(ok);
    acc_cb.store_zeroes_bool(3);                                  // extra:StorageExtraInfo (regular$0 + 2 bits)
    acc_cb.store_long_bool(0, 33);                                // last_paid:uint32(0) + due_payment:nothing
    acc_cb.append_data_cell_bool(storage_cell);                   // storage:AccountStorage
    auto account_cell = acc_cb.finalize();

    // Validate — catches TLB-encoding bugs early.
    CHECK(block::gen::t_Account.validate_ref(account_cell));

    // 4. Wrap as a ShardAccount entry and insert as the sole dict value.
    //    ShardAccounts dict value layout: ^Account + last_trans_hash:bits256
    //    + last_trans_lt:uint64 (= 320 trailing zero bits at genesis).
    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder vcb;
    vcb.store_ref_bool(account_cell);
    vcb.store_zeroes_bool(256 + 64);                              // last_trans_hash + last_trans_lt
    accounts_dict.set_builder(td::ConstBitPtr{kUnoExecutorAddressBytes}, 256, vcb);

    vm::CellBuilder cb;
    accounts_dict.append_dict_to_bool(cb);
    return cb.finalize();
}

}  // namespace uno_workchain
