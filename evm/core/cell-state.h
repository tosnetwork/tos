/*
    EVM Workchain — cell-native state adapter.

    CellEvmState implements silkworm::State backed by TOS cells:

      - Accounts live in a vm::Dictionary keyed by 256-bit address (left-padded
        EVM 20-byte address). Each value is an EvmAccountData cell.
      - Per-account storage lives in a vm::Dictionary keyed by 256-bit slot,
        referenced from the account's storage_root cell.
      - Bytecode lives in cells, indexed by code_hash (silkworm-style content
        addressing).

    All EVM state is therefore representable as a single root cell — directly
    insertable into TOS ShardState. There is no second key-value database.
    Atomic block commits are achieved by the standard CellDb WriteBatch.

    This adapter holds an in-memory `vm::Dictionary` for the working set;
    serialize_to_cell() / load_from_cell() let callers persist the state via
    any cell store (currently: BoC file; future: TOS CellDb via collator).

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/account.hpp>

#include "evm/core/mpt-trie.h"
#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/dict.h"

#include <atomic>
#include <cstddef>
#include <map>
#include <set>
#include <unordered_map>
#include <mutex>

namespace evm_workchain {

/// Selects how aggressively `CellEvmState::load_from_cell` validates the
/// supplied state-root cell.
///
///   - StrictValidateAndRebuildWitness: full account/storage walk, decode all
///     bytecode, then rebuild the Ethereum MPT witness from scratch. Used for
///     hydration, snapshot import, manual repair, and offline verification.
///   - StrictValidateNoWitness: same eager walk, but leave the witness empty
///     (caller will load a separate witness cell).
///   - TrustedLazy: only verify the root cell is non-special and bind the
///     account dictionary; do NOT walk accounts/storage and do NOT decode
///     bytecode. Designed for the consensus-bound EVM compute hot path where
///     the input cell hash is already authenticated by the surrounding TOS
///     account state and a per-tx full-state scan would be unmetered host
///     work.
enum class CellStateLoadMode {
    StrictValidateAndRebuildWitness,
    StrictValidateNoWitness,
    TrustedLazy,
};

/// Selects how aggressively `CellEvmState::load_trie_witness_from_cell`
/// validates the supplied witness root cell.
///
///   - StrictRecursive: walks the whole account trie (and validates each
///     cached RLP byte against the recomputed RLP) before binding. Used by
///     hydration, snapshot import, manual repair, and offline verification.
///   - TrustedShallow: only verifies the witness root cell decodes into a
///     non-special root node. Account-trie internal nodes are decoded lazily
///     on the proof / mutation path. Designed for the consensus-bound EVM
///     compute hot path where the input cell hash is already authenticated by
///     the surrounding TOS account state and a strict per-tx walk would be
///     unmetered host work scaling with global account count.
enum class TrieWitnessLoadMode {
    StrictRecursive,
    TrustedShallow,
};

#ifdef TOS_EVM_TEST_INSTRUMENTATION
/// Test-only instrumentation. Each global counter is bumped exactly once per
/// full-walk operation in CellEvmState. Tests reset to 0 before exercising a
/// lazy hot-path call and assert the counter stays at the expected value.
extern std::atomic<size_t> g_cell_state_full_walks;
extern std::atomic<size_t> g_storage_index_walks;
#endif

struct CellEvmStateSizeStats {
    size_t accounts{0};
    size_t storage_slots{0};
    bool exceeded{false};
    bool malformed{false};
};

struct CellEvmStateDeltaStats {
    size_t new_accounts{0};
    size_t deleted_accounts{0};
    size_t new_storage_slots{0};
    size_t cleared_storage_slots{0};
};

/// silkworm::State implementation backed by a vm::Dictionary of EvmAccountData
/// cells. Designed for single-threaded EVM execution; callers wrap with
/// EvmState's shared_mutex for concurrent RPC access.
class CellEvmState : public silkworm::State {
  public:
    /// Create empty state.
    CellEvmState();
    ~CellEvmState() override = default;

    // ----- silkworm::State read interface -----

    std::optional<silkworm::Account> read_account(const evmc::address& address) const noexcept override;

    silkworm::ByteView read_code(const evmc::address& address,
                                  const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address,
                                uint64_t incarnation,
                                const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    silkworm::BlockNum current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(silkworm::BlockNum block_num) const override;

    void insert_block(const silkworm::Block& block, const evmc::bytes32& hash) override;

    void canonize_block(silkworm::BlockNum block_num, const evmc::bytes32& block_hash) override;

    void decanonize_block(silkworm::BlockNum block_num) override;

    void insert_call_traces(silkworm::BlockNum, const silkworm::CallTraces&) override {}

    // ----- silkworm::BlockState interface -----

    std::optional<silkworm::BlockHeader> read_header(
        silkworm::BlockNum block_num,
        const evmc::bytes32& block_hash) const noexcept override;

    bool read_body(silkworm::BlockNum, const evmc::bytes32&,
                   silkworm::BlockBody&) const noexcept override {
        return false;
    }

    std::optional<intx::uint256> total_difficulty(
        uint64_t, const evmc::bytes32&) const noexcept override {
        return std::nullopt;
    }

    // ----- silkworm::State write interface -----

    void begin_block(silkworm::BlockNum block_num, size_t updated_accounts_count) override;

    void update_account(const evmc::address& address,
                        std::optional<silkworm::Account> initial,
                        std::optional<silkworm::Account> current) override;

    void update_account_code(const evmc::address& address,
                             uint64_t incarnation,
                             const evmc::bytes32& code_hash,
                             silkworm::ByteView code) override;

    void update_storage(const evmc::address& address,
                        uint64_t incarnation,
                        const evmc::bytes32& location,
                        const evmc::bytes32& initial,
                        const evmc::bytes32& current) override;

    void unwind_state_changes(silkworm::BlockNum) override {}

    // ----- Cell-native extensions -----

    /// Iterate over every account in the dictionary, in nibbled key order.
    /// The callback receives the 256-bit address-padded key and the decoded Account.
    /// (The key's last 20 bytes are the EVM address.)
    bool for_each_account_while(std::function<bool(const unsigned char key[32],
                                                   const silkworm::Account&)> cb) const;
    void for_each_account(std::function<void(const unsigned char key[32],
                                              const silkworm::Account&)> cb) const;

    /// Iterate over every storage slot of one account.
    bool for_each_storage_while(const evmc::address& address,
                                std::function<bool(const evmc::bytes32& slot,
                                                   const evmc::bytes32& value)> cb) const;
    void for_each_storage(const evmc::address& address,
                          std::function<void(const evmc::bytes32& slot,
                                              const evmc::bytes32& value)> cb) const;

    /// Bounded state-size scan used before full Ethereum MPT root rebuild.
    /// Stops as soon as either limit is exceeded, so the preflight itself is
    /// bounded by the configured safety budget.
    CellEvmStateSizeStats count_entries_bounded(size_t max_accounts,
                                                size_t max_storage_slots) const noexcept;

    /// Track actual account/storage growth produced by the next write_to_db().
    /// Kept for diagnostics/tests; stateRoot production now uses the
    /// persistent Ethereum trie witness instead of full-state budget scans.
    void reset_delta_stats() noexcept { delta_stats_ = {}; }
    CellEvmStateDeltaStats delta_stats() const noexcept { return delta_stats_; }

    /// Ethereum execution-layer MPT witness. These methods use the persisted
    /// witness maintained by update_account/update_storage and do not walk the
    /// full cell state on the hot path.
    evmc::bytes32 ethereum_state_root_hash() const;
    /// Legacy storage-root helper. May lazy-load and mutate
    /// `touched_storage_tries_` under a const member, and may trigger strict
    /// recursive validation on a fresh witness load. The execution-side
    /// update path (`update_account_trie_leaf`) is the only place this should
    /// keep getting called — it already runs under a unique lock and benefits
    /// from the populated cache. Public RPC and any read-only path must use
    /// `ethereum_storage_root_hash_safe_no_cache` instead.
    evmc::bytes32 ethereum_storage_root_hash_unsafe_for_execution_cache(
        const evmc::address& address) const;
    /// Test-only proof helpers. They wrap the path-bounded `_safe` variants
    /// but discard the `td::Status` so corrupt-witness errors surface as an
    /// empty proof — fine for the regression suite, never acceptable on the
    /// production RPC / consensus path. Production code MUST use
    /// `ethereum_account_proof_safe` and `ethereum_storage_proof_safe[_no_cache]`.
    std::vector<silkworm::Bytes> ethereum_account_proof_unsafe_for_tests_only(
        const evmc::address& address) const;
    std::vector<silkworm::Bytes> ethereum_storage_proof_unsafe_for_tests_only(
        const evmc::address& address, const evmc::bytes32& slot) const;
    /// Fail-closed proof variants. A corrupt witness (lazy node fails to
    /// decode, or a structural inconsistency surfaces during the walk)
    /// returns a `td::Status` error rather than crashing the node, so RPC
    /// handlers can map it to a JSON-RPC -32000 response.
    td::Result<std::vector<silkworm::Bytes>> ethereum_account_proof_safe(
        const evmc::address& address) const;
    td::Result<std::vector<silkworm::Bytes>> ethereum_storage_proof_safe(
        const evmc::address& address, const evmc::bytes32& slot) const;

    /// Read-only proof helper for public RPC `eth_getProof`. Builds the
    /// storage proof from a temporary local `MptTrie` shallow-loaded directly
    /// out of `storage_trie_index_root_`, so the `mutable touched_storage_tries_`
    /// cache is **not** mutated under the shared lock. Returns an empty proof
    /// when the address has no entry in the witness storage-trie index
    /// (canonical empty-trie semantics matching `ethereum_storage_proof_safe`).
    td::Result<std::vector<silkworm::Bytes>> ethereum_storage_proof_safe_no_cache(
        const evmc::address& address, const evmc::bytes32& slot) const;

    /// Read-only storage-root helper for public RPC `eth_getProof`. Mirrors
    /// `ethereum_storage_proof_safe_no_cache`: shallow-loads the per-account
    /// storage trie from `storage_trie_index_root_` into a local temporary
    /// (never writes `mutable touched_storage_tries_`) and never triggers
    /// strict recursive validation. Returns the canonical empty-trie root
    /// when the address has no entry in the witness storage-trie index, and
    /// a `td::Status` error on any malformed cell so the RPC layer can map
    /// it to a JSON-RPC `-32000 corrupt EVM trie witness`.
    td::Result<evmc::bytes32> ethereum_storage_root_hash_safe_no_cache(
        const evmc::address& address) const;
    /// Cross-check helpers: re-encode the canonical Ethereum account / storage
    /// leaf from the flat cell state and compare it to the value the witness
    /// MPT path-bounded walker reports for `keccak(address)` /
    /// `keccak(slot)`. Returns `td::Status::OK()` only when the witness leaf
    /// payload matches the flat state byte-for-byte (or both agree on
    /// canonical absence). Any mismatch — or a malformed/over-budget descent —
    /// surfaces as a non-OK status so the EVM compute hot path can fail closed
    /// before EVM execution starts. The implementation never touches the
    /// `mutable touched_storage_tries_` cache; it uses its own shallow lookup
    /// out of `storage_trie_index_root_` for the storage-trie side.
    td::Status verify_account_witness_matches_flat_state(
        const evmc::address& address) const;
    td::Status verify_storage_witness_matches_flat_state(
        const evmc::address& address, const evmc::bytes32& slot) const;
    bool trie_witness_ready() const noexcept { return trie_witness_ready_; }
    bool rebuild_trie_witness() noexcept;

    /// Serialize/load the persistent Ethereum MPT witness. Null witness means
    /// the empty state trie. The mode-aware overload selects between strict
    /// recursive validation (hydration/import/repair) and a cheap trusted
    /// shallow bind suitable for the EVM compute hot path.
    td::Ref<vm::Cell> serialize_trie_witness_to_cell() const;
    bool load_trie_witness_from_cell(td::Ref<vm::Cell> root, TrieWitnessLoadMode mode);

    /// Legacy entry point that defaults to `StrictRecursive`. New consensus
    /// hot-path callers must pass `TrieWitnessLoadMode::TrustedShallow`
    /// explicitly so a per-tx full account-trie walk is not reintroduced.
    bool load_trie_witness_from_cell(td::Ref<vm::Cell> root) {
        return load_trie_witness_from_cell(std::move(root),
                                            TrieWitnessLoadMode::StrictRecursive);
    }

    /// Serialize the entire account dictionary into a single cell (suitable
    /// for storing in a ShardAccounts cell or a BoC).
    /// Returns a null cell if the dictionary is empty.
    td::Ref<vm::Cell> serialize_to_cell() const;

    /// Replace the current account dictionary with one decoded from the given cell.
    /// Pass a null cell to start from empty.
    bool load_from_cell(td::Ref<vm::Cell> root, CellStateLoadMode mode);

    /// Legacy boolean shim. Maps `true` to `StrictValidateAndRebuildWitness`
    /// (preserving the previous default) and `false` to
    /// `StrictValidateNoWitness`. New callers on the consensus hot path should
    /// pass `CellStateLoadMode::TrustedLazy` explicitly.
    bool load_from_cell(td::Ref<vm::Cell> root, bool rebuild_trie_witness = true) {
        return load_from_cell(
            std::move(root),
            rebuild_trie_witness ? CellStateLoadMode::StrictValidateAndRebuildWitness
                                 : CellStateLoadMode::StrictValidateNoWitness);
    }

    /// Serialize / load the canonical EVM block-hash history used by
    /// BLOCKHASH and the EIP-2935 history-storage system call. The serialized
    /// form keeps the latest 256 canonical hashes, which is exactly the EVM
    /// lookback window.
    td::Ref<vm::Cell> serialize_block_hashes_to_cell() const;
    bool load_block_hashes_from_cell(td::Ref<vm::Cell> root);

    /// Direct read-only access to the underlying account dictionary cell.
    /// Useful for collator integration (sync to ShardAccounts).
    td::Ref<vm::Cell> account_dict_root() const;

    /// Convenience: drop all blocks from the cache (for tests).
    void clear_block_cache();

    /// Used by `populate_state_from_shard_accounts` to re-attach a storage
    /// root cell to an account that was just hydrated via update_account()
    /// (silkworm's update_account drops the storage_root field). Public
    /// hydration-only entry point for the otherwise-private set_storage_root.
    void set_storage_root_for_hydration(const evmc::address& address,
                                         td::Ref<vm::Cell> root);

    // ----- Free helpers (used outside CellEvmState) -----

  private:
    /// Read the storage dict root cell for an account. Returns null if account
    /// has no storage.
    td::Ref<vm::Cell> get_storage_root(const evmc::address& address) const;

    /// Write or clear the storage dict root for an account.
    void set_storage_root(const evmc::address& address, td::Ref<vm::Cell> root);
    bool ensure_trie_witness();
    bool rebuild_storage_trie_for_account(const evmc::address& address);
    bool update_account_trie_leaf(const evmc::address& address,
                                  const std::optional<silkworm::Account>& account);

    /// Look up the inner EvmAccountData cell for an address from the account
    /// dictionary. Returns false if the account is missing or if the dict
    /// value has the wrong shape. Used by lazy `read_code` and by the lazy
    /// storage-trie helpers.
    bool lookup_account_data_cell(const evmc::address& address,
                                  td::Ref<vm::Cell>& out) const;

    /// Lazy storage-trie helpers. `for_update` marks the trie dirty so the
    /// next `serialize_trie_witness_to_cell` writes a fresh entry into the
    /// storage-trie index dictionary. `for_read` only loads into the
    /// touched-cache without marking dirty.
    ///
    /// The mode-aware overloads pick between strict recursive validation
    /// (used by repair/import paths) and the shallow bind used by the EVM
    /// compute hot path. Default callers (no `mode` argument) keep the
    /// historical strict-recursive behaviour for legacy import paths.
    MptTrie* get_or_load_storage_trie_for_update(const evmc::address& address);
    MptTrie* get_or_load_storage_trie_for_update(const evmc::address& address,
                                                  MptWitnessValidationMode mode);
    const MptTrie* get_or_load_storage_trie_for_read(const evmc::address& address) const;
    const MptTrie* get_or_load_storage_trie_for_read(
        const evmc::address& address, MptWitnessValidationMode mode) const;

    mutable vm::Dictionary account_dict_;  // 256-bit keys → EvmAccountData cells

    // Code storage: code_hash → bytes (silkworm content-addressed). `mutable`
    // so the lazy `read_code` path can populate the cache from inside a const
    // member function.
    mutable std::unordered_map<evmc::bytes32, silkworm::Bytes> code_;

    // Block cache for BLOCKHASH opcode (silkworm requires it)
    std::unordered_map<silkworm::BlockNum, evmc::bytes32> canonical_;

    // Read-code returns ByteView; needs persistent buffer (per-thread)
    static thread_local silkworm::Bytes tl_code_buf_;

    MptTrie account_trie_;

    // Lazy storage trie witness (P1). `storage_trie_index_root_` holds the
    // root cell of the witness storage-trie index dictionary (256-bit address
    // → ^MptTrieRoot). Only addresses actually touched by the current
    // execution are materialised into `touched_storage_tries_`;
    // `dirty_storage_trie_roots_` records which of those need to be flushed
    // back into the index on the next serialize.
    td::Ref<vm::Cell> storage_trie_index_root_;
    mutable std::map<evmc::address, MptTrie> touched_storage_tries_;
    std::set<evmc::address> dirty_storage_trie_roots_;

    bool trie_witness_ready_{true};

    CellEvmStateDeltaStats delta_stats_;
};

}  // namespace evm_workchain
