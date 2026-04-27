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
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace evm_workchain {

/// Hasher for `evmc::address` keys in `std::unordered_set` /
/// `std::unordered_map`. Wraps `std::hash<std::string_view>` over the 20
/// little-endian bytes that already form a high-entropy keccak prefix. The
/// hash is therefore stable across runs / TUs and avoids the cost of an
/// auxiliary boost-style mix on every lookup.
struct AddressHash {
    size_t operator()(const evmc::address& a) const noexcept {
        return std::hash<std::string_view>{}(
            std::string_view{reinterpret_cast<const char*>(a.bytes), 20});
    }
};

/// Composite key for the dynamic witness consistency tracker: an EVM
/// account address paired with a 256-bit storage slot. Used to dedupe
/// per-(address, slot) checks across an EVM transaction so a hot SLOAD /
/// SSTORE loop doesn't pay the path-bounded MPT proof cost more than once.
struct StorageKey {
    evmc::address address{};
    evmc::bytes32 slot{};
    bool operator==(const StorageKey& other) const noexcept {
        return std::memcmp(address.bytes, other.address.bytes, 20) == 0 &&
               std::memcmp(slot.bytes, other.slot.bytes, 32) == 0;
    }
};

struct StorageKeyHash {
    size_t operator()(const StorageKey& k) const noexcept {
        // Concatenate address (20 bytes) and slot (32 bytes) into a stable
        // 52-byte view and hash via std::hash<std::string_view>. Avoids a
        // bespoke mix and keeps the implementation portable across libstdc++
        // / libc++ / Windows STLs.
        unsigned char buf[52];
        std::memcpy(buf, k.address.bytes, 20);
        std::memcpy(buf + 20, k.slot.bytes, 32);
        return std::hash<std::string_view>{}(
            std::string_view{reinterpret_cast<const char*>(buf), sizeof(buf)});
    }
};

/// Per-transaction tracker for the dynamic flat-state / MPT witness
/// consistency check. The compute-phase opens a context around
/// `execute_evm_transaction()`; the State read/update path consults the
/// context inside `noexcept` Silkworm-State overrides and records any
/// consistency error into `first_error` instead of throwing. The executor
/// then drains `first_error` after EVM execution and treats a non-OK
/// status as a fail-closed consensus invariant violation (rollback +
/// `sk_bad_state`).
struct WitnessFlatConsistencyContext {
    bool enabled{false};
    std::unordered_set<evmc::address, AddressHash> checked_accounts;
    std::unordered_set<StorageKey, StorageKeyHash> checked_storage;
    td::Status first_error = td::Status::OK();
    /// Optional human-readable context for logging on the rollback path.
    /// Captured at the point of the first detected mismatch, before the
    /// outer compute-phase rollback overwrites `first_error.message()` via
    /// move semantics (the message is moved during reject path string
    /// construction).
    std::string offending_what;
};

#ifdef TOS_EVM_TEST_INSTRUMENTATION
/// Test-only counter incremented every time the dynamic witness consistency
/// verifier runs the *real* path-bounded MPT proof check (i.e. only the
/// first time per (address) or (address, slot) inside a transaction).
/// Fast paths (already-checked dedup, ctx disabled, prior error sticky)
/// do NOT bump this counter, so a test can assert "static precheck already
/// covered the address → no double-check" by observing 0.
extern std::atomic<size_t> g_witness_consistency_checks;

/// Test-only high-water mark of the thread-local recursion-depth guard
/// used by `verify_account_before_return` / `verify_storage_before_return`.
/// Each call records `t_witness_verify_depth` after the guard increments
/// it, so tests can assert "normal verify_account flow only reaches
/// depth 1 because the dedup-then-call ordering is intact". Reset by the
/// test before each scenario.
extern std::atomic<int> g_witness_verify_depth_max_observed;

/// Test-only setter that overrides the thread-local recursion-depth
/// counter prior to invoking the verifier hooks. Returns the previous
/// value so tests can restore the counter after the scenario. Used to
/// drive the depth-guard bail-out path without faking the (correctly
/// ordered) dedup-before-verify call chain.
int set_witness_verify_depth_for_testing(int new_depth) noexcept;

/// Test-only getter for the current value of the thread-local depth
/// counter. Mirrors the setter above and is exposed only so a test can
/// verify the counter restored cleanly after a guarded call.
int get_witness_verify_depth_for_testing() noexcept;

/// Sentinel returned by `get_bad_alloc_injection_for_test` and accepted by
/// `enable_bad_alloc_injection_for_test` to mean "injection disabled". It
/// is INT_MIN so the production hot path can perform a single signed
/// integer comparison and bail before any decrement work is attempted.
constexpr int kWitnessBadAllocInjectionDisabled =
    std::numeric_limits<int>::min();
/// Test-only setter that arms a thread-local countdown for the dynamic
/// witness consistency dedup-set insert. After the next `n` insert
/// attempts (account or storage) succeed, the (n+1)-th attempt throws
/// `std::bad_alloc` from inside the verifier's try/catch, exercising the
/// sticky `first_error` ("witness consistency tracker exhausted
/// (allocation failure)") path. Pass `kWitnessBadAllocInjectionDisabled`
/// to disarm. Returns the previous value so tests can save / restore.
///
/// Production paths see no overhead: the verifier compares against the
/// sentinel and skips the decrement-and-throw block entirely when it is
/// not armed. The setter is wrapped in `TOS_EVM_TEST_INSTRUMENTATION` so
/// release builds do not link the symbol at all.
int enable_bad_alloc_injection_for_test(int n) noexcept;

/// Test-only getter for the bad-alloc injection countdown. Returns
/// `kWitnessBadAllocInjectionDisabled` when no injection is armed.
int get_bad_alloc_injection_for_test() noexcept;
#endif

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

/// Audit K-02 (H-01 follow-up): test-only mirror of the always-on
/// production counter `s_code_root_hash_mismatch_count_inner` (defined in
/// `cell-state.cpp`). It increments in lockstep with the production
/// counter so test-only instrumentation can assert the precise number of
/// `read_code` mismatches the verifier observed even in scenarios where a
/// `WitnessFlatConsistencyContext` is not bound.
extern std::atomic<uint64_t> g_code_root_hash_mismatch_count;
#endif

/// Audit K-02 (H-01 follow-up): always-on counter accessor. Returns the
/// total number of `read_code` calls that detected a code-root vs
/// `code_hash` mismatch since process start (or since the last
/// `reset_code_root_hash_mismatch_count_for_test`). RPC handlers that do
/// NOT run under an active `WitnessFlatConsistencyContext` (for example
/// `eth_call`'s read-only fast path) snapshot this counter before
/// invoking the EVM and compare again afterwards: a non-zero delta means
/// silkworm internal helpers consumed corrupt bytecode during the
/// handler's frame, and the handler maps the response to a JSON-RPC
/// `-32000 corrupt EVM code root` error instead of silently returning
/// the wrong code (or, worse, "0x" because `read_code` returns an empty
/// `ByteView` on mismatch). Linked unconditionally — production paths
/// rely on it.
uint64_t code_root_hash_mismatch_count() noexcept;

/// Audit K-02 (H-01 follow-up): test-only reset for the always-on
/// counter exposed by `code_root_hash_mismatch_count`. Production code
/// must not call this — the counter is monotone for the lifetime of the
/// process and the RPC handlers' "snapshot-and-check" pattern would race
/// against any concurrent reset. Used by the K-02 unit tests so the
/// exact mismatch delta from a single `read_code` invocation is
/// observable.
void reset_code_root_hash_mismatch_count_for_test() noexcept;

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
#ifdef TOS_EVM_TEST_INSTRUMENTATION
    /// Legacy storage-root helper. May lazy-load and mutate
    /// `touched_storage_tries_` under a const member, and may trigger strict
    /// recursive validation on a fresh witness load. The execution-side
    /// update path (`update_account_trie_leaf`) is the only place this should
    /// keep getting called — it already runs under a unique lock and benefits
    /// from the populated cache. Public RPC and any read-only path must use
    /// `ethereum_storage_root_hash_safe_no_cache` instead.
    ///
    /// L-01 (audit): test-only API gated behind
    /// `TOS_EVM_TEST_INSTRUMENTATION`. Production targets do NOT define
    /// the macro and therefore do not export this symbol — production
    /// callers cannot accidentally link against it.
    evmc::bytes32 ethereum_storage_root_hash_unsafe_for_execution_cache(
        const evmc::address& address) const;
    /// Test-only proof helpers. They wrap the path-bounded `_safe` variants
    /// but discard the `td::Status` so corrupt-witness errors surface as an
    /// empty proof — fine for the regression suite, never acceptable on the
    /// production RPC / consensus path. Production code MUST use
    /// `ethereum_account_proof_safe` and `ethereum_storage_proof_safe[_no_cache]`.
    ///
    /// L-01 (audit): same `TOS_EVM_TEST_INSTRUMENTATION` gating.
    std::vector<silkworm::Bytes> ethereum_account_proof_unsafe_for_tests_only(
        const evmc::address& address) const;
    std::vector<silkworm::Bytes> ethereum_storage_proof_unsafe_for_tests_only(
        const evmc::address& address, const evmc::bytes32& slot) const;
#endif  // TOS_EVM_TEST_INSTRUMENTATION
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

    /// Open / close a per-transaction dynamic witness consistency check.
    /// While a context is bound, every State read / mutation path that
    /// surfaces a flat-dict value to the EVM also runs a path-bounded
    /// witness MPT proof on first touch and records any disagreement into
    /// the context. Mutations check the *pre-mutation* value so a write
    /// path can never silently ratify a corrupt witness.
    ///
    /// `begin_witness_consistency_check(ctx)` requires `ctx != nullptr`
    /// and stores a borrowed pointer; the caller owns `ctx` lifetime and
    /// MUST call `end_witness_consistency_check()` before destroying it.
    /// Both calls are idempotent w.r.t. parallel executors (each
    /// CellEvmState instance is single-writer; locking is done at the
    /// EvmState facade).
    void begin_witness_consistency_check(
        WitnessFlatConsistencyContext* ctx) noexcept;
    void end_witness_consistency_check() noexcept;
    /// Drain the context's first error. Returns OK if no mismatch was
    /// recorded. Resets `first_error` so subsequent transactions get a
    /// clean slate (the context is conceptually per-tx, but reusing the
    /// allocated unordered_sets across txs would still be safe).
    td::Status consume_witness_consistency_error() noexcept;
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

#ifdef TOS_EVM_TEST_INSTRUMENTATION
    /// Audit H-01 (P0.3): test-only helper that pollutes the
    /// verified-only code cache so the K-02 cache-hit invariant can be
    /// exercised against a deliberately corrupted entry. Stores
    /// `(stored_bytes, advertised_hash)` under `cache_key`; if
    /// `advertised_hash != cache_key` (the typical pollution pattern), a
    /// subsequent `read_code(_, cache_key)` will hit the cache, observe
    /// the stored hash mismatch against the requested key, bump the
    /// always-on K-02 mismatch counter, and return an empty `ByteView`.
    /// The setter is gated behind `TOS_EVM_TEST_INSTRUMENTATION` so
    /// release builds neither define the symbol nor expose the
    /// poisoning surface.
    void poison_code_cache_for_test(const evmc::bytes32& cache_key,
                                     const evmc::bytes32& advertised_hash,
                                     silkworm::ByteView stored_bytes);
#endif  // TOS_EVM_TEST_INSTRUMENTATION

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

    /// Audit H-01 / K-02 (P0.3): verified-only code-cache entry. Every
    /// insertion into `code_` MUST have already passed the canonical
    /// `keccak(bytes) == hash` invariant via `decode_and_verify_code_root`
    /// (or its sister helper for in-memory writes). Storing the verified
    /// `hash` alongside the bytes lets the cache-hit path re-check the
    /// invariant without recomputing keccak: a cheap `bytes32` compare
    /// against the requested `code_hash` is sufficient because the only
    /// way a stored entry can disagree with its key is direct memory
    /// corruption — and even then the compare fails closed instead of
    /// silently surfacing the wrong bytecode to silkworm.
    struct VerifiedCodeEntry {
        silkworm::Bytes bytes;
        evmc::bytes32 hash;
    };

    // Code storage: code_hash → verified-bytecode entry (silkworm content-
    // addressed). `mutable` so the lazy `read_code` path can populate the
    // cache from inside a const member function.
    mutable std::unordered_map<evmc::bytes32, VerifiedCodeEntry> code_;

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

    /// Borrowed pointer to the active dynamic consistency tracker. Set by
    /// `begin_witness_consistency_check`, cleared by `end_witness_consistency_check`.
    /// Mutable so that `noexcept const` Silkworm-State overrides
    /// (`read_account`, `read_code`, `read_storage`, `previous_incarnation`)
    /// can record errors without dropping `const`-correctness on the
    /// public API.
    mutable WitnessFlatConsistencyContext* witness_ctx_{nullptr};

    /// First-touch verifier hooks. These run inside `noexcept` Silkworm
    /// State overrides, so they MUST NOT throw. Any verification failure
    /// is captured into `witness_ctx_->first_error` and surfaced after
    /// EVM execution by `consume_witness_consistency_error()`.
    void verify_account_before_return(
        const evmc::address& address) const noexcept;
    void verify_storage_before_return(
        const evmc::address& address,
        const evmc::bytes32& slot) const noexcept;

    /// Audit H-01: keccak256 of the supplied bytecode. Used by
    /// `read_code` / `update_account_code` to enforce the canonical
    /// Ethereum invariant `keccak(code) == account.codeHash` whenever
    /// bytecode is decoded from the flat-state cell tree or accepted
    /// from a mutation. `noexcept` so it remains usable from the
    /// `noexcept` Silkworm-State overrides.
    static evmc::bytes32 keccak_code_hash(silkworm::ByteView code) noexcept;

    /// Audit H-01 (P0.1 / P0.4): single chokepoint that decodes a
    /// per-account code_root cell and verifies the canonical Ethereum
    /// invariant `keccak(decoded) == expected_hash` BEFORE the bytes
    /// are admitted to the verified-only code cache. Every path that
    /// populates `code_` from a flat-state cell tree (lazy
    /// `read_code` decode, eager strict-mode `load_from_cell`, future
    /// hydration / repair tooling) MUST funnel through this helper so
    /// no caller can re-introduce the unauthenticated decode bug.
    ///
    /// Contract:
    ///   * `expected_hash == kEmptyHash` && `code_root` null → returns
    ///     an empty `Bytes` (canonical "no code").
    ///   * `expected_hash == kEmptyHash` && `code_root` non-null →
    ///     `Status::Error("empty codeHash has non-null code_root")`.
    ///   * non-empty hash && null `code_root` →
    ///     `Status::Error("non-empty codeHash has null code_root")`.
    ///   * decode produces empty for non-empty hash →
    ///     `Status::Error("non-empty codeHash has empty decoded
    ///     bytecode")`.
    ///   * `keccak(decoded) != expected_hash` →
    ///     `Status::Error("EVM code_root bytecode hash mismatch")`.
    ///
    /// `context` is appended to error messages so callers (strict
    /// load, lazy decode, hydration) surface their own provenance in
    /// logs without each having to format the prefix themselves.
    static td::Result<silkworm::Bytes> decode_and_verify_code_root(
        const td::Ref<vm::Cell>& code_root,
        const evmc::bytes32& expected_hash,
        td::Slice context);

    /// Audit H-01: record a witness consistency error from a
    /// `noexcept` State path. Sets `witness_ctx_->first_error` and
    /// `witness_ctx_->offending_what` only when a context is bound,
    /// is enabled, and has not already captured an earlier error
    /// (sticky). Safe to call from any first-touch read/update hook.
    void record_witness_error_if_active(
        const evmc::address& address, td::Slice what) const noexcept;
};

}  // namespace evm_workchain
