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

    No-MPT native-only adapter: there is no Ethereum execution-layer MPT, no
    persistent witness, and no in-memory account/storage trie. Native canonical
    state is the single source of truth, identified by the cell hash of the
    account dictionary root cell. The Ethereum-format MPT machinery has been
    removed entirely; readers that need a state commitment use the native
    state-root commitment computed in evm/core/native-commitment.{h,cpp}.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/account.hpp>

#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/dict.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <unordered_map>

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

/// Audit K-02 (H-01 follow-up): always-on counter accessor. Returns the
/// total number of `read_code` calls that detected a code-root vs
/// `code_hash` mismatch since process start (or since the last
/// `reset_code_root_hash_mismatch_count_for_test`). RPC handlers
/// snapshot this counter before invoking the EVM and compare again
/// afterwards: a non-zero delta means silkworm internal helpers
/// consumed corrupt bytecode during the handler's frame, and the
/// handler maps the response to a JSON-RPC `-32000 corrupt EVM code
/// root` error instead of silently returning the wrong code (or,
/// worse, "0x" because `read_code` returns an empty `ByteView` on
/// mismatch). Linked unconditionally — production paths rely on it.
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

/// Selects how aggressively `CellEvmState::load_from_cell` validates the
/// supplied state-root cell.
///
///   - TrustedLazy: hot path. Verify the root cell is non-special and
///     bind the account dictionary. Do NOT walk accounts/storage and do
///     NOT decode bytecode. Designed for the consensus-bound EVM
///     compute hot path where the input cell hash is already
///     authenticated by the surrounding TOS account state and a per-tx
///     full-state scan would be unmetered host work.
///   - StrictValidateNative: import / debug / test deep native shape
///     validation. Iterate the account dictionary; for every account
///     decode `EvmAccountData`, verify the storage_root dict shape, and
///     run the H-01 chokepoint `decode_and_verify_code_root` so
///     `keccak(decoded) == account.code_hash` is enforced before the
///     bytecode is admitted to the verified-only code cache. No MPT
///     root is computed.
enum class CellStateLoadMode {
    TrustedLazy,
    StrictValidateNative,
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

    /// Bounded state-size scan. Stops as soon as either limit is exceeded,
    /// so the preflight itself is bounded by the configured safety budget.
    CellEvmStateSizeStats count_entries_bounded(size_t max_accounts,
                                                size_t max_storage_slots) const noexcept;

    /// Track actual account/storage growth produced by the next write_to_db().
    /// Kept for diagnostics/tests.
    void reset_delta_stats() noexcept { delta_stats_ = {}; }
    CellEvmStateDeltaStats delta_stats() const noexcept { return delta_stats_; }

    /// Serialize the entire account dictionary into a single cell (suitable
    /// for storing in a ShardAccounts cell or a BoC).
    /// Returns a null cell if the dictionary is empty.
    td::Ref<vm::Cell> serialize_to_cell() const;

    /// Replace the current account dictionary with one decoded from the given cell.
    /// Pass a null cell to start from empty.
    bool load_from_cell(td::Ref<vm::Cell> root,
                        CellStateLoadMode mode = CellStateLoadMode::TrustedLazy);

    /// Audit Q1 (tos16 P0 follow-up): describes the most recent strict-mode
    /// `load_from_cell` failure. Empty when the last strict load succeeded
    /// or no strict load has run on this instance. Populated atomically
    /// just before a strict load returns `false`, so the caller can read a
    /// human-readable reason (e.g. `"strict load: EVM code_root bytecode
    /// hash mismatch (account=0x..., code_hash=0x...)"`) and surface it as
    /// a structured hydration error / forensic log instead of dying with a
    /// bare `false`. Reset on every entry into `load_from_cell` so a
    /// successful subsequent strict load clears the previous reason.
    td::Slice last_strict_load_failure_reason() const noexcept {
        return td::Slice(last_strict_load_failure_reason_);
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

    /// Per-state code-integrity error counter. Incremented every time the
    /// no-MPT native state observes a `keccak(decoded_code) != code_hash`
    /// mismatch — covers `read_code` lazy-decode mismatches, the H-01
    /// verified-only code cache hit invariant, the strict-load walk
    /// mismatch path, and the `update_account_code` write-side mismatch
    /// guard. The compute phase snapshots this counter around each
    /// execution boundary (cheap prevalidation, EIP-4788 / EIP-2935
    /// system txs, the user tx, and the final serialize) so any delta
    /// reliably surfaces as `sk_bad_state` with the rollback snapshot
    /// restored before `cp.new_data` is written. Read-only / `noexcept`
    /// so it can be invoked from inside silkworm's `noexcept` State
    /// overrides.
    uint64_t code_integrity_error_count() const noexcept;

    /// Per-state native-shape error counter. Incremented whenever a
    /// `TrustedLazy` first-touch read encounters a malformed dictionary
    /// node, an account leaf that doesn't decode as `EvmAccountData`,
    /// or any `vm::VmError` / `vm::VmVirtError` / `std::exception`
    /// thrown by the dictionary access path. Compute phase fail-closed
    /// gates pair this with `code_integrity_error_count()` so first-
    /// touch shape corruption is mapped to `sk_bad_state` instead of
    /// degenerating into "account does not exist" / "storage = 0"
    /// reads.
    uint64_t state_shape_error_count() const noexcept;

    /// Test-only resets for the per-state counters above. Production
    /// code MUST NOT call these — the counters are monotone for the
    /// lifetime of the state and the snapshot/check pattern in the
    /// compute phase would race against any concurrent reset.
    void reset_code_integrity_error_count_for_test() noexcept;
    void reset_state_shape_error_count_for_test() noexcept;

    // ----- Free helpers (used outside CellEvmState) -----

  private:
    /// Read the storage dict root cell for an account. Returns null if account
    /// has no storage. On any malformed-shape exception caught by the no-MPT
    /// `TrustedLazy` first-touch helper, increments the per-state shape
    /// error counter and returns a null ref so the caller treats the slot as
    /// missing — compute-phase fail-closed gates then translate the counter
    /// delta into `sk_bad_state` and roll back any speculative state
    /// changes.
    td::Ref<vm::Cell> get_storage_root(const evmc::address& address) const;

    /// Write or clear the storage dict root for an account.
    void set_storage_root(const evmc::address& address, td::Ref<vm::Cell> root);

    /// Look up the inner EvmAccountData cell for an address from the account
    /// dictionary. Returns false if the account is missing or if the dict
    /// value has the wrong shape. Used by lazy `read_code`. On any
    /// malformed-shape failure path the helper records a per-state native-
    /// shape error so consensus fail-closed checks observe the corruption.
    bool lookup_account_data_cell(const evmc::address& address,
                                  td::Ref<vm::Cell>& out) const;

    /// Record a per-state code-integrity error. `noexcept` because every
    /// fault site (including the `noexcept` silkworm State overrides) needs
    /// to bump the counter without surfacing exceptions.
    void record_code_integrity_error() const noexcept;

    /// Record a per-state native-state-shape error. Accepts a static
    /// string identifying the call site (used for diagnostic logs). The
    /// pointer is borrowed; the helper does not retain it.
    void record_state_shape_error(const char* where) const noexcept;

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

    /// Audit Q1 (tos16 P0 follow-up): most recent strict-mode
    /// `load_from_cell` failure reason. Populated by the strict-walk
    /// lambda just before it returns `false` (e.g. on
    /// `decode_and_verify_code_root` mismatch); cleared on every fresh
    /// entry into `load_from_cell`. Read by callers via
    /// `last_strict_load_failure_reason()` so a hydration / repair /
    /// resync driver can surface a structured error instead of dying on
    /// a bare boolean.
    ///
    /// `mutable` because `load_from_cell` itself mutates the field even
    /// on the success path (it always resets to empty at entry).
    std::string last_strict_load_failure_reason_;

    CellEvmStateDeltaStats delta_stats_;

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

    /// P0-A / P0-B owner: counts every code-integrity fault observed by
    /// this CellEvmState instance (lazy-decode mismatch, cache-hit
    /// poisoning, strict-load mismatch, write-side mismatch). `mutable`
    /// because the `noexcept` silkworm State overrides — `read_code`
    /// in particular — are logically `const` from the caller's view but
    /// must record the fault before returning the empty `ByteView`.
    mutable std::atomic<uint64_t> code_integrity_error_count_{0};

    /// P1-C owner: counts every TrustedLazy first-touch shape failure
    /// observed by this CellEvmState instance (malformed dict leaves,
    /// VmError / VmVirtError / std::exception caught at the dictionary
    /// access boundary). Same `mutable` rationale as the code-integrity
    /// counter.
    mutable std::atomic<uint64_t> state_shape_error_count_{0};
};

}  // namespace evm_workchain
