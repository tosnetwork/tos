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
#include "vm/cells.h"
#include "vm/dict.h"

#include <cstddef>
#include <map>
#include <unordered_map>
#include <mutex>

namespace evm_workchain {

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
    evmc::bytes32 ethereum_storage_root_hash(const evmc::address& address) const;
    std::vector<silkworm::Bytes> ethereum_account_proof(const evmc::address& address) const;
    std::vector<silkworm::Bytes> ethereum_storage_proof(const evmc::address& address,
                                                        const evmc::bytes32& slot) const;
    bool trie_witness_ready() const noexcept { return trie_witness_ready_; }
    bool rebuild_trie_witness() noexcept;

    /// Serialize/load the persistent Ethereum MPT witness. Null witness means
    /// the empty state trie.
    td::Ref<vm::Cell> serialize_trie_witness_to_cell() const;
    bool load_trie_witness_from_cell(td::Ref<vm::Cell> root);

    /// Serialize the entire account dictionary into a single cell (suitable
    /// for storing in a ShardAccounts cell or a BoC).
    /// Returns a null cell if the dictionary is empty.
    td::Ref<vm::Cell> serialize_to_cell() const;

    /// Replace the current account dictionary with one decoded from the given cell.
    /// Pass a null cell to start from empty.
    bool load_from_cell(td::Ref<vm::Cell> root, bool rebuild_trie_witness = true);

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

    mutable vm::Dictionary account_dict_;  // 256-bit keys → EvmAccountData cells

    // Code storage: code_hash → bytes (silkworm content-addressed)
    mutable std::unordered_map<evmc::bytes32, silkworm::Bytes> code_;

    // Block cache for BLOCKHASH opcode (silkworm requires it)
    std::unordered_map<silkworm::BlockNum, evmc::bytes32> canonical_;

    // Read-code returns ByteView; needs persistent buffer (per-thread)
    static thread_local silkworm::Bytes tl_code_buf_;

    MptTrie account_trie_;
    std::map<evmc::address, MptTrie> storage_tries_;
    bool trie_witness_ready_{true};

    CellEvmStateDeltaStats delta_stats_;
};

}  // namespace evm_workchain
