/*
    EVM Workchain — persistent state adapter (RocksDB-backed).

    Implements silkworm::State using a dedicated RocksDB instance at
    {db_root}/evm-state.  Accounts, storage slots, code, receipts, and
    block metadata survive process restarts.

    Key schema (plain state):
      "A" + address(20)                        → encoded Account
      "S" + address(20) + incarnation(8) + key(32)  → bytes32 value
      "C" + code_hash(32)                      → bytecode
      "R" + tx_hash(32)                        → serialised StoredReceipt
      "M" + meta_key                           → metadata values

    Key schema (hashed state — for incremental state root):
      "H"  + keccak256(address)(32)                                     → encoded Account
      "HS" + keccak256(address)(32) + incarnation(8) + keccak256(slot)(32) → bytes32 value
      "TA" + nibbled_key                                                → encoded trie node
      "TS" + keccak256(address)(32) + incarnation(8) + nibbled_key      → encoded trie node

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>

#include "evm-state.h"

namespace td {
class RocksDb;
}

namespace evm_workchain {

class PersistentEvmState : public silkworm::State {
  public:
    /// Open (or create) the EVM state database at the given path.
    static std::unique_ptr<PersistentEvmState> open(const std::string& db_path);

    ~PersistentEvmState() override;

    // --- silkworm::State (reader) ---
    std::optional<silkworm::Account> read_account(const evmc::address& address) const noexcept override;
    silkworm::ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept override;
    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept override;
    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;
    evmc::bytes32 state_root_hash() const override;
    silkworm::BlockNum current_canonical_block() const override;
    std::optional<evmc::bytes32> canonical_hash(silkworm::BlockNum block_num) const override;

    // --- silkworm::State (writer) ---
    void insert_block(const silkworm::Block& block, const evmc::bytes32& hash) override;
    void canonize_block(silkworm::BlockNum block_num, const evmc::bytes32& block_hash) override;
    void decanonize_block(silkworm::BlockNum block_num) override;
    void insert_call_traces(silkworm::BlockNum block_num, const silkworm::CallTraces& traces) override;
    void begin_block(silkworm::BlockNum block_num, size_t updated_accounts_count) override;
    void update_account(const evmc::address& address, std::optional<silkworm::Account> initial, std::optional<silkworm::Account> current) override;
    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash, silkworm::ByteView code) override;
    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location, const evmc::bytes32& initial, const evmc::bytes32& current) override;
    void unwind_state_changes(silkworm::BlockNum block_num) override;

    // --- silkworm::BlockState (block reader) ---
    std::optional<silkworm::BlockHeader> read_header(silkworm::BlockNum, const evmc::bytes32&) const noexcept override { return std::nullopt; }
    bool read_body(silkworm::BlockNum, const evmc::bytes32&, silkworm::BlockBody&) const noexcept override { return false; }
    std::optional<intx::uint256> total_difficulty(silkworm::BlockNum, const evmc::bytes32&) const noexcept override { return std::nullopt; }

    // --- Receipt storage ---
    void store_receipt(const evmc::bytes32& tx_hash, const StoredReceipt& receipt);
    std::optional<StoredReceipt> get_receipt(const evmc::bytes32& tx_hash) const;

    // --- Block number ---
    uint64_t block_number() const;
    void set_block_number(uint64_t n);

    // --- Hashed state key builders ---
    static std::string hashed_account_key(const evmc::bytes32& hashed_addr);
    static std::string hashed_storage_key(const evmc::bytes32& hashed_addr,
                                           uint64_t incarnation,
                                           const evmc::bytes32& hashed_slot);
    static std::string trie_account_key(const silkworm::Bytes& nibbled_key);
    static std::string trie_storage_key(const evmc::bytes32& hashed_addr,
                                         uint64_t incarnation,
                                         const silkworm::Bytes& nibbled_key);

    // --- Hashed state encoding ---
    static std::string encode_hashed_account(const silkworm::Account& acct);
    static std::optional<silkworm::Account> decode_hashed_account(const std::string& data);

    // --- Hashed state iteration ---
    void for_each_hashed_account(
        std::function<void(const evmc::bytes32& hashed_addr,
                           const silkworm::Account& acct)> callback) const;

    void for_each_hashed_storage(
        const evmc::bytes32& hashed_addr, uint64_t incarnation,
        std::function<void(const evmc::bytes32& hashed_slot,
                           const evmc::bytes32& value)> callback) const;

    // --- Trie node cache ---
    void write_trie_account_node(const silkworm::Bytes& nibbled_key,
                                  const silkworm::Bytes& encoded_node);
    void delete_trie_account_node(const silkworm::Bytes& nibbled_key);
    std::optional<silkworm::Bytes> read_trie_account_node(
        const silkworm::Bytes& nibbled_key) const;

    void write_trie_storage_node(const evmc::bytes32& hashed_addr,
                                  uint64_t incarnation,
                                  const silkworm::Bytes& nibbled_key,
                                  const silkworm::Bytes& encoded_node);
    void delete_trie_storage_node(const evmc::bytes32& hashed_addr,
                                   uint64_t incarnation,
                                   const silkworm::Bytes& nibbled_key);
    std::optional<silkworm::Bytes> read_trie_storage_node(
        const evmc::bytes32& hashed_addr, uint64_t incarnation,
        const silkworm::Bytes& nibbled_key) const;

  private:
    explicit PersistentEvmState(std::unique_ptr<td::RocksDb> db);

    std::unique_ptr<td::RocksDb> db_;
};

}  // namespace evm_workchain
