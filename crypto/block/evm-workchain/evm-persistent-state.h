/*
    EVM Workchain — persistent state adapter (RocksDB-backed).

    Implements silkworm::State using a dedicated RocksDB instance at
    {db_root}/evm-state.  Accounts, storage slots, code, receipts, and
    block metadata survive process restarts.

    Key schema:
      "A" + address(20)                        → RLP-encoded Account
      "S" + address(20) + incarnation(8) + key(32)  → bytes32 value
      "C" + code_hash(32)                      → bytecode
      "R" + tx_hash(32)                        → serialised StoredReceipt
      "M" + meta_key                           → metadata values

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <memory>
#include <string>

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

  private:
    explicit PersistentEvmState(std::unique_ptr<td::RocksDb> db);

    std::unique_ptr<td::RocksDb> db_;
    mutable silkworm::Bytes code_read_buf_;  // reusable buffer for read_code
};

}  // namespace evm_workchain
