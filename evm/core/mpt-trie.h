/*
    EVM Workchain — persistent Ethereum Merkle Patricia Trie witness.

    This is the execution-side trie/witness store used by CellEvmState.  It
    keeps canonical Ethereum MPT node RLP alongside a compact cell-native node
    shape, so stateRoot and eth_getProof can be served from persisted witness
    nodes instead of rebuilding the trie from all accounts/storage slots.

    Source: TOS-specific adapter, following the Erigon/Silkworm execution
    model of flat state plus persisted trie witness/intermediate nodes.
*/
#pragma once

#include <memory>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "vm/cells.h"

namespace evm_workchain {

class MptTrie {
  public:
    struct Node;

    MptTrie() = default;

    bool empty() const noexcept { return !root_; }
    void clear() noexcept;

    /// Insert or replace a 32-byte hashed key with its already RLP-encoded
    /// Ethereum trie value.
    bool upsert_hashed(const silkworm::ByteView& hashed_key,
                       const silkworm::ByteView& rlp_value);

    /// Remove a 32-byte hashed key. Missing keys are a no-op.
    bool erase_hashed(const silkworm::ByteView& hashed_key);

    /// Ethereum MPT root hash. Empty trie returns keccak256(RLP("")).
    evmc::bytes32 root_hash() const;

    /// Standard Ethereum proof nodes, root to terminal/exclusion node.
    std::vector<silkworm::Bytes> proof(const silkworm::ByteView& hashed_key) const;

    /// Persist/load the witness root node. Null cell means empty trie.
    td::Ref<vm::Cell> serialize_to_cell() const;
    bool load_from_cell(td::Ref<vm::Cell> root);

  private:
    std::shared_ptr<Node> root_;
};

/// RLP-encode an Ethereum storage trie value. Zero values are expected to be
/// omitted by callers and are encoded here only for defensive completeness.
silkworm::Bytes encode_mpt_storage_value(const evmc::bytes32& value);

/// Hash helpers used by CellEvmState and tests.
evmc::bytes32 keccak_evm_address(const evmc::address& address);
evmc::bytes32 keccak_bytes32_value(const evmc::bytes32& value);

}  // namespace evm_workchain
