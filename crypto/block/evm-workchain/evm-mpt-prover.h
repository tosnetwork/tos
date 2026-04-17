/*
    EVM Workchain — Ethereum Merkle Patricia Trie inclusion-proof generator.

    Builds a canonical Ethereum MPT from a sorted (key → value) map and walks
    it to produce a list of RLP-encoded nodes from root to the target leaf.

    The output format matches what eth_getProof returns and what every
    Ethereum light client / cross-chain bridge / zkEVM circuit expects.

    Note: silkworm's HashBuilder uses Erigon-optimized intermediate node
    format that cannot directly emit standard MPT proof RLP. This is a
    from-scratch implementation of the Yellow Paper Appendix D.

    Source: TOS-specific (no silkworm reference exists for proof generation).
*/
#pragma once

#include <map>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace evm_workchain {

/// Generate an Ethereum MPT inclusion proof for `target_key`.
///
/// @param sorted_kv  Sorted map of (32-byte key) → (RLP-encoded value).
///                   Keys are typically keccak256(address) for the state trie
///                   or keccak256(slot) for a storage trie.
/// @param target_key The 32-byte key to prove. May or may not exist in the
///                   trie — if absent, the result is an "exclusion proof"
///                   (path to where the key would be).
/// @return  List of RLP-encoded nodes from root to target leaf. The first
///          element is the root node; its keccak256 hash equals the trie
///          root hash. Each subsequent element's keccak256 (or embedded RLP
///          if < 32 bytes) appears as a reference in the previous node.
///          Empty list if `sorted_kv` is empty (proof for the empty trie).
std::vector<silkworm::Bytes> generate_mpt_proof(
    const std::map<silkworm::Bytes, silkworm::Bytes>& sorted_kv,
    const silkworm::Bytes& target_key);

/// Compute the trie root hash without producing a proof. Useful for
/// verification: trie_root(kv) must equal the keccak256 of the first node
/// returned by generate_mpt_proof(kv, any_key_in_kv).
evmc::bytes32 mpt_root(const std::map<silkworm::Bytes, silkworm::Bytes>& sorted_kv);

}  // namespace evm_workchain
