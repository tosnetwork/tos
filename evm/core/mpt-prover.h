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

/// Result of verifying an MPT proof against an expected root.
enum class MptProofResult {
    kValidExistence,     // Proof terminates at a leaf whose key == target_key, with `out_value` populated.
    kValidNonExistence,  // Proof terminates at a node demonstrating the target_key is absent.
    kInvalidRoot,        // First node's keccak256 doesn't match expected_root.
    kInvalidLink,        // A child reference in some node didn't match the next node's hash/embedded RLP.
    kInvalidStructure,   // RLP structure malformed (wrong arity, bad HP path, etc.).
};

/// Verify an MPT proof against the expected root for `target_key`.
///
/// Walks the proof list node-by-node, checking:
///   1. keccak256(proof[0]) == expected_root
///   2. each non-terminal node's link to the next is consistent
///      (either a 32-byte keccak hash or an embedded RLP < 32 bytes)
///   3. the path of nibbles consumed matches keccak256(target_key)
///
/// On kValidExistence, `out_value` receives the leaf's RLP-encoded value.
/// On kValidNonExistence, `out_value` is left empty.
///
/// This is the verification half of generate_mpt_proof — used by self-tests
/// to confirm the prover's output is a real Yellow Paper Appendix D proof
/// (a fully-formed witness, not a stub byte sequence) without round-tripping
/// through an external verifier. The check is linear in proof length.
MptProofResult verify_mpt_proof(
    const std::vector<silkworm::Bytes>& proof,
    const evmc::bytes32& expected_root,
    const silkworm::Bytes& target_key,
    silkworm::Bytes& out_value);

}  // namespace evm_workchain
