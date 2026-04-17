/*
    EVM Workchain — Ethereum Merkle Patricia Trie prover implementation.
    Source: TOS-specific.
*/
#include "evm-mpt-prover.h"

#include <algorithm>
#include <cstring>
#include <memory>

#include <ethash/keccak.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace evm_workchain {

using silkworm::Bytes;
using silkworm::ByteView;

// ---------------------------------------------------------------------------
// Hex-prefix encoding (Yellow Paper Appendix C)
// ---------------------------------------------------------------------------
//
// HP encodes a nibble path with a leading "type" nibble:
//   bit 5 = leaf flag (1=leaf, 0=extension)
//   bit 4 = odd-length flag (1=odd nibble count, 0=even)
//   first 4 bits = if odd, the first nibble of the path; else padding zeros

static Bytes hex_prefix_encode(ByteView nibbles, bool is_leaf) {
    const bool odd = (nibbles.size() % 2) != 0;
    const uint8_t flag = static_cast<uint8_t>((is_leaf ? 0x20 : 0x00) | (odd ? 0x10 : 0x00));
    Bytes out;
    out.reserve(nibbles.size() / 2 + 1);
    if (odd) {
        out.push_back(static_cast<uint8_t>(flag | nibbles[0]));
        for (size_t i = 1; i + 1 < nibbles.size(); i += 2) {
            out.push_back(static_cast<uint8_t>((nibbles[i] << 4) | nibbles[i + 1]));
        }
    } else {
        out.push_back(flag);
        for (size_t i = 0; i + 1 < nibbles.size(); i += 2) {
            out.push_back(static_cast<uint8_t>((nibbles[i] << 4) | nibbles[i + 1]));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Trie node types (Yellow Paper Appendix D)
// ---------------------------------------------------------------------------

struct TrieNode {
    enum Kind { kLeaf, kExtension, kBranch };
    Kind kind;

    // For Leaf and Extension:
    Bytes path_nibbles;

    // For Leaf:
    Bytes value;

    // For Extension:
    std::shared_ptr<TrieNode> child;

    // For Branch:
    std::array<std::shared_ptr<TrieNode>, 16> children;
    Bytes branch_value;  // value at exact-match (rare; typically empty)
};

// ---------------------------------------------------------------------------
// Build trie bottom-up from sorted (nibbled-key → value) range
// ---------------------------------------------------------------------------

namespace {

struct KV {
    Bytes nibbles;
    Bytes value;
};

size_t common_prefix_len(ByteView a, ByteView b, size_t start) {
    size_t i = start;
    while (i < a.size() && i < b.size() && a[i] == b[i]) ++i;
    return i - start;
}

std::shared_ptr<TrieNode> build_subtree(
    const std::vector<KV*>& items,
    size_t depth) {
    // depth = number of nibbles already consumed by ancestors

    if (items.empty()) return nullptr;

    if (items.size() == 1) {
        auto node = std::make_shared<TrieNode>();
        node->kind = TrieNode::kLeaf;
        const auto& nibs = items[0]->nibbles;
        node->path_nibbles.assign(nibs.begin() + depth, nibs.end());
        node->value = items[0]->value;
        return node;
    }

    // Find longest common prefix beyond `depth` shared by ALL items
    size_t min_remain = items[0]->nibbles.size() - depth;
    for (auto* it : items) {
        min_remain = std::min(min_remain, it->nibbles.size() - depth);
    }
    size_t common = 0;
    while (common < min_remain) {
        uint8_t n = items[0]->nibbles[depth + common];
        bool all_match = true;
        for (auto* it : items) {
            if (it->nibbles[depth + common] != n) { all_match = false; break; }
        }
        if (!all_match) break;
        ++common;
    }

    if (common > 0) {
        // Extension node + recursive child
        auto node = std::make_shared<TrieNode>();
        node->kind = TrieNode::kExtension;
        node->path_nibbles.assign(
            items[0]->nibbles.begin() + depth,
            items[0]->nibbles.begin() + depth + common);
        node->child = build_subtree(items, depth + common);
        return node;
    }

    // Branch node: split by next nibble
    auto node = std::make_shared<TrieNode>();
    node->kind = TrieNode::kBranch;
    std::array<std::vector<KV*>, 16> buckets;
    for (auto* it : items) {
        if (it->nibbles.size() == depth) {
            // Exact-match: value lives at the branch slot
            node->branch_value = it->value;
        } else {
            buckets[it->nibbles[depth]].push_back(it);
        }
    }
    for (int i = 0; i < 16; ++i) {
        if (!buckets[i].empty()) {
            node->children[i] = build_subtree(buckets[i], depth + 1);
        }
    }
    return node;
}

std::shared_ptr<TrieNode> build_trie(
    const std::map<Bytes, Bytes>& sorted_kv) {
    std::vector<KV> storage;
    storage.reserve(sorted_kv.size());
    for (const auto& [k, v] : sorted_kv) {
        KV kv;
        kv.nibbles = silkworm::trie::unpack_nibbles(k);
        kv.value = v;
        storage.push_back(std::move(kv));
    }
    std::vector<KV*> ptrs;
    ptrs.reserve(storage.size());
    for (auto& kv : storage) ptrs.push_back(&kv);
    if (ptrs.empty()) return nullptr;
    return build_subtree(ptrs, 0);
}

// ---------------------------------------------------------------------------
// RLP encoding for trie nodes
// ---------------------------------------------------------------------------

Bytes encode_node(const TrieNode& node);

// Reference to a child: either embedded RLP (< 32 bytes) or
// RLP-encoded keccak hash (always 33 bytes: 0xa0 + 32 bytes).
Bytes encode_child_ref(const std::shared_ptr<TrieNode>& child) {
    if (!child) {
        // Empty: RLP empty string = 0x80
        return Bytes{0x80};
    }
    Bytes child_rlp = encode_node(*child);
    if (child_rlp.size() < 32) {
        // Embedded inline (the RLP itself, not wrapped)
        return child_rlp;
    }
    auto h = ethash::keccak256(child_rlp.data(), child_rlp.size());
    Bytes out;
    silkworm::rlp::encode(out, ByteView{h.bytes, 32});
    return out;
}

Bytes encode_node(const TrieNode& node) {
    Bytes payload;

    switch (node.kind) {
        case TrieNode::kLeaf: {
            Bytes path = hex_prefix_encode(node.path_nibbles, /*is_leaf=*/true);
            silkworm::rlp::encode(payload, ByteView{path});
            silkworm::rlp::encode(payload, ByteView{node.value});
            break;
        }
        case TrieNode::kExtension: {
            Bytes path = hex_prefix_encode(node.path_nibbles, /*is_leaf=*/false);
            silkworm::rlp::encode(payload, ByteView{path});
            // Child reference: append raw (already RLP-encoded)
            payload.append(encode_child_ref(node.child));
            break;
        }
        case TrieNode::kBranch: {
            for (int i = 0; i < 16; ++i) {
                payload.append(encode_child_ref(node.children[i]));
            }
            // 17th element: optional value at exact branch (usually empty)
            silkworm::rlp::encode(payload, ByteView{node.branch_value});
            break;
        }
    }

    Bytes out;
    silkworm::rlp::encode_header(out, silkworm::rlp::Header{true, payload.size()});
    out.append(payload);
    return out;
}

// ---------------------------------------------------------------------------
// Walk to target key, collecting proof nodes
// ---------------------------------------------------------------------------

void walk_proof(
    const std::shared_ptr<TrieNode>& node,
    ByteView target_nibbles,
    size_t depth,
    std::vector<Bytes>& proof) {
    if (!node) return;
    proof.push_back(encode_node(*node));

    switch (node->kind) {
        case TrieNode::kLeaf:
            // Terminal — nothing to descend into.
            return;

        case TrieNode::kExtension: {
            // Verify path matches; if not, exclusion proof terminates here.
            const size_t plen = node->path_nibbles.size();
            if (depth + plen > target_nibbles.size()) return;
            for (size_t i = 0; i < plen; ++i) {
                if (target_nibbles[depth + i] != node->path_nibbles[i]) return;
            }
            walk_proof(node->child, target_nibbles, depth + plen, proof);
            return;
        }

        case TrieNode::kBranch: {
            if (depth >= target_nibbles.size()) {
                // Target ends exactly at this branch — value (if any) is here
                return;
            }
            uint8_t nibble = target_nibbles[depth];
            walk_proof(node->children[nibble], target_nibbles, depth + 1, proof);
            return;
        }
    }
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<Bytes> generate_mpt_proof(
    const std::map<Bytes, Bytes>& sorted_kv,
    const Bytes& target_key) {
    if (sorted_kv.empty()) return {};

    auto root = build_trie(sorted_kv);
    if (!root) return {};

    Bytes target_nibbles = silkworm::trie::unpack_nibbles(target_key);

    std::vector<Bytes> proof;
    walk_proof(root, target_nibbles, 0, proof);
    return proof;
}

evmc::bytes32 mpt_root(const std::map<Bytes, Bytes>& sorted_kv) {
    if (sorted_kv.empty()) return silkworm::kEmptyRoot;
    auto root = build_trie(sorted_kv);
    if (!root) return silkworm::kEmptyRoot;
    Bytes root_rlp = encode_node(*root);
    if (root_rlp.size() < 32) {
        // Tiny tree: the "root hash" is keccak of the tiny RLP anyway
        // (Ethereum stores the hash of the root node, not the embedded form)
    }
    auto h = ethash::keccak256(root_rlp.data(), root_rlp.size());
    evmc::bytes32 result{};
    std::memcpy(result.bytes, h.bytes, 32);
    return result;
}

}  // namespace evm_workchain
