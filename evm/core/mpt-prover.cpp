/*
    EVM Workchain — Ethereum Merkle Patricia Trie prover implementation.
    Source: TOS-specific.
*/
#include "evm/core/mpt-prover.h"

#include <algorithm>
#include <cstring>
#include <memory>

#include <ethash/keccak.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/rlp/decode.hpp>
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

// ---------------------------------------------------------------------------
// MPT proof verification (the inverse of generate_mpt_proof)
// ---------------------------------------------------------------------------
//
// Walks the proof list in lockstep with the keccak(target_key) nibble path,
// re-checking the structural invariants required by Yellow Paper Appendix D:
//   1. keccak256(proof[0]) == expected_root
//   2. each child reference (32-byte hash form) matches the next proof node
//   3. the encountered node-types follow a legal sequence
//   4. the path consumed equals a prefix of target_nibbles (existence) or
//      diverges (non-existence) without proof being short of evidence
//
// Returns kValidExistence if a leaf with key == target_key is reached; in
// that case `out_value` holds the leaf's RLP-encoded value. Otherwise it
// returns kValidNonExistence (the absence is structurally proven) or one
// of the kInvalid* codes if any check fails.
//
// Used by self-tests to confirm our prover output cryptographically — never
// on a hot path.

namespace {

// Decode an RLP list header at the start of `view` and return a span over
// its payload (the elements). Returns false if not a list.
bool peek_list_payload(ByteView view, ByteView& payload_out) {
    ByteView cursor = view;
    auto h = silkworm::rlp::decode_header(cursor);
    if (!h || !h->list) return false;
    if (h->payload_length > cursor.size()) return false;
    payload_out = ByteView{cursor.data(), h->payload_length};
    return true;
}

// Iterate elements within a list payload, returning the next element's
// raw bytes (header + payload). Advances `view` past the element. Used
// to walk through the 17 entries of a branch node or 2 entries of a
// leaf/extension.
bool next_element(ByteView& view, ByteView& elem_out) {
    if (view.empty()) return false;
    ByteView saved = view;
    auto h = silkworm::rlp::decode_header(view);
    if (!h) return false;
    if (h->payload_length > view.size()) return false;
    size_t header_len = saved.size() - view.size();
    elem_out = ByteView{saved.data(), header_len + h->payload_length};
    view.remove_prefix(h->payload_length);
    return true;
}

// Decode an RLP-encoded byte string into its raw payload bytes.
// Returns false if the element is a list.
bool decode_string_payload(ByteView elem, ByteView& payload_out) {
    ByteView cursor = elem;
    auto h = silkworm::rlp::decode_header(cursor);
    if (!h || h->list) return false;
    if (h->payload_length > cursor.size()) return false;
    payload_out = ByteView{cursor.data(), h->payload_length};
    return true;
}

// Resolve a child reference (one element of a branch/extension node).
// If it's an RLP-encoded 32-byte string, look up the next proof node by hash.
// If it's an inline RLP list (< 32 bytes), use the embedded RLP directly.
// If it's an empty string (0x80), there's no child — return false.
//
// On success, sets `next_node_rlp` to the next node's full RLP (header + body).
bool resolve_child(
    ByteView ref_elem,
    const std::vector<Bytes>& proof,
    size_t next_proof_idx,
    Bytes& next_node_rlp) {
    // Try: empty string (0x80) → no child
    if (ref_elem.size() == 1 && ref_elem[0] == 0x80) {
        return false;
    }
    // Try: a single-byte ref (which would just be a payload byte < 0x80)
    // — that can't happen in MPT since child refs are always either an
    // empty string, a 32-byte hash string, or an embedded list.
    ByteView cursor = ref_elem;
    auto h = silkworm::rlp::decode_header(cursor);
    if (!h) return false;
    // After decode_header, `cursor` points just past the header.

    if (!h->list) {
        // String form: should be an empty string (handled above) or 32-byte hash.
        ByteView payload{cursor.data(), h->payload_length};
        if (payload.empty()) return false;  // empty string == no child
        if (payload.size() != 32) return false;  // not a hash → invalid
        if (next_proof_idx >= proof.size()) return false;
        // Hash must match the next proof node.
        const auto& next = proof[next_proof_idx];
        auto k = ethash::keccak256(next.data(), next.size());
        for (int i = 0; i < 32; ++i) {
            if (k.bytes[i] != payload[i]) return false;
        }
        next_node_rlp.assign(next.begin(), next.end());
        return true;
    } else {
        // Inline node: ref_elem itself is the next node's RLP (already a list).
        next_node_rlp.assign(ref_elem.begin(), ref_elem.end());
        return true;
    }
}

// Decode an HP-encoded path back into nibbles + leaf flag.
// Returns false on malformed input.
bool decode_hex_prefix(ByteView hp, Bytes& nibbles_out, bool& is_leaf_out) {
    if (hp.empty()) return false;
    uint8_t flag = hp[0];
    is_leaf_out = (flag & 0x20) != 0;
    bool odd = (flag & 0x10) != 0;
    nibbles_out.clear();
    if (odd) {
        nibbles_out.push_back(static_cast<uint8_t>(flag & 0x0F));
        for (size_t i = 1; i < hp.size(); ++i) {
            nibbles_out.push_back(static_cast<uint8_t>(hp[i] >> 4));
            nibbles_out.push_back(static_cast<uint8_t>(hp[i] & 0x0F));
        }
    } else {
        // Even: low nibble of flag must be 0 (padding)
        if ((flag & 0x0F) != 0) return false;
        for (size_t i = 1; i < hp.size(); ++i) {
            nibbles_out.push_back(static_cast<uint8_t>(hp[i] >> 4));
            nibbles_out.push_back(static_cast<uint8_t>(hp[i] & 0x0F));
        }
    }
    return true;
}

}  // anonymous namespace

MptProofResult verify_mpt_proof(
    const std::vector<Bytes>& proof,
    const evmc::bytes32& expected_root,
    const Bytes& target_key,
    Bytes& out_value) {
    out_value.clear();
    if (proof.empty()) {
        return MptProofResult::kInvalidStructure;
    }

    // Special case: a single-node proof of `0x80` (empty trie sentinel).
    // Valid if expected_root == kEmptyRoot, and only as a non-existence proof.
    if (proof.size() == 1 && proof[0].size() == 1 && proof[0][0] == 0x80) {
        if (expected_root == silkworm::kEmptyRoot) {
            return MptProofResult::kValidNonExistence;
        }
        return MptProofResult::kInvalidRoot;
    }

    // 1) keccak(proof[0]) == expected_root
    {
        auto h = ethash::keccak256(proof[0].data(), proof[0].size());
        for (int i = 0; i < 32; ++i) {
            if (h.bytes[i] != expected_root.bytes[i]) {
                return MptProofResult::kInvalidRoot;
            }
        }
    }

    // 2) Walk along target_nibbles, checking each node and its link to the next.
    Bytes target_nibbles = silkworm::trie::unpack_nibbles(ByteView{target_key});
    size_t depth = 0;
    Bytes current_rlp = proof[0];
    size_t next_idx = 1;

    while (true) {
        ByteView payload;
        if (!peek_list_payload(ByteView{current_rlp}, payload)) {
            return MptProofResult::kInvalidStructure;
        }
        // Count elements
        std::vector<ByteView> elems;
        ByteView scan = payload;
        while (!scan.empty()) {
            ByteView e;
            if (!next_element(scan, e)) {
                return MptProofResult::kInvalidStructure;
            }
            elems.push_back(e);
        }

        if (elems.size() == 17) {
            // Branch node
            if (depth > target_nibbles.size()) {
                return MptProofResult::kInvalidStructure;
            }
            if (depth == target_nibbles.size()) {
                // Target lands at the branch value slot (17th).
                ByteView vpl;
                if (!decode_string_payload(elems[16], vpl)) {
                    return MptProofResult::kInvalidStructure;
                }
                if (vpl.empty()) {
                    return MptProofResult::kValidNonExistence;
                }
                out_value.assign(vpl.begin(), vpl.end());
                return MptProofResult::kValidExistence;
            }
            uint8_t nibble = target_nibbles[depth];
            ByteView ref = elems[nibble];
            // Empty slot (0x80) → divergence; valid non-existence proof.
            if (ref.size() == 1 && ref[0] == 0x80) {
                return MptProofResult::kValidNonExistence;
            }
            Bytes next_rlp;
            if (!resolve_child(ref, proof, next_idx, next_rlp)) {
                return MptProofResult::kInvalidLink;
            }
            // If we consumed a full proof entry (hash-style ref), advance the
            // proof cursor; embedded refs don't bump it.
            ByteView ref_cursor = ref;
            auto h2 = silkworm::rlp::decode_header(ref_cursor);
            if (h2 && !h2->list && h2->payload_length == 32) {
                ++next_idx;
            }
            current_rlp = std::move(next_rlp);
            depth += 1;
            continue;
        }

        if (elems.size() == 2) {
            // Leaf or extension. Decode the path.
            ByteView hp_payload;
            if (!decode_string_payload(elems[0], hp_payload)) {
                return MptProofResult::kInvalidStructure;
            }
            Bytes path_nibbles;
            bool is_leaf;
            if (!decode_hex_prefix(hp_payload, path_nibbles, is_leaf)) {
                return MptProofResult::kInvalidStructure;
            }
            // Check the path matches the next chunk of target_nibbles.
            const size_t plen = path_nibbles.size();
            const size_t avail = target_nibbles.size() - depth;
            const size_t cmp_len = std::min(plen, avail);
            bool matches = true;
            for (size_t i = 0; i < cmp_len; ++i) {
                if (path_nibbles[i] != target_nibbles[depth + i]) {
                    matches = false;
                    break;
                }
            }

            if (is_leaf) {
                // Leaf: full path must match remaining target nibbles for existence.
                if (matches && plen == avail) {
                    ByteView vpl;
                    if (!decode_string_payload(elems[1], vpl)) {
                        return MptProofResult::kInvalidStructure;
                    }
                    out_value.assign(vpl.begin(), vpl.end());
                    return MptProofResult::kValidExistence;
                }
                // Leaf encodes a different key — non-existence proof.
                return MptProofResult::kValidNonExistence;
            }

            // Extension: if path doesn't fully match, divergence proves absence.
            if (!matches || plen > avail) {
                return MptProofResult::kValidNonExistence;
            }
            // Match: descend into the child (elems[1] is the child ref).
            Bytes next_rlp;
            if (!resolve_child(elems[1], proof, next_idx, next_rlp)) {
                return MptProofResult::kInvalidLink;
            }
            ByteView ext_cursor = elems[1];
            auto h2 = silkworm::rlp::decode_header(ext_cursor);
            if (h2 && !h2->list && h2->payload_length == 32) {
                ++next_idx;
            }
            current_rlp = std::move(next_rlp);
            depth += plen;
            continue;
        }

        return MptProofResult::kInvalidStructure;
    }
}

}  // namespace evm_workchain
