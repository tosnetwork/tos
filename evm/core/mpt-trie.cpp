/*
    EVM Workchain — persistent Ethereum MPT witness implementation.
*/
#include "evm/core/mpt-trie.h"

#include "evm/core/cell-codec.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>

#include <ethash/keccak.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace evm_workchain {

using silkworm::Bytes;
using silkworm::ByteView;

namespace {

constexpr uint8_t kNodeLeaf = 0;
constexpr uint8_t kNodeExtension = 1;
constexpr uint8_t kNodeBranch = 2;
constexpr size_t kHashLength = 32;
constexpr size_t kKeyNibbles = 64;
constexpr size_t kMaxSerializedNodesPerTrie = 8'000'000;

Bytes hex_prefix_encode(ByteView nibbles, bool is_leaf) {
    const bool odd = (nibbles.size() % 2) != 0;
    const uint8_t flag = static_cast<uint8_t>((is_leaf ? 0x20 : 0x00) |
                                              (odd ? 0x10 : 0x00));
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

size_t common_prefix_len(ByteView a, ByteView b) {
    const size_t n = std::min(a.size(), b.size());
    size_t i = 0;
    while (i < n && a[i] == b[i]) {
        ++i;
    }
    return i;
}

Bytes concat_path(ByteView a, ByteView b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

Bytes one_plus_path(uint8_t nibble, ByteView suffix) {
    Bytes out;
    out.reserve(1 + suffix.size());
    out.push_back(nibble);
    out.insert(out.end(), suffix.begin(), suffix.end());
    return out;
}

td::Ref<vm::Cell> encode_bytes_cell(const Bytes& bytes) {
    if (bytes.empty()) {
        vm::CellBuilder cb;
        cb.store_long(0, 1);
        return cb.finalize();
    }
    return encode_evm_bytecode(td::Slice{
        reinterpret_cast<const char*>(bytes.data()), bytes.size()});
}

Bytes decode_bytes_cell(td::Ref<vm::Cell> cell) {
    auto decoded = decode_evm_bytecode(std::move(cell));
    return Bytes{decoded.begin(), decoded.end()};
}

}  // namespace

struct MptTrie::Node {
    uint8_t kind{kNodeLeaf};
    Bytes path;
    Bytes value;
    std::shared_ptr<Node> child;
    std::array<std::shared_ptr<Node>, 16> children{};

    mutable bool decoded{true};
    mutable bool dirty{true};
    mutable td::Ref<vm::Cell> cell_cache;
    mutable Bytes rlp_cache;
    mutable std::optional<evmc::bytes32> hash_cache;

    static std::shared_ptr<Node> lazy(td::Ref<vm::Cell> cell) {
        auto node = std::make_shared<Node>();
        node->decoded = false;
        node->dirty = false;
        node->cell_cache = std::move(cell);
        node->rlp_cache.clear();
        node->hash_cache.reset();
        return node;
    }

    static std::shared_ptr<Node> leaf(Bytes leaf_path, Bytes leaf_value) {
        auto node = std::make_shared<Node>();
        node->kind = kNodeLeaf;
        node->path = std::move(leaf_path);
        node->value = std::move(leaf_value);
        return node;
    }

    static std::shared_ptr<Node> extension(Bytes extension_path,
                                           std::shared_ptr<Node> extension_child) {
        auto node = std::make_shared<Node>();
        node->kind = kNodeExtension;
        node->path = std::move(extension_path);
        node->child = std::move(extension_child);
        return node;
    }

    static std::shared_ptr<Node> branch() {
        auto node = std::make_shared<Node>();
        node->kind = kNodeBranch;
        return node;
    }

    bool ensure_decoded() const {
        if (decoded) {
            return true;
        }
        if (cell_cache.is_null()) {
            return false;
        }
        try {
            bool special = false;
            auto cs = vm::load_cell_slice_special(cell_cache, special);
            if (special || cs.size() < 2 || cs.size_refs() < 1) {
                return false;
            }

            auto* self = const_cast<Node*>(this);
            self->kind = static_cast<uint8_t>(cs.fetch_ulong(2));
            if (self->kind > kNodeBranch) {
                return false;
            }

            if (self->kind == kNodeLeaf || self->kind == kNodeExtension) {
                if (cs.size() < 7) {
                    return false;
                }
                const auto path_len = cs.fetch_ulong(7);
                if (path_len > kKeyNibbles || cs.size() < path_len * 4) {
                    return false;
                }
                self->path.clear();
                self->path.reserve(path_len);
                for (size_t i = 0; i < path_len; ++i) {
                    auto nibble = cs.fetch_ulong(4);
                    if (nibble > 0x0f) {
                        return false;
                    }
                    self->path.push_back(static_cast<uint8_t>(nibble));
                }
            }

            if (cs.size_refs() < 1) {
                return false;
            }
            auto rlp_cell = cs.fetch_ref();
            self->rlp_cache = decode_bytes_cell(rlp_cell);
            if (self->rlp_cache.empty()) {
                return false;
            }

            if (self->kind == kNodeLeaf) {
                if (cs.size() != 0 || cs.size_refs() != 1) {
                    return false;
                }
                self->value = decode_bytes_cell(cs.fetch_ref());
                if (self->value.empty()) {
                    return false;
                }
            } else if (self->kind == kNodeExtension) {
                if (self->path.empty() || cs.size() != 0 || cs.size_refs() != 1) {
                    return false;
                }
                self->child = lazy(cs.fetch_ref());
            } else {
                if (cs.size() != 0 || cs.size_refs() != 1) {
                    return false;
                }
                vm::Dictionary dict(cs.fetch_ref(), 4);
                bool ok = true;
                bool walked = dict.check_for_each(
                    [self, &ok](td::Ref<vm::CellSlice> value,
                                td::ConstBitPtr key, int n) -> bool {
                    if (n != 4 || value.is_null() ||
                        value->size() != 0 || value->size_refs() != 1) {
                        ok = false;
                        return false;
                    }
                    td::BitArray<4> key_bits(key);
                    auto idx = key_bits.to_ulong();
                    if (idx >= 16 || self->children[idx]) {
                        ok = false;
                        return false;
                    }
                    self->children[idx] = lazy(value->prefetch_ref(0));
                    return true;
                });
                if (!walked || !ok) {
                    return false;
                }
            }

            self->decoded = true;
            self->dirty = false;
            self->hash_cache.reset();
            return true;
        } catch (vm::VmError&) {
            return false;
        } catch (vm::VmVirtError&) {
            return false;
        } catch (std::exception&) {
            return false;
        } catch (...) {
            return false;
        }
    }

    void mark_dirty() {
        dirty = true;
        cell_cache = {};
        rlp_cache.clear();
        hash_cache.reset();
    }

    Bytes child_ref(const std::shared_ptr<Node>& node) const {
        if (!node) {
            return Bytes{silkworm::rlp::kEmptyStringCode};
        }
        const Bytes& child_rlp = node->rlp();
        if (child_rlp.size() < kHashLength) {
            return child_rlp;
        }
        auto h = node->hash();
        Bytes out;
        silkworm::rlp::encode(out, ByteView{h.bytes, kHashLength});
        return out;
    }

    const Bytes& rlp() const {
        if (!dirty && !rlp_cache.empty()) {
            return rlp_cache;
        }
        // ensure_decoded() failure here means the witness cell is corrupt;
        // callers reach this through proof()/serialize_cell() etc., which is
        // why those entry points have shallow CHECK guards. The fail-closed
        // counterpart is `proof_safe()`, which calls `ensure_decoded()`
        // explicitly before invoking `rlp()`.
        CHECK(ensure_decoded());

        rlp_cache = compute_rlp_from_shape(/*trust_cache=*/true);
        hash_cache.reset();
        return rlp_cache;
    }

    /// Recompute this node's canonical RLP encoding from the decoded shape.
    /// When `trust_cache` is false, child RLP is recomputed recursively
    /// without consulting any per-node `rlp_cache`. This is the verification
    /// path for `MptWitnessValidationMode::StrictRecursive`.
    Bytes compute_rlp_from_shape(bool trust_cache) const {
        Bytes payload;
        switch (kind) {
            case kNodeLeaf: {
                Bytes encoded_path = hex_prefix_encode(path, true);
                silkworm::rlp::encode(payload, ByteView{encoded_path});
                silkworm::rlp::encode(payload, ByteView{value});
                break;
            }
            case kNodeExtension: {
                Bytes encoded_path = hex_prefix_encode(path, false);
                silkworm::rlp::encode(payload, ByteView{encoded_path});
                payload.append(child_ref_with_mode(child, trust_cache));
                break;
            }
            case kNodeBranch:
                for (const auto& branch_child : children) {
                    payload.append(child_ref_with_mode(branch_child, trust_cache));
                }
                silkworm::rlp::encode(payload, ByteView{});
                break;
            default:
                return {};
        }

        Bytes out;
        silkworm::rlp::encode_header(out, silkworm::rlp::Header{true, payload.size()});
        out.append(payload);
        return out;
    }

    Bytes child_ref_with_mode(const std::shared_ptr<Node>& node,
                               bool trust_cache) const {
        if (!node) {
            return Bytes{silkworm::rlp::kEmptyStringCode};
        }
        if (trust_cache) {
            return child_ref(node);
        }
        // Strict recompute: do not look at child->rlp_cache. Force
        // recomputation from the child's own decoded shape.
        if (!node->ensure_decoded()) {
            return Bytes{silkworm::rlp::kEmptyStringCode};
        }
        Bytes child_rlp = node->compute_rlp_from_shape(false);
        if (child_rlp.size() < kHashLength) {
            return child_rlp;
        }
        auto h = ethash::keccak256(child_rlp.data(), child_rlp.size());
        evmc::bytes32 hash{};
        std::memcpy(hash.bytes, h.bytes, kHashLength);
        Bytes out;
        silkworm::rlp::encode(out, ByteView{hash.bytes, kHashLength});
        return out;
    }

    evmc::bytes32 hash() const {
        if (hash_cache.has_value()) {
            return *hash_cache;
        }
        const auto& encoded = rlp();
        auto h = ethash::keccak256(encoded.data(), encoded.size());
        evmc::bytes32 out{};
        std::memcpy(out.bytes, h.bytes, kHashLength);
        hash_cache = out;
        return out;
    }

    td::Ref<vm::Cell> serialize_cell() const {
        if (!dirty && cell_cache.not_null()) {
            return cell_cache;
        }
        CHECK(ensure_decoded());
        (void)rlp();

        vm::CellBuilder cb;
        cb.store_long(kind, 2);
        if (kind == kNodeLeaf || kind == kNodeExtension) {
            CHECK(path.size() <= kKeyNibbles);
            cb.store_long(path.size(), 7);
            for (uint8_t nibble : path) {
                CHECK(nibble <= 0x0f);
                cb.store_long(nibble, 4);
            }
        }
        cb.store_ref(encode_bytes_cell(rlp_cache));

        if (kind == kNodeLeaf) {
            cb.store_ref(encode_bytes_cell(value));
        } else if (kind == kNodeExtension) {
            CHECK(child);
            cb.store_ref(child->serialize_cell());
        } else {
            vm::Dictionary dict(4);
            vm::CellBuilder value_cb;
            for (int i = 0; i < 16; ++i) {
                if (!children[i]) {
                    continue;
                }
                value_cb.store_ref(children[i]->serialize_cell());
                CHECK(dict.set_builder(td::BitArray<4>(i), value_cb));
                CHECK(value_cb.reset_bool());
            }
            auto dict_root = dict.get_root_cell();
            CHECK(dict_root.not_null());
            cb.store_ref(dict_root);
        }

        cell_cache = cb.finalize();
        dirty = false;
        return cell_cache;
    }

    size_t child_count() const {
        CHECK(ensure_decoded());
        size_t count = 0;
        for (const auto& branch_child : children) {
            if (branch_child) {
                ++count;
            }
        }
        return count;
    }
};

namespace {

struct UpdateResult {
    std::shared_ptr<MptTrie::Node> node;
    bool changed{false};
};

std::shared_ptr<MptTrie::Node> normalize_extension(
    Bytes path,
    std::shared_ptr<MptTrie::Node> child) {
    if (!child) {
        return nullptr;
    }
    if (path.empty()) {
        return child;
    }
    CHECK(child->ensure_decoded());
    if (child->kind == kNodeLeaf) {
        return MptTrie::Node::leaf(concat_path(path, child->path), child->value);
    }
    if (child->kind == kNodeExtension) {
        return MptTrie::Node::extension(concat_path(path, child->path), child->child);
    }
    return MptTrie::Node::extension(std::move(path), std::move(child));
}

std::shared_ptr<MptTrie::Node> collapse_branch(std::shared_ptr<MptTrie::Node> branch) {
    CHECK(branch && branch->ensure_decoded() && branch->kind == kNodeBranch);
    int only_child = -1;
    size_t count = 0;
    for (int i = 0; i < 16; ++i) {
        if (branch->children[i]) {
            only_child = i;
            ++count;
        }
    }
    if (count == 0) {
        return nullptr;
    }
    if (count > 1) {
        branch->mark_dirty();
        return branch;
    }

    auto child = branch->children[only_child];
    CHECK(child && child->ensure_decoded());
    if (child->kind == kNodeLeaf) {
        return MptTrie::Node::leaf(
            one_plus_path(static_cast<uint8_t>(only_child), child->path),
            child->value);
    }
    if (child->kind == kNodeExtension) {
        return MptTrie::Node::extension(
            one_plus_path(static_cast<uint8_t>(only_child), child->path),
            child->child);
    }
    return MptTrie::Node::extension(
        Bytes{static_cast<uint8_t>(only_child)},
        std::move(child));
}

UpdateResult insert_rec(std::shared_ptr<MptTrie::Node> node,
                        ByteView key,
                        ByteView value) {
    if (!node) {
        return {MptTrie::Node::leaf(Bytes{key.begin(), key.end()},
                                    Bytes{value.begin(), value.end()}), true};
    }
    CHECK(node->ensure_decoded());

    if (node->kind == kNodeLeaf) {
        const size_t common = common_prefix_len(node->path, key);
        if (common == node->path.size() && common == key.size()) {
            if (ByteView{node->value.data(), node->value.size()} == value) {
                return {node, false};
            }
            node->value = Bytes{value.begin(), value.end()};
            node->mark_dirty();
            return {node, true};
        }

        auto branch = MptTrie::Node::branch();
        if (common < node->path.size()) {
            uint8_t idx = node->path[common];
            branch->children[idx] = MptTrie::Node::leaf(
                Bytes{node->path.begin() + static_cast<std::ptrdiff_t>(common + 1),
                      node->path.end()},
                node->value);
        }
        if (common < key.size()) {
            uint8_t idx = key[common];
            branch->children[idx] = MptTrie::Node::leaf(
                Bytes{key.begin() + static_cast<std::ptrdiff_t>(common + 1), key.end()},
                Bytes{value.begin(), value.end()});
        }
        Bytes prefix{key.begin(), key.begin() + static_cast<std::ptrdiff_t>(common)};
        return {normalize_extension(std::move(prefix), std::move(branch)), true};
    }

    if (node->kind == kNodeExtension) {
        const size_t common = common_prefix_len(node->path, key);
        if (common == node->path.size()) {
            auto updated = insert_rec(node->child, key.substr(common), value);
            if (!updated.changed) {
                return {node, false};
            }
            node->child = std::move(updated.node);
            node->mark_dirty();
            return {normalize_extension(node->path, node->child), true};
        }

        auto branch = MptTrie::Node::branch();
        uint8_t old_idx = node->path[common];
        Bytes old_suffix{node->path.begin() + static_cast<std::ptrdiff_t>(common + 1),
                         node->path.end()};
        branch->children[old_idx] =
            old_suffix.empty()
                ? node->child
                : MptTrie::Node::extension(std::move(old_suffix), node->child);

        if (common < key.size()) {
            uint8_t new_idx = key[common];
            branch->children[new_idx] = MptTrie::Node::leaf(
                Bytes{key.begin() + static_cast<std::ptrdiff_t>(common + 1), key.end()},
                Bytes{value.begin(), value.end()});
        }
        Bytes prefix{key.begin(), key.begin() + static_cast<std::ptrdiff_t>(common)};
        return {normalize_extension(std::move(prefix), std::move(branch)), true};
    }

    CHECK(node->kind == kNodeBranch);
    if (key.empty()) {
        return {node, false};
    }
    uint8_t idx = key[0];
    auto updated = insert_rec(node->children[idx], key.substr(1), value);
    if (!updated.changed) {
        return {node, false};
    }
    node->children[idx] = std::move(updated.node);
    node->mark_dirty();
    return {node, true};
}

UpdateResult erase_rec(std::shared_ptr<MptTrie::Node> node, ByteView key) {
    if (!node) {
        return {nullptr, false};
    }
    if (!node->ensure_decoded()) {
        // Fail closed: surface a corrupt lazy node as a no-change result
        // rather than aborting the process. The trie root stays bound to
        // its previous (potentially stale) shape; callers see no apparent
        // mutation and the next `serialize_to_cell` will rebuild from the
        // unchanged root.
        return {nullptr, false};
    }

    if (node->kind == kNodeLeaf) {
        if (ByteView{node->path} == key) {
            return {nullptr, true};
        }
        return {node, false};
    }

    if (node->kind == kNodeExtension) {
        if (key.size() < node->path.size() ||
            !std::equal(node->path.begin(), node->path.end(), key.begin())) {
            return {node, false};
        }
        auto updated = erase_rec(node->child, key.substr(node->path.size()));
        if (!updated.changed) {
            return {node, false};
        }
        return {normalize_extension(node->path, std::move(updated.node)), true};
    }

    if (node->kind != kNodeBranch) {
        return {nullptr, false};
    }
    if (key.empty()) {
        return {node, false};
    }
    const uint8_t idx = key[0];
    auto updated = erase_rec(node->children[idx], key.substr(1));
    if (!updated.changed) {
        return {node, false};
    }
    node->children[idx] = std::move(updated.node);
    return {collapse_branch(std::move(node)), true};
}

void walk_proof(const std::shared_ptr<MptTrie::Node>& node,
                ByteView target,
                std::vector<Bytes>& proof) {
    if (!node) {
        return;
    }
    CHECK(node->ensure_decoded());
    proof.push_back(node->rlp());

    if (node->kind == kNodeLeaf) {
        return;
    }
    if (node->kind == kNodeExtension) {
        if (target.size() < node->path.size() ||
            !std::equal(node->path.begin(), node->path.end(), target.begin())) {
            return;
        }
        walk_proof(node->child, target.substr(node->path.size()), proof);
        return;
    }
    if (target.empty()) {
        return;
    }
    walk_proof(node->children[target[0]], target.substr(1), proof);
}

/// Fail-closed proof walk. Mirrors `walk_proof` but returns a `td::Status`
/// when a lazy node's cell cannot be decoded, so the caller (RPC layer) can
/// surface a corrupt witness as a JSON-RPC error instead of triggering a
/// process abort via `CHECK`.
td::Status walk_proof_safe(const std::shared_ptr<MptTrie::Node>& node,
                            ByteView target,
                            std::vector<Bytes>& proof) {
    if (!node) {
        return td::Status::OK();
    }
    if (!node->ensure_decoded()) {
        return td::Status::Error("MPT proof: failed to decode lazy node");
    }
    proof.push_back(node->rlp());

    if (node->kind == kNodeLeaf) {
        return td::Status::OK();
    }
    if (node->kind == kNodeExtension) {
        if (target.size() < node->path.size() ||
            !std::equal(node->path.begin(), node->path.end(), target.begin())) {
            return td::Status::OK();
        }
        return walk_proof_safe(node->child, target.substr(node->path.size()), proof);
    }
    if (node->kind != kNodeBranch) {
        return td::Status::Error("MPT proof: unknown node kind");
    }
    if (target.empty()) {
        return td::Status::OK();
    }
    return walk_proof_safe(node->children[target[0]], target.substr(1), proof);
}

bool validate_node_shallow(const std::shared_ptr<MptTrie::Node>& node,
                           size_t& visited) {
    if (!node) {
        return true;
    }
    if (++visited > kMaxSerializedNodesPerTrie || !node->ensure_decoded()) {
        return false;
    }
    if (node->kind == kNodeLeaf) {
        return !node->value.empty() && node->path.size() <= kKeyNibbles;
    }
    if (node->kind == kNodeExtension) {
        return !node->path.empty() && node->path.size() <= kKeyNibbles && node->child != nullptr;
    }
    return node->child_count() >= 2;
}

/// Strict validation budget. Caps total nodes touched, total bytes of RLP
/// recomputed, and recursion depth so a maliciously deep / wide witness
/// cannot turn validation itself into a DoS vector.
struct MptValidationBudget {
    size_t nodes = 0;
    size_t rlp_bytes = 0;
    static constexpr size_t kMaxNodes = 200000;
    static constexpr size_t kMaxRlpBytes = 64ull * 1024ull * 1024ull;
    static constexpr size_t kMaxDepth = 128;
};

bool validate_node_strict(const std::shared_ptr<MptTrie::Node>& node,
                          MptValidationBudget& budget,
                          size_t depth) {
    if (!node) {
        return true;
    }
    if (++budget.nodes > MptValidationBudget::kMaxNodes) {
        return false;
    }
    if (depth > MptValidationBudget::kMaxDepth) {
        return false;
    }
    if (!node->ensure_decoded()) {
        return false;
    }

    // Recompute the canonical RLP from the decoded shape WITHOUT trusting
    // the per-node `rlp_cache`. A tampered witness whose `rlp_cache` does
    // not match its structural fields will fail this comparison.
    Bytes recomputed = node->compute_rlp_from_shape(/*trust_cache=*/false);
    if (recomputed.empty()) {
        return false;
    }
    if (recomputed.size() > MptValidationBudget::kMaxRlpBytes ||
        budget.rlp_bytes > MptValidationBudget::kMaxRlpBytes - recomputed.size()) {
        return false;
    }
    budget.rlp_bytes += recomputed.size();
    if (node->rlp_cache.empty() || node->rlp_cache != recomputed) {
        return false;
    }

    if (node->kind == kNodeLeaf) {
        // A leaf must have either a non-empty path or non-empty value (the
        // single-leaf root case has empty path but kKeyNibbles-length nibble
        // path is fine; the audit accepts either constraint).
        if (node->path.size() > kKeyNibbles) {
            return false;
        }
        return !node->path.empty() || !node->value.empty();
    }
    if (node->kind == kNodeExtension) {
        if (node->path.empty() || node->path.size() > kKeyNibbles ||
            node->child == nullptr) {
            return false;
        }
        // Depth grows by the number of nibbles consumed plus one for the
        // extension itself, capped against kMaxDepth.
        size_t next_depth = depth + node->path.size() + 1;
        if (next_depth > MptValidationBudget::kMaxDepth) {
            return false;
        }
        return validate_node_strict(node->child, budget, next_depth);
    }
    if (node->kind == kNodeBranch) {
        size_t children_count = 0;
        for (const auto& c : node->children) {
            if (c) {
                ++children_count;
                if (!validate_node_strict(c, budget, depth + 1)) {
                    return false;
                }
            }
        }
        return children_count >= 2;
    }
    return false;
}

}  // namespace

void MptTrie::clear() noexcept {
    root_.reset();
}

bool MptTrie::upsert_hashed(const ByteView& hashed_key, const ByteView& rlp_value) {
    if (hashed_key.size() != kHashLength || rlp_value.empty()) {
        return false;
    }
    Bytes nibbles = silkworm::trie::unpack_nibbles(hashed_key);
    auto updated = insert_rec(root_, nibbles, rlp_value);
    root_ = std::move(updated.node);
    return true;
}

bool MptTrie::erase_hashed(const ByteView& hashed_key) {
    if (hashed_key.size() != kHashLength) {
        return false;
    }
    Bytes nibbles = silkworm::trie::unpack_nibbles(hashed_key);
    auto updated = erase_rec(root_, nibbles);
    root_ = std::move(updated.node);
    return true;
}

evmc::bytes32 MptTrie::root_hash() const {
    if (!root_) {
        return silkworm::kEmptyRoot;
    }
    return root_->hash();
}

std::vector<Bytes> MptTrie::proof(const ByteView& hashed_key) const {
    if (hashed_key.size() != kHashLength || !root_) {
        return {};
    }
    Bytes nibbles = silkworm::trie::unpack_nibbles(hashed_key);
    std::vector<Bytes> out;
    walk_proof(root_, nibbles, out);
    return out;
}

td::Result<std::vector<Bytes>> MptTrie::proof_safe(const ByteView& hashed_key) const {
    if (hashed_key.size() != kHashLength) {
        return td::Status::Error("MPT proof_safe: hashed key must be 32 bytes");
    }
    if (!root_) {
        return std::vector<Bytes>{};
    }
    Bytes nibbles = silkworm::trie::unpack_nibbles(hashed_key);
    std::vector<Bytes> out;
    if (auto status = walk_proof_safe(root_, nibbles, out); status.is_error()) {
        return std::move(status);
    }
    return out;
}

td::Ref<vm::Cell> MptTrie::serialize_to_cell() const {
    if (!root_) {
        return {};
    }
    return root_->serialize_cell();
}

bool MptTrie::load_from_cell(td::Ref<vm::Cell> root,
                              MptWitnessValidationMode mode) {
    if (root.is_null()) {
        clear();
        return true;
    }
    auto loaded = Node::lazy(std::move(root));
    if (mode == MptWitnessValidationMode::StrictRecursive) {
        MptValidationBudget budget;
        if (!validate_node_strict(loaded, budget, 0)) {
            // Reject the tampered witness rather than binding it. Subsequent
            // proof / update operations therefore see an empty trie instead
            // of a half-decoded structure that could trigger a CHECK abort.
            return false;
        }
    } else {
        size_t visited = 0;
        if (!validate_node_shallow(loaded, visited)) {
            return false;
        }
    }
    root_ = std::move(loaded);
    return true;
}

Bytes encode_mpt_storage_value(const evmc::bytes32& value) {
    size_t start = 0;
    while (start < kHashLength && value.bytes[start] == 0) {
        ++start;
    }
    Bytes out;
    if (start == kHashLength) {
        silkworm::rlp::encode(out, ByteView{});
    } else {
        silkworm::rlp::encode(out, ByteView{value.bytes + start, kHashLength - start});
    }
    return out;
}

evmc::bytes32 keccak_evm_address(const evmc::address& address) {
    auto h = ethash::keccak256(address.bytes, 20);
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, kHashLength);
    return out;
}

evmc::bytes32 keccak_bytes32_value(const evmc::bytes32& value) {
    auto h = ethash::keccak256(value.bytes, kHashLength);
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, kHashLength);
    return out;
}

}  // namespace evm_workchain
