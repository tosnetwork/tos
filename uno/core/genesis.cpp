/*
    Uno Workchain — zerostate builder + genesis distribution loader.

    Source: TOS-specific adapter; see doc/uno-workchain.md §10.3.
*/
#include "uno/core/genesis.h"
#include "uno/core/cell-state.h"
#include "uno/core/config-param.h"
#include "uno/core/workchain.h"

#include "vm/cells/CellBuilder.h"
#include "vm/boc.h"

#include "td/utils/Status.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"  // td::buffer_to_hex

#include <cstring>

// Full declarations of the sub-object types owned by Agent 2 (§5.2/§5.3/§5.4)
// are required at the call sites below because the zerostate path
// instantiates CommitmentTree / NullifierSet / AnchorWindow via Agent 2's
// factory functions and calls their mutators.
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Sub-object factory forward declarations (Agent 2)
// ---------------------------------------------------------------------------
// These are the entry points the genesis path expects Agent 2 to expose.
// TODO(uno-integration): exact signatures to be confirmed with Agent 2.
// The shapes below are what §5.2 / §5.3 / §5.4 imply.

/// Build an empty CommitmentTree pre-populated with 32 canonical empty-
/// subtree hashes (§5.2). The empty-subtree hashes are derived from the
/// Poseidon2-over-Goldilocks zero leaf, forward-declared in crypto/.
/// The returned tree is ready to accept append() calls.
std::unique_ptr<CommitmentTree> make_empty_commitment_tree();

/// Empty nullifier set backed by an empty vm::Dictionary (§5.3).
std::unique_ptr<NullifierSet> make_empty_nullifier_set();

/// Empty anchor window (§5.4). The zerostate path seeds the first entry
/// via `anchor_window->push(initial_root)` rather than via the factory,
/// so the factory returns a zero-length ring.
std::unique_ptr<AnchorWindow> make_empty_anchor_window();

// ---------------------------------------------------------------------------
// Sub-object operation forward declarations (Agent 2)
// ---------------------------------------------------------------------------

/// Append a note commitment to the tree (§5.2). Returns the updated root.
std::array<uint8_t, kHashBytes> commitment_tree_append(
    CommitmentTree& tree, const std::array<uint8_t, kHashBytes>& cm);

/// Push a root into the anchor window (§5.4). Evicts the oldest when the
/// buffer is full.
void anchor_window_push(AnchorWindow& win,
                        const std::array<uint8_t, kHashBytes>& root);

/// Query the current commitment-tree root. Read-only helper.
std::array<uint8_t, kHashBytes> commitment_tree_root(const CommitmentTree& tree);

// ---------------------------------------------------------------------------
// build_zerostate_state
// ---------------------------------------------------------------------------

UnoShardState build_zerostate_state(const GenesisDistribution& dist) {
    UnoShardState s = UnoShardState::make_empty();
    s.version = kShardStateVersion;
    s.scheme_id = kSchemeIdV1;
    s.next_position = 0;

    s.commitment_tree = make_empty_commitment_tree();
    s.nullifier_set   = make_empty_nullifier_set();
    s.anchor_window   = make_empty_anchor_window();

    if (!s.commitment_tree || !s.nullifier_set || !s.anchor_window) {
        LOG(ERROR) << "uno/genesis: sub-object factory returned null";
        return UnoShardState::make_empty();
    }

    // Append each genesis note's commitment in canonical order.
    uint64_t total = 0;
    for (size_t i = 0; i < dist.notes.size(); ++i) {
        const auto& note = dist.notes[i];
        // Overflow-checked supply sum (§10.3 total_supply).
        if (total > UINT64_MAX - note.value) {
            LOG(ERROR) << "uno/genesis: total_supply overflow at note " << i;
            return UnoShardState::make_empty();
        }
        total += note.value;

        auto new_root = commitment_tree_append(*s.commitment_tree, note.cm);
        s.commitment_tree_root = new_root;
        s.next_position = i + 1;
    }

    // If the caller provided an explicit total_supply_nano, validate.
    if (dist.total_supply_nano != 0 && dist.total_supply_nano != total) {
        LOG(ERROR) << "uno/genesis: declared total_supply_nano="
                   << dist.total_supply_nano
                   << " does not match sum=" << total;
        return UnoShardState::make_empty();
    }

    // Seed the anchor window with the post-genesis root so the first user
    // spend can reference it (§10.3 step 3 interpreted against §5.4).
    anchor_window_push(*s.anchor_window, s.commitment_tree_root);

    // Stats: one synthetic genesis tx minted |notes| outputs; no fee.
    s.stats.burned_fees = 0;
    s.stats.tx_count    = dist.notes.empty() ? 0 : 1;
    s.stats.note_count  = static_cast<uint64_t>(dist.notes.size());

    // config_hash is populated after cell-state serialization, where the
    // caller also has the live ConfigParam 26 bytes in hand.  Leave zero
    // here; init code overwrites before writing to disk.

    return s;
}

td::Ref<vm::Cell> build_zerostate_state_cell(const GenesisDistribution& dist) {
    auto s = build_zerostate_state(dist);
    if (s.is_empty() && !dist.notes.empty()) {
        LOG(ERROR) << "uno/genesis: build_zerostate_state returned empty "
                   << "despite " << dist.notes.size() << " genesis notes";
        return {};
    }
    return serialize_state(s);
}

// ---------------------------------------------------------------------------
// build_zerostate (full outer cell carrying the state cell)
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> build_zerostate(const GenesisDistribution& dist,
                                   tos::RootHash& out_root,
                                   tos::FileHash& out_file) {
    auto state_cell = build_zerostate_state_cell(dist);
    if (state_cell.is_null()) {
        LOG(ERROR) << "uno/genesis: inner state cell build failed";
        return {};
    }

    // Minimal ShardState-shaped envelope mirroring evm::build_evm_zerostate.
    // A full ShardState would carry the block reference, but at genesis
    // seq_no=0, gen_utime=0, etc., so a simplified envelope suffices.
    vm::CellBuilder cb;
    cb.store_long(0x9023afe2, 32);                 // shard_state tag
    cb.store_long(dist.chain_id, 32);              // global_id
    cb.store_long(kWorkchainId, 32);               // shard_ident.workchain_id
    cb.store_long(0, 64);                          // shard_ident prefix/bits
    cb.store_long(0, 32);                          // seq_no
    cb.store_long(0, 32);                          // vert_seqno
    cb.store_long(0, 32);                          // gen_utime
    cb.store_long(0, 64);                          // gen_lt
    cb.store_long(0, 32);                          // min_ref_mc_seqno
    // Ref: the wc=2 UnoShardState cell itself, as the single "accounts"
    // ref for this minimal envelope. Full ShardAccounts dict wrapping is
    // Agent 6's responsibility (genesis boc file assembly).
    if (!cb.store_ref_bool(std::move(state_cell))) return {};

    auto cell = cb.finalize();
    out_root = cell->get_hash().bits();

    auto boc_r = vm::std_boc_serialize(cell);
    if (boc_r.is_error()) {
        LOG(ERROR) << "uno/genesis: BoC serialize failed: "
                   << boc_r.error().message();
        return {};
    }
    auto boc = boc_r.move_as_ok();
    unsigned char sha[32];
    td::sha256(boc.as_slice(), td::MutableSlice(sha, 32));
    out_file = tos::FileHash(td::ConstBitPtr(sha));

    LOG(WARNING) << "uno/genesis: zerostate built, root=" << out_root.to_hex()
                 << ", file=" << out_file.to_hex()
                 << ", notes=" << dist.notes.size();
    return cell;
}

// ---------------------------------------------------------------------------
// JSON I/O for zerostate-genesis-notes.json
// ---------------------------------------------------------------------------

td::Result<GenesisDistribution> load_genesis_distribution(
    const std::string& json_path) {
    auto text_r = td::read_file(json_path);
    if (text_r.is_error()) return text_r.move_as_error();
    // TODO(uno-integration): full JSON parse + hex decoding not implemented
    // yet. Chain-boot tooling produces the canonical file; validators
    // normally consume the BoC genesis artefact, not this JSON. Wire up
    // td::JsonValue parsing here once the chain-boot tool's canonical
    // schema is pinned by Agent 6.
    (void)text_r;
    return td::Status::Error("uno/genesis: load_genesis_distribution: "
                             "JSON parser not yet implemented");
}

td::Result<std::string> dump_genesis_distribution(
    const GenesisDistribution& dist) {
    // Deterministic, hand-formatted JSON. td::JsonBuilder's nested scopes
    // are awkward for this schema (nested object values keyed from an
    // object scope), and this helper is off-consensus off-chain tooling
    // so a plain string builder is fine. Format: compact, single line,
    // hex byte fields, decimal-string large numbers.
    auto hex = [](const uint8_t* data, size_t len) -> std::string {
        return td::buffer_to_hex(td::Slice(data, len));
    };

    std::string out;
    out.reserve(128 + dist.notes.size() * 2048);
    out += "{\"chain_id\":";
    out += std::to_string(dist.chain_id);
    out += ",\"total_supply_nano\":\"";
    out += std::to_string(dist.total_supply_nano);
    out += "\",\"notes\":[";
    for (size_t i = 0; i < dist.notes.size(); ++i) {
        const auto& note = dist.notes[i];
        if (i) out += ',';
        out += "{\"recipient\":{\"d\":\"";
        out += hex(note.recipient.diversifier.data(),
                   note.recipient.diversifier.size());
        out += "\",\"pk_d\":\"";
        out += hex(note.recipient.pk_d_compressed.data(),
                   note.recipient.pk_d_compressed.size());
        out += "\",\"pk_mlkem\":\"";
        out += hex(note.recipient.pk_mlkem.data(),
                   note.recipient.pk_mlkem.size());
        out += "\"},\"value\":\"";
        out += std::to_string(note.value);
        out += "\",\"rseed\":\"";
        out += hex(note.rseed.data(), note.rseed.size());
        out += "\",\"cm\":\"";
        out += hex(note.cm.data(), note.cm.size());
        out += "\"}";
    }
    out += "]}";
    return out;
}

}  // namespace uno_workchain
