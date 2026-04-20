/*
    Uno Workchain — zerostate builder + genesis distribution loader.

    Source: TOS-specific adapter; see doc/uno-workchain.md §10.3.

    -------------------------------------------------------------------------
    `zerostate-genesis-notes.json` — canonical schema (K-genesis-loader)
    -------------------------------------------------------------------------
    The on-disk file is UTF-8 JSON, one top-level object. Fields are parsed
    in the order the JSON decoder yields them; ordering of the `notes` array
    IS consensus-relevant because each note's leaf position in the initial
    commitment tree equals its JSON index (§10.3 step 3 — "canonical append
    order"). Validators and wallets that load this file MUST produce the
    same commitment-tree root after appending.

    Top-level object:

        {
          "scheme_id":         1,              // u8, §2.0 — must equal kSchemeIdV1 at launch
          "chain_id":          1431520589,     // u32, §10.4 — 0x554E4F4D ("UNOM") for mainnet,
                                               //              0x554E4F54 ("UNOT") for testnet.
                                               //              Also accepted as a hex string
                                               //              ("0x554E4F4D") or ASCII-4 string
                                               //              ("UNOM" / "UNOT").
          "total_supply_nano": "21000000000000000", // optional string; recomputed if absent,
                                               //   verified if present. §10.3 fixes at 2.1e16.
          "notes": [ <NoteEntry>, ... ]         // ordered; index == leaf position
        }

    Per-note entry (`NoteEntry`):

        {
          "recipient": {
            "d":              "<hex 11 B>",    // §2.6 diversifier
            "pk_d":           "<hex 32 B>",    // compressed Ristretto255
            "ivk_commitment": "<hex 32 B>",    // Poseidon2("uno-ivk-cm-v1", ivk, d) — decision #1
            "pk_mlkem":       "<hex 1184 B>"   // ML-KEM-768 public key
          },
          "value":  1000000000,                 // u64 nano-UNO; number or decimal string. Must be
                                                //   ≥ 0 (JSON number with "-" prefix is rejected).
          "rseed":  "<hex 32 B>",               // trapdoor seed; `0x`-prefix accepted
          "cm":     "<hex 32 B>"                // OPTIONAL — if present, it is verified against
                                                //   the Poseidon2 cm recomputed from the
                                                //   (recipient, value, rseed) tuple per §3.2.
                                                //   If absent, the loader fills it in.
        }

    The loader computes each `cm` via `compute_note_commitment()` (§3.2):

        rcm = Poseidon2("uno-rcm-v1", rseed)              // §3.1
        cm  = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm)  // §3.2

    Bech32m envelope (§2.6 `AddressEnvelope`, HRP "uno" / "unot") is NOT
    accepted by this loader. The dedicated `uno-bech32-v1` decoder is not
    in-tree yet (see decision-log commit K-genesis-loader); once it lands
    the schema will gain a `"address": "unot1…"` alternative to the hex
    `recipient` block and auto-detect which form was used. Adopting the
    Bech32m envelope here without the canonical decoder would risk a spec
    divergence — per §2.6 the envelope is a protocol-level MUST and must
    round-trip bit-identically to every wallet implementation.
    -------------------------------------------------------------------------
*/
#include "uno/core/genesis.h"
#include "uno/core/cell-state.h"
#include "uno/core/config-param.h"
#include "uno/core/workchain.h"

#include "vm/cells/CellBuilder.h"
#include "vm/boc.h"

#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"  // td::buffer_to_hex, td::hex_decode

#include <cstring>
#include <string>

// Full declarations of the sub-object types owned by Agent 2 (§5.2/§5.3/§5.4)
// are required at the call sites below because the zerostate path
// instantiates CommitmentTree / NullifierSet / AnchorWindow via Agent 2's
// factory functions and calls their mutators.
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"

// ---------------------------------------------------------------------------
// Forward declarations from transaction.h / poseidon2.h.
//
// We do NOT `#include "uno/core/transaction.h"` or `"uno/crypto/poseidon2.h"`
// here because both headers currently collide with symbols declared by
// `uno/core/workchain.h` (kTransferVersion, kSchemeIdV1, the noexcept-agnostic
// `poseidon2_goldilocks_compress_2to1`). The real definitions link in from
// the corresponding TUs; we only need the narrow surface below.
// ---------------------------------------------------------------------------
namespace uno_workchain {
struct NoteCommitmentInputs {
    std::array<uint8_t, 11>  d{};
    std::array<uint8_t, 32>  pk_d_bytes{};
    std::array<uint8_t, 32>  ivk_commitment{};
    uint64_t                 value{0};
    std::array<uint8_t, 32>  rcm{};
};
std::array<uint8_t, 32> compute_note_commitment(
    const NoteCommitmentInputs& in) noexcept;
}  // namespace uno_workchain

// The Fp / Digest value types live in goldilocks.h, which does NOT
// collide with workchain.h. Poseidon2 symbols are forward-declared AFTER
// this header because they need the `Fp` / `Digest` full definitions.
#include "uno/crypto/goldilocks.h"

namespace uno_workchain::crypto {
// Re-declared copies of the two Poseidon2 helpers we need for `compute_rcm`.
// Duplicating the signatures here rather than pulling in
// `uno/crypto/poseidon2.h` keeps this TU independent of the
// transaction.h / workchain.h duplicate-constant and
// poseidon2.h / commitment-tree.h noexcept-disagreement collisions noted
// above.
Digest poseidon2_hash_tagged(td::Slice tag, const Fp* inputs, size_t n_inputs);
}  // namespace uno_workchain::crypto

namespace uno_workchain {

// ---------------------------------------------------------------------------
// build_zerostate_state
// ---------------------------------------------------------------------------
//
// Decision #14 replaces A1's free-function placeholders
// (`make_empty_commitment_tree`, `commitment_tree_append`,
// `anchor_window_push`, ...) with A2's method-based API. The zerostate path
// default-constructs each sub-object and drives it through append() / push().

UnoShardState build_zerostate_state(const GenesisDistribution& dist) {
    UnoShardState s = UnoShardState::make_empty();
    s.version = kShardStateVersion;
    s.scheme_id = kSchemeIdV1;
    s.next_position = 0;

    s.commitment_tree = std::make_unique<CommitmentTree>();
    s.nullifier_set   = std::make_unique<NullifierSet>();
    s.anchor_window   = std::make_unique<AnchorWindow>();

    if (!s.commitment_tree || !s.nullifier_set || !s.anchor_window) {
        LOG(ERROR) << "uno/genesis: sub-object factory returned null";
        return UnoShardState::make_empty();
    }

    // Seed commitment_tree_root with the empty-tree root so the pre-notes
    // case (dist.notes.empty()) still reports the canonical value.
    {
        const NoteHash& empty_root = s.commitment_tree->get_root();
        std::copy(empty_root.begin(), empty_root.end(),
                  s.commitment_tree_root.begin());
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

        // A2's CommitmentTree::append takes a NoteHash (32-byte array) and
        // returns the new root. GenesisNote::cm is also a 32-byte array but
        // with a different alias (`std::array<uint8_t, kHashBytes>`) so we
        // copy byte-wise.
        NoteHash cm_hash{};
        std::copy(note.cm.begin(), note.cm.end(), cm_hash.begin());
        NoteHash new_root = s.commitment_tree->append(cm_hash);
        std::copy(new_root.begin(), new_root.end(),
                  s.commitment_tree_root.begin());
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
    {
        NoteHash root_hash{};
        std::copy(s.commitment_tree_root.begin(),
                  s.commitment_tree_root.end(),
                  root_hash.begin());
        s.anchor_window->push(root_hash);
    }

    // Stats: one synthetic genesis tx minted |notes| outputs; no fee.
    s.stats.burned_fees = 0;
    s.stats.tx_count    = dist.notes.empty() ? 0 : 1;
    s.stats.note_count  = static_cast<uint64_t>(dist.notes.size());

    // config_hash is populated after cell-state serialization, where the
    // caller also has the live ConfigParam 84 bytes in hand.  Leave zero
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

// ---------------------------------------------------------------------------
// JSON parse helpers (scoped to this TU).
//
// None of these helpers abort on failure — every error is surfaced as a
// td::Status and propagated up to `load_genesis_distribution`, so malformed
// input yields a clean Result<> error path that the unit test asserts
// against.
// ---------------------------------------------------------------------------
namespace {

/// Strip an optional `0x` / `0X` prefix from a hex-encoded field.
td::Slice strip_hex_prefix(td::Slice s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return s.substr(2);
    }
    return s;
}

/// Decode a hex-encoded JSON string into a fixed-length byte buffer.
/// `expected_bytes` is the required output length in bytes; returns an
/// error if the decoded length disagrees or any non-hex character appears.
/// `0x` prefix is accepted but not required.
td::Status decode_hex_fixed(td::Slice hex_str, uint8_t* out,
                            size_t expected_bytes, const char* field_name) {
    td::Slice body = strip_hex_prefix(hex_str);
    if (body.size() != expected_bytes * 2) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name << "\" has "
            << body.size() / 2 << " bytes, expected " << expected_bytes);
    }
    TRY_RESULT(bytes, td::hex_decode(body));
    if (bytes.size() != expected_bytes) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name
            << "\" non-hex character or odd length");
    }
    std::memcpy(out, bytes.data(), expected_bytes);
    return td::Status::OK();
}

/// Decode a hex-encoded JSON string into a variable-length byte buffer.
td::Status decode_hex_var(td::Slice hex_str, std::vector<uint8_t>& out,
                          size_t expected_bytes, const char* field_name) {
    td::Slice body = strip_hex_prefix(hex_str);
    if (body.size() != expected_bytes * 2) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name << "\" has "
            << body.size() / 2 << " bytes, expected " << expected_bytes);
    }
    TRY_RESULT(bytes, td::hex_decode(body));
    if (bytes.size() != expected_bytes) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name
            << "\" non-hex character or odd length");
    }
    out.assign(bytes.begin(), bytes.end());
    return td::Status::OK();
}

/// Parse a u64 from either a JSON number or a JSON decimal/hex string.
/// A leading `-` (negative value) is rejected before parsing — this is the
/// canonical "negative value" reject path exercised by the unit test.
td::Result<uint64_t> parse_u64(const td::JsonValue& v, const char* field_name) {
    td::Slice digits;
    if (v.type() == td::JsonValue::Type::Number) {
        digits = v.get_number();
    } else if (v.type() == td::JsonValue::Type::String) {
        digits = v.get_string();
    } else {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name
            << "\" must be a JSON number or string");
    }
    if (digits.empty()) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name << "\" is empty");
    }
    if (digits[0] == '-') {
        return td::Status::Error(PSLICE()
            << "uno/genesis: field \"" << field_name
            << "\" is negative; u64 expected");
    }
    // Accept `0x` hex syntax explicitly; decimals otherwise.
    if (digits.size() >= 2 && digits[0] == '0'
        && (digits[1] == 'x' || digits[1] == 'X')) {
        TRY_RESULT(v64, td::hex_to_integer_safe<uint64_t>(digits.substr(2)));
        return v64;
    }
    TRY_RESULT(v64, td::to_integer_safe<uint64_t>(digits));
    return v64;
}

/// Parse the top-level "chain_id": accepts a JSON number, a decimal string,
/// a `"0x..."` hex string, or an ASCII-4 token ("UNOM" / "UNOT").
td::Result<uint32_t> parse_chain_id(const td::JsonValue& v) {
    if (v.type() == td::JsonValue::Type::Number) {
        TRY_RESULT(n64, td::to_integer_safe<uint64_t>(v.get_number()));
        if (n64 > 0xFFFFFFFFULL) {
            return td::Status::Error("uno/genesis: chain_id does not fit in u32");
        }
        return static_cast<uint32_t>(n64);
    }
    if (v.type() != td::JsonValue::Type::String) {
        return td::Status::Error("uno/genesis: chain_id must be a number or string");
    }
    td::Slice s = v.get_string();
    if (s.size() == 4 && s[0] != '0') {
        // ASCII-4 convenience form ("UNOM" / "UNOT"). Interpret as big-endian
        // so "UNOM" → 0x554E4F4D.
        uint32_t packed = 0;
        for (size_t i = 0; i < 4; ++i) {
            packed = (packed << 8) | static_cast<uint8_t>(s[i]);
        }
        return packed;
    }
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        TRY_RESULT(v64, td::hex_to_integer_safe<uint64_t>(s.substr(2)));
        if (v64 > 0xFFFFFFFFULL) {
            return td::Status::Error("uno/genesis: chain_id does not fit in u32");
        }
        return static_cast<uint32_t>(v64);
    }
    TRY_RESULT(v64, td::to_integer_safe<uint64_t>(s));
    if (v64 > 0xFFFFFFFFULL) {
        return td::Status::Error("uno/genesis: chain_id does not fit in u32");
    }
    return static_cast<uint32_t>(v64);
}

/// Compute `rcm = Poseidon2("uno-rcm-v1", rseed)` in canonical wire form
/// (§3.1). `rseed` is 32 bytes interpreted as 4 little-endian u64 words,
/// each reduced mod Goldilocks p before absorption — identical semantics
/// to the packing `compute_note_commitment` uses for its 32 B fields.
std::array<uint8_t, 32> compute_rcm(const std::array<uint8_t, 32>& rseed) noexcept {
    using ::uno_workchain::crypto::Fp;
    using ::uno_workchain::crypto::Digest;
    using ::uno_workchain::crypto::fp_from_u64;
    using ::uno_workchain::crypto::poseidon2_hash_tagged;

    Fp inputs[4];
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) {
            w |= static_cast<uint64_t>(rseed[limb * 8 + j]) << (8 * j);
        }
        inputs[limb] = fp_from_u64(w);
    }
    Digest d = poseidon2_hash_tagged(td::Slice(kDomainSepRcmV1, 9), inputs, 4);
    std::array<uint8_t, 32> out{};
    d.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

/// Fill `note.cm` from the (recipient, value, rseed) tuple. If the caller
/// already populated `note.cm` (non-zero), verify that the computed value
/// matches and emit an error on mismatch so the fixture file's `cm` field
/// can act as a third-party cross-check.
td::Status fill_or_verify_cm(GenesisNote& note, bool cm_supplied) {
    NoteCommitmentInputs nci{};
    nci.d              = note.recipient.diversifier;
    nci.pk_d_bytes     = note.recipient.pk_d_compressed;
    nci.ivk_commitment = note.recipient.ivk_commitment;
    nci.value          = note.value;
    nci.rcm            = compute_rcm(note.rseed);

    std::array<uint8_t, 32> cm_calc = compute_note_commitment(nci);
    if (cm_supplied) {
        if (cm_calc != note.cm) {
            return td::Status::Error("uno/genesis: note \"cm\" field "
                "disagrees with Poseidon2(\"uno-cm-v1\", ...) recomputation");
        }
    } else {
        note.cm = cm_calc;
    }
    return td::Status::OK();
}

/// Parse a single per-note object.
td::Status parse_note(td::JsonValue& note_val, size_t idx, GenesisNote& out) {
    if (note_val.type() != td::JsonValue::Type::Object) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: notes[" << idx << "] is not an object");
    }
    auto& obj = note_val.get_object();

    // Recipient ------------------------------------------------------------
    TRY_RESULT(recipient_v,
               obj.extract_required_field("recipient",
                                          td::JsonValue::Type::Object));
    auto& rcp = recipient_v.get_object();

    TRY_RESULT(d_s,              rcp.get_required_string_field("d"));
    TRY_STATUS(decode_hex_fixed(d_s,
                                out.recipient.diversifier.data(),
                                out.recipient.diversifier.size(),
                                "recipient.d"));

    TRY_RESULT(pk_d_s,           rcp.get_required_string_field("pk_d"));
    TRY_STATUS(decode_hex_fixed(pk_d_s,
                                out.recipient.pk_d_compressed.data(),
                                out.recipient.pk_d_compressed.size(),
                                "recipient.pk_d"));

    TRY_RESULT(ivk_cm_s,         rcp.get_required_string_field("ivk_commitment"));
    TRY_STATUS(decode_hex_fixed(ivk_cm_s,
                                out.recipient.ivk_commitment.data(),
                                out.recipient.ivk_commitment.size(),
                                "recipient.ivk_commitment"));

    TRY_RESULT(pk_mlkem_s,       rcp.get_required_string_field("pk_mlkem"));
    // §2.7: ML-KEM-768 public key is exactly 1184 bytes.
    constexpr size_t kMlkemPkBytes = 1184;
    TRY_STATUS(decode_hex_var(pk_mlkem_s, out.recipient.pk_mlkem,
                              kMlkemPkBytes, "recipient.pk_mlkem"));

    // value ---------------------------------------------------------------
    // `extract_required_field` demands a single JSON type, but the schema
    // permits either a JSON number or a decimal/hex string. We pull the
    // raw JsonValue and delegate to `parse_u64` for type-agnostic parsing.
    if (!obj.has_field("value")) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: notes[" << idx << "] missing field \"value\"");
    }
    td::JsonValue value_v = obj.extract_field("value");
    TRY_RESULT_ASSIGN(out.value, parse_u64(value_v, "value"));

    // rseed ---------------------------------------------------------------
    TRY_RESULT(rseed_s, obj.get_required_string_field("rseed"));
    TRY_STATUS(decode_hex_fixed(rseed_s,
                                out.rseed.data(), out.rseed.size(),
                                "rseed"));

    // cm (optional) -------------------------------------------------------
    bool cm_supplied = false;
    if (obj.has_field("cm")) {
        TRY_RESULT(cm_s, obj.get_required_string_field("cm"));
        TRY_STATUS(decode_hex_fixed(cm_s,
                                    out.cm.data(), out.cm.size(),
                                    "cm"));
        cm_supplied = true;
    }

    TRY_STATUS(fill_or_verify_cm(out, cm_supplied));
    return td::Status::OK();
}

}  // namespace

td::Result<GenesisDistribution> load_genesis_distribution(
    const std::string& json_path) {
    TRY_RESULT(text, td::read_file(json_path));

    // td::json_decode consumes a MutableSlice.
    td::MutableSlice buf(text.as_slice().begin(), text.as_slice().size());
    TRY_RESULT(root, td::json_decode(buf));

    if (root.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("uno/genesis: top-level JSON must be an object");
    }
    auto& root_obj = root.get_object();

    // scheme_id — optional at load time; when present, must equal kSchemeIdV1.
    // Downstream consensus also checks this via tx-level admission (§2.0).
    if (root_obj.has_field("scheme_id")) {
        td::JsonValue sv = root_obj.extract_field("scheme_id");
        TRY_RESULT(sid, parse_u64(sv, "scheme_id"));
        if (sid != static_cast<uint64_t>(kSchemeIdV1)) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: unsupported scheme_id=" << sid
                << " (expected " << static_cast<uint64_t>(kSchemeIdV1) << ")");
        }
    }

    GenesisDistribution dist;

    // chain_id (required).
    if (!root_obj.has_field("chain_id")) {
        return td::Status::Error("uno/genesis: top-level missing \"chain_id\"");
    }
    {
        td::JsonValue ci = root_obj.extract_field("chain_id");
        TRY_RESULT_ASSIGN(dist.chain_id, parse_chain_id(ci));
    }

    // total_supply_nano (optional; if absent, defaults to sum of note values).
    uint64_t declared_supply = 0;
    bool supply_declared = false;
    if (root_obj.has_field("total_supply_nano")) {
        td::JsonValue sv = root_obj.extract_field("total_supply_nano");
        TRY_RESULT_ASSIGN(declared_supply, parse_u64(sv, "total_supply_nano"));
        supply_declared = true;
    }

    // notes (required, must be an array).
    TRY_RESULT(notes_v,
               root_obj.extract_required_field("notes",
                                               td::JsonValue::Type::Array));
    auto& arr = notes_v.get_array();

    dist.notes.reserve(arr.size());
    uint64_t total = 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        GenesisNote note;
        TRY_STATUS(parse_note(arr[i], i, note));
        if (total > UINT64_MAX - note.value) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: total_supply overflow at notes[" << i << "]");
        }
        total += note.value;
        dist.notes.emplace_back(std::move(note));
    }

    if (supply_declared) {
        if (declared_supply != total) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: declared total_supply_nano="
                << declared_supply
                << " != sum(notes.value)=" << total);
        }
        dist.total_supply_nano = declared_supply;
    } else {
        dist.total_supply_nano = total;
    }

    return dist;
}

// ---------------------------------------------------------------------------
// build_genesis_state — convenience wrapper for the K-genesis-loader contract.
//
// Takes a raw `std::vector<GenesisNote>` (as emitted by the chain-boot tool
// or synthesized by tests), fills in any missing `cm` fields via Poseidon2,
// and delegates to `build_zerostate_state`. Mirrors the § 10.3 step 3
// "canonical append order" contract end-to-end: commitment tree appended in
// vector order, anchor window seeded with the post-genesis root.
// ---------------------------------------------------------------------------

UnoShardState build_genesis_state(const std::vector<GenesisNote>& notes) {
    GenesisDistribution dist;
    dist.chain_id = current_uno_chain_id();
    dist.notes.reserve(notes.size());
    for (const auto& n : notes) {
        GenesisNote copy = n;
        // If the caller left `cm` zero, recompute it; otherwise verify.
        bool cm_supplied = false;
        for (uint8_t b : copy.cm) { if (b != 0) { cm_supplied = true; break; } }
        auto status = fill_or_verify_cm(copy, cm_supplied);
        if (status.is_error()) {
            LOG(ERROR) << "uno/genesis: build_genesis_state: "
                       << status.message();
            return UnoShardState::make_empty();
        }
        dist.notes.emplace_back(std::move(copy));
    }
    return build_zerostate_state(dist);
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
        out += "\",\"ivk_commitment\":\"";
        out += hex(note.recipient.ivk_commitment.data(),
                   note.recipient.ivk_commitment.size());
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
