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

    Bech32m envelope (§2.6 `AddressEnvelope`, HRP "uno" / "unot") is ALSO
    accepted — the per-note schema is EITHER the hex `recipient` block
    above OR a single string field:

        "address": "unot1q…"   // Bech32m-enveloped, §2.6

    Both MAY be present (useful for operator cross-checks); if both are
    present, the decoded envelope's `(d, pk_d, ivk_commitment, pk_mlkem)`
    MUST agree byte-for-byte with the explicit hex block, otherwise the
    loader rejects. Decoding goes through
    `uno::crypto::decode_address_envelope` (`uno/crypto/bech32m.h`) which
    performs the BIP-350 Bech32m polymod check, a BLAKE3 content-bound
    checksum cross-check, HRP/network cross-validation, and a
    version_tag whitelist.
    -------------------------------------------------------------------------
*/
#include "uno/core/genesis.h"
#include "uno/core/cell-state.h"
#include "uno/core/config-param.h"
#include "uno/core/mine_constants.h"
#include "uno/core/workchain.h"
#include "uno/crypto/bech32m.h"

#include "vm/cells/CellBuilder.h"
#include "vm/boc.h"

#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"  // td::buffer_to_hex, td::hex_decode

#include <sodium.h>   // crypto_generichash (BLAKE2b) — already a project-wide dep

#include <algorithm>
#include <cstring>
#include <set>
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

// ---------------------------------------------------------------------------
// Dev-mode mining-target override (UNO_INIT_MINE_TARGET_HEX).
//
// Read once at first call; subsequent calls reuse the cached decision so
// the four dev validators in a local testnet all see the same target even
// if one of them gets started after the env var was unset. Returns nullptr
// when the env var is unset / malformed; in that case the caller falls
// back to `select_init_mine_target(global_id)`.
//
// The env-var path is the deliberate escape hatch for chain-boot operators
// who need a target that isn't either mainnet's 2^219 or dev's 2^40 (e.g.
// reproducing a particular historical difficulty for forensic replay).
// On mainnet it should remain unset.
// ---------------------------------------------------------------------------
const std::array<uint8_t, 32>* try_load_env_mine_target() {
    static std::array<uint8_t, 32> cached{};
    static bool                   cached_set{false};
    static bool                   probed{false};
    if (probed) return cached_set ? &cached : nullptr;
    probed = true;

    const char* env = std::getenv("UNO_INIT_MINE_TARGET_HEX");
    if (env == nullptr) return nullptr;
    td::Slice body(env);
    if (body.size() >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X')) {
        body = body.substr(2);
    }
    if (body.size() != 64) {
        LOG(ERROR) << "uno/genesis: UNO_INIT_MINE_TARGET_HEX must be 64 hex "
                   << "chars (got " << body.size() << "); ignoring override";
        return nullptr;
    }
    auto bytes_r = td::hex_decode(body);
    if (bytes_r.is_error() || bytes_r.ok().size() != 32) {
        LOG(ERROR) << "uno/genesis: UNO_INIT_MINE_TARGET_HEX malformed "
                   << "(non-hex / wrong length); ignoring override";
        return nullptr;
    }
    auto bytes = bytes_r.move_as_ok();
    std::memcpy(cached.data(), bytes.data(), 32);
    cached_set = true;
    LOG(WARNING) << "uno/genesis: UNO_INIT_MINE_TARGET_HEX override active "
                 << "(target=" << env << ")";
    return &cached;
}

UnoShardState build_zerostate_state(const GenesisDistribution& dist,
                                    int32_t global_id) {
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

    // Mining state (uno-mine-v1 Phase 2; see doc/uno-mine-air-constraints.md).
    // mine_remaining starts at the full 21M UNO cap in nano-UNO units.
    // mine_epoch and halving_era start at 0 (no solves yet).
    // mine_target selection order (decreasing priority):
    //   1. `UNO_INIT_MINE_TARGET_HEX` env var (operator override; see the
    //      `try_load_env_mine_target` helper above). Intended for chain-boot
    //      calibration work; unset on mainnet.
    //   2. `select_init_mine_target(global_id)` — hard-wired mainnet
    //      (2^219, kInitMineTargetBE) vs local-dev (2^40, kDevMineTargetBE)
    //      split. `global_id == 3` means local dev per gen-zerostate-test.fif
    //      and test/tostester/src/tostester/zerostate.py; every other value
    //      keeps the production target.
    s.mine_remaining = kMineSupplyNano;         // = 21,000,000 × 10^9 nano-UNO
    s.mine_epoch     = 0;
    if (const auto* override_target = try_load_env_mine_target()) {
        std::copy(override_target->begin(), override_target->end(),
                  s.mine_target.begin());
    } else {
        const uint8_t* selected = select_init_mine_target(global_id);
        std::copy(selected, selected + 32, s.mine_target.begin());
    }
    s.halving_era    = 0;

    return s;
}

td::Ref<vm::Cell> build_zerostate_state_cell(const GenesisDistribution& dist,
                                              int32_t global_id) {
    auto s = build_zerostate_state(dist, global_id);
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
                                   tos::FileHash& out_file,
                                   int32_t global_id) {
    auto state_cell = build_zerostate_state_cell(dist, global_id);
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
    // §3.1 tag "uno-rcm-v1" is 10 chars. (`kDomainSepRcmV1` is a
    // null-terminated char[]; `std::strlen` gives the correct 10-byte
    // length. A previous revision passed `9` here, truncating to
    // "uno-rcm-v", which disagreed with the Rust wallet's rcm tag and
    // silently produced a different cm. Fixed under K-genesis-distribution
    // cross-impl parity.)
    Digest d = poseidon2_hash_tagged(
        td::Slice(kDomainSepRcmV1, std::strlen(kDomainSepRcmV1)),
        inputs, 4);
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

/// Unmarshal an `AddressEnvelope.payload` into the GenesisAddress fields.
/// The payload layout (§2.6) is:
///   [0..11)     diversifier `d`
///   [11..43)    compressed Ristretto255 `pk_d`
///   [43..75)    `ivk_commitment`
///   [75..1259)  ML-KEM-768 `pk_mlkem` (1184 B)
void unpack_address_payload(const ::uno_workchain::crypto::AddressEnvelope& env,
                            GenesisAddress& out) {
    constexpr size_t kMlkemPkBytes = 1184;
    std::memcpy(out.diversifier.data(),     env.payload.data() +   0, 11);
    std::memcpy(out.pk_d_compressed.data(), env.payload.data() +  11, 32);
    std::memcpy(out.ivk_commitment.data(),  env.payload.data() +  43, 32);
    out.pk_mlkem.assign(env.payload.data() + 75,
                        env.payload.data() + 75 + kMlkemPkBytes);
}

/// Parse a single per-note object.
///
/// The recipient can be specified in two mutually-compatible forms:
///   * `"recipient": { d, pk_d, ivk_commitment, pk_mlkem }`  — hex block
///   * `"address":   "unot1q…"`                              — Bech32m envelope
/// At least ONE must be present. If BOTH are present, the envelope's
/// unpacked payload MUST byte-match the explicit hex block. Reject at
/// parse time on any malformed envelope (§2.6 MUST).
td::Status parse_note(td::JsonValue& note_val, size_t idx, GenesisNote& out) {
    if (note_val.type() != td::JsonValue::Type::Object) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: notes[" << idx << "] is not an object");
    }
    auto& obj = note_val.get_object();

    // ML-KEM-768 public key is exactly 1184 bytes (§2.7).
    constexpr size_t kMlkemPkBytes = 1184;

    // Track which forms we saw so we can (a) require at least one, and
    // (b) cross-check when both are present.
    bool have_hex_recipient = obj.has_field("recipient");
    bool have_address_env   = obj.has_field("address");
    if (!have_hex_recipient && !have_address_env) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: notes[" << idx
            << "] missing both \"recipient\" and \"address\"");
    }

    // --- Envelope form (§2.6 Bech32m). ---------------------------------
    GenesisAddress env_addr{};
    bool env_ok = false;
    if (have_address_env) {
        TRY_RESULT(addr_s, obj.get_required_string_field("address"));
        ::uno_workchain::crypto::AddressEnvelope env{};
        auto err = ::uno_workchain::crypto::decode_address_envelope(
            td::Slice(addr_s).str(), env);
        if (err != ::uno_workchain::crypto::EnvelopeError::kOk) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: notes[" << idx
                << "] malformed Bech32m address envelope (err="
                << static_cast<int>(err) << ")");
        }
        unpack_address_payload(env, env_addr);
        env_ok = true;
    }

    // --- Explicit hex block. --------------------------------------------
    GenesisAddress hex_addr{};
    bool hex_ok = false;
    if (have_hex_recipient) {
        TRY_RESULT(recipient_v,
                   obj.extract_required_field("recipient",
                                              td::JsonValue::Type::Object));
        auto& rcp = recipient_v.get_object();

        TRY_RESULT(d_s,              rcp.get_required_string_field("d"));
        TRY_STATUS(decode_hex_fixed(d_s,
                                    hex_addr.diversifier.data(),
                                    hex_addr.diversifier.size(),
                                    "recipient.d"));

        TRY_RESULT(pk_d_s,           rcp.get_required_string_field("pk_d"));
        TRY_STATUS(decode_hex_fixed(pk_d_s,
                                    hex_addr.pk_d_compressed.data(),
                                    hex_addr.pk_d_compressed.size(),
                                    "recipient.pk_d"));

        TRY_RESULT(ivk_cm_s,         rcp.get_required_string_field("ivk_commitment"));
        TRY_STATUS(decode_hex_fixed(ivk_cm_s,
                                    hex_addr.ivk_commitment.data(),
                                    hex_addr.ivk_commitment.size(),
                                    "recipient.ivk_commitment"));

        TRY_RESULT(pk_mlkem_s,       rcp.get_required_string_field("pk_mlkem"));
        TRY_STATUS(decode_hex_var(pk_mlkem_s, hex_addr.pk_mlkem,
                                  kMlkemPkBytes, "recipient.pk_mlkem"));
        hex_ok = true;
    }

    // --- Reconcile / choose. --------------------------------------------
    if (env_ok && hex_ok) {
        // Both forms present → cross-check byte-for-byte.
        if (env_addr.diversifier      != hex_addr.diversifier      ||
            env_addr.pk_d_compressed  != hex_addr.pk_d_compressed  ||
            env_addr.ivk_commitment   != hex_addr.ivk_commitment   ||
            env_addr.pk_mlkem         != hex_addr.pk_mlkem) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: notes[" << idx
                << "] \"address\" envelope disagrees with \"recipient\" hex block");
        }
        out.recipient = std::move(hex_addr);
    } else if (env_ok) {
        out.recipient = std::move(env_addr);
    } else {
        out.recipient = std::move(hex_addr);
    }

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

// ---------------------------------------------------------------------------
// §10.3 60 / 25 / 15 distribution builder (K-genesis-distribution)
// ---------------------------------------------------------------------------
//
// Public entry: `build_genesis_notes_json`.
//
// Contract (design doc §10.3):
//   Input  : three recipient lists (airdrop / treasury / team), each a
//            sequence of (Address, nano-UNO value) pairs.
//   Output : canonical `zerostate-genesis-notes.json` — the same file the
//            K-genesis-loader `load_genesis_distribution` accepts
//            byte-for-byte.
//
// Steps, in the order the task spec pins:
//   1. Validate each list's sum matches the §10.3 category target
//      (12,600,000 / 5,250,000 / 3,150,000 UNO × 10^9).
//   2. Reject duplicate addresses (compared on the 1259-byte payload).
//   3. Sort each list by BLAKE2b-256(address_payload) ascending.
//   4. Concatenate airdrop || treasury || team → canonical index `i`.
//   5. For each entry:
//        rseed[i] = BLAKE2b-256(kGenesisRseedTagV1 || u32_be(i))
//        cm[i]    = Poseidon2("uno-cm-v1",
//                             d, pk_d, ivk_commitment, value,
//                             Poseidon2("uno-rcm-v1", rseed[i]))
//   6. Emit JSON via dump_genesis_distribution (same writer the loader
//      test already pins for byte output).

namespace {

// Build the 1259-byte flat address payload in §2.6 layout.
std::array<uint8_t, ::uno_workchain::crypto::kAddressPayloadBytes>
    flatten_address(const GenesisAddress& addr) {
    constexpr std::size_t N = ::uno_workchain::crypto::kAddressPayloadBytes;
    std::array<uint8_t, N> out{};
    std::memcpy(out.data() +  0, addr.diversifier.data(),     11);
    std::memcpy(out.data() + 11, addr.pk_d_compressed.data(), 32);
    std::memcpy(out.data() + 43, addr.ivk_commitment.data(),  32);
    // pk_mlkem MUST be 1184 B (§2.6); validate_recipient below rejects shorter.
    if (addr.pk_mlkem.size() == 1184) {
        std::memcpy(out.data() + 75, addr.pk_mlkem.data(), 1184);
    }
    return out;
}

static_assert(::uno_workchain::crypto::kAddressPayloadBytes == 1259,
              "address payload layout changed — rehash the canonical "
              "genesis sort");

td::Status validate_recipient(const DistributionRecipient& r,
                              const char* list_name, size_t idx) {
    if (r.address.pk_mlkem.size() != 1184) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: " << list_name << "[" << idx
            << "] pk_mlkem length " << r.address.pk_mlkem.size()
            << " != 1184 (§2.6)");
    }
    if (r.value_nano == 0) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: " << list_name << "[" << idx
            << "] value_nano == 0 (rejected — zero-value notes pollute "
               "the commitment tree without funding anyone)");
    }
    return td::Status::OK();
}

td::Result<uint64_t> sum_category(
        const std::vector<DistributionRecipient>& list,
        const char* list_name) {
    uint64_t total = 0;
    for (size_t i = 0; i < list.size(); ++i) {
        TRY_STATUS(validate_recipient(list[i], list_name, i));
        if (total > UINT64_MAX - list[i].value_nano) {
            return td::Status::Error(PSLICE()
                << "uno/genesis: " << list_name
                << " sum overflow at index " << i);
        }
        total += list[i].value_nano;
    }
    return total;
}

}  // namespace

std::array<uint8_t, 32> canonical_address_hash(const GenesisAddress& addr) {
    auto flat = flatten_address(addr);
    std::array<uint8_t, 32> out{};
    // Untagged BLAKE2b-256 over the raw address payload. Untagged chosen
    // deliberately — the sort key is an internal ordering primitive, not
    // a cryptographic commitment; a tag would only add ceremony without
    // changing the collision-resistance bound.
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 32);
    crypto_generichash_update(&st, flat.data(), flat.size());
    crypto_generichash_final(&st, out.data(), out.size());
    return out;
}

std::array<uint8_t, 32> derive_genesis_rseed(uint32_t address_index) {
    std::array<uint8_t, 32> out{};
    // rseed[i] = BLAKE2b-256("uno-genesis-rseed-v1" || u32_be(i))
    //
    // u32 big-endian so the wire layout matches the Rust-side derivation
    // byte-for-byte; the 4-byte index width accommodates up to
    // ~4.3 billion recipients (more than enough for any plausible 21 M
    // UNO airdrop).
    uint8_t idx_be[4] = {
        static_cast<uint8_t>((address_index >> 24) & 0xFF),
        static_cast<uint8_t>((address_index >> 16) & 0xFF),
        static_cast<uint8_t>((address_index >>  8) & 0xFF),
        static_cast<uint8_t>((address_index >>  0) & 0xFF),
    };
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 32);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(kGenesisRseedTagV1),
                              std::strlen(kGenesisRseedTagV1));
    crypto_generichash_update(&st, idx_be, 4);
    crypto_generichash_final(&st, out.data(), out.size());
    return out;
}

td::Result<std::string> build_genesis_notes_json(
        const GenesisDistributionInputs& inputs) {
    if (sodium_init() < 0) {
        return td::Status::Error("uno/genesis: libsodium init failed");
    }

    // --- Step 1: per-category sums -----------------------------------------
    TRY_RESULT(airdrop_sum,  sum_category(inputs.airdrop,  "airdrop"));
    TRY_RESULT(treasury_sum, sum_category(inputs.treasury, "treasury"));
    TRY_RESULT(team_sum,     sum_category(inputs.team,     "team"));

    if (inputs.airdrop.empty()) {
        return td::Status::Error("uno/genesis: airdrop list is empty");
    }
    if (airdrop_sum != kGenesisAirdropNano) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: airdrop sum " << airdrop_sum
            << " != §10.3 target " << kGenesisAirdropNano
            << " (12,600,000 × 10^9 nano-UNO)");
    }
    if (treasury_sum != kGenesisTreasuryNano) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: treasury sum " << treasury_sum
            << " != §10.3 target " << kGenesisTreasuryNano
            << " (5,250,000 × 10^9 nano-UNO)");
    }
    if (team_sum != kGenesisTeamNano) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: team sum " << team_sum
            << " != §10.3 target " << kGenesisTeamNano
            << " (3,150,000 × 10^9 nano-UNO)");
    }
    const uint64_t total = airdrop_sum + treasury_sum + team_sum;
    if (total != kGenesisTotalSupplyNano) {
        return td::Status::Error(PSLICE()
            << "uno/genesis: total supply " << total
            << " != §10.3 fixed supply " << kGenesisTotalSupplyNano);
    }

    // --- Step 2: duplicate-address check (across ALL three lists) ----------
    std::set<std::array<uint8_t, ::uno_workchain::crypto::kAddressPayloadBytes>>
        seen;
    auto probe_dup = [&](const std::vector<DistributionRecipient>& list,
                         const char* list_name) -> td::Status {
        for (size_t i = 0; i < list.size(); ++i) {
            auto flat = flatten_address(list[i].address);
            if (!seen.insert(flat).second) {
                return td::Status::Error(PSLICE()
                    << "uno/genesis: duplicate address detected at "
                    << list_name << "[" << i << "]");
            }
        }
        return td::Status::OK();
    };
    TRY_STATUS(probe_dup(inputs.airdrop,  "airdrop"));
    TRY_STATUS(probe_dup(inputs.treasury, "treasury"));
    TRY_STATUS(probe_dup(inputs.team,     "team"));

    // --- Step 3 + 4: sort each category, concatenate in order --------------
    auto sort_by_address_hash = [](std::vector<DistributionRecipient> in) {
        std::vector<std::pair<std::array<uint8_t, 32>,
                              DistributionRecipient>> keyed;
        keyed.reserve(in.size());
        for (auto& r : in) {
            keyed.emplace_back(canonical_address_hash(r.address),
                               std::move(r));
        }
        std::sort(keyed.begin(), keyed.end(),
                  [](const auto& a, const auto& b) {
                      return a.first < b.first;
                  });
        std::vector<DistributionRecipient> out;
        out.reserve(keyed.size());
        for (auto& kv : keyed) out.emplace_back(std::move(kv.second));
        return out;
    };
    auto airdrop_sorted  = sort_by_address_hash(inputs.airdrop);
    auto treasury_sorted = sort_by_address_hash(inputs.treasury);
    auto team_sorted     = sort_by_address_hash(inputs.team);

    std::vector<DistributionRecipient> canonical;
    canonical.reserve(airdrop_sorted.size() + treasury_sorted.size()
                      + team_sorted.size());
    for (auto& r : airdrop_sorted)  canonical.emplace_back(std::move(r));
    for (auto& r : treasury_sorted) canonical.emplace_back(std::move(r));
    for (auto& r : team_sorted)     canonical.emplace_back(std::move(r));

    // --- Step 5: assign rseed, compute cm ----------------------------------
    GenesisDistribution dist;
    dist.chain_id = inputs.chain_id;
    dist.notes.reserve(canonical.size());
    dist.total_supply_nano = total;
    for (size_t i = 0; i < canonical.size(); ++i) {
        GenesisNote n;
        n.recipient = std::move(canonical[i].address);
        n.value     = canonical[i].value_nano;
        n.rseed     = derive_genesis_rseed(static_cast<uint32_t>(i));

        NoteCommitmentInputs nci{};
        nci.d              = n.recipient.diversifier;
        nci.pk_d_bytes     = n.recipient.pk_d_compressed;
        nci.ivk_commitment = n.recipient.ivk_commitment;
        nci.value          = n.value;
        nci.rcm            = compute_rcm(n.rseed);
        n.cm               = compute_note_commitment(nci);

        dist.notes.emplace_back(std::move(n));
    }

    // --- Step 6: serialize via the loader-compatible writer ----------------
    return dump_genesis_distribution(dist);
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
