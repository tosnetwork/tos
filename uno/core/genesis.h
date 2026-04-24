/*
    Uno Workchain — zerostate builder and genesis note loader (§10.3).

    build_zerostate() returns the cell tree for the wc=2 zerostate. That
    cell tree contains the single executor account `(wc=2, 0x…01)` whose
    `StateInit.data` is the initial `UnoShardState`:

      - Empty frontier with 32 canonical empty-subtree hashes.
      - Empty nullifier set.
      - Anchor window seeded with one entry: the root of the empty tree.
      - Stats zeroed.
      - N genesis notes appended as leaves of the commitment tree (the
        zerostate "genesis tx") — see §10.3.

    The `zerostate-genesis-notes.json` file (loaded by the wallet & by
    this module's helpers) carries the `(Note plaintext, Address)` pairs
    so genesis recipients can later spend their notes.  After genesis,
    note plaintexts never appear on-chain again.

    TODO(uno-design-gap): the total UNO supply and the explicit genesis
    distribution list are marked TBD in §10.3.  The API below accepts an
    explicit `GenesisDistribution` so network ops can supply the final
    list at chain-boot time without a rebuild.

    Source: TOS-specific adapter; see doc/uno-workchain.md §10.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells.h"
#include "tos/tos-types.h"

#include "uno/core/state.h"
#include "uno/core/workchain.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Genesis distribution
// ---------------------------------------------------------------------------

/// Plaintext address bytes (§2.6 Addresses, updated per decision #1):
///   11 B diversifier `d`
///   32 B compressed Ristretto `pk_d`
///   32 B `ivk_commitment` = Poseidon2("uno-ivk-cm-v1", ivk, d)
///   1184 B ML-KEM-768 `pk_mlkem`
/// Total 1259 B. Stored raw; genesis consumers interpret the layout.
/// `ivk_commitment` is the public binding anchor that will later be hashed
/// into every `cm` sent to this address (§3.2), so it must be present at
/// genesis time — the chain-boot tool computes it from the recipient's
/// wallet-side `ivk`.
struct GenesisAddress {
    std::array<uint8_t, 11>   diversifier;         // d
    std::array<uint8_t, 32>   pk_d_compressed;     // Ristretto255 pk_d
    std::array<uint8_t, 32>   ivk_commitment{};    // Poseidon2("uno-ivk-cm-v1", ivk, d)
    std::vector<uint8_t>      pk_mlkem;            // ML-KEM-768, 1184 B
};

/// One entry of the genesis distribution. `cm` is the note commitment
/// (Poseidon2 over Goldilocks, §3.2); computed off-line by the chain-boot
/// tool and fed into this module. `rseed` and `value` travel with the
/// entry only so the wallet-side genesis note loader can publish
/// `zerostate-genesis-notes.json`.
struct GenesisNote {
    GenesisAddress                   recipient;
    uint64_t                         value{0};           // UNO nano-units
    std::array<uint8_t, 32>          rseed{};            // 32 B randomness seed
    std::array<uint8_t, kHashBytes>  cm{};               // pre-computed commitment
};

/// The full genesis distribution: a list of notes in canonical order. The
/// canonical order defines the leaf positions in the commitment tree —
/// note `i` appends at leaf position `i`, so wallets can locate their
/// genesis leaves deterministically from the published JSON.
struct GenesisDistribution {
    uint32_t chain_id{kDefaultTestnetChainId};
    std::vector<GenesisNote> notes;

    /// Monotone total of `value` across every note. This is the fixed UNO
    /// supply (§10.3 "sole and permanent source of UNO supply"). Overflow
    /// is checked at build time via `build_zerostate_state()`.
    // TODO(uno-design-gap): the target total is TBD; callers pass the
    // final number at chain boot.
    uint64_t total_supply_nano{0};
};

// ---------------------------------------------------------------------------
// §10.3 60 / 25 / 15 distribution builder (K-genesis-distribution)
// ---------------------------------------------------------------------------

/// Per-recipient input for the §10.3 distribution builder. `rseed` and
/// `cm` are populated by the builder; the caller only supplies the address
/// (in any of the three forms GenesisAddress accepts) and the nano-UNO
/// value. Duplicate addresses anywhere across the three lists are a
/// validation error.
struct DistributionRecipient {
    GenesisAddress address;
    uint64_t       value_nano{0};
};

/// 60% airdrop / 25% treasury / 15% team lists, as enumerated by the
/// genesis-distribution operator. The builder canonicalises the order
/// (each list sorted by address hash, then airdrop → treasury → team in
/// that order) and validates the per-category and total sums against the
/// §10.3 constants before emitting.
struct GenesisDistributionInputs {
    uint32_t                          chain_id{kChainIdTestnet};
    std::vector<DistributionRecipient> airdrop;
    std::vector<DistributionRecipient> treasury;
    std::vector<DistributionRecipient> team;
};

/// Canonical §10.3 constants (K-genesis-distribution). The builder and
/// loader BOTH pin these — any future change requires a `scheme_id` bump
/// because the zerostate state root is bound to the resulting cm set.
///
/// 200,000,000 UNO × 10^9 nano-units/UNO = 2.0e17 nano-UNO.
/// (Raised from the original 21,000,000 cap per network-wide 200 M
/// issuance alignment across TOS / EMO / UNO; supersedes uno-workchain.md
/// Decision #36.)
constexpr uint64_t kGenesisTotalSupplyNano = 200'000'000ULL * 1'000'000'000ULL;

/// Per-category targets. 200M is divisible by 20 so 60/25/15 still lands
/// on whole-UNO boundaries (120M / 50M / 30M).
constexpr uint64_t kGenesisAirdropNano  = 120'000'000ULL * 1'000'000'000ULL;  // 60%
constexpr uint64_t kGenesisTreasuryNano =  50'000'000ULL * 1'000'000'000ULL;  // 25%
constexpr uint64_t kGenesisTeamNano     =  30'000'000ULL * 1'000'000'000ULL;  // 15%

static_assert(kGenesisAirdropNano + kGenesisTreasuryNano + kGenesisTeamNano
              == kGenesisTotalSupplyNano,
              "genesis category splits must sum to total supply");

/// Domain-separation tag for the per-note rseed derivation (§10.3 step 2):
///
///     rseed[i] = BLAKE2b-256("uno-genesis-rseed-v1" || u32_be(i))
///
/// where `i` is the canonical-order index (0..N-1) AFTER sorting per
/// category by address hash and concatenating airdrop → treasury → team.
/// 4-byte big-endian index matches the wire convention the loader reads.
constexpr const char kGenesisRseedTagV1[] = "uno-genesis-rseed-v1";

/// Build the canonical `zerostate-genesis-notes.json` for the given
/// distribution (§10.3, K-genesis-distribution).
///
/// Steps, in order:
///   1. Validate each list's sum matches the §10.3 category target
///      (12.6 M / 5.25 M / 3.15 M nano-UNO).
///   2. Reject duplicate addresses anywhere across the three lists
///      (compared on the 1259-byte payload).
///   3. Sort each list by BLAKE2b-256(address_bytes) ascending.
///   4. Concatenate in order airdrop || treasury || team. The resulting
///      index `i` is the canonical position in the commitment tree.
///   5. For each entry: rseed = BLAKE2b-256(kGenesisRseedTagV1 || u32_be(i));
///      cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value,
///           Poseidon2("uno-rcm-v1", rseed)).
///   6. Emit JSON via `dump_genesis_distribution` so byte output exactly
///      matches what `load_genesis_distribution` accepts.
///
/// Uses the Bech32m envelope form for the `address` field when available
/// (K-bech32m). The hex `recipient` block is emitted alongside it so
/// third-party tooling without a Bech32m decoder can still read the file.
td::Result<std::string> build_genesis_notes_json(
    const GenesisDistributionInputs& inputs);

/// Canonical sort key for a GenesisAddress: BLAKE2b-256 over the 1259-byte
/// address payload (§2.6 layout). Exposed so tests and Rust-side tooling
/// can mirror the sort byte-for-byte.
std::array<uint8_t, 32> canonical_address_hash(const GenesisAddress& addr);

/// Canonical rseed derivation exposed for cross-impl parity tests.
std::array<uint8_t, 32> derive_genesis_rseed(uint32_t address_index);

// ---------------------------------------------------------------------------
// Zerostate builders
// ---------------------------------------------------------------------------

/// Build the in-memory `UnoShardState` corresponding to the genesis state.
/// Populates:
///   - An empty `CommitmentTree` seeded with 32 canonical empty-subtree
///     hashes, then extended by appending every `GenesisNote::cm` in
///     declaration order.
///   - An empty `NullifierSet`.
///   - An `AnchorWindow` seeded with one entry: the root of the tree AFTER
///     the genesis notes were appended (this matches §10.3 "Anchor window
///     seeded with the root of an empty tree (one entry)" reinterpreted
///     against the "seed N genesis notes" step 2 — the window stores the
///     post-genesis root so the first user spend can reference it).
///   - `stats.burned_fees = 0`, `tx_count = 1` (the synthetic genesis tx),
///     `note_count = |notes|`.
///   - `next_position = |notes|`.
///
/// Returns a populated state on success and logs ERROR + returns
/// `UnoShardState::make_empty()` on any failure.
UnoShardState build_zerostate_state(const GenesisDistribution& dist);

/// K-genesis-loader convenience wrapper: takes a raw `std::vector<GenesisNote>`
/// and returns the corresponding `UnoShardState`. For each note, if
/// `GenesisNote::cm` is all-zero the loader recomputes it from the
/// (recipient, value, rseed) tuple per §3.2; if the caller supplied `cm`
/// it is verified against the recomputation and the function returns an
/// empty state on mismatch. `chain_id` is taken from the runtime
/// ConfigParam 84 setting (`current_uno_chain_id()`).
///
/// Canonical §10.3 step-3 append order is preserved: commitment tree
/// appended in vector order, post-genesis root pushed into the anchor
/// window.
UnoShardState build_genesis_state(const std::vector<GenesisNote>& notes);

/// Convenience: build_zerostate_state + serialize via `cell-state.h`. Used
/// by `init_uno_workchain` to write the initial StateInit.data.
td::Ref<vm::Cell> build_zerostate_state_cell(const GenesisDistribution& dist);

/// Build the wc=2 zerostate root cell the masterchain registry consumes
/// (ConfigParam 12 refers to its root_hash + file_hash via
/// `build_uno_workchain_descr`). The root cell encodes a minimal
/// ShardState-shaped envelope carrying `(wc=2 shard ident, chain_id,
/// serialized UnoShardState)`.
///
/// @param dist         Genesis distribution (may be empty for an unseeded
///                     zerostate used in dev-net smoke tests).
/// @param out_root     [out] Root hash of the resulting cell.
/// @param out_file     [out] BoC file hash of the resulting cell.
/// @return             Cell on success, null Ref on failure.
td::Ref<vm::Cell> build_zerostate(const GenesisDistribution& dist,
                                   tos::RootHash& out_root,
                                   tos::FileHash& out_file);

// ---------------------------------------------------------------------------
// Genesis-notes JSON I/O
// ---------------------------------------------------------------------------

/// Load `zerostate-genesis-notes.json` from disk (§10.3 final sentence).
/// Returns a populated distribution on success.
///
/// The JSON schema the loader expects:
/// ```
/// {
///   "chain_id": 0x554E4F54,
///   "total_supply_nano": "100000000000000000",   // optional; recomputed if absent
///   "notes": [
///     {
///       "recipient": {
///         "d":              "hex:11B",
///         "pk_d":           "hex:32B",
///         "ivk_commitment": "hex:32B",   // decision #1: published ivk-binding field
///         "pk_mlkem":       "hex:1184B"
///       },
///       "value":  "100000000",
///       "rseed":  "hex:32B",
///       "cm":     "hex:32B"
///     },
///     ...
///   ]
/// }
/// ```
///
/// Off-chain tooling (`tosctl uno-genesis-build`) produces the file;
/// validators load it at boot only if they are re-deriving the zerostate
/// locally (the canonical zerostate cell is distributed via the
/// genesis BoC, so most nodes never need this path).
td::Result<GenesisDistribution> load_genesis_distribution(
    const std::string& json_path);

/// Serialize a `GenesisDistribution` to the canonical JSON representation
/// described above. Deterministic within a minor-version: identical input
/// bytes on every host.
td::Result<std::string> dump_genesis_distribution(
    const GenesisDistribution& dist);

}  // namespace uno_workchain
