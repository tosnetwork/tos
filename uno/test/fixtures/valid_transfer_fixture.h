/*
    uno/test/fixtures/valid_transfer_fixture.h

    Shared valid-Transfer builder for Uno Workchain tests.

    Extracted from `uno/test/test-uno-end-to-end.cpp` under K-p7-fixtures so
    `test-uno-mandatory-negatives.cpp` can exercise the §4.3 reject paths that
    sit AFTER steps 1–3 (Schnorr / Ristretto validation) without re-implementing
    the valid-Transfer pipeline in every TU.

    ## What the fixture produces

    A `Transfer` whose §4.3 steps 1–3 are valid against the supplied UnoState
    config:

      * real Ristretto255 points (`rk`, `epk` via `derive_diversified_base_point`);
      * real `rk = ak + α·G` randomised spend-auth key;
      * real Schnorr-on-Ristretto255 signature over `canonical_tx_hash(tx)`;
      * deterministic sha256-derived `cm` / `nullifier` stand-ins (self-consistent
        within a test binary — the Poseidon2 identities enforced in-circuit are
        P.2 / A4 territory and not the contract of this fixture);
      * a non-empty `zk_proof` chunk chain (accepted as load-bearing for the
        decoder; content bytes are opaque — the Plonky3 verify step is either
        stubbed with a weak `uno_plonky3_verify` that always returns
        VerifyFailed, or provided by the real Rust crate in full-build CI).

    ## Test-only proof-override contract

    `uno/core/compute-phase.cpp` exports
    `install_test_proof_override_for_test(fn)` which installs a callback
    consulted in lieu of the Rust Plonky3 verifier. In the skeleton / test
    builds wired through this fixture the override IS installed — but under
    the current linker setup the weak `uno_plonky3_verify` stub from each
    test TU returns VerifyFailed (code 4), so `verify_transfer_serial`
    deterministically returns `VerifyResult::BadPlonky3Proof` at §4.3 step 4.

    Callers that want a tx to pass ALL of verify steps 1–4 must either:
      (a) link the real `uno_plonky3_ffi` crate into the test target, or
      (b) build a valid-up-to-step-3 Transfer with this fixture and assert
          their expected pre-step-4 reject (e.g. `NullifierAlreadySpent` by
          pre-inserting the nullifier into state before calling verify).

    Neither `test-uno-end-to-end.cpp` nor `test-uno-mandatory-negatives.cpp`
    currently wires option (a); the end-to-end test bypasses
    `verify_transfer_serial` entirely and drives the apply-phase invariants
    directly against the state mutators, while the mandatory-negatives tests
    pin the specific reject they care about (step 2 for replay, step 4 for
    cross-chain / inflation — where "step 4 reject" under weak stubs is
    produced by the stub itself, byte-identically to what a mismatched
    chain_id / unbalanced-output-sum public-input would cause under the
    real Rust verifier).

    ## Source of truth

    The inline construction in the pre-refactor `test-uno-end-to-end.cpp`'s
    `build_transfer()`. Kept byte-for-byte equivalent under refactor (the
    end-to-end test's output is invariant through this change).
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "td/utils/SharedSlice.h"
#include "td/utils/UInt.h"

#include "uno/core/transaction.h"
#include "uno/crypto/ristretto255.h"
#include "uno/crypto/schnorr-ristretto.h"

namespace uno_workchain::test_fixtures {

// ---------------------------------------------------------------------------
// Wallet stand-in.
//
// Provides just enough material to build a valid Spend / Output pair:
//   - `ask` / `ak`: real Ristretto scalar + point
//   - `nk` / `ivk`: sha256-derived stand-ins for the (still-stubbed) Poseidon2
//   - `ovk`:       32 random bytes for the audit path
//   - `pk_d`:      valid Ristretto point via hash-to-curve on diversifier
// The field shapes match the DemoWallet struct originally living in
// `test-uno-end-to-end.cpp`.
// ---------------------------------------------------------------------------
struct DemoWallet {
    std::string name;
    std::array<uint8_t, 32>                           seed_bytes{};
    uno_workchain::crypto::RistrettoScalar            ask;
    uno_workchain::crypto::RistrettoPoint             ak;
    std::array<uint8_t, 32>                           nk{};
    std::array<uint8_t, 32>                           ivk{};
    td::SecureString                                  ovk;
    std::array<uint8_t, 11>                           diversifier{};
    uno_workchain::crypto::RistrettoPoint             pk_d;
    std::array<uint8_t, 32>                           ivk_commitment{};
};

/// Deterministic wallet constructor. `seed_byte` is the only "randomness" so
/// two calls with the same seed yield byte-identical wallets across runs.
DemoWallet make_wallet(const char* name, uint8_t seed_byte);

// ---------------------------------------------------------------------------
// Small helpers re-exported so TUs using the fixture do not need to duplicate
// them.
// ---------------------------------------------------------------------------

/// Deterministic sha256-based note-commitment stand-in (see file-header note
/// on Poseidon2 deferral). Byte-equivalent to the pre-refactor inline fn.
td::Bits256 make_note_cm(const DemoWallet& rec,
                         uint64_t value,
                         const std::array<uint8_t, 32>& rcm);

/// sha256 over a byte buffer. Exposed for filter-tag / nullifier-rho
/// derivations that need a deterministic 32-byte digest in tests.
std::array<uint8_t, 32> test_digest(const void* p, std::size_t n);

/// Compress a RistrettoPoint into a Bits256 (32-byte) field form.
td::Bits256 point_to_bits256(const uno_workchain::crypto::RistrettoPoint& p);

// ---------------------------------------------------------------------------
// make_valid_transfer
// ---------------------------------------------------------------------------

/// Per-output spec. The first entry in `outputs` is "to receiver"; any
/// subsequent entries are "change to sender" — matching the original
/// build_transfer layout. `out_ciphertext` is the 80-byte on-wire slot;
/// callers that wire ovk-AEAD (end-to-end audit path) fill it in, otherwise
/// zeros are fine for the verify-rejection tests (verify doesn't inspect
/// out_ciphertext contents, only its 80-byte length and its role in
/// canonical_tx_hash).
struct OutputSpec {
    uint64_t                    value{0};
    std::array<uint8_t, 80>     out_ciphertext{};
};

/// Builder knobs for `make_valid_transfer`. Holds references into the caller-
/// owned wallets so the fixture does not copy keys.
struct ValidTransferParams {
    const DemoWallet*           sender{nullptr};
    const DemoWallet*           receiver{nullptr};
    uint64_t                    spend_value{0};        // Σ input (single spend)
    std::vector<OutputSpec>     outputs;               // ≥1; first is to receiver
    uint64_t                    fee_nano{0};
    td::Bits256                 anchor{};
    uint64_t                    expiry_block{0};
    uint32_t                    chain_id{0};
    // Optional: override the nullifier bytes for the (single) spend. When
    // unset, the fixture derives a deterministic nullifier from `sender.nk`.
    // Exposed so the replay test can echo a previously-spent nullifier.
    bool                        override_nullifier{false};
    std::array<uint8_t, 32>     nullifier_bytes{};
    // Validation switch: when true, the fixture asserts that
    //   spend_value == Σ outputs[i].value + fee_nano
    // which is §3.3 claim 8 balance. Set to false for the inflation-attempt
    // test which DELIBERATELY breaks balance (Σ outputs + fee > spend).
    bool                        enforce_balance{true};
};

/// A built Transfer, plus the Schnorr key material used to sign it. The
/// holder keeps `rsk` / `rk` so callers can re-sign after a post-build
/// mutation of the tx (e.g. flipping chain_id → tx_hash changes → re-sign).
struct ValidTransferFixture {
    uno_workchain::Transfer                 tx;
    uno_workchain::crypto::RistrettoScalar  rsk;
    uno_workchain::crypto::RistrettoPoint   rk;
};

/// Build a valid-up-to-§4.3-step-3 Transfer. Aborts via std::exit if the
/// underlying crypto call fails (the same behaviour as the pre-refactor
/// inline builder — any failure here is a harness bug, not a test reject).
ValidTransferFixture make_valid_transfer(const ValidTransferParams& p);

/// Re-sign a mutated Transfer with the held `rsk`. Use after mutating any
/// field that contributes to `canonical_tx_hash` (chain_id, anchor, fee,
/// outputs, ...). Recomputes tx_hash, then writes `spend_auth_sig[0]`.
void resign_spend0(ValidTransferFixture& fx);

}  // namespace uno_workchain::test_fixtures
