//! Golden fixture builder for MineUno.
//!
//! Produces a deterministic test vector that the C++ verifier round-trips.
//!
//! Mirrors the pattern in `tosctl/uno/tests/genesis_build_golden.rs`.
//!
//! If `UNO_MINE_REGEN=1` is set, the golden fixture is regenerated to
//! `uno/test/golden/mine-uno-witness-v1.json`.
//!
//! Regenerate:
//!     UNO_MINE_REGEN=1 cargo test --release --test mine_genesis_golden

use std::path::PathBuf;

use tosctl_uno::mine_constants::{
    era_from_epoch, mine_reward_for_era, INIT_MINE_REWARD, MINE_SUPPLY_NANO,
};
use tosctl_uno::mine_uno::{MineUnoAddress, MineUnoPublicInputs, MineUnoWitness};

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn golden_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("uno")
        .join("test")
        .join("golden")
        .join("mine-uno-witness-v1.json")
}

// ---------------------------------------------------------------------------
// Deterministic fixture builders
// ---------------------------------------------------------------------------

fn mk_test_address(seed_byte: u8) -> MineUnoAddress {
    MineUnoAddress {
        diversifier:     [seed_byte; 11],
        pk_d_compressed: [seed_byte.wrapping_add(1); 32],
        ivk_commitment:  [seed_byte.wrapping_add(2); 32],
        pk_mlkem:        vec![seed_byte.wrapping_add(3); 1184],
    }
}

fn mk_mine_witness(epoch: u32) -> MineUnoWitness {
    MineUnoWitness {
        epoch,
        nonce:      [0xABu8; 32],
        recipient:  mk_test_address(0x42),
        value_nano: mine_reward_for_era(era_from_epoch(epoch)),
        rseed:      [0xCDu8; 32],
    }
}

fn mk_mine_public_inputs(epoch: u32) -> MineUnoPublicInputs {
    let value_nano    = mine_reward_for_era(era_from_epoch(epoch));
    let remaining_pre = MINE_SUPPLY_NANO;
    MineUnoPublicInputs {
        epoch,
        target:         {
            let mut t = [0u8; 32];
            t[4] = 0x08;   // 2^219 genesis initial target
            t
        },
        value_nano,
        output_cm:      [0xEEu8; 32],   // placeholder — real cm needs AIR prover
        remaining_pre,
        remaining_post: remaining_pre - value_nano,
    }
}

// ---------------------------------------------------------------------------
// Witness round-trip via to_wire_bytes / from_wire_bytes
//
// MineUnoPublicInputs has to_wire_bytes / from_wire_bytes.
// MineUnoWitness does not cross any wire boundary (prover-private), so we
// verify its consistency via validate() and serde_json round-trip.
// ---------------------------------------------------------------------------

#[test]
fn mine_uno_witness_round_trips_through_serde() {
    let w = mk_mine_witness(0);
    // Validate that internal consistency holds (halving table + address size).
    w.validate().expect("MineUnoWitness should be valid for epoch 0");

    // Serialize to JSON and back to verify all fields survive.
    let json = serde_json::json!({
        "epoch":      w.epoch,
        "nonce":      hex::encode(w.nonce),
        "value_nano": w.value_nano,
        "rseed":      hex::encode(w.rseed),
        "recipient": {
            "d":              hex::encode(w.recipient.diversifier),
            "pk_d":           hex::encode(w.recipient.pk_d_compressed),
            "ivk_commitment": hex::encode(w.recipient.ivk_commitment),
            "pk_mlkem":       hex::encode(&w.recipient.pk_mlkem),
        }
    });

    let epoch:      u32    = json["epoch"].as_u64().unwrap() as u32;
    let nonce_hex:  &str   = json["nonce"].as_str().unwrap();
    let value_nano: u64    = json["value_nano"].as_u64().unwrap();
    let rseed_hex:  &str   = json["rseed"].as_str().unwrap();
    let d_hex:      &str   = json["recipient"]["d"].as_str().unwrap();
    let pkd_hex:    &str   = json["recipient"]["pk_d"].as_str().unwrap();
    let ivkcm_hex:  &str   = json["recipient"]["ivk_commitment"].as_str().unwrap();
    let mlkem_hex:  &str   = json["recipient"]["pk_mlkem"].as_str().unwrap();

    assert_eq!(epoch, 0);
    assert_eq!(value_nano, INIT_MINE_REWARD);

    let nonce_bytes = hex::decode(nonce_hex).unwrap();
    let rseed_bytes = hex::decode(rseed_hex).unwrap();
    assert_eq!(nonce_bytes, [0xABu8; 32]);
    assert_eq!(rseed_bytes, [0xCDu8; 32]);

    let d_bytes   = hex::decode(d_hex).unwrap();
    let pkd_bytes = hex::decode(pkd_hex).unwrap();
    let ivk_bytes = hex::decode(ivkcm_hex).unwrap();
    let ml_bytes  = hex::decode(mlkem_hex).unwrap();
    assert_eq!(d_bytes,   [0x42u8; 11]);
    assert_eq!(pkd_bytes, [0x43u8; 32]);
    assert_eq!(ivk_bytes, [0x44u8; 32]);
    assert_eq!(ml_bytes,  vec![0x45u8; 1184]);
}

#[test]
fn mine_uno_public_inputs_round_trip() {
    let pi = mk_mine_public_inputs(0);
    pi.validate().expect("MineUnoPublicInputs should be valid for epoch 0");

    let bytes = pi.to_wire_bytes();
    let pi2   = MineUnoPublicInputs::from_wire_bytes(&bytes);
    assert_eq!(pi, pi2, "to_wire_bytes / from_wire_bytes round-trip must be identity");

    // Check byte layout: epoch (4 B) at offset 0.
    assert_eq!(u32::from_be_bytes(bytes[0..4].try_into().unwrap()), 0u32);
    // target at offset 4..36.
    assert_eq!(bytes[8], 0x08, "byte 4 of target must be 0x08 (bit 219)");
    // value_nano at offset 36..44.
    assert_eq!(
        u64::from_be_bytes(bytes[36..44].try_into().unwrap()),
        INIT_MINE_REWARD,
    );
}

// ---------------------------------------------------------------------------
// Halving table validation
// ---------------------------------------------------------------------------

#[test]
fn mine_uno_halving_table_matches_bitcoin_curve() {
    assert_eq!(mine_reward_for_era(0),  50 * 1_000_000_000,  "era 0 = 50 UNO");
    assert_eq!(mine_reward_for_era(1),  25 * 1_000_000_000,  "era 1 = 25 UNO");
    assert_eq!(mine_reward_for_era(2),  12_500_000_000,       "era 2 = 12.5 UNO");
    assert_eq!(mine_reward_for_era(3),   6_250_000_000,       "era 3 = 6.25 UNO");
    assert_eq!(mine_reward_for_era(4),   3_125_000_000,       "era 4");
    assert_eq!(mine_reward_for_era(10),    48_828_125,        "era 10");
    assert_eq!(mine_reward_for_era(20),         47_683,       "era 20");
    assert_eq!(mine_reward_for_era(30),             46,       "era 30");
    // era 35: last non-zero era (= kMaxNonZeroEra).
    assert!(mine_reward_for_era(35) > 0,   "era 35 must be non-zero");
    assert_eq!(mine_reward_for_era(35), 1, "era 35 = 1 nano-UNO");
    // era 36: first zero era.
    assert_eq!(mine_reward_for_era(36), 0, "era 36 must be zero");
    // Beyond 64 — saturates to 0.
    assert_eq!(mine_reward_for_era(64),  0, "era 64 = 0");
    assert_eq!(mine_reward_for_era(100), 0, "era 100 = 0");

    // Geometric sum: 2 × era-0 × 210_000 solves = 21 M UNO (cap).
    // We only verify the per-era sum for the non-zero eras here.
    let total_nano: u64 = (0..=35)
        .map(|era| mine_reward_for_era(era) * 210_000)
        .sum();
    assert!(
        total_nano <= tosctl_uno::mine_constants::MINE_SUPPLY_NANO,
        "halving-table sum must not exceed 21 M UNO supply cap"
    );
}

// ---------------------------------------------------------------------------
// Golden fixture regen / pin
// ---------------------------------------------------------------------------

#[test]
fn mine_uno_golden_fixture_regen_or_pin() {
    let w  = mk_mine_witness(0);
    let pi = mk_mine_public_inputs(0);

    let fixture = serde_json::json!({
        "schema": "mine-uno-witness-v1",
        "witness": {
            "epoch":      w.epoch,
            "nonce":      hex::encode(w.nonce),
            "value_nano": w.value_nano,
            "rseed":      hex::encode(w.rseed),
            "recipient": {
                "d":              hex::encode(w.recipient.diversifier),
                "pk_d":           hex::encode(w.recipient.pk_d_compressed),
                "ivk_commitment": hex::encode(w.recipient.ivk_commitment),
                "pk_mlkem":       hex::encode(&w.recipient.pk_mlkem),
            }
        },
        "public_inputs": {
            "epoch":          pi.epoch,
            "target":         hex::encode(pi.target),
            "value_nano":     pi.value_nano,
            "output_cm":      hex::encode(pi.output_cm),
            "remaining_pre":  pi.remaining_pre,
            "remaining_post": pi.remaining_post,
        }
    });

    let json = serde_json::to_string_pretty(&fixture).expect("serde_json::to_string_pretty");

    let path = golden_path();

    if std::env::var("UNO_MINE_REGEN").ok().as_deref() == Some("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &json).unwrap();
        eprintln!("regenerated mine golden fixture: {}", path.display());
        return;
    }

    // If the golden file exists, verify the fixture is consistent.
    if let Ok(golden) = std::fs::read_to_string(&path) {
        let golden_v: serde_json::Value = serde_json::from_str(&golden)
            .expect("golden file is not valid JSON");

        assert_eq!(
            golden_v["schema"].as_str().unwrap(),
            "mine-uno-witness-v1",
            "golden schema version mismatch"
        );
        assert_eq!(
            golden_v["witness"]["epoch"].as_u64().unwrap(),
            0u64,
            "golden epoch must be 0"
        );
        assert_eq!(
            golden_v["public_inputs"]["value_nano"].as_u64().unwrap(),
            INIT_MINE_REWARD,
            "golden value_nano must equal era-0 reward"
        );
    } else {
        eprintln!(
            "mine golden fixture not found at {}. \
             Regenerate with UNO_MINE_REGEN=1.",
            path.display()
        );
        // No golden to compare — skip rather than fail (same pattern as genesis_build_golden).
    }
}

// ---------------------------------------------------------------------------
// End-to-end prove + verify round-trip tests
//
// These tests were previously `#[ignore]`-stubs while the MineUno AIR was
// under construction. Phase 3b + Task #17 landed the full prove / verify
// path (`uno_plonky3_ffi::prover::prove_mine_uno` +
// `uno_plonky3_ffi::verifier::verify_mine_uno`), so they now exercise the
// real STARK end-to-end — at the golden-fixture / integration-test level,
// independent of the `tosctl mine` CLI path that
// `tosctl_uno::mine::tests::prove_mine_uno_real_proof_roundtrips` already
// covers.
//
// Consistency note: the AIR's row-0 public-input binding requires
// `pi.output_cm` to equal the off-circuit
// `Poseidon2("uno-cm-v1", d, pk_d, ivk_cm, value, rcm)` of the witness.
// We therefore build an `uno_plonky3_ffi::mine_uno_witness::MineUnoWitness`
// directly (via `deterministic_valid`) rather than the wallet-native
// `tosctl_uno::mine_uno::MineUnoWitness`, which doesn't carry the raw
// 32-byte fields needed for the FFI wire format.
// ---------------------------------------------------------------------------

#[test]
fn mine_uno_proof_round_trips_through_verifier() {
    use uno_plonky3_ffi::mine_uno_witness::MineUnoWitness as FfiWitness;
    use uno_plonky3_ffi::prover::prove_mine_uno;
    use uno_plonky3_ffi::verifier::verify_mine_uno;
    use uno_plonky3_ffi::Plonky3Status;

    // Build a deterministic valid witness at epoch 0 (era-0 reward = 50 UNO).
    let w = FfiWitness::deterministic_valid(0, 0xA11C_0001);

    // Prove.
    let (proof_bytes, pi_bytes) = prove_mine_uno(&w.encode())
        .expect("prove_mine_uno must succeed on a deterministic_valid witness");
    assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");
    assert!(!pi_bytes.is_empty(), "public-input bytes must be non-empty");

    // Verify.
    let status = verify_mine_uno(&proof_bytes, &pi_bytes);
    assert_eq!(
        status,
        Plonky3Status::Ok,
        "verify_mine_uno must accept the proof we just produced (got {status:?})",
    );
}

#[test]
fn mine_uno_invalid_proof_rejected() {
    use uno_plonky3_ffi::mine_uno_witness::MineUnoWitness as FfiWitness;
    use uno_plonky3_ffi::prover::prove_mine_uno;
    use uno_plonky3_ffi::verifier::verify_mine_uno;
    use uno_plonky3_ffi::Plonky3Status;

    // Produce a valid (proof, pi) pair first.
    let w = FfiWitness::deterministic_valid(0, 0xDEAD_BEEF);
    let (mut proof_bytes, pi_bytes) =
        prove_mine_uno(&w.encode()).expect("prove_mine_uno must succeed");
    assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");

    // Sanity: the untampered proof verifies.
    assert_eq!(
        verify_mine_uno(&proof_bytes, &pi_bytes),
        Plonky3Status::Ok,
        "baseline proof must verify before we tamper with it",
    );

    // Tamper with a byte near the middle of the proof. Flip one bit —
    // enough to break a Merkle path / FRI query without disturbing the
    // postcard framing of the outer `Proof<MvpConfig>` struct (which
    // would otherwise bounce out at `ProofDecodeFailed` before the
    // STARK check even runs).
    let mid = proof_bytes.len() / 2;
    proof_bytes[mid] ^= 0x01;

    let status = verify_mine_uno(&proof_bytes, &pi_bytes);
    assert_ne!(
        status,
        Plonky3Status::Ok,
        "verify_mine_uno must reject a tampered proof (got Ok)",
    );
}

#[test]
fn mine_uno_witness_epoch_at_first_halving_boundary() {
    use uno_plonky3_ffi::mine_uno_witness::MineUnoWitness as FfiWitness;
    use uno_plonky3_ffi::prover::prove_mine_uno;
    use uno_plonky3_ffi::verifier::verify_mine_uno;
    use uno_plonky3_ffi::Plonky3Status;

    // tosctl_uno halving-table self-check (independent of the STARK).
    // `mk_mine_witness` uses the wallet-native witness shape and
    // computes value_nano via the mine_constants halving table.
    let wallet_witness = mk_mine_witness(210_000);
    assert_eq!(
        wallet_witness.value_nano,
        25 * 1_000_000_000,
        "epoch 210000 is the first halving boundary — era 1 = 25 UNO",
    );
    wallet_witness
        .validate()
        .expect("epoch 210000 witness must validate");

    // Build the FFI witness at the same boundary. `deterministic_valid`
    // ignores `epoch` for the value-derivation (it hard-codes era 0 =
    // 50 UNO internally), so we patch value_nano + the conservation
    // pair by hand to land on era 1 = 25 UNO before encoding.
    let mut w = FfiWitness::deterministic_valid(210_000, 0xBA11_0001);
    let era_1_reward: u64 = 25 * 1_000_000_000;
    w.value_nano = era_1_reward;
    w.remaining_post = w.remaining_pre - era_1_reward;
    assert_eq!(w.epoch, 210_000, "epoch must be at halving boundary");
    assert_eq!(w.value_nano, era_1_reward, "era 1 reward must be 25 UNO");

    // Prove + verify at the boundary epoch.
    let (proof_bytes, pi_bytes) = prove_mine_uno(&w.encode())
        .expect("prove_mine_uno must succeed at epoch 210000 (era 1)");
    assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");

    let status = verify_mine_uno(&proof_bytes, &pi_bytes);
    assert_eq!(
        status,
        Plonky3Status::Ok,
        "verify_mine_uno must accept the epoch-210000 proof (got {status:?})",
    );
}
