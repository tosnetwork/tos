//! K-genesis-distribution — byte-identical golden-fixture test.
//!
//! Exercises `genesis_build::build_genesis_notes_json` against a deterministic
//! 3-airdrop + 2-treasury + 1-team distribution summing exactly to 21 M UNO
//! and pins the resulting JSON against `uno/test/golden/genesis-distribution-v1.json`.
//!
//! The golden file is checked into the repo as the source-of-truth for
//! cross-impl parity — the C++ `build_genesis_notes_json` must emit the
//! same bytes, and the C++ `load_genesis_distribution` must accept them.
//!
//! Regenerate the golden with:
//!
//!     UNO_GENESIS_REGEN=1 cargo test --release --test genesis_build_golden
//!
//! The regen path is gated on the env var so accidental test runs can't
//! silently rewrite the fixture.

use std::path::PathBuf;

use tosctl_uno::address::Address;
use tosctl_uno::genesis_build::{
    build_genesis_distribution, build_genesis_notes_json, canonical_address_hash,
    derive_genesis_rseed, DistributionRecipient, GenesisDistributionInputs,
    CHAIN_ID_TESTNET, GENESIS_AIRDROP_NANO, GENESIS_TEAM_NANO, GENESIS_TOTAL_SUPPLY_NANO,
    GENESIS_TREASURY_NANO,
};
use tosctl_uno::keygen::derive_fvk;

fn golden_path() -> PathBuf {
    // CARGO_MANIFEST_DIR points to tosctl/uno; the fixture lives under
    // ../../uno/test/golden/ relative to that.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("uno")
        .join("test")
        .join("golden")
        .join("genesis-distribution-v1.json")
}

/// Deterministically build the 6-entry fixture. `seed_byte` drives the
/// BIP-39-skipped seed derivation: fvk_i = derive_fvk(seed_i_repeated). The
/// diversifier is `d_byte` × 11.
fn mk_addr(seed_byte: u8, d_byte: u8) -> Address {
    let mut seed = [0u8; 32];
    for i in 0..32 {
        // Deterministic, non-zero, host-independent — repeat-byte seeds
        // would collide across (seed_byte, d_byte) pairs, so mix the index.
        seed[i] = seed_byte.wrapping_add(i as u8);
    }
    let fvk = derive_fvk(&seed).unwrap();
    Address::build(&fvk, &[d_byte; 11]).unwrap()
}

fn mk_fixture_inputs() -> GenesisDistributionInputs {
    GenesisDistributionInputs {
        chain_id: CHAIN_ID_TESTNET,
        airdrop: vec![
            DistributionRecipient {
                address: mk_addr(0x01, 0x01),
                value_nano: GENESIS_AIRDROP_NANO / 2,
            },
            DistributionRecipient {
                address: mk_addr(0x02, 0x02),
                value_nano: GENESIS_AIRDROP_NANO / 4,
            },
            DistributionRecipient {
                address: mk_addr(0x03, 0x03),
                value_nano: GENESIS_AIRDROP_NANO / 4,
            },
        ],
        treasury: vec![
            DistributionRecipient {
                address: mk_addr(0x04, 0x04),
                value_nano: GENESIS_TREASURY_NANO / 2,
            },
            DistributionRecipient {
                address: mk_addr(0x05, 0x05),
                value_nano: GENESIS_TREASURY_NANO / 2,
            },
        ],
        team: vec![DistributionRecipient {
            address: mk_addr(0x06, 0x06),
            value_nano: GENESIS_TEAM_NANO,
        }],
    }
}

#[test]
fn golden_fixture_matches_builder_output() {
    let inputs = mk_fixture_inputs();
    let json = build_genesis_notes_json(&inputs).expect("build_genesis_notes_json");

    let path = golden_path();

    if std::env::var("UNO_GENESIS_REGEN").ok().as_deref() == Some("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &json).unwrap();
        eprintln!("regenerated golden fixture: {}", path.display());
        return;
    }

    let golden = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read golden fixture {}: {}. \
             Regenerate with UNO_GENESIS_REGEN=1.",
            path.display(),
            e
        )
    });

    if golden != json {
        // Surface a helpful diff prefix before the assertion fails.
        let prefix_len = golden.chars().zip(json.chars()).take_while(|(a, b)| a == b).count();
        eprintln!(
            "golden mismatch (common prefix {} chars).\n  golden[len {}]: {:?}...\n  built [len {}]: {:?}...",
            prefix_len,
            golden.len(),
            &golden.chars().skip(prefix_len.saturating_sub(16)).take(80).collect::<String>(),
            json.len(),
            &json.chars().skip(prefix_len.saturating_sub(16)).take(80).collect::<String>(),
        );
    }
    assert_eq!(golden, json, "golden fixture drifted; regenerate with UNO_GENESIS_REGEN=1");
}

#[test]
fn fixture_round_trips_through_serde_json() {
    // Parse the builder's JSON back with serde_json and assert the structure
    // matches the canonical loader schema.
    let inputs = mk_fixture_inputs();
    let json = build_genesis_notes_json(&inputs).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["chain_id"], CHAIN_ID_TESTNET);
    assert_eq!(
        parsed["total_supply_nano"],
        serde_json::Value::String(GENESIS_TOTAL_SUPPLY_NANO.to_string())
    );
    let notes = parsed["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 6);

    for (i, note) in notes.iter().enumerate() {
        // rseed must match canonical derivation.
        let rseed_hex = note["rseed"].as_str().unwrap();
        let rseed_bytes = hex::decode(rseed_hex).unwrap();
        assert_eq!(rseed_bytes.len(), 32);
        assert_eq!(rseed_bytes, derive_genesis_rseed(i as u32));

        // cm present, 32 bytes, non-zero.
        let cm_hex = note["cm"].as_str().unwrap();
        let cm_bytes = hex::decode(cm_hex).unwrap();
        assert_eq!(cm_bytes.len(), 32);
        assert!(cm_bytes.iter().any(|&b| b != 0));

        // recipient hex block has the expected shapes.
        let rcp = &note["recipient"];
        assert_eq!(hex::decode(rcp["d"].as_str().unwrap()).unwrap().len(), 11);
        assert_eq!(hex::decode(rcp["pk_d"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(hex::decode(rcp["ivk_commitment"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(hex::decode(rcp["pk_mlkem"].as_str().unwrap()).unwrap().len(), 1184);
    }

    // Sections are sorted by canonical_address_hash; per-section totals
    // match the §10.3 targets.
    let out = build_genesis_distribution(&inputs).unwrap();
    let (a, t, m): (u64, u64, u64) = (
        out.notes[0].value_nano + out.notes[1].value_nano + out.notes[2].value_nano,
        out.notes[3].value_nano + out.notes[4].value_nano,
        out.notes[5].value_nano,
    );
    assert_eq!(a, GENESIS_AIRDROP_NANO);
    assert_eq!(t, GENESIS_TREASURY_NANO);
    assert_eq!(m, GENESIS_TEAM_NANO);

    // Airdrop section sort.
    for i in 1..3 {
        let p = canonical_address_hash(&out.notes[i - 1].address);
        let c = canonical_address_hash(&out.notes[i].address);
        assert!(p < c, "airdrop section not sorted at {i}");
    }
    // Treasury section sort.
    let p = canonical_address_hash(&out.notes[3].address);
    let c = canonical_address_hash(&out.notes[4].address);
    assert!(p < c, "treasury section not sorted");
}

#[test]
fn fixture_loader_compatible_shape() {
    // Independent check that the serialized output matches the loader's
    // minimal required schema (no `scheme_id`, hex `recipient` block only).
    let inputs = mk_fixture_inputs();
    let json = build_genesis_notes_json(&inputs).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Top-level must NOT contain a scheme_id field (the builder omits it;
    // the loader treats it as optional and defaults to kSchemeIdV1).
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("scheme_id"),
        "builder must not emit scheme_id; loader defaults it");
    assert!(obj.contains_key("chain_id"));
    assert!(obj.contains_key("total_supply_nano"));
    assert!(obj.contains_key("notes"));

    for note in v["notes"].as_array().unwrap() {
        // Each note MUST have hex recipient + rseed + cm + value; MUST NOT
        // carry an `address` envelope (builder chooses hex block for
        // portability).
        let n = note.as_object().unwrap();
        assert!(n.contains_key("recipient"));
        assert!(n.contains_key("value"));
        assert!(n.contains_key("rseed"));
        assert!(n.contains_key("cm"));
        assert!(!n.contains_key("address"));
    }
}
