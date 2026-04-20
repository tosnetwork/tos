//! `tosctl uno send` round-trip integration test.
//!
//! Scope (M-send scaffold):
//!
//! 1. Two-wallet setup (Alice + Bob) from distinct deterministic seeds.
//! 2. Synthetic owned-note fixtures for Alice (bypasses the RPC scan).
//! 3. Alice runs the full `send::test_build_transfer` pipeline:
//!      - note selection
//!      - recipient + change output construction
//!      - hybrid-KEM encrypt per output
//!      - canonical `tx_hash`
//!      - Schnorr-sign each spend
//!      - wire serialize
//! 4. Assertions:
//!      - built Transfer decodes back byte-identically
//!      - `tx_hash` recomputed from the decoded tx equals the pre-submit hash
//!      - `zk_proof` is the 43-byte stubbed placeholder (so the M-P2
//!        integration point is exercised by the scaffold)
//!      - Bob's wallet trial-decrypts the recipient output (send →
//!        scan closes the loop without a network)
//!      - each spend's `spend_auth_sig` verifies against its `rk` over tx_hash
//!
//! All-offline. No `#[tokio::test]`, no network.

use tosctl_uno::{
    address::Address,
    keygen,
    scan::{self, OwnedNote},
    schnorr,
    send,
    transfer::{self, STUB_PROOF_BYTES, TRANSFER_VERSION, SCHEME_ID_V1},
    wire as wire_mod,
};

fn seed_for(label: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for i in 0..32 { s[i] = label.wrapping_add(i as u8); }
    s
}

fn fake_note(value: u64, salt: u8) -> OwnedNote {
    OwnedNote {
        block_seqno: 0,
        global_index: salt as u64,
        cm: [salt; 32],
        nullifier: [salt.wrapping_add(0x80); 32],
        value,
        diversifier: [salt.wrapping_add(0x10); 11],
        position: salt as u64,
    }
}

#[test]
fn send_pipeline_builds_well_formed_transfer_with_stub_proof() {
    // --- Setup two wallets ---------------------------------------------
    let alice = keygen::derive_fvk(&seed_for(0x01)).expect("alice fvk");
    let bob   = keygen::derive_fvk(&seed_for(0x02)).expect("bob fvk");

    // Bob's receive address (what Alice sends to).
    let bob_diversifier = [0x42u8; 11];
    let bob_addr = Address::build(&bob, &bob_diversifier).expect("bob addr");

    // --- Alice has a single 1,000 nano-UNO note ------------------------
    // Value chosen so after (amount=700, fee=25) we get change=275 >0
    // and the test exercises the 2-output branch.
    let alice_notes = vec![fake_note(1_000, 0x05)];

    // --- Build the Transfer --------------------------------------------
    let anchor = [0xa5u8; 32];
    let chain_id = 2u32;
    let expiry = 1_234_567u64;
    let memo = "hello bob";

    let (tx, tx_bytes, tx_hash) = send::test_build_transfer(
        &alice,
        &bob_addr,
        &alice_notes,
        /* amount = */ 700,
        /* fee    = */ 25,
        &anchor,
        chain_id,
        expiry,
        Some(memo),
    ).expect("build transfer");

    // --- Well-formedness -----------------------------------------------
    assert_eq!(tx.version, TRANSFER_VERSION);
    assert_eq!(tx.scheme_id, SCHEME_ID_V1);
    assert_eq!(tx.chain_id, chain_id);
    assert_eq!(tx.anchor, anchor);
    assert_eq!(tx.expiry_block, expiry);
    assert_eq!(tx.fee, 25);
    assert_eq!(tx.spends.len(), 1);
    assert_eq!(tx.outputs.len(), 2, "recipient + change → 2 outputs");

    // --- Stub-proof assertion ------------------------------------------
    assert_eq!(
        tx.zk_proof.len(),
        STUB_PROOF_BYTES,
        "zk_proof must be the 43-byte stub — M-P2 integration point"
    );
    assert!(
        tx.zk_proof.iter().all(|&b| b == 0),
        "stub proof is all-zero so it's unmistakable at the validator"
    );

    // --- Wire round-trip ------------------------------------------------
    let decoded = transfer::decode_transfer_wire(&tx_bytes)
        .expect("decode wire bytes");
    assert_eq!(decoded, tx, "decode(encode(tx)) == tx");

    // tx_hash is deterministic from the decoded form.
    let tx_hash_decoded = transfer::canonical_tx_hash(&decoded);
    assert_eq!(tx_hash, tx_hash_decoded, "tx_hash stable across encode/decode");

    // --- Bob can trial-decrypt the recipient output ---------------------
    //
    // Outputs appear in (recipient, change) order — recipient is index 0.
    let wire_out = wire_mod::OutputDescription {
        cm: tx.outputs[0].cm,
        epk: tx.outputs[0].epk,
        filter_tag: tx.outputs[0].filter_tag,
        enc_ciphertext: tx.outputs[0].enc_ciphertext.clone(),
        mlkem_ct: tx.outputs[0].mlkem_ct.clone(),
        out_ciphertext: tx.outputs[0].out_ciphertext,
    };
    let bob_sees = scan::try_open(&bob, &wire_out)
        .expect("try_open");
    let bob_note = bob_sees.expect("bob should own the recipient output");
    assert_eq!(bob_note.value, 700);
    assert_eq!(bob_note.d, bob_diversifier);

    // --- Alice can trial-decrypt her own change output ------------------
    let wire_change = wire_mod::OutputDescription {
        cm: tx.outputs[1].cm,
        epk: tx.outputs[1].epk,
        filter_tag: tx.outputs[1].filter_tag,
        enc_ciphertext: tx.outputs[1].enc_ciphertext.clone(),
        mlkem_ct: tx.outputs[1].mlkem_ct.clone(),
        out_ciphertext: tx.outputs[1].out_ciphertext,
    };
    let alice_sees = scan::try_open(&alice, &wire_change)
        .expect("try_open change");
    let change_note = alice_sees.expect("alice should own the change output");
    assert_eq!(change_note.value, 1_000 - 700 - 25);

    // --- Each spend_auth_sig verifies -----------------------------------
    for spend in &tx.spends {
        schnorr::verify(&spend.rk, &tx_hash, &spend.spend_auth_sig)
            .expect("spend_auth_sig must verify under rk over tx_hash");
    }

    // --- Sanity: mutating the zk_proof does NOT change tx_hash ----------
    // (§4.1: signatures and proof are excluded from the hash preimage).
    let mut mutated = tx.clone();
    mutated.zk_proof[0] ^= 0xff;
    assert_eq!(
        transfer::canonical_tx_hash(&mutated),
        tx_hash,
        "tx_hash excludes zk_proof bytes"
    );
}

#[test]
fn send_pipeline_rejects_insufficient_funds() {
    let alice = keygen::derive_fvk(&seed_for(0x11)).expect("alice fvk");
    let bob = keygen::derive_fvk(&seed_for(0x22)).expect("bob fvk");
    let bob_addr = Address::build(&bob, &[0x33u8; 11]).expect("bob addr");

    // Alice has 10 nano-UNO; trying to send 100 + fee must fail cleanly.
    let alice_notes = vec![fake_note(10, 0x01)];
    let anchor = [0u8; 32];
    let err = send::test_build_transfer(
        &alice, &bob_addr, &alice_notes, 100, 1, &anchor, 2, 100, None,
    );
    assert!(err.is_err(), "send should reject insufficient funds");
}

#[test]
fn send_pipeline_handles_single_output_no_change() {
    // If the selected notes exactly cover amount + fee (change == 0),
    // we emit a single recipient output — no change branch.
    let alice = keygen::derive_fvk(&seed_for(0x33)).expect("alice fvk");
    let bob = keygen::derive_fvk(&seed_for(0x44)).expect("bob fvk");
    let bob_addr = Address::build(&bob, &[0x55u8; 11]).expect("bob addr");

    // Exact-cover note: 500 + fee 10 = 510 → note value 510.
    let alice_notes = vec![fake_note(510, 0x07)];
    let anchor = [0xddu8; 32];

    let (tx, _bytes, _hash) = send::test_build_transfer(
        &alice, &bob_addr, &alice_notes, 500, 10, &anchor, 2, 99, None,
    ).expect("exact cover build");

    assert_eq!(tx.outputs.len(), 1, "no change → 1 output");
    assert_eq!(tx.spends.len(), 1);
    // Still stubbed proof.
    assert_eq!(tx.zk_proof.len(), STUB_PROOF_BYTES);
}
