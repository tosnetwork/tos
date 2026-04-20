//! End-to-end integration test per P.6 foundation task:
//!
//!   derive keys from a fixed TOS seed
//!     → build a diversified address at a chosen diversifier
//!     → verify the Address.ivk_commitment matches an independent
//!       Poseidon2("uno-ivk-cm-v1", ivk, d) recomputation
//!     → verify the wire round-trip and base58-with-checksum string form
//!     → verify the hybrid-KEM + AEAD self-round-trip for a note addressed
//!       to this wallet
//!
//! This is the smallest coherent cross-module check that the P.6 foundation
//! foundation library reproduces the §2.6 / §2.7 receive-side contracts.
//! It runs with `cargo test --test derive_keys_then_address` (offline).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::ristretto::CompressedRistretto;
use tosctl_uno::{address, hybrid_kem, keygen, poseidon2, scan};

fn fixed_seed() -> [u8; 32] {
    // Deterministic test vector — first 32 natural numbers.
    let mut s = [0u8; 32];
    for i in 0..32 { s[i] = i as u8; }
    s
}

#[test]
fn derive_keys_then_address_verifies_ivk_commitment_chain() {
    // Step 1. Derive the FVK from a fixed seed.
    let fvk = keygen::derive_fvk(&fixed_seed()).expect("derive_fvk");
    assert_eq!(fvk.pk_mlkem.len(), tosctl_uno::sizes::MLKEM768_PK);
    assert_eq!(fvk.sk_mlkem.len(), tosctl_uno::sizes::MLKEM768_SK);

    // Step 2. Build two addresses under distinct diversifiers.
    let d1 = [0x11u8; 11];
    let d2 = [0x22u8; 11];
    let a1 = address::Address::build(&fvk, &d1).expect("address 1");
    let a2 = address::Address::build(&fvk, &d2).expect("address 2");

    // Step 3. The ivk_commitment on each address must equal an independent
    //         Poseidon2("uno-ivk-cm-v1", ivk, d) recomputation.
    let ic1 = keygen::ivk_commitment(&fvk.ivk.0, &d1).expect("ivk_cm 1");
    let ic2 = keygen::ivk_commitment(&fvk.ivk.0, &d2).expect("ivk_cm 2");
    assert_eq!(a1.ivk_commitment, ic1);
    assert_eq!(a2.ivk_commitment, ic2);
    assert_ne!(ic1, ic2, "different diversifiers must produce different commitments");

    // Step 4. Wire round-trip: the 1259-byte layout parses back to the same
    //         struct.
    let bytes1 = a1.to_bytes();
    assert_eq!(bytes1.len(), 1259);
    let parsed1 = address::Address::from_bytes(&bytes1).expect("parse wire");
    assert_eq!(a1, parsed1);

    // Step 5. String round-trip under both HRPs.
    for hrp in ["uno1", "unos"] {
        let s = a1.to_string_with_hrp(hrp);
        assert!(s.starts_with(hrp));
        let (parsed, got_hrp) = address::Address::from_string(&s).expect("parse string");
        assert_eq!(parsed, a1);
        assert_eq!(got_hrp, hrp);
    }

    // Step 6. Hybrid-KEM receive-side self-round-trip.
    //
    // Sender side: use the diversified base point for d1, a fresh ephemeral
    // scalar, encapsulate to pk_mlkem, derive k_aead + nonce, encrypt a
    // plausible note plaintext. Receiver side: use the FVK's ivk to derive
    // the same k_aead (ECDH symmetry + ML-KEM decap), then AEAD-Open.
    let g_d = address::derive_diversified_base_point(&d1).expect("g_d");
    // Ephemeral: deterministic for test reproducibility. Any non-zero scalar
    // works; we derive one from the fixed seed via a hash.
    let esk = curve25519_dalek::scalar::Scalar::from_bytes_mod_order({
        let mut h = blake3::Hasher::new();
        h.update(b"test-esk");
        h.update(&fixed_seed());
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    });
    let epk = esk * g_d;
    let epk_compressed = epk.compress().to_bytes();

    // Sender computes s_dh = esk * pk_d (where pk_d = ivk · g_d).
    let pk_d_point = CompressedRistretto(a1.pk_d).decompress().expect("pk_d decompress");
    let s_dh_sender = esk * pk_d_point;
    let s_dh_sender_compressed = s_dh_sender.compress().to_bytes();

    // Sender encapsulates to pk_mlkem.
    let (mlkem_ct, s_pq_sender) =
        keygen::mlkem_encap(&fvk.pk_mlkem).expect("encap");

    let k_aead = hybrid_kem::derive_key(
        &s_dh_sender_compressed,
        &s_pq_sender,
        &epk_compressed,
        &mlkem_ct,
    );
    let nonce = hybrid_kem::derive_nonce(&epk_compressed);

    // Plaintext layout matches src/scan.rs::NotePlaintext::parse:
    //   d(11) || pk_d(32) || value_le_u64(8) || rseed(32)
    let mut plaintext = Vec::with_capacity(11 + 32 + 8 + 32);
    plaintext.extend_from_slice(&d1);
    plaintext.extend_from_slice(&a1.pk_d);
    plaintext.extend_from_slice(&123_456_789u64.to_le_bytes());
    plaintext.extend_from_slice(&[0xaa; 32]);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_aead));
    let enc_ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .expect("aead encrypt");

    // Build a synthetic OutputDescription and run the receiver through
    // scan::try_open to close the loop.
    let filter_tag = poseidon2::filter_tag(&k_aead);
    let output = tosctl_uno::wire::OutputDescription {
        cm: [0u8; 32],     // not verified by try_open
        epk: epk_compressed,
        filter_tag,
        enc_ciphertext,
        mlkem_ct,
        out_ciphertext: [0u8; 80],
    };

    let recovered = scan::try_open(&fvk, &output)
        .expect("try_open returned Err")
        .expect("try_open returned None — AEAD-tag failure on our own note");

    // The recovered plaintext must match what we encrypted.
    assert_eq!(recovered.d, d1);
    assert_eq!(recovered.pk_d, a1.pk_d);
    assert_eq!(recovered.value, 123_456_789);
    assert_eq!(recovered.rseed, [0xaa; 32]);
}
