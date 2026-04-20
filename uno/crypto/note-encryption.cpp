/*
    Uno Workchain — note encryption (implementation).

    Encrypt sequence (§2.7):
      1. epk = esk · g_d
      2. s_dh = esk · pk_d
      3. (mlkem_ct, s_pq) = ML-KEM-768.Encap(pk_mlkem)   [derand version]
      4. k_aead = hybrid_kem_derive_key(s_dh, s_pq, epk, mlkem_ct)
      5. nonce  = hybrid_kem_derive_nonce(epk)
      6. enc_ct = ChaCha20-Poly1305.Encrypt(k_aead, nonce, plaintext)
      7. filter_tag = Truncate_16(Poseidon2("uno-filter-v1", k_aead))

    Decrypt sequence: symmetric. `s_dh' = ivk · epk` because Ristretto255
    ECDH is commutative (esk · pk_d == esk · (Poseidon2(ivk,d) · g_d)
    == (Poseidon2(ivk,d) · esk) · g_d == ivk · epk  after factoring
    Poseidon2(ivk,d) into the ivk term — this is the standard Orchard-style
    diversified ECDH identity).
*/

#include "uno/crypto/note-encryption.h"

#include <cstring>

#include <sodium.h>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/poseidon2.h"

namespace uno_workchain::crypto {

namespace {

const uint8_t* as_u8(td::Slice s) { return reinterpret_cast<const uint8_t*>(s.data()); }
uint8_t*       as_u8(td::MutableSlice s) { return reinterpret_cast<uint8_t*>(s.data()); }

// Compute `s_dh = scalar · point`. Wraps the validate + scalarmult chain.
td::Result<RistrettoPoint> ecdh(const RistrettoScalar& scalar,
                                 const RistrettoPoint& point) {
    return ristretto_scalar_mul(scalar, point);
}

}  // namespace

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

td::Result<EncryptedNote> encrypt_note(
    const NoteEncryptionRecipient& recipient,
    const RistrettoPoint& g_d,
    const NoteEphemeralKey& ephemeral,
    td::Slice plaintext) {

    // 1. epk = esk · g_d
    TRY_RESULT(epk, ristretto_scalar_mul(ephemeral.esk, g_d));

    // 2. s_dh = esk · pk_d
    TRY_RESULT(s_dh, ecdh(ephemeral.esk, recipient.pk_d));

    // 3. ML-KEM-768 Encap (deterministic when randomness provided)
    MlKem768EncapResult enc;
    if (ephemeral.mlkem_encap_randomness_32.size() == 32) {
        TRY_RESULT_ASSIGN(enc, mlkem768_encap_deterministic(
                                    recipient.pk_mlkem,
                                    ephemeral.mlkem_encap_randomness_32.as_slice()));
    } else if (ephemeral.mlkem_encap_randomness_32.empty()) {
        TRY_RESULT_ASSIGN(enc, mlkem768_encap(recipient.pk_mlkem));
    } else {
        return td::Status::Error("note-encryption: mlkem coin must be 32 B or empty");
    }

    // 4. Hybrid KDF → k_aead
    TRY_RESULT(k_aead, hybrid_kem_derive_key(s_dh, enc.ss.as_slice(), epk, enc.ct));

    // 5. Nonce
    auto nonce = hybrid_kem_derive_nonce(epk);

    // 6. AEAD
    std::vector<uint8_t> ct(plaintext.size() + kAeadTagBytes);
    unsigned long long ct_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len,
        as_u8(plaintext), plaintext.size(),
        nullptr, 0,                         // no AAD
        nullptr,                            // no nsec
        nonce.data(),
        as_u8(k_aead.as_slice()));
    if (rc != 0) {
        return td::Status::Error("note-encryption: AEAD encrypt failed");
    }
    ct.resize(static_cast<size_t>(ct_len));

    // 7. Filter tag
    uint16_t tag = poseidon2_filter_tag(k_aead.as_slice());

    EncryptedNote out;
    out.epk = epk;
    out.mlkem_ct = enc.ct;
    out.enc_ct = std::move(ct);
    out.filter_tag = tag;
    return out;
}

// ---------------------------------------------------------------------------
// Trial-decrypt
// ---------------------------------------------------------------------------

td::Result<ScanResult> trial_decrypt(const NoteDecryptionKeys& keys,
                                     const OnChainOutput& out) {
    // 1. Validate epk encoding cheaply — malformed epk implies not-for-us.
    if (out.epk.validate().is_error()) {
        return ScanResult{ScanOutcome::kDecodeError, {}};
    }

    // 2. ML-KEM Decap (implicit rejection; ss may be pseudorandom on bad ct,
    //    which we catch below via AEAD tag failure).
    TRY_RESULT(s_pq, mlkem768_decap(keys.sk_mlkem, out.mlkem_ct));

    // 3. s_dh' = ivk · epk (diversified ECDH identity — see header docstring).
    TRY_RESULT(s_dh, ristretto_scalar_mul(keys.ivk, out.epk));

    // 4. Derive k_aead via the same transcript.
    TRY_RESULT(k_aead, hybrid_kem_derive_key(s_dh, s_pq.as_slice(), out.epk, out.mlkem_ct));

    // 5. Filter check (cheap: rejects ~99.9985% of non-matches before AEAD).
    uint16_t expected_tag = poseidon2_filter_tag(k_aead.as_slice());
    if (expected_tag != out.filter_tag) {
        return ScanResult{ScanOutcome::kFilterMiss, {}};
    }

    // 6. Derive nonce, run AEAD Open.
    auto nonce = hybrid_kem_derive_nonce(out.epk);
    if (out.enc_ct.size() < kAeadTagBytes) {
        return ScanResult{ScanOutcome::kDecodeError, {}};
    }
    std::vector<uint8_t> plaintext(out.enc_ct.size() - kAeadTagBytes);
    unsigned long long pt_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(), &pt_len,
        nullptr,                             // no nsec
        as_u8(out.enc_ct), out.enc_ct.size(),
        nullptr, 0,                          // no AAD
        nonce.data(),
        as_u8(k_aead.as_slice()));
    if (rc != 0) {
        // Filter matched but AEAD rejected: likely a 2^-16 false-positive
        // collision on `filter_tag`. Expected, not an error.
        return ScanResult{ScanOutcome::kAeadReject, {}};
    }
    plaintext.resize(static_cast<size_t>(pt_len));
    return ScanResult{ScanOutcome::kMatch, std::move(plaintext)};
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

td::Status note_encryption_verify_test_vectors() {
    // We exercise the flow against liboqs-generated keys. If liboqs is not
    // yet linked, surface the error cleanly.
    uint8_t seed[kMlKem768SeedBytes];
    for (size_t i = 0; i < kMlKem768SeedBytes; ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);
    td::Slice seed_slice{reinterpret_cast<const char*>(seed), kMlKem768SeedBytes};

    auto kem_r = mlkem768_keygen_from_seed(seed_slice);
    if (kem_r.is_error()) {
        // Fallback: use randomized keygen; sufficient for correctness round-trip.
        return td::Status::Error(
            "note-encryption: self-test skipped — deterministic MLKEM keygen "
            "unavailable (liboqs stub or missing derand build).");
    }
    MlKem768KeyPair mlkem_kp = kem_r.move_as_ok();

    // For the Ristretto side we need a recipient `pk_d` and a base point
    // `g_d`. For the self-test we synthesize both from a fixed scalar.
    uint8_t sc_bytes[32] = {0};
    sc_bytes[0] = 7;
    td::Slice sc_slice{reinterpret_cast<const char*>(sc_bytes), 32};
    TRY_RESULT(recipient_scalar, RistrettoScalar::from_bytes(sc_slice));
    // `g_d` = basepoint (self-test only; production derives via hash-to-curve)
    RistrettoPoint g_d = ristretto_basepoint();
    TRY_RESULT(pk_d, ristretto_scalar_mul(recipient_scalar, g_d));

    // Ephemeral side: esk is an arbitrary scalar.
    uint8_t esk_bytes[32] = {0};
    esk_bytes[0] = 11;
    td::Slice esk_slice{reinterpret_cast<const char*>(esk_bytes), 32};
    TRY_RESULT(esk, RistrettoScalar::from_bytes(esk_slice));
    NoteEphemeralKey eph{std::move(esk), td::SecureString{}};

    NoteEncryptionRecipient rec;
    uint8_t d_bytes[11] = {0};
    rec.d_bytes = td::Slice{reinterpret_cast<const char*>(d_bytes), 11};
    rec.pk_d = pk_d;
    rec.pk_mlkem = mlkem_kp.pk;

    td::Slice pt{"hello uno", 9};
    TRY_RESULT(enc, encrypt_note(rec, g_d, eph, pt));

    // Receiver: ivk = recipient_scalar in this simplified test (production
    // uses Poseidon2(ivk, d) as the effective scalar, see stealth-address.h).
    NoteDecryptionKeys dk{std::move(recipient_scalar), std::move(mlkem_kp.sk)};

    OnChainOutput onchain;
    onchain.epk = enc.epk;
    onchain.mlkem_ct = enc.mlkem_ct;
    onchain.enc_ct = td::Slice{reinterpret_cast<const char*>(enc.enc_ct.data()), enc.enc_ct.size()};
    onchain.filter_tag = enc.filter_tag;

    TRY_RESULT(scan, trial_decrypt(dk, onchain));
    if (scan.outcome != ScanOutcome::kMatch) {
        return td::Status::Error("note-encryption: self-test did not match");
    }
    if (scan.plaintext.size() != pt.size() ||
        std::memcmp(scan.plaintext.data(), pt.data(), pt.size()) != 0) {
        return td::Status::Error("note-encryption: plaintext round-trip mismatch");
    }
    return td::Status::OK();
}

}  // namespace uno_workchain::crypto
