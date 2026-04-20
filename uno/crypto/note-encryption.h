/*
    Uno Workchain — note encryption (hybrid KEM + ChaCha20-Poly1305).

    End-to-end wrapper implementing §2.7 and §2.8. A single `encrypt_note`
    call takes plaintext + recipient material, runs the full hybrid KEM
    + AEAD chain, and returns every byte that the caller must write into
    the `OutputDescription`:
       • epk          (compressed Ristretto255, 32 B)
       • mlkem_ct     (ML-KEM-768 ciphertext, 1088 B)
       • enc_ct       (AEAD ciphertext = plaintext + 16 B tag)
       • filter_tag   (§2.8, 16 bits)

    Scan / decrypt is symmetric: given `ivk`, `sk_mlkem`, and the on-chain
    bytes, return the plaintext on match or an error on filter/AEAD failure.

    AEAD: ChaCha20-Poly1305 IETF variant (RFC 8439). 256-bit key, 12-byte
    nonce, 128-bit tag. Backend is libsodium's
    `crypto_aead_chacha20poly1305_ietf_encrypt` / `_decrypt`.

    No AAD is used: the note payload is self-contained, and the transcript
    already binds `epk` / `mlkem_ct` via the KEM combiner (§2.7 informal
    argument). If Agent 6's test suite flags a malleability concern Agent
    2 can add an AAD tying the commitment `cm` without changing this
    public surface — add a parameter.
*/
#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/hybrid-kem.h"
#include "uno/crypto/mlkem768.h"
#include "uno/crypto/ristretto255.h"

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// AEAD constants (libsodium / RFC 8439)
// ---------------------------------------------------------------------------

inline constexpr size_t kAeadTagBytes = 16;  // Poly1305 tag

// ---------------------------------------------------------------------------
// Encrypt (sender)
// ---------------------------------------------------------------------------

/// Inputs that define "who the note is for". Mirrors Address + the field
/// needed to derive `g_d` (the diversifier `d`, 11 bytes).
///
/// `ivk_commitment` is copied straight from the recipient's published
/// Address (decision #1, §2.6). The sender cannot derive it locally — only
/// the recipient knows `ivk` — so this struct simply forwards the bytes.
/// The sender hashes `ivk_commitment` into `cm` per §3.2; the recipient
/// recomputes and matches the field during scan.
struct NoteEncryptionRecipient {
    td::Slice d_bytes;              // 11 bytes; diversifier
    RistrettoPoint pk_d;             // diversified transmission key
    /// 32-byte ivk-binding anchor from the recipient's Address.
    /// Empty slice is tolerated only by callers that don't need cm-building
    /// (e.g. ciphertext-only fuzz); consensus-path encrypt callers must pass
    /// the real 32 bytes.
    td::Slice ivk_commitment;       // 32 bytes (decision #1)
    MlKem768PublicKey pk_mlkem;      // 1184-byte PQ KEM pubkey
};

/// Fresh per-output ephemeral material. `esk` is a Ristretto scalar; the
/// sender derives it from `esk_seed = BLAKE2b-256("uno-esk-v1" || uno_seed
/// || output_index)` and passes the scalar in. We accept the scalar form
/// so that this module does not depend on the stealth-address wallet hierarchy.
struct NoteEphemeralKey {
    RistrettoScalar esk;             // 32-byte scalar
    /// 32 bytes of randomness for deterministic ML-KEM Encap, so the
    /// entire output is reconstructable for audit/resync. If the caller
    /// does not need determinism they can pass a freshly-random buffer.
    td::SecureString mlkem_encap_randomness_32;
};

/// Outputs: byte fields the caller writes into an `OutputDescription`.
struct EncryptedNote {
    RistrettoPoint epk;              // sender's ephemeral public key
    MlKem768Ciphertext mlkem_ct;     // 1088 B
    std::vector<uint8_t> enc_ct;     // plaintext_len + kAeadTagBytes
    uint16_t filter_tag;             // §2.8
};

/// Full encrypt.
///
/// `g_d` must be pre-computed by the caller via
///     g_d = HashToRistretto("uno-diversifier-v1" || d)
/// (see stealth-address.h). We accept it here to avoid re-hashing inside
/// and to keep this module decoupled from the diversifier derivation.
///
/// Returns an `EncryptedNote` on success, Error on any step failure
/// (invalid pk_d encoding, libsodium failure, etc.).
td::Result<EncryptedNote> encrypt_note(
    const NoteEncryptionRecipient& recipient,
    const RistrettoPoint& g_d,
    const NoteEphemeralKey& ephemeral,
    td::Slice plaintext);

// ---------------------------------------------------------------------------
// Trial-decrypt (receiver)
// ---------------------------------------------------------------------------

/// On-chain artifacts the wallet-scanner reads back.
struct OnChainOutput {
    RistrettoPoint epk;
    MlKem768Ciphertext mlkem_ct;
    td::Slice enc_ct;                 // references caller-owned buffer
    uint16_t filter_tag;
};

/// Receiver-side material for scanning a block.
struct NoteDecryptionKeys {
    RistrettoScalar ivk;             // incoming viewing key (Ristretto scalar form)
    MlKem768SecretKey sk_mlkem;      // PQ KEM secret (2400 B)
};

/// Outcome of a scan: either the plaintext (note matches this wallet)
/// or an explicit mismatch status. A mismatch can be:
///   - filter_tag miss (cheap)
///   - AEAD tag failure (note not for us)
///   - decode error (non-canonical epk or mlkem_ct)
enum class ScanOutcome { kMatch, kFilterMiss, kAeadReject, kDecodeError };

struct ScanResult {
    ScanOutcome outcome;
    std::vector<uint8_t> plaintext;  // populated only when outcome==kMatch
};

/// Trial-decrypt. Performs filter_tag match first (cheap); on hit,
/// performs the full hybrid-KEM + AEAD path. On AEAD failure, returns
/// ScanOutcome::kAeadReject (not an Error, since mismatched notes are
/// the common case).
td::Result<ScanResult> trial_decrypt(const NoteDecryptionKeys& keys,
                                     const OnChainOutput& out);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Round-trip: build a fresh keypair, encrypt a short message, scan, verify
/// plaintext matches. Does not pin wire bytes (that's Agent 6's integration
/// vector).
td::Status note_encryption_verify_test_vectors();

}  // namespace uno_workchain::crypto
