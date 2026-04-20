/*
    Uno Workchain — stealth-address / key-hierarchy derivation.

    Implementation uses:
      - libsodium's BLAKE2b (`crypto_generichash`) for off-circuit secrets.
      - Our Poseidon2 wrapper for `nk` and `ivk`.
      - libsodium's Ristretto255 for curve ops.
      - Our ML-KEM-768 wrapper for the PQ keypair.

    Byte layout of `Address`: 11 B diversifier, 32 B compressed Ristretto255
    pk_d, 1184 B ML-KEM-768 pk — 1227 B total, matching §2.6.
*/

#include "uno/crypto/stealth-address.h"

#include <cstring>

#include <sodium.h>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/core/workchain.h"   // kDomainSepIvkCmV1
#include "uno/crypto/poseidon2.h"

namespace uno_workchain::crypto {

namespace {

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

void blake2b_256(td::Slice tag, td::Slice input, uint8_t out[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 32);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(input.data()), input.size());
    crypto_generichash_final(&st, out, 32);
}

void blake2b_512(td::Slice tag, td::Slice input, uint8_t out[64]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 64);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(input.data()), input.size());
    crypto_generichash_final(&st, out, 64);
}

RistrettoScalar reduce_to_scalar(td::Slice in_32) {
    // Pad to 64 bytes; keep it zero-high so reduction is purely of a 32-bit
    // value. Matches standard Ristretto scalar construction from 32-byte
    // output.
    uint8_t padded[64] = {0};
    std::memcpy(padded, in_32.data(), 32);
    td::Slice padded_slice{reinterpret_cast<const char*>(padded), 64};
    auto out = RistrettoScalar::reduce_64_bytes(padded_slice);
    sodium_memzero(padded, sizeof(padded));
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

td::Result<FullViewingKey> derive_keys_from_seed(td::Slice uno_seed_32) {
    if (uno_seed_32.size() != kUnoSeedBytes) {
        return td::Status::Error("stealth-address: uno_seed must be 32 bytes");
    }

    // ------------------------------------------------------------------
    // 1. ask = BLAKE2b-256("uno-ask-v1" || seed) reduced mod L
    // ------------------------------------------------------------------
    uint8_t ask_digest[32];
    blake2b_256({"uno-ask-v1", 10}, uno_seed_32, ask_digest);
    td::Slice ask_slice{reinterpret_cast<const char*>(ask_digest), 32};
    RistrettoScalar ask = reduce_to_scalar(ask_slice);
    sodium_memzero(ask_digest, sizeof(ask_digest));

    // 2. ak = ask · G
    TRY_RESULT(ak, ristretto_basepoint_mul(ask));

    // ------------------------------------------------------------------
    // 3. nk = Poseidon2("uno-nk-v1", seed)
    // ------------------------------------------------------------------
    // Interpret `seed` as 4 Goldilocks field elements (reducing each word
    // mod p). The AIR consumes `uno_seed` the same way: as a sequence of
    // Fp inputs to Poseidon2. For the AIR this is a witness field-element
    // vector; off-circuit we reduce each little-endian 8-byte word.
    Fp seed_fp[4];
    for (size_t i = 0; i < 4; ++i) {
        uint64_t w;
        std::memcpy(&w, uno_seed_32.data() + i * 8, 8);
        seed_fp[i] = fp_from_u64(w);
    }
    Digest nk = poseidon2_hash_tagged(td::Slice{"uno-nk-v1", 9}, seed_fp, 4);

    // ------------------------------------------------------------------
    // 4. ivk = Poseidon2("uno-ivk-v1", nk, ak_bytes)
    //
    // Here ak_bytes is the 32-byte compressed Ristretto encoding, packed
    // as 4 Goldilocks field elements (word-by-word reduction) to feed
    // Poseidon2. The in-circuit AIR will pack ak_bytes the same way
    // (committed as witness field elements).
    // ------------------------------------------------------------------
    Fp combined[8];
    for (size_t i = 0; i < 4; ++i) combined[i] = nk.e[i];
    for (size_t i = 0; i < 4; ++i) {
        uint64_t w;
        std::memcpy(&w, ak.bytes.data() + i * 8, 8);
        combined[4 + i] = fp_from_u64(w);
    }
    Digest ivk = poseidon2_hash_tagged(td::Slice{"uno-ivk-v1", 10}, combined, 8);

    // ------------------------------------------------------------------
    // 5. ovk = BLAKE2b-256("uno-ovk-v1" || seed), 32 B secure buffer.
    // ------------------------------------------------------------------
    td::SecureString ovk(kOvkBytes, '\0');
    blake2b_256({"uno-ovk-v1", 10}, uno_seed_32,
                reinterpret_cast<uint8_t*>(ovk.as_mutable_slice().data()));

    // ------------------------------------------------------------------
    // 6. ML-KEM-768 keypair: seed derivation.
    //    spec: mlkem_seed = BLAKE2b-256("uno-mlkem-v1" || seed)
    //    For FIPS 203 derand KeyGen we need 64 bytes (d||z). We expand
    //    via BLAKE2b-512 with the same tag (single hash, 64-byte output)
    //    so the derivation is one call and collision-free.
    // ------------------------------------------------------------------
    uint8_t mlkem_seed64[64];
    blake2b_512({"uno-mlkem-v1", 12}, uno_seed_32, mlkem_seed64);
    td::Slice mlkem_seed_slice{reinterpret_cast<const char*>(mlkem_seed64), 64};
    auto mlkem_r = mlkem768_keygen_from_seed(mlkem_seed_slice);
    sodium_memzero(mlkem_seed64, sizeof(mlkem_seed64));
    if (mlkem_r.is_error()) return mlkem_r.move_as_error();
    auto mlkem_kp = mlkem_r.move_as_ok();

    // ------------------------------------------------------------------
    FullViewingKey fvk;
    fvk.ak = ak;
    fvk.nk = nk;
    fvk.ovk = std::move(ovk);
    fvk.sk_mlkem = std::move(mlkem_kp.sk);
    fvk.pk_mlkem = mlkem_kp.pk;
    fvk.ask = std::move(ask);
    fvk.ivk = ivk;
    return fvk;
}

// ---------------------------------------------------------------------------
// Diversified-address helpers
// ---------------------------------------------------------------------------

RistrettoPoint derive_diversified_base_point(td::Slice diversifier_11) {
    // Produce 64 uniform bytes from ("uno-diversifier-v1" || d) then map to
    // a curve point.
    uint8_t hash64[64];
    blake2b_512({"uno-diversifier-v1", 18}, diversifier_11, hash64);
    td::Slice hash_slice{reinterpret_cast<const char*>(hash64), 64};
    RistrettoPoint g_d = ristretto_from_hash_64(hash_slice);
    sodium_memzero(hash64, sizeof(hash64));
    return g_d;
}

RistrettoScalar ivk_to_scalar(const Digest& ivk) {
    uint8_t bytes32[32];
    ivk.to_bytes({reinterpret_cast<char*>(bytes32), 32});
    td::Slice s{reinterpret_cast<const char*>(bytes32), 32};
    auto sc = reduce_to_scalar(s);
    sodium_memzero(bytes32, sizeof(bytes32));
    return sc;
}

RistrettoScalar derive_diversified_scalar(const Digest& ivk,
                                          td::Slice diversifier_11) {
    // Poseidon2(ivk, d). We pack `ivk` as 4 Fp and `d` (11 bytes) as 2 Fp:
    // 8 bytes into Fp #0, remaining 3 bytes into Fp #1 (LE, zero-padded).
    Fp inputs[6];
    for (size_t i = 0; i < 4; ++i) inputs[i] = ivk.e[i];
    uint8_t pad[16] = {0};
    std::memcpy(pad, diversifier_11.data(), 11);
    uint64_t w0, w1;
    std::memcpy(&w0, pad, 8);
    std::memcpy(&w1, pad + 8, 8);
    inputs[4] = fp_from_u64(w0);
    inputs[5] = fp_from_u64(w1);

    Digest h = poseidon2_hash_tagged(td::Slice{"uno-ivk-d", 9}, inputs, 6);
    return ivk_to_scalar(h);
}

td::Result<RistrettoPoint> derive_pk_d(const Digest& ivk,
                                       td::Slice diversifier_11) {
    if (diversifier_11.size() != kDiversifierBytes) {
        return td::Status::Error("stealth-address: diversifier must be 11 bytes");
    }
    RistrettoPoint g_d = derive_diversified_base_point(diversifier_11);
    RistrettoScalar sc  = derive_diversified_scalar(ivk, diversifier_11);
    return ristretto_scalar_mul(sc, g_d);
}

// ---------------------------------------------------------------------------
// ivk_commitment (decision #1 / §2.6)
// ---------------------------------------------------------------------------

std::array<uint8_t, kIvkCommitmentBytes>
derive_ivk_commitment_bytes(const Digest& ivk, td::Slice diversifier_11) {
    // `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)`.
    //
    // We pack ivk as 4 Fp (its canonical form) and d (11 bytes) as 2 Fp — 8
    // bytes into Fp #0, remaining 3 bytes into Fp #1 (zero-padded LE).
    // Matches the in-circuit absorb order in the Transfer AIR (claim 3,
    // `transfer_air.rs`) so prover and off-circuit wallet agree on a single
    // 32-byte wire value.
    //
    // The diversifier packing is identical to `derive_diversified_scalar` to
    // keep address-time derivations consistent (ivk-commitment and pk_d both
    // absorb d the same way).
    std::array<uint8_t, kIvkCommitmentBytes> out{};
    if (diversifier_11.size() != kDiversifierBytes) {
        return out;  // caller should have validated; zero-fill on abuse
    }

    Fp inputs[6];
    for (size_t i = 0; i < 4; ++i) inputs[i] = ivk.e[i];
    uint8_t pad[16] = {0};
    std::memcpy(pad, diversifier_11.data(), kDiversifierBytes);
    uint64_t w0, w1;
    std::memcpy(&w0, pad, 8);
    std::memcpy(&w1, pad + 8, 8);
    inputs[4] = fp_from_u64(w0);
    inputs[5] = fp_from_u64(w1);

    Digest h = poseidon2_hash_tagged(
        td::Slice{kDomainSepIvkCmV1, sizeof(kDomainSepIvkCmV1) - 1},
        inputs, 6);
    h.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

// ---------------------------------------------------------------------------
// Address encoding
// ---------------------------------------------------------------------------

std::vector<uint8_t> Address::to_bytes() const {
    std::vector<uint8_t> out(kAddressBytes);
    size_t off = 0;
    std::memcpy(out.data() + off, d.data(), kDiversifierBytes);
    off += kDiversifierBytes;
    std::memcpy(out.data() + off,
                compressed_pk_d.bytes.data(), kRistrettoPointBytes);
    off += kRistrettoPointBytes;
    std::memcpy(out.data() + off, ivk_commitment.data(), kIvkCommitmentBytes);
    off += kIvkCommitmentBytes;
    std::memcpy(out.data() + off,
                pk_mlkem.bytes.data(), kMlKem768PublicKeyBytes);
    return out;
}

td::Result<Address> Address::from_bytes(td::Slice in) {
    if (in.size() != kAddressBytes) {
        return td::Status::Error("stealth-address: wrong address length");
    }
    Address a;
    size_t off = 0;
    std::memcpy(a.d.data(), in.data() + off, kDiversifierBytes);
    off += kDiversifierBytes;
    std::memcpy(a.compressed_pk_d.bytes.data(),
                in.data() + off, kRistrettoPointBytes);
    off += kRistrettoPointBytes;
    std::memcpy(a.ivk_commitment.data(),
                in.data() + off, kIvkCommitmentBytes);
    off += kIvkCommitmentBytes;
    std::memcpy(a.pk_mlkem.bytes.data(),
                in.data() + off, kMlKem768PublicKeyBytes);
    TRY_STATUS(a.compressed_pk_d.validate());
    return a;
}

td::Result<Address> build_address(const FullViewingKey& fvk,
                                  td::Slice diversifier_11) {
    if (diversifier_11.size() != kDiversifierBytes) {
        return td::Status::Error("stealth-address: diversifier must be 11 bytes");
    }
    Address a;
    std::memcpy(a.d.data(), diversifier_11.data(), kDiversifierBytes);
    TRY_RESULT(pk_d, derive_pk_d(fvk.ivk, diversifier_11));
    a.compressed_pk_d = pk_d;
    // decision #1: published 32-byte ivk-binding field.
    a.ivk_commitment = derive_ivk_commitment_bytes(fvk.ivk, diversifier_11);
    a.pk_mlkem = fvk.pk_mlkem;
    return a;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

td::Status stealth_address_verify_test_vectors() {
    uint8_t seed[kUnoSeedBytes];
    for (size_t i = 0; i < kUnoSeedBytes; ++i) seed[i] = static_cast<uint8_t>(0x10 ^ i);
    td::Slice seed_slice{reinterpret_cast<const char*>(seed), kUnoSeedBytes};

    auto fvk_r = derive_keys_from_seed(seed_slice);
    if (fvk_r.is_error()) {
        // Most likely cause: Agent 4's Poseidon2 FFI not yet linked, or
        // Agent 5's liboqs not yet linked. Forward the error verbatim so
        // the failing invariant is clear.
        return fvk_r.move_as_error();
    }

    auto fvk2_r = derive_keys_from_seed(seed_slice);
    if (fvk2_r.is_error()) return fvk2_r.move_as_error();
    const auto& a = fvk_r.ok();
    const auto& b = fvk2_r.ok();
    if (a.ak.bytes != b.ak.bytes) {
        return td::Status::Error("stealth-address: non-deterministic ak");
    }
    if (a.nk != b.nk) return td::Status::Error("stealth-address: non-deterministic nk");
    if (a.ivk != b.ivk) return td::Status::Error("stealth-address: non-deterministic ivk");
    if (a.pk_mlkem.bytes != b.pk_mlkem.bytes) {
        return td::Status::Error("stealth-address: non-deterministic pk_mlkem");
    }

    // Diversified-address round-trip.
    std::array<uint8_t, kDiversifierBytes> d{};
    for (size_t i = 0; i < kDiversifierBytes; ++i) d[i] = static_cast<uint8_t>(i);
    td::Slice d_slice{reinterpret_cast<const char*>(d.data()), kDiversifierBytes};
    TRY_RESULT(addr, build_address(a, d_slice));
    auto bytes = addr.to_bytes();
    if (bytes.size() != kAddressBytes) {
        return td::Status::Error("stealth-address: wrong address byte size");
    }
    td::Slice bytes_slice{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    TRY_RESULT(decoded, Address::from_bytes(bytes_slice));
    if (decoded.compressed_pk_d.bytes != addr.compressed_pk_d.bytes) {
        return td::Status::Error("stealth-address: address round-trip mismatch");
    }
    if (decoded.ivk_commitment != addr.ivk_commitment) {
        return td::Status::Error("stealth-address: ivk_commitment round-trip mismatch");
    }
    // Decision #1: address MUST carry a non-zero ivk_commitment derived
    // from (ivk, d). A zero field would imply the Poseidon2 backend was
    // not linked.
    bool ivkcm_all_zero = true;
    for (uint8_t b : addr.ivk_commitment) if (b != 0) { ivkcm_all_zero = false; break; }
    if (ivkcm_all_zero) {
        return td::Status::Error(
            "stealth-address: ivk_commitment is all-zero — "
            "Poseidon2 backend missing?");
    }
    // Determinism: re-derivation from the same (ivk, d) must match byte-for-byte.
    auto ivkcm2 = derive_ivk_commitment_bytes(a.ivk, d_slice);
    if (ivkcm2 != addr.ivk_commitment) {
        return td::Status::Error(
            "stealth-address: ivk_commitment derivation is non-deterministic");
    }

    // Explicit consistency: pk_d = scalar · g_d.
    RistrettoPoint g_d = derive_diversified_base_point(d_slice);
    RistrettoScalar sc  = derive_diversified_scalar(a.ivk, d_slice);
    TRY_RESULT(pk_d, ristretto_scalar_mul(sc, g_d));
    if (pk_d.bytes != addr.compressed_pk_d.bytes) {
        return td::Status::Error(
            "stealth-address: pk_d inconsistent with (ivk,d) derivation");
    }
    return td::Status::OK();
}

}  // namespace uno_workchain::crypto
