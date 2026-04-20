/*
    Uno Workchain — Poseidon2 over Goldilocks (wrapper implementation).

    This file binds the C++ surface in poseidon2.h to the Plonky3 FFI crate
    owned by Agent 4 at `uno/plonky3-ffi/`. The FFI crate exports:

        void uno_poseidon2_goldilocks_permute_t8 (uint64_t state[8]);
        void uno_poseidon2_goldilocks_permute_t16(uint64_t state[16]);

    These symbols MUST exist at link time; there is no soft fallback. If
    Agent 4's crate has not been wired yet, define
    `UNO_POSEIDON2_STUB_FFI` at compile time — the stub aborts on call and
    documents the missing dependency. The goldilocks.{h,cpp} pure-C++
    arithmetic on its own is sufficient to compile/test this unit.
*/

#include "uno/crypto/poseidon2.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// FFI bindings (expected to be exported by uno/plonky3-ffi)
// ---------------------------------------------------------------------------

extern "C" {

#ifdef UNO_POSEIDON2_STUB_FFI
// Compile-time opt-in stubs so the crypto TU can link while Agent 4 finishes
// the Rust FFI crate. Any actual call aborts with a clear message.
static void uno_poseidon2_goldilocks_permute_t8(uint64_t[8]) {
    std::fprintf(stderr,
                 "uno_workchain::crypto::poseidon2: FFI symbol "
                 "`uno_poseidon2_goldilocks_permute_t8` not linked. "
                 "Wire uno/plonky3-ffi (Agent 4) into the crypto target.\n");
    std::abort();
}
static void uno_poseidon2_goldilocks_permute_t16(uint64_t[16]) {
    std::fprintf(stderr,
                 "uno_workchain::crypto::poseidon2: FFI symbol "
                 "`uno_poseidon2_goldilocks_permute_t16` not linked. "
                 "Wire uno/plonky3-ffi (Agent 4) into the crypto target.\n");
    std::abort();
}
#else
void uno_poseidon2_goldilocks_permute_t8 (uint64_t state[8]);
void uno_poseidon2_goldilocks_permute_t16(uint64_t state[16]);
#endif

}  // extern "C"

// ---------------------------------------------------------------------------
// Permutations
// ---------------------------------------------------------------------------

void poseidon2_permute_t8(std::array<Fp, 8>& state) noexcept {
    static_assert(sizeof(Fp) == sizeof(uint64_t), "Fp must be layout-compatible with u64");
    uint64_t raw[8];
    for (size_t i = 0; i < 8; ++i) raw[i] = state[i].v;
    uno_poseidon2_goldilocks_permute_t8(raw);
    for (size_t i = 0; i < 8; ++i) {
        // FFI returns canonical limbs; defensive canonicalize.
        state[i] = Fp{raw[i] >= kGoldilocksPrime ? raw[i] - kGoldilocksPrime : raw[i]};
    }
}

void poseidon2_permute_t16(std::array<Fp, 16>& state) noexcept {
    uint64_t raw[16];
    for (size_t i = 0; i < 16; ++i) raw[i] = state[i].v;
    uno_poseidon2_goldilocks_permute_t16(raw);
    for (size_t i = 0; i < 16; ++i) {
        state[i] = Fp{raw[i] >= kGoldilocksPrime ? raw[i] - kGoldilocksPrime : raw[i]};
    }
}

// ---------------------------------------------------------------------------
// Compressions
// ---------------------------------------------------------------------------

Digest poseidon2_compress_2to1(const Digest& left, const Digest& right) noexcept {
    std::array<Fp, 8> state{};
    for (size_t i = 0; i < kDigestFieldElements; ++i) state[i] = left.e[i];
    for (size_t i = 0; i < kDigestFieldElements; ++i)
        state[kDigestFieldElements + i] = right.e[i];
    poseidon2_permute_t8(state);
    Digest out;
    for (size_t i = 0; i < kDigestFieldElements; ++i) out.e[i] = state[i];
    return out;
}

Digest poseidon2_compress_4to1(const std::array<Fp, 16>& inputs) noexcept {
    std::array<Fp, 16> state = inputs;
    poseidon2_permute_t16(state);
    Digest out;
    for (size_t i = 0; i < kDigestFieldElements; ++i) out.e[i] = state[i];
    return out;
}

// ---------------------------------------------------------------------------
// Tagged hash (domain-separated sponge)
// ---------------------------------------------------------------------------

namespace {

Digest hash_with_tag_and_fp(td::Slice tag, const Fp* inputs, size_t n) {
    // Width selection: absorb a single t=8 block if tag + inputs fit; else
    // use the t=16 wide sponge with the tag occupying the first 8 elements
    // and inputs absorbed into the remaining capacity.
    std::array<Fp, 8> tag_block{};
    pack_domain_tag(tag, tag_block);

    if (n + 8 <= 8) {
        // Single block, tag already fills it — this case never happens in
        // practice since we always have at least one input.
        std::array<Fp, 8> state = tag_block;
        poseidon2_permute_t8(state);
        Digest out;
        for (size_t i = 0; i < kDigestFieldElements; ++i) out.e[i] = state[i];
        return out;
    }

    if (n <= 8) {
        // t=16: [tag(8) || inputs(n) || pad(8-n)]
        std::array<Fp, 16> state{};
        for (size_t i = 0; i < 8; ++i) state[i] = tag_block[i];
        for (size_t i = 0; i < n; ++i) state[8 + i] = inputs[i];
        poseidon2_permute_t16(state);
        Digest out;
        for (size_t i = 0; i < kDigestFieldElements; ++i) out.e[i] = state[i];
        return out;
    }

    // n > 8: iterated t=16 sponge. Rate = 8 (input), capacity = 8 (state
    // tail carries the tag/chaining).
    std::array<Fp, 16> state{};
    for (size_t i = 0; i < 8; ++i) state[8 + i] = tag_block[i];

    size_t i = 0;
    while (i + 8 <= n) {
        for (size_t j = 0; j < 8; ++j) state[j] = state[j].add(inputs[i + j]);
        poseidon2_permute_t16(state);
        i += 8;
    }
    size_t rem = n - i;
    if (rem > 0) {
        for (size_t j = 0; j < rem; ++j) state[j] = state[j].add(inputs[i + j]);
        // 10* padding: first unused rate slot absorbs 1
        state[rem] = state[rem].add(Fp::one());
        poseidon2_permute_t16(state);
    } else {
        // Even multiple of 8: absorb a lone padding block.
        state[0] = state[0].add(Fp::one());
        poseidon2_permute_t16(state);
    }
    Digest out;
    for (size_t j = 0; j < kDigestFieldElements; ++j) out.e[j] = state[j];
    return out;
}

}  // namespace

Digest poseidon2_hash_tagged(td::Slice tag, const Fp* inputs, size_t n_inputs) {
    return hash_with_tag_and_fp(tag, inputs, n_inputs);
}

Digest poseidon2_hash_tagged_bytes(td::Slice tag, td::Slice inputs_le_bytes) {
    assert(inputs_le_bytes.size() % kFieldElementBytes == 0);
    size_t n = inputs_le_bytes.size() / kFieldElementBytes;
    std::vector<Fp> tmp(n);
    for (size_t i = 0; i < n; ++i) {
        auto r = Fp::from_le_bytes(
            inputs_le_bytes.substr(i * kFieldElementBytes, kFieldElementBytes));
        if (r.is_error()) {
            // Non-canonical input; callers are expected to pre-canonicalize.
            std::abort();
        }
        tmp[i] = r.move_as_ok();
    }
    return hash_with_tag_and_fp(tag, tmp.data(), tmp.size());
}

// ---------------------------------------------------------------------------
// Filter-tag (§2.8): Truncate_16bit(Poseidon2("uno-filter-v1", k_aead))
// ---------------------------------------------------------------------------

uint16_t poseidon2_filter_tag(td::Slice k_aead_32) {
    assert(k_aead_32.size() == 32);
    // Interpret the 32-byte AEAD key as 4 Goldilocks field elements
    // (little-endian), reducing each word mod p. Per §2.8 the tag input
    // is the 32-byte `k_aead`; reduction is unambiguous because the tag
    // formula discards all but the low 16 bits afterward.
    Fp inputs[4];
    const uint8_t* p = reinterpret_cast<const uint8_t*>(k_aead_32.data());
    for (size_t i = 0; i < 4; ++i) {
        uint64_t w;
        std::memcpy(&w, p + i * 8, 8);
        inputs[i] = fp_from_u64(w);
    }
    Digest d = hash_with_tag_and_fp(td::Slice("uno-filter-v1"), inputs, 4);
    // Truncate to 16 bits: low bits of first field element (little-endian view).
    return static_cast<uint16_t>(d.e[0].v & 0xFFFFu);
}

// ---------------------------------------------------------------------------
// Self-test (pending Agent 4 vector)
// ---------------------------------------------------------------------------

void _poseidon2_verify_test_vectors() {
#ifdef UNO_POSEIDON2_HAVE_REF_VECTOR
    // TODO(agent-4): import reference vector from uno/plonky3-ffi/tests/
    //                and assert permutation outputs.
    //
    //   std::array<Fp, 8> st{Fp{0}, Fp{1}, ..., Fp{7}};
    //   poseidon2_permute_t8(st);
    //   assert(st[0].v == <pinned>);
    //
    // Without the Plonky3 source-of-truth vector we must not make up
    // values; a fabricated assertion would permanently wedge the wire
    // format.
#endif
}

}  // namespace uno_workchain::crypto

// ---------------------------------------------------------------------------
// C ABI export consumed by Agent 2 (commitment-tree). Global-scope extern "C",
// matching the forward declaration in poseidon2.h.
// ---------------------------------------------------------------------------

extern "C" void poseidon2_goldilocks_compress_2to1(const uint64_t left[4],
                                                   const uint64_t right[4],
                                                   uint64_t out[4]) {
    using uno_workchain::crypto::Digest;
    using uno_workchain::crypto::Fp;
    using uno_workchain::crypto::kGoldilocksPrime;

    Digest l;
    Digest r;
    for (size_t i = 0; i < 4; ++i) {
        l.e[i] = Fp{left[i] >= kGoldilocksPrime ? left[i] - kGoldilocksPrime : left[i]};
        r.e[i] = Fp{right[i] >= kGoldilocksPrime ? right[i] - kGoldilocksPrime : right[i]};
    }
    Digest d = uno_workchain::crypto::poseidon2_compress_2to1(l, r);
    for (size_t i = 0; i < 4; ++i) out[i] = d.e[i].v;
}
