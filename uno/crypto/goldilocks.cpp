/*
    Uno Workchain — Goldilocks field arithmetic (implementation).

    Reference: "Plonky2: Fast Recursive Arguments with PLONK and FRI"
    (Polygon Zero, 2022) Appendix B, which specifies Goldilocks reduction.
    Also matches the Plonky3 Rust crate `p3-goldilocks` at FIELD_ORDER
    = 0xFFFFFFFF00000001.

    Mul reduction: write the 128-bit product as hi:lo. Using p = 2^64 - 2^32 + 1,
    we have  2^64 ≡ 2^32 − 1 (mod p),  2^96 ≡ 2^32 (2^32 − 1) − 1 ≡ −1 (mod p).
    Split hi = hi_hi:hi_lo (two 32-bit halves):
        product mod p = lo + hi_lo·(2^32 − 1) − hi_hi
    done with three 64-bit adds/subs + two conditional p-reductions.
*/

#include "uno/crypto/goldilocks.h"

#include <cassert>
#include <cstdlib>
#include <cstring>

#include "td/utils/Status.h"

namespace uno_workchain::crypto {

namespace {

// 128-bit multiply helper. Returns (hi, lo).
inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) noexcept {
    __uint128_t p = (__uint128_t)a * (__uint128_t)b;
    lo = (uint64_t)p;
    hi = (uint64_t)(p >> 64);
}

// Reduce a 128-bit value (hi<<64 | lo) modulo kGoldilocksPrime.
// Returns canonical representative in [0, p).
inline uint64_t reduce128(uint64_t hi, uint64_t lo) noexcept {
    // p = 2^64 - 2^32 + 1
    // 2^64 mod p = 2^32 - 1
    // 2^96 mod p = -1 (i.e. p - 1)
    const uint64_t mask32 = 0xFFFFFFFFULL;
    uint64_t hi_hi = hi >> 32;       // coefficient of 2^96
    uint64_t hi_lo = hi & mask32;    // coefficient of 2^64

    // r = lo + hi_lo * (2^32 - 1) - hi_hi  (mod p)
    // Step 1: lo + hi_lo * (2^32 - 1) == lo + (hi_lo << 32) - hi_lo

    // Compute (hi_lo << 32) - hi_lo; fits in 64 bits (hi_lo < 2^32).
    uint64_t t = (hi_lo << 32) - hi_lo;

    // Add lo
    uint64_t r;
    unsigned char carry = __builtin_add_overflow(lo, t, &r) ? 1 : 0;
    if (carry) {
        // We overflowed 2^64. 2^64 ≡ 2^32 - 1 (mod p) → add (2^32 - 1).
        // We may overflow again by at most one limb carry, then fix up.
        uint64_t adj = 0xFFFFFFFFULL;  // 2^32 - 1
        unsigned char c2 = __builtin_add_overflow(r, adj, &r) ? 1 : 0;
        if (c2) {
            // Second overflow: add another (2^32 - 1), no further overflow
            // possible since r < 2^32 before this add.
            r += 0xFFFFFFFFULL;
        }
    }

    // Subtract hi_hi (coefficient of 2^96 ≡ -1)
    if (r >= hi_hi) {
        r -= hi_hi;
    } else {
        // Borrow: r - hi_hi + p
        r = r + kGoldilocksPrime - hi_hi;
    }

    // Final canonical reduction
    if (r >= kGoldilocksPrime) {
        r -= kGoldilocksPrime;
    }
    return r;
}

inline uint64_t load_le64(const uint8_t* p) noexcept {
    uint64_t x;
    std::memcpy(&x, p, 8);
    return x;
}

inline void store_le64(uint8_t* p, uint64_t x) noexcept {
    std::memcpy(p, &x, 8);
}

}  // namespace

// ---------------------------------------------------------------------------
// Fp arithmetic
// ---------------------------------------------------------------------------

Fp Fp::add(Fp o) const noexcept {
    uint64_t r;
    if (__builtin_add_overflow(v, o.v, &r)) {
        // Overflow across 2^64 → subtract p, which is ≡ adding (2^32 - 1).
        r += 0xFFFFFFFFULL;
    }
    if (r >= kGoldilocksPrime) r -= kGoldilocksPrime;
    return Fp{r};
}

Fp Fp::sub(Fp o) const noexcept {
    uint64_t r;
    if (__builtin_sub_overflow(v, o.v, &r)) {
        r -= 0xFFFFFFFFULL;  // == + (p mod 2^64) = + (−(2^32 − 1)) reversed
    }
    // Canonicalize
    if (r >= kGoldilocksPrime) r -= kGoldilocksPrime;
    return Fp{r};
}

Fp Fp::mul(Fp o) const noexcept {
    uint64_t hi, lo;
    mul64x64_128(v, o.v, hi, lo);
    return Fp{reduce128(hi, lo)};
}

Fp Fp::neg() const noexcept {
    return v == 0 ? Fp{0} : Fp{kGoldilocksPrime - v};
}

Fp Fp::inv() const noexcept {
    if (v == 0) return Fp{0};
    // Fermat's little theorem: a^(p-2) mod p. Square-and-multiply with
    // p - 2 = 0xFFFFFFFEFFFFFFFF.
    uint64_t exp = kGoldilocksPrime - 2;
    Fp result = Fp::one();
    Fp base = *this;
    while (exp) {
        if (exp & 1) result = result.mul(base);
        base = base.mul(base);
        exp >>= 1;
    }
    return result;
}

void Fp::to_le_bytes(td::MutableSlice out) const {
    assert(out.size() >= kFieldElementBytes);
    store_le64(reinterpret_cast<uint8_t*>(out.data()), v);
}

td::Result<Fp> Fp::from_le_bytes(td::Slice in) {
    if (in.size() < kFieldElementBytes) {
        return td::Status::Error("goldilocks: short field-element encoding");
    }
    uint64_t x = load_le64(reinterpret_cast<const uint8_t*>(in.data()));
    if (x >= kGoldilocksPrime) {
        return td::Status::Error("goldilocks: non-canonical field element");
    }
    return Fp{x};
}

// ---------------------------------------------------------------------------
// Digest (4 field elements = 256 bits)
// ---------------------------------------------------------------------------

void Digest::to_bytes(td::MutableSlice out) const {
    assert(out.size() >= kDigestBytes);
    for (size_t i = 0; i < kDigestFieldElements; ++i) {
        e[i].to_le_bytes(out.substr(i * kFieldElementBytes, kFieldElementBytes));
    }
}

td::Result<Digest> Digest::from_bytes(td::Slice in) {
    if (in.size() < kDigestBytes) {
        return td::Status::Error("goldilocks: short digest encoding");
    }
    Digest d;
    for (size_t i = 0; i < kDigestFieldElements; ++i) {
        TRY_RESULT_ASSIGN(d.e[i],
                          Fp::from_le_bytes(in.substr(i * kFieldElementBytes, kFieldElementBytes)));
    }
    return d;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

Fp fp_from_u64(uint64_t x) noexcept {
    // x can be up to 2^64 - 1, so a single conditional subtract suffices.
    return Fp{x >= kGoldilocksPrime ? x - kGoldilocksPrime : x};
}

size_t pack_domain_tag(td::Slice tag, std::array<Fp, 8>& out) {
    // Absorb at most 8 field elements (64 bytes); Uno domain tags are <= 32 B,
    // so one t=8 block is always enough.
    for (auto& fp : out) fp = Fp::zero();
    const uint8_t* p = reinterpret_cast<const uint8_t*>(tag.data());
    size_t n = tag.size();
    size_t full = n / 8;
    if (full > 8) full = 8;
    for (size_t i = 0; i < full; ++i) {
        uint64_t v = load_le64(p + i * 8);
        // Tag is ASCII; always < p. Assert defensively.
        assert(v < kGoldilocksPrime);
        out[i] = Fp{v};
    }
    size_t rem = n - full * 8;
    if (rem > 0 && full < 8) {
        uint8_t buf[8] = {0};
        std::memcpy(buf, p + full * 8, rem);
        uint64_t v = load_le64(buf);
        assert(v < kGoldilocksPrime);
        out[full] = Fp{v};
    }
    return 8;
}

// ---------------------------------------------------------------------------
// Self-test (developer guardrail)
// ---------------------------------------------------------------------------

void _verify_test_vectors() {
    // 1. p - 1 + 1 == 0
    Fp a{kGoldilocksPrime - 1};
    Fp b{1};
    if (!a.add(b).is_zero()) std::abort();

    // 2. 0 - 1 == p - 1
    Fp zero{0};
    Fp one{1};
    if (zero.sub(one) != Fp{kGoldilocksPrime - 1}) std::abort();

    // 3. Multiplication overflow edge: (2^32) * (2^32) mod p
    //    2^64 mod p = 2^32 - 1
    Fp x{1ULL << 32};
    Fp r = x.mul(x);
    if (r != Fp{0xFFFFFFFFULL}) std::abort();

    // 4. Max field element squared: (p - 1)^2 ≡ 1 (mod p)
    Fp pm1{kGoldilocksPrime - 1};
    if (pm1.mul(pm1) != Fp::one()) std::abort();

    // 5. Inverse round-trip
    Fp k{0xDEADBEEFCAFEULL};
    Fp ki = k.inv();
    if (k.mul(ki) != Fp::one()) std::abort();

    // 6. Encoding round-trip
    uint8_t buf[8];
    Fp q{0x1234567890ABCDEFULL};
    q.to_le_bytes({reinterpret_cast<char*>(buf), 8});
    auto qr = Fp::from_le_bytes({reinterpret_cast<char*>(buf), 8});
    if (qr.is_error()) std::abort();
    if (qr.ok() != q) std::abort();

    // 7. Non-canonical decode rejected
    uint8_t bad[8];
    uint64_t p_itself = kGoldilocksPrime;
    std::memcpy(bad, &p_itself, 8);
    auto br = Fp::from_le_bytes({reinterpret_cast<char*>(bad), 8});
    if (br.is_ok()) std::abort();
}

namespace {
struct GoldilocksSelfTest {
    GoldilocksSelfTest() { _verify_test_vectors(); }
};
// Disabled at static-init by default to avoid surprises under sanitizer/fuzz
// builds; explicit call via tests is preferred. Uncomment once Agent 5 wires
// the crypto target and confirms CI picks it up.
// static GoldilocksSelfTest kGoldilocksSelfTest;
}  // namespace

}  // namespace uno_workchain::crypto
