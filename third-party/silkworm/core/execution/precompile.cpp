// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "precompile.hpp"

#ifndef SILKWORM_NO_LIBFF
#include <gmp.h>
#endif

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include <evmone_precompiles/blake2b.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/ripemd160.hpp>
#include <evmone_precompiles/sha256.hpp>

#ifndef SILKWORM_NO_LIBFF
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#pragma GCC diagnostic pop
#endif  // SILKWORM_NO_LIBFF

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::precompile {

static void right_pad(Bytes& str, const size_t min_size) noexcept {
    if (str.size() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
    Bytes d{input};
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!is_valid_signature(r, s, homestead)) {
        return Bytes{};
    }

    if (v != 27 && v != 28) {
        return Bytes{};
    }

    Bytes out(32, 0);
    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(&out[12], &d[0], &d[64], v != 27, context)) {
        return Bytes{};
    }
    return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept {
    return 60 + 12 * num_words(input.size());
}

std::optional<Bytes> sha256_run(ByteView input) noexcept {
    Bytes out(32, 0);
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(out.data()),
                           reinterpret_cast<const std::byte*>(input.data()),
                           input.size());
    return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept {
    return 600 + 120 * num_words(input.size());
}

std::optional<Bytes> rip160_run(ByteView input) noexcept {
    Bytes out(32, 0);
    SILKWORM_ASSERT(input.size() <= std::numeric_limits<uint32_t>::max());
    evmone::crypto::ripemd160(reinterpret_cast<std::byte*>(&out[12]),
                              reinterpret_cast<const std::byte*>(input.data()),
                              input.size());
    return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept {
    return 15 + 3 * num_words(input.size());
}

std::optional<Bytes> id_run(ByteView input) noexcept {
    return Bytes{input};
}

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    }
    if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    }
    return (x_squared >> 4) + 480 * x - 199680;
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

#ifndef SILKWORM_NO_LIBFF
// EIP-7823 (Fusaka): per-parameter input length cap (8192 bytes).
constexpr uint64_t kModexpMaxInputLen = 8192;

uint64_t expmod_gas(ByteView input_view, evmc_revision rev) noexcept {
    // EIP-7883 (Fusaka) raises the minimum from 200 to 500.
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : (rev >= EVMC_OSAKA ? 500u : 200u)};

    Bytes input{input_view};
    right_pad(input, 3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0) {
        return min_gas;
    }

    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) {
        return UINT64_MAX;
    }

    // EIP-7823 hard cap on each length parameter.
    if (rev >= EVMC_OSAKA) {
        if (base_len256 > kModexpMaxInputLen || exp_len256 > kModexpMaxInputLen || mod_len256 > kModexpMaxInputLen) {
            return UINT64_MAX;
        }
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.size() > base_len64) {
        input.erase(0, static_cast<size_t>(base_len64));
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    // EIP-7883 changes the iteration_count (a.k.a. adjusted_exponent_len)
    // formula for long exponents from 8*(exp_len-32) to 16*(exp_len-32).
    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) {
        const intx::uint256 mult{rev >= EVMC_OSAKA ? intx::uint256{16} : intx::uint256{8}};
        adjusted_exponent_len = mult * (exp_len256 - 32);
    }
    if (bit_len > 1) {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1) {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else if (rev >= EVMC_OSAKA) {
        // EIP-7883 multiplication_complexity:
        //   max_length <= 32  →  16
        //   max_length  > 32  →  2 * words²
        intx::uint256 mc;
        if (max_length <= 32) {
            mc = 16;
        } else {
            mc = 2 * mult_complexity_eip2565(max_length);
        }
        gas = mc * adjusted_exponent_len / 3;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    }
    return std::max(min_gas, static_cast<uint64_t>(gas));
}

std::optional<Bytes> expmod_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 3 * 32);

    uint64_t base_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t exponent_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t modulus_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    if (modulus_len == 0) {
        return Bytes{};
    }

    right_pad(input, static_cast<size_t>(base_len + exponent_len + modulus_len));

    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(base_len));
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(exponent_len));
    }

    mpz_t modulus;
    mpz_init(modulus);
    mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());

    Bytes out(static_cast<size_t>(modulus_len), 0);

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return out;
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    // export as little-endian
    mpz_export(out.data(), nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::ranges::reverse(out);

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return out;
}
#endif  // SILKWORM_NO_LIBFF (expmod section)

#ifndef SILKWORM_NO_LIBFF
// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128
// EIP-197: Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128
using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

// Must be called prior to invoking any other method.
// May be called many times from multiple threads.
static void init_libff() noexcept {
    // magic static
    [[maybe_unused]] static bool initialized = []() noexcept {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
}

static Scalar to_scalar(const uint8_t bytes_be[32]) noexcept {
    mpz_t m;
    mpz_init(m);
    mpz_import(m, 32, /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, bytes_be);
    Scalar out{m};
    mpz_clear(m);
    return out;
}

// Notation warning: Yellow Paper's p is the same libff's q.
// Returns x < p (YP notation).
static bool valid_element_of_fp(const Scalar& x) noexcept {
    return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
}

static std::optional<libff::alt_bn128_G1> decode_g1_element(const uint8_t bytes_be[64]) noexcept {
    Scalar x{to_scalar(bytes_be)};
    if (!valid_element_of_fp(x)) {
        return {};
    }

    Scalar y{to_scalar(bytes_be + 32)};
    if (!valid_element_of_fp(y)) {
        return {};
    }

    if (x.is_zero() && y.is_zero()) {
        return libff::alt_bn128_G1::zero();
    }

    libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
    if (!point.is_well_formed()) {
        return {};
    }
    return point;
}

static std::optional<libff::alt_bn128_Fq2> decode_fp2_element(const uint8_t bytes_be[64]) noexcept {
    // big-endian encoding
    Scalar c0{to_scalar(bytes_be + 32)};
    Scalar c1{to_scalar(bytes_be)};

    if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
        return {};
    }

    return libff::alt_bn128_Fq2{c0, c1};
}

static std::optional<libff::alt_bn128_G2> decode_g2_element(const uint8_t bytes_be[128]) noexcept {
    std::optional<libff::alt_bn128_Fq2> x{decode_fp2_element(bytes_be)};
    if (!x) {
        return {};
    }

    std::optional<libff::alt_bn128_Fq2> y{decode_fp2_element(bytes_be + 64)};
    if (!y) {
        return {};
    }

    if (x->is_zero() && y->is_zero()) {
        return libff::alt_bn128_G2::zero();
    }

    libff::alt_bn128_G2 point{*x, *y, libff::alt_bn128_Fq2::one()};
    if (!point.is_well_formed()) {
        return {};
    }

    if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
        // wrong order, doesn't belong to the subgroup G2
        return {};
    }

    return point;
}

static Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
    Bytes out(64, '\0');
    if (p.is_zero()) {
        return out;
    }

    p.to_affine_coordinates();

    auto x{p.X.as_bigint()};
    auto y{p.Y.as_bigint()};

    // Here we convert little-endian data to big-endian output
    static_assert(sizeof(x.data) == 32);

    std::memcpy(&out[0], y.data, 32);
    std::memcpy(&out[32], x.data, 32);

    std::ranges::reverse(out);
    return out;
}

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<Bytes> bn_add_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 128);

    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    std::optional<libff::alt_bn128_G1> y{decode_g1_element(&input[64])};
    if (!y) {
        return std::nullopt;
    }

    libff::alt_bn128_G1 sum{*x + *y};
    return encode_g1_element(sum);
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

std::optional<Bytes> bn_mul_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 96);

    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    Scalar n{to_scalar(&input[64])};

    libff::alt_bn128_G1 product{n * *x};
    return encode_g1_element(product);
}

static constexpr size_t kSnarkvStride{192};

uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
    uint64_t k{input.size() / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<Bytes> snarkv_run(ByteView input) noexcept {
    if (input.size() % kSnarkvStride != 0) {
        return std::nullopt;
    }
    size_t k{input.size() / kSnarkvStride};

    init_libff();
    using namespace libff;

    static const auto kOne{alt_bn128_Fq12::one()};
    auto accumulator{kOne};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{decode_g1_element(&input[i * kSnarkvStride])};
        if (!a) {
            return std::nullopt;
        }
        std::optional<alt_bn128_G2> b{decode_g2_element(&input[i * kSnarkvStride + 64])};
        if (!b) {
            return std::nullopt;
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    Bytes out(32, 0);
    if (alt_bn128_final_exponentiation(accumulator) == kOne) {
        out[31] = 1;
    }
    return out;
}
#else  // SILKWORM_NO_LIBFF — use evmone's blst-based bn254 + fallback stubs

// expmod_gas: pure intx math, no GMP needed — copy from the #ifndef path above
uint64_t expmod_gas(ByteView input_view, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};
    Bytes input{input_view};
    right_pad(input, 3 * 32);
    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};
    if (base_len256 == 0 && mod_len256 == 0) return min_gas;
    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) return UINT64_MAX;
    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};
    input.erase(0, 3 * 32);
    intx::uint256 exp_head{0};
    if (input.size() > base_len64) {
        input.erase(0, static_cast<size_t>(base_len64));
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};
    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) adjusted_exponent_len = 8 * (exp_len256 - 32);
    if (bit_len > 1) adjusted_exponent_len += bit_len - 1;
    if (adjusted_exponent_len < 1) adjusted_exponent_len = 1;
    const intx::uint256 max_length{std::max(mod_len256, base_len256)};
    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }
    if (intx::count_significant_words(gas) > 1) return UINT64_MAX;
    return std::max(min_gas, static_cast<uint64_t>(gas));
}

// expmod_run: requires GMP — stub returns failure for now.
// TODO: add GMP dependency or implement with intx for small moduli.
std::optional<Bytes> expmod_run(ByteView) noexcept { return std::nullopt; }

// bn_add / bn_mul: use evmone's blst-based bn254 implementation
}  // temporarily close namespace silkworm::precompile
#include <evmone_precompiles/bn254.hpp>
namespace silkworm::precompile {  // reopen

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<Bytes> bn_add_run(ByteView input_view) noexcept {
    uint8_t input_buffer[128]{};
    if (!input_view.empty())
        std::memcpy(input_buffer, input_view.data(), std::min(input_view.size(), size_t{128}));

    const evmmax::bn254::Point p = {intx::be::unsafe::load<intx::uint256>(input_buffer),
                                     intx::be::unsafe::load<intx::uint256>(input_buffer + 32)};
    const evmmax::bn254::Point q = {intx::be::unsafe::load<intx::uint256>(input_buffer + 64),
                                     intx::be::unsafe::load<intx::uint256>(input_buffer + 96)};

    if (!evmmax::bn254::validate(p) || !evmmax::bn254::validate(q))
        return std::nullopt;

    const auto res = evmmax::bn254::add(p, q);
    Bytes out(64, 0);
    intx::be::unsafe::store(out.data(), res.x);
    intx::be::unsafe::store(out.data() + 32, res.y);
    return out;
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 6000 : 40000;
}

std::optional<Bytes> bn_mul_run(ByteView input_view) noexcept {
    uint8_t input_buffer[96]{};
    if (!input_view.empty())
        std::memcpy(input_buffer, input_view.data(), std::min(input_view.size(), size_t{96}));

    const evmmax::bn254::Point p = {intx::be::unsafe::load<intx::uint256>(input_buffer),
                                     intx::be::unsafe::load<intx::uint256>(input_buffer + 32)};
    const auto c = intx::be::unsafe::load<intx::uint256>(input_buffer + 64);

    if (!evmmax::bn254::validate(p))
        return std::nullopt;

    const auto res = evmmax::bn254::mul(p, c);
    Bytes out(64, 0);
    intx::be::unsafe::store(out.data(), res.x);
    intx::be::unsafe::store(out.data() + 32, res.y);
    return out;
}

// snarkv (ecpairing): requires libff or blst pairing support.
// Stub for now — ecpairing is less commonly needed than ecadd/ecmul.
uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
    constexpr size_t kSnarkvStride{192};
    uint64_t k = input.size() / kSnarkvStride;
    return rev >= EVMC_ISTANBUL ? (34000 * k + 45000) : (80000 * k + 100000);
}
std::optional<Bytes> snarkv_run(ByteView) noexcept { return std::nullopt; }

#endif  // SILKWORM_NO_LIBFF

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
    if (input.size() < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView input) noexcept {
    if (input.size() != 213) {
        return std::nullopt;
    }
    const uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return std::nullopt;
    }

    uint64_t h[8];
    std::memcpy(h, &input[4], sizeof(h));
    uint64_t m[16];
    std::memcpy(m, &input[68], sizeof(m));
    uint64_t t[2];
    std::memcpy(t, &input[196], sizeof(t));

    static_assert(std::endian::native == std::endian::little);

    uint32_t r{endian::load_big_u32(input.data())};
    evmone::crypto::blake2b_compress(r, h, m, t, f != 0);

    Bytes out(sizeof(h), 0);
    std::memcpy(&out[0], h, sizeof(h));
    return out;
}

uint64_t point_evaluation_gas(ByteView, evmc_revision) noexcept {
    return 50000;
}

// https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
std::optional<Bytes> point_evaluation_run(ByteView input) noexcept {
    if (input.size() != 192) {
        return std::nullopt;
    }

    std::span<const uint8_t, 32> versioned_hash{&input[0], 32};
    std::span<const uint8_t, 32> z{&input[32], 32};
    std::span<const uint8_t, 32> y{&input[64], 32};
    std::span<const uint8_t, 48> commitment{&input[96], 48};
    std::span<const uint8_t, 48> proof{&input[144], 48};

    if (!evmone::crypto::kzg_verify_proof(
            std::as_bytes(versioned_hash).data(),
            std::as_bytes(z).data(),
            std::as_bytes(y).data(),
            std::as_bytes(commitment).data(),
            std::as_bytes(proof).data())) {
        return std::nullopt;
    }

    return from_hex(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}

// =============================================================================
// EIP-2537: BLS12-381 precompiles (0x0b–0x11), Pectra fork.
// =============================================================================
//
// Wires evmone's bls.cpp (G1/G2 add, msm, pairing, map_to_curve) into
// silkworm's precompile dispatch. Per-precompile gas costs from EIP-2537;
// the discount table for MSM is included verbatim for k=1..128, with k>128
// using the floor of 174 (also per spec).
//
// Spec input/output layout per https://eips.ethereum.org/EIPS/eip-2537:
//   G1 point  : 128 bytes (2 × 64-byte field element, x then y)
//   G2 point  : 256 bytes (2 × 128-byte Fp2 element, x then y)
//   Scalar    : 32 bytes (big-endian uint256)
//   Field elt : 64 bytes (Fp), 128 bytes (Fp2)
//
// All input is right-padded with zeros to the expected size BEFORE we
// invoke evmone — same convention as bn_add_run/bn_mul_run above.

}  // close namespace silkworm::precompile to include evmone bls header
#include <evmone_precompiles/bls.hpp>
namespace silkworm::precompile {

// EIP-2537 §"MSM gas discount" table, indexed by k-1 (so kBlsMsmDiscount[0]
// is for k=1). Values stay constant at 174 for k > 128.
inline constexpr uint16_t kBlsMsmDiscount[128] = {
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712,
    705, 698, 692, 687, 682, 677, 673, 669, 665, 661,
    658, 654, 651, 648, 645, 642, 640, 637, 635, 632,
    630, 627, 625, 623, 621, 619, 617, 615, 613, 611,
    609, 608, 606, 604, 603, 601, 599, 598, 596, 595,
    593, 592, 591, 589, 588, 586, 585, 584, 582, 581,
    580, 579, 577, 576, 575, 574, 573, 572, 570, 569,
    568, 567, 566, 565, 564, 563, 562, 561, 560, 559,
    558, 557, 556, 555, 554, 553, 552, 551, 550, 549,
    548, 547, 547, 546, 545, 544, 543, 542, 541, 540,
    540, 539, 538, 537, 536, 536, 535, 534, 533, 532,
    532, 531, 530, 529, 528, 528, 527, 526, 525, 525,
    524, 523, 522, 522, 521, 520, 520, 519,
};

inline constexpr uint16_t bls_msm_discount(size_t k) noexcept {
    if (k == 0) return 1000;  // shouldn't happen — caller validates
    if (k > 128) return 174;
    return kBlsMsmDiscount[k - 1];
}

// 0x0b — BLS12_G1ADD
uint64_t bls_g1add_gas(ByteView, evmc_revision) noexcept { return 375; }
std::optional<Bytes> bls_g1add_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 256);
    uint8_t rx[64], ry[64];
    if (!evmone::crypto::bls::g1_add(rx, ry,
            input.data(),       input.data() + 64,
            input.data() + 128, input.data() + 192)) {
        return std::nullopt;
    }
    Bytes out(128, 0);
    std::memcpy(out.data(), rx, 64);
    std::memcpy(out.data() + 64, ry, 64);
    return out;
}

// 0x0c — BLS12_G1MSM
uint64_t bls_g1msm_gas(ByteView input, evmc_revision) noexcept {
    constexpr size_t kPairBytes = 160;  // 128B G1 point + 32B scalar
    if (input.empty() || input.size() % kPairBytes != 0) {
        return UINT64_MAX;  // forces out-of-gas — caller will see "ran out" failure
    }
    const size_t k = input.size() / kPairBytes;
    return (k * 12000ull * bls_msm_discount(k)) / 1000ull;
}
std::optional<Bytes> bls_g1msm_run(ByteView input_view) noexcept {
    constexpr size_t kPairBytes = 160;
    if (input_view.empty() || input_view.size() % kPairBytes != 0) {
        return std::nullopt;
    }
    Bytes input{input_view};
    uint8_t rx[64], ry[64];
    if (!evmone::crypto::bls::g1_msm(rx, ry, input.data(), input.size())) {
        return std::nullopt;
    }
    Bytes out(128, 0);
    std::memcpy(out.data(), rx, 64);
    std::memcpy(out.data() + 64, ry, 64);
    return out;
}

// 0x0d — BLS12_G2ADD
uint64_t bls_g2add_gas(ByteView, evmc_revision) noexcept { return 600; }
std::optional<Bytes> bls_g2add_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 512);
    uint8_t rx[128], ry[128];
    if (!evmone::crypto::bls::g2_add(rx, ry,
            input.data(),       input.data() + 128,
            input.data() + 256, input.data() + 384)) {
        return std::nullopt;
    }
    Bytes out(256, 0);
    std::memcpy(out.data(), rx, 128);
    std::memcpy(out.data() + 128, ry, 128);
    return out;
}

// 0x0e — BLS12_G2MSM
uint64_t bls_g2msm_gas(ByteView input, evmc_revision) noexcept {
    constexpr size_t kPairBytes = 288;  // 256B G2 point + 32B scalar
    if (input.empty() || input.size() % kPairBytes != 0) {
        return UINT64_MAX;
    }
    const size_t k = input.size() / kPairBytes;
    return (k * 22500ull * bls_msm_discount(k)) / 1000ull;
}
std::optional<Bytes> bls_g2msm_run(ByteView input_view) noexcept {
    constexpr size_t kPairBytes = 288;
    if (input_view.empty() || input_view.size() % kPairBytes != 0) {
        return std::nullopt;
    }
    Bytes input{input_view};
    uint8_t rx[128], ry[128];
    if (!evmone::crypto::bls::g2_msm(rx, ry, input.data(), input.size())) {
        return std::nullopt;
    }
    Bytes out(256, 0);
    std::memcpy(out.data(), rx, 128);
    std::memcpy(out.data() + 128, ry, 128);
    return out;
}

// 0x0f — BLS12_PAIRING_CHECK
uint64_t bls_pairing_gas(ByteView input, evmc_revision) noexcept {
    constexpr size_t kPairBytes = 384;  // G1(128) + G2(256)
    if (input.empty() || input.size() % kPairBytes != 0) {
        return UINT64_MAX;
    }
    const size_t k = input.size() / kPairBytes;
    return 32600ull + 37700ull * k;
}
std::optional<Bytes> bls_pairing_run(ByteView input_view) noexcept {
    constexpr size_t kPairBytes = 384;
    if (input_view.empty() || input_view.size() % kPairBytes != 0) {
        return std::nullopt;
    }
    Bytes input{input_view};
    uint8_t r[32];
    if (!evmone::crypto::bls::pairing_check(r, input.data(), input.size())) {
        return std::nullopt;
    }
    return Bytes{r, r + 32};
}

// 0x10 — BLS12_MAP_FP_TO_G1
uint64_t bls_map_fp_to_g1_gas(ByteView, evmc_revision) noexcept { return 5500; }
std::optional<Bytes> bls_map_fp_to_g1_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 64);
    uint8_t rx[64], ry[64];
    if (!evmone::crypto::bls::map_fp_to_g1(rx, ry, input.data())) {
        return std::nullopt;
    }
    Bytes out(128, 0);
    std::memcpy(out.data(), rx, 64);
    std::memcpy(out.data() + 64, ry, 64);
    return out;
}

// 0x11 — BLS12_MAP_FP2_TO_G2
uint64_t bls_map_fp2_to_g2_gas(ByteView, evmc_revision) noexcept { return 23800; }
std::optional<Bytes> bls_map_fp2_to_g2_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 128);
    uint8_t rx[128], ry[128];
    if (!evmone::crypto::bls::map_fp2_to_g2(rx, ry, input.data())) {
        return std::nullopt;
    }
    Bytes out(256, 0);
    std::memcpy(out.data(), rx, 128);
    std::memcpy(out.data() + 128, ry, 128);
    return out;
}

// =============================================================================
// EIP-7951 (Fusaka): secp256r1 (P-256) ECDSA verify precompile at 0x100.
// =============================================================================
//
// Input layout (160 bytes, big-endian throughout):
//   bytes [0   .. 32) : msg_hash (32B)
//   bytes [32  .. 64) : r        (32B, signature scalar)
//   bytes [64  .. 96) : s        (32B, signature scalar)
//   bytes [96  ..128) : qx       (32B, public key x)
//   bytes [128 ..160) : qy       (32B, public key y)
//
// Output: 32-byte big-endian uint256 == 1 on valid signature, OR empty
// bytes on any failure (invalid input length, point not on curve, r/s
// out of range, signature does not verify).
//
// Crypto: delegates to OpenSSL libcrypto (NID_X9_62_prime256v1). Silkworm's
// core lib gains a libcrypto link in CMakeLists.txt for this precompile.

}  // close namespace silkworm::precompile to include OpenSSL headers
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
namespace silkworm::precompile {

uint64_t p256verify_gas(ByteView, evmc_revision) noexcept {
    return 6900;  // EIP-7951
}

std::optional<Bytes> p256verify_run(ByteView input_view) noexcept {
    // Strict length check — EIP-7951 says non-160-byte input is invalid.
    if (input_view.size() != 160) {
        return Bytes{};  // empty output → "verification failed" per spec
    }

    auto* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return Bytes{};

    auto cleanup_group = [&]() { EC_GROUP_free(group); };

    BIGNUM* qx = BN_bin2bn(input_view.data() + 96, 32, nullptr);
    BIGNUM* qy = BN_bin2bn(input_view.data() + 128, 32, nullptr);
    BIGNUM* r = BN_bin2bn(input_view.data() + 32, 32, nullptr);
    BIGNUM* s = BN_bin2bn(input_view.data() + 64, 32, nullptr);
    if (!qx || !qy || !r || !s) {
        BN_free(qx); BN_free(qy); BN_free(r); BN_free(s);
        cleanup_group();
        return Bytes{};
    }

    // Build public key point and validate.
    auto* pub = EC_POINT_new(group);
    if (!pub) {
        BN_free(qx); BN_free(qy); BN_free(r); BN_free(s);
        cleanup_group();
        return Bytes{};
    }
    bool ok = EC_POINT_set_affine_coordinates(group, pub, qx, qy, nullptr) == 1
              && EC_POINT_is_on_curve(group, pub, nullptr) == 1
              && EC_POINT_is_at_infinity(group, pub) == 0;

    // Validate r,s ∈ [1, n-1].
    if (ok) {
        const BIGNUM* order = EC_GROUP_get0_order(group);
        ok = !BN_is_zero(r) && !BN_is_zero(s)
             && BN_cmp(r, order) < 0 && BN_cmp(s, order) < 0;
    }

    int verify_result = 0;
    if (ok) {
        auto* key = EC_KEY_new();
        if (key && EC_KEY_set_group(key, group) == 1
                && EC_KEY_set_public_key(key, pub) == 1) {
            auto* sig = ECDSA_SIG_new();
            if (sig && ECDSA_SIG_set0(sig, r, s) == 1) {
                // ECDSA_SIG_set0 takes ownership of r and s; null them out
                // so the cleanup below doesn't double-free.
                r = nullptr;
                s = nullptr;
                verify_result = ECDSA_do_verify(input_view.data(), 32, sig, key);
                ECDSA_SIG_free(sig);  // also frees the consumed r,s
            } else if (sig) {
                ECDSA_SIG_free(sig);
            }
            EC_KEY_free(key);
        } else if (key) {
            EC_KEY_free(key);
        }
    }

    BN_free(qx); BN_free(qy); BN_free(r); BN_free(s);
    EC_POINT_free(pub);
    cleanup_group();

    if (verify_result == 1) {
        Bytes out(32, 0);
        out[31] = 1;
        return out;
    }
    return Bytes{};  // empty bytes on any failure (per EIP-7951)
}

// EIP-7951: P-256 lives at address 0x000…0100 (= 256 decimal). Out-of-table
// — the contiguous kContracts[] dispatch only covers addresses ≤ 0xff.
inline constexpr evmc::address kP256VerifyAddress{
    0x0000000000000000000000000000000000000100_address};
inline constexpr Contract kP256VerifyContract{p256verify_gas, p256verify_run};

const Contract* find_precompile(const evmc::address& address, evmc_revision rev) noexcept {
    using namespace evmc::literals;

    // EIP-7951 (Osaka): P-256 verify at 0x100.
    if (rev >= EVMC_OSAKA && address == kP256VerifyAddress) {
        return &kP256VerifyContract;
    }

    static_assert(std::size(kContracts) < 256);
    static constexpr evmc::address kMaxOneByteAddress{0x00000000000000000000000000000000000000ff_address};
    if (address > kMaxOneByteAddress) {
        return nullptr;
    }

    const uint8_t num{address.bytes[kAddressLength - 1]};
    if (num >= std::size(kContracts) || !kContracts[num]) {
        return nullptr;
    }
    if (kContracts[num]->added_in > rev) {
        return nullptr;
    }
    return &kContracts[num]->contract;
}

bool is_precompile(const evmc::address& address, evmc_revision rev) noexcept {
    return find_precompile(address, rev) != nullptr;
}

}  // namespace silkworm::precompile
