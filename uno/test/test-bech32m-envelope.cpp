/*
    Uno Workchain — Bech32m address envelope codec test (K-bech32m).

    Exercises `encode_address_envelope` / `decode_address_envelope` against
    §2.6 of doc/uno-workchain.md:

      * Round-trip: 3 pinned envelopes (testnet v1, mainnet v1, v1 with
        high-byte payload) encode then decode to byte-identical inputs.
      * Reject cases:
          - Wrong HRP            (e.g. "tos1..." instead of "uno1...")
          - HRP / inner network mismatch (decoded network_tag != HRP)
          - Flipped checksum byte (single bit-flip in last char)
          - Flipped payload byte  (BLAKE3 content tag then disagrees)
          - Short payload         (truncated mid-data)
          - Unknown version_tag   (envelope uses 0x02)
          - Mixed case            (half-upper, half-lower)
          - Illegal charset       (char 'b' is not in Bech32 alphabet)

    The BLAKE3 tag backend is the avatar adapter (configured by
    uno_workchain's CMake wiring). No Plonky3 FFI, no liboqs.
*/

#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "uno/crypto/bech32m.h"

using uno_workchain::crypto::AddressEnvelope;
using uno_workchain::crypto::EnvelopeError;
using uno_workchain::crypto::decode_address_envelope;
using uno_workchain::crypto::encode_address_envelope;
using uno_workchain::crypto::kAddressEnvelopeVersionV1;
using uno_workchain::crypto::kAddressNetworkMainnet;
using uno_workchain::crypto::kAddressNetworkTestnet;

// ----- Tracked-printf harness (shared idiom with other uno/test files) ----

static std::atomic<int> g_failures{0};
static std::atomic<int> g_passes{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize((size_t)needed + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize((size_t)needed);
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("PASSED") != std::string::npos) g_passes.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// Populate `payload` with a deterministic byte pattern driven by `seed`.
// Each byte becomes `(seed + i) & 0xFF` so every fixture has a unique
// payload and the Bech32m encoded strings are distinct.
static AddressEnvelope make_fixture(std::uint8_t version,
                                    std::uint8_t network,
                                    std::uint8_t seed) {
    AddressEnvelope env{};
    env.version_tag = version;
    env.network_tag = network;
    for (std::size_t i = 0; i < env.payload.size(); ++i) {
        env.payload[i] = static_cast<std::uint8_t>(seed + i);
    }
    return env;
}

// ---------------------------------------------------------------------------
// Round-trip: encode → decode byte-identical
// ---------------------------------------------------------------------------

static void test_roundtrip(const char* label,
                           const AddressEnvelope& env,
                           const char* expected_hrp_prefix) {
    tprintf("[TEST] test_roundtrip(%s)\n", label);

    std::string encoded = encode_address_envelope(env);
    if (encoded.empty()) {
        tprintf("  FAILED: encode returned empty string\n");
        return;
    }
    // HRP prefix check — "unot1" for testnet, "uno1" for mainnet.
    if (encoded.rfind(expected_hrp_prefix, 0) != 0) {
        tprintf("  FAILED: encoded string does not start with \"%s\" (got \"%.8s...\")\n",
                expected_hrp_prefix, encoded.c_str());
        return;
    }

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err != EnvelopeError::kOk) {
        tprintf("  FAILED: decode returned err=%d\n", static_cast<int>(err));
        return;
    }
    if (got.version_tag != env.version_tag ||
        got.network_tag != env.network_tag ||
        got.payload     != env.payload) {
        tprintf("  FAILED: decoded envelope != original\n");
        return;
    }

    tprintf("  PASSED (%zu-char address, HRP=\"%s\")\n",
            encoded.size(), expected_hrp_prefix);
}

// ---------------------------------------------------------------------------
// Reject: HRP is not "uno" / "unot"
// ---------------------------------------------------------------------------

static void test_reject_bad_hrp() {
    tprintf("[TEST] test_reject_bad_hrp\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x10);
    std::string encoded = encode_address_envelope(env);

    // Swap "unot" → "tost" — same length, different HRP. The stem
    // ("1<data>") stays valid, but the polymod binds to the original
    // "unot" HRP so the checksum will fail; an "unknown HRP" short-circuit
    // rejects before that anyway.
    // First, check "unot" is actually the prefix we expect.
    assert(encoded.rfind("unot1", 0) == 0);
    encoded[0] = 't';
    encoded[1] = 'o';
    encoded[2] = 's';
    encoded[3] = 't';

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted address with HRP=\"tost\"\n");
        return;
    }
    if (err != EnvelopeError::kBadHrp) {
        tprintf("  FAILED: expected kBadHrp, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kBadHrp)\n");
}

// ---------------------------------------------------------------------------
// Reject: HRP / inner network_tag disagreement
//
// Encode with network_tag = testnet under HRP "unot", then string-rewrite
// the HRP to "uno" (mainnet). Checksum will fail because the polymod binds
// HRP; this exercises the kBadChecksum path (the inner-tag cross-check
// would also fire if the Bech32m polymod somehow passed).
// ---------------------------------------------------------------------------

static void test_reject_network_mismatch() {
    tprintf("[TEST] test_reject_network_mismatch\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x20);
    std::string encoded = encode_address_envelope(env);
    assert(encoded.rfind("unot1", 0) == 0);

    // Rewrite HRP from "unot" to "uno" (drop one char). Body and separator
    // stay put after shift.
    std::string mutated = "uno" + encoded.substr(4);

    AddressEnvelope got{};
    auto err = decode_address_envelope(mutated, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted HRP-rewritten address\n");
        return;
    }
    // Either the HRP-bound polymod fails, or (if it miraculously passed)
    // the inner network_tag cross-check fires. Both are valid rejects.
    if (err != EnvelopeError::kBadChecksum &&
        err != EnvelopeError::kBadHrp) {
        tprintf("  FAILED: expected kBadChecksum or kBadHrp, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: err=%d)\n", static_cast<int>(err));
}

// ---------------------------------------------------------------------------
// Reject: flipped checksum symbol
// ---------------------------------------------------------------------------

static void test_reject_flipped_checksum() {
    tprintf("[TEST] test_reject_flipped_checksum\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x30);
    std::string encoded = encode_address_envelope(env);

    // Flip the last character to a different alphabet entry. The Bech32
    // alphabet is "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; cycle to the next
    // character that isn't equal to the original.
    const char* kAlph = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    char last = encoded.back();
    char replacement = (last == 'q' ? 'p' : 'q');
    // Ensure replacement is actually in the alphabet.
    assert(std::strchr(kAlph, replacement) != nullptr);
    encoded.back() = replacement;

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted checksum-flipped address\n");
        return;
    }
    if (err != EnvelopeError::kBadChecksum) {
        tprintf("  FAILED: expected kBadChecksum, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kBadChecksum)\n");
}

// ---------------------------------------------------------------------------
// Reject: flipped payload byte — Bech32m polymod stays valid only if the
// attacker re-computes the 6 checksum symbols, but the inner BLAKE3
// content tag (bound to version/network/payload via "uno-addr-checksum-v1")
// still disagrees. We simulate that attack by encoding an envelope, then
// decoding it, mutating the payload in the DECODED struct's expected
// encoding, recomputing the Bech32m checksum over the tampered byte
// stream, and re-emitting. Simpler: directly mutate one data char and
// pin kBadChecksum regardless of which layer caught it.
// ---------------------------------------------------------------------------

static void test_reject_flipped_payload() {
    tprintf("[TEST] test_reject_flipped_payload\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x40);
    std::string encoded = encode_address_envelope(env);

    // Mutate a character ~10 chars into the data section. Bech32m polymod
    // should detect this (single-char error detectability is one of
    // BIP-173's guarantees).
    // Skip 'unot1' prefix → data starts at offset 5.
    std::size_t target = 5 + 10;
    assert(target < encoded.size() - 6);
    const char* kAlph = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    char orig = encoded[target];
    char repl = (orig == 'q' ? 'p' : 'q');
    assert(std::strchr(kAlph, repl) != nullptr);
    encoded[target] = repl;

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted payload-flipped address\n");
        return;
    }
    if (err != EnvelopeError::kBadChecksum) {
        tprintf("  FAILED: expected kBadChecksum, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kBadChecksum)\n");
}

// ---------------------------------------------------------------------------
// Reject: truncated address (payload too short)
// ---------------------------------------------------------------------------

static void test_reject_short_payload() {
    tprintf("[TEST] test_reject_short_payload\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x50);
    std::string encoded = encode_address_envelope(env);
    // Drop the last ~50 chars — makes the 5→8 unpack short of 1267 bytes.
    encoded.resize(encoded.size() - 50);

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted truncated address\n");
        return;
    }
    // Truncation can surface as either kBadLength (short unpack) or
    // kBadChecksum (polymod fails before length is re-checked). Both
    // are valid rejects; §2.6 only requires "wallet MUST reject".
    if (err != EnvelopeError::kBadLength &&
        err != EnvelopeError::kBadChecksum) {
        tprintf("  FAILED: expected kBadLength or kBadChecksum, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: err=%d)\n", static_cast<int>(err));
}

// ---------------------------------------------------------------------------
// Reject: unknown version_tag
// ---------------------------------------------------------------------------

static void test_reject_bad_version() {
    tprintf("[TEST] test_reject_bad_version\n");

    AddressEnvelope env = make_fixture(/*version=*/0x02,  // unknown
                                       kAddressNetworkTestnet, 0x60);
    std::string encoded = encode_address_envelope(env);

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted version_tag=0x02\n");
        return;
    }
    if (err != EnvelopeError::kBadVersion) {
        tprintf("  FAILED: expected kBadVersion, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kBadVersion)\n");
}

// ---------------------------------------------------------------------------
// Reject: mixed case
// ---------------------------------------------------------------------------

static void test_reject_mixed_case() {
    tprintf("[TEST] test_reject_mixed_case\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x70);
    std::string encoded = encode_address_envelope(env);
    // Uppercase the 6th character (first data symbol after 'unot1'). One
    // uppercase letter + existing lowercase letters = mixed case.
    for (std::size_t i = 5; i < encoded.size(); ++i) {
        if (encoded[i] >= 'a' && encoded[i] <= 'z') {
            encoded[i] = static_cast<char>(encoded[i] - 'a' + 'A');
            break;
        }
    }

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted mixed-case address\n");
        return;
    }
    if (err != EnvelopeError::kMixedCase) {
        tprintf("  FAILED: expected kMixedCase, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kMixedCase)\n");
}

// ---------------------------------------------------------------------------
// Reject: illegal charset character ('b' is not in the Bech32 alphabet).
//
// The Bech32 alphabet omits '1', 'b', 'i', 'o' (to avoid visual confusion).
// Injecting a 'b' mid-data-section must surface kBadCharset.
// ---------------------------------------------------------------------------

static void test_reject_illegal_charset() {
    tprintf("[TEST] test_reject_illegal_charset\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkTestnet, 0x80);
    std::string encoded = encode_address_envelope(env);
    // Inject a 'b' 30 chars in.
    encoded[5 + 30] = 'b';

    AddressEnvelope got{};
    auto err = decode_address_envelope(encoded, got);
    if (err == EnvelopeError::kOk) {
        tprintf("  FAILED: accepted 'b' in data section\n");
        return;
    }
    if (err != EnvelopeError::kBadCharset) {
        tprintf("  FAILED: expected kBadCharset, got err=%d\n",
                static_cast<int>(err));
        return;
    }
    tprintf("  PASSED (rejected: kBadCharset)\n");
}

// ---------------------------------------------------------------------------
// Uppercase round-trip: BIP-173 allows all-upper-case. Sanity check: an
// all-upper-case version of a valid encoding must decode identically to
// the lowercase form.
// ---------------------------------------------------------------------------

static void test_uppercase_roundtrip() {
    tprintf("[TEST] test_uppercase_roundtrip\n");

    auto env = make_fixture(kAddressEnvelopeVersionV1,
                            kAddressNetworkMainnet, 0x90);
    std::string encoded = encode_address_envelope(env);
    std::string upper = encoded;
    for (char& c : upper) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }

    AddressEnvelope got{};
    auto err = decode_address_envelope(upper, got);
    if (err != EnvelopeError::kOk) {
        tprintf("  FAILED: all-upper decode err=%d\n", static_cast<int>(err));
        return;
    }
    if (got.payload != env.payload) {
        tprintf("  FAILED: all-upper payload mismatch\n");
        return;
    }
    tprintf("  PASSED\n");
}

// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("Uno Workchain — K-bech32m envelope codec test\n");
    tprintf("==============================================\n\n");

    // --- Round-trip pins (3 pinned envelopes + uppercase sanity) ---
    test_roundtrip("testnet_v1", make_fixture(kAddressEnvelopeVersionV1,
                                              kAddressNetworkTestnet,
                                              0x01), "unot1");
    test_roundtrip("mainnet_v1", make_fixture(kAddressEnvelopeVersionV1,
                                              kAddressNetworkMainnet,
                                              0x11), "uno1");
    test_roundtrip("testnet_v1_high", make_fixture(kAddressEnvelopeVersionV1,
                                                   kAddressNetworkTestnet,
                                                   0xA5), "unot1");
    test_uppercase_roundtrip();

    // --- Reject pins ---
    test_reject_bad_hrp();
    test_reject_network_mismatch();
    test_reject_flipped_checksum();
    test_reject_flipped_payload();
    test_reject_short_payload();
    test_reject_bad_version();
    test_reject_mixed_case();
    test_reject_illegal_charset();

    tprintf("\nTotal: passed=%d, failures=%d\n",
            g_passes.load(), g_failures.load());
    return g_failures.load() == 0 ? 0 : 1;
}
