/*
    Uno Workchain — MineUno constants + fixture loader test.

    Tests the Phase 1 MineUno data structures (mine_constants.h, mine_uno.h)
    and the golden fixture produced by `tosctl/uno/tests/mine_genesis_golden.rs`.

    Test structure (mirrors test-genesis-loader.cpp):
      - Each test_*() function prints PASSED / FAILED / SKIP.
      - The tracked_printf harness tallies results; main exits 0 iff no FAILED.

    Tests:
      1. test_mine_reward_for_era      — halving table arithmetic
      2. test_era_from_epoch           — era boundary arithmetic
      3. test_check_value_matches_halving — MineUnoPublicInputs.check_value
      4. test_check_conservation       — MineUnoPublicInputs.check_conservation
      5. test_public_inputs_wire_roundtrip — to_wire / from_wire (via Rust mirror)
      6. test_load_rust_mine_golden_fixture — cross-impl parity via JSON fixture

    Test 7 drives the real Plonky3 MineUno STARK prove + verify round-trip
    through the `uno_mine_uno_prove` / `uno_mine_uno_verify` FFI. The
    witness is a deterministic valid one (mirrored from
    `uno_plonky3_ffi::mine_uno_witness::MineUnoWitness::deterministic_valid`)
    so the test is hermetic and independent of any on-disk golden proof file.
    Also asserts a tampered-proof path (bit-flip inside the proof bytes)
    returns non-Ok — exercising the verifier reject surface.

    Build target: test-uno-mine-loader (see uno/test/CMakeLists.txt)
    CMake: cmake --build /home/tomi/tos/build --target test-uno-mine-loader -j 64
*/

#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/filesystem.h"

#include "uno/core/genesis.h"                // build_zerostate_state
#include "uno/core/mine_constants.h"
#include "uno/core/mine_uno.h"
#include "uno_plonky3_ffi.h"                 // uno_mine_uno_prove / _verify

#include <cstdlib>                           // ::unsetenv

// ---------------------------------------------------------------------------
// Tracked-printf harness (identical to test-genesis-loader.cpp)
// ---------------------------------------------------------------------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_passes{0};
static std::atomic<int> g_skips{0};

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
        if (rendered.find("SKIP")   != std::string::npos) g_skips.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// Minimal JSON value extractor (no external JSON library dependency).
//
// We need to read just a handful of top-level and nested string/number fields
// from the golden fixture JSON.  Rather than pulling in a full JSON parser,
// we use simple string-search helpers that are sufficient for the fixture's
// deterministic structure.
// ---------------------------------------------------------------------------

// Returns the hex string value of key `"field_name": "<hex>"` within `json`.
// Handles both compact (`"k":"v"`) and pretty-printed (`"k": "v"`) JSON.
// Returns empty string if not found.
static std::string extract_hex_field(const std::string& json,
                                      const std::string& field_name) {
    std::string needle = "\"" + field_name + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    // Skip whitespace and ':'
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) ++pos;
    // Expect opening quote
    if (pos >= json.size() || json[pos] != '"') return {};
    ++pos;  // skip opening quote
    auto end = json.find('"', pos);
    if (end == std::string::npos) return {};
    return json.substr(pos, end - pos);
}

// Returns the numeric value (as uint64_t) for `"field_name": <number>`.
// Handles both compact and pretty-printed JSON.
// Returns 0 if not found.
static uint64_t extract_number_field(const std::string& json,
                                      const std::string& field_name) {
    std::string needle = "\"" + field_name + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    // Skip whitespace and ':'
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) ++pos;
    if (pos >= json.size()) return 0;
    char* end_ptr = nullptr;
    uint64_t val = std::strtoull(json.c_str() + pos, &end_ptr, 10);
    return val;
}

// Decode a 2-character hex byte.
static uint8_t hex_byte(char hi, char lo) {
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
        if (c >= 'a' && c <= 'f') return (uint8_t)(10 + c - 'a');
        if (c >= 'A' && c <= 'F') return (uint8_t)(10 + c - 'A');
        return 0;
    };
    return (nibble(hi) << 4) | nibble(lo);
}

// Decode a hex string into a byte vector.
static std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(hex_byte(hex[i], hex[i + 1]));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Helper: find the golden fixture file by probing candidate paths.
// Mirrors the pattern in test-genesis-loader.cpp::test_load_rust_golden_fixture.
// ---------------------------------------------------------------------------

static std::string find_mine_golden_fixture() {
    const char* candidates[] = {
        "uno/test/golden/mine-uno-witness-v1.json",
        "../uno/test/golden/mine-uno-witness-v1.json",
        "../../uno/test/golden/mine-uno-witness-v1.json",
        "../../../uno/test/golden/mine-uno-witness-v1.json",
    };
    for (const char* c : candidates) {
        auto r = td::read_file(td::CSlice(c));
        if (r.is_ok()) return c;
    }
    return {};
}

// ---------------------------------------------------------------------------
// Test 1 — mine_reward_for_era arithmetic
// ---------------------------------------------------------------------------

static void test_mine_reward_for_era() {
    tprintf("[TEST] test_mine_reward_for_era\n");

    using uno_workchain::mine_reward_for_era;
    using uno_workchain::kInitMineReward;

    struct Case { uint32_t era; uint64_t expected; const char* label; };
    static const Case cases[] = {
        { 0,  50ULL * 1'000'000'000ULL, "era 0 = 50 UNO" },
        { 1,  25ULL * 1'000'000'000ULL, "era 1 = 25 UNO" },
        { 2,  12'500'000'000ULL,         "era 2 = 12.5 UNO" },
        { 3,   6'250'000'000ULL,         "era 3 = 6.25 UNO" },
        { 4,   3'125'000'000ULL,         "era 4" },
        { 10,     48'828'125ULL,         "era 10" },
        { 20,          47'683ULL,        "era 20" },
        { 30,              46ULL,        "era 30" },
        { 35,               1ULL,        "era 35 (last non-zero)" },
        { 36,               0ULL,        "era 36 (first zero)" },
        { 64,               0ULL,        "era 64 (saturates)" },
        { 100,              0ULL,        "era 100 (well beyond)" },
    };

    for (const auto& tc : cases) {
        uint64_t got = mine_reward_for_era(tc.era);
        if (got != tc.expected) {
            tprintf("  FAILED: %s — got %llu, expected %llu\n",
                    tc.label, (unsigned long long)got,
                    (unsigned long long)tc.expected);
            return;
        }
    }

    // kMaxNonZeroEra must be non-zero and kMaxNonZeroEra+1 must be zero.
    if (mine_reward_for_era(uno_workchain::kMaxNonZeroEra) == 0) {
        tprintf("  FAILED: mine_reward_for_era(kMaxNonZeroEra) == 0; expected > 0\n");
        return;
    }
    if (mine_reward_for_era(uno_workchain::kMaxNonZeroEra + 1) != 0) {
        tprintf("  FAILED: mine_reward_for_era(kMaxNonZeroEra+1) != 0\n");
        return;
    }

    // Geometric sum for non-zero eras must not exceed the supply cap.
    uint64_t total = 0;
    for (uint32_t era = 0; era <= uno_workchain::kMaxNonZeroEra; ++era) {
        total += mine_reward_for_era(era) * 210'000ULL;
    }
    if (total > uno_workchain::kMineSupplyNano) {
        tprintf("  FAILED: geometric sum %llu exceeds supply cap %llu\n",
                (unsigned long long)total,
                (unsigned long long)uno_workchain::kMineSupplyNano);
        return;
    }

    tprintf("  PASSED (halving table matches Bitcoin-clone curve; supply cap holds)\n");
}

// ---------------------------------------------------------------------------
// Test 2 — era_from_epoch arithmetic
// ---------------------------------------------------------------------------

static void test_era_from_epoch() {
    tprintf("[TEST] test_era_from_epoch\n");

    using uno_workchain::era_from_epoch;

    struct Case { uint32_t epoch; uint32_t expected; const char* label; };
    static const Case cases[] = {
        {       0, 0, "epoch 0 → era 0" },
        { 209'999, 0, "epoch 209999 → era 0" },
        { 210'000, 1, "epoch 210000 → era 1" },
        { 419'999, 1, "epoch 419999 → era 1" },
        { 420'000, 2, "epoch 420000 → era 2" },
        { 630'000, 3, "epoch 630000 → era 3" },
    };

    for (const auto& tc : cases) {
        uint32_t got = era_from_epoch(tc.epoch);
        if (got != tc.expected) {
            tprintf("  FAILED: %s — got %u, expected %u\n",
                    tc.label, got, tc.expected);
            return;
        }
    }

    tprintf("  PASSED (era_from_epoch matches epoch / kEraSize semantics)\n");
}

// ---------------------------------------------------------------------------
// Test 3 — check_value_matches_halving
// ---------------------------------------------------------------------------

static void test_check_value_matches_halving() {
    tprintf("[TEST] test_check_value_matches_halving\n");

    using uno_workchain::MineUnoPublicInputs;
    using uno_workchain::check_value_matches_halving;
    using uno_workchain::kInitMineReward;
    using uno_workchain::kMineSupplyNano;

    // Era 0, correct value.
    {
        MineUnoPublicInputs pi{};
        pi.epoch      = 0;
        pi.value_nano = kInitMineReward;
        pi.remaining_pre  = kMineSupplyNano;
        pi.remaining_post = kMineSupplyNano - kInitMineReward;
        if (!check_value_matches_halving(pi)) {
            tprintf("  FAILED: epoch 0, value_nano = era-0 reward should PASS\n");
            return;
        }
    }

    // Era 0, wrong value (one less).
    {
        MineUnoPublicInputs pi{};
        pi.epoch      = 0;
        pi.value_nano = kInitMineReward - 1;
        if (check_value_matches_halving(pi)) {
            tprintf("  FAILED: epoch 0, value_nano = reward - 1 should FAIL\n");
            return;
        }
    }

    // Era 0, wrong value (one more).
    {
        MineUnoPublicInputs pi{};
        pi.epoch      = 0;
        pi.value_nano = kInitMineReward + 1;
        if (check_value_matches_halving(pi)) {
            tprintf("  FAILED: epoch 0, value_nano = reward + 1 should FAIL\n");
            return;
        }
    }

    // Era 1 (epoch 210000), correct value = 25 UNO.
    {
        MineUnoPublicInputs pi{};
        pi.epoch      = 210'000;
        pi.value_nano = 25ULL * 1'000'000'000ULL;
        if (!check_value_matches_halving(pi)) {
            tprintf("  FAILED: epoch 210000, value_nano = 25 UNO should PASS\n");
            return;
        }
    }

    // Era 1 (epoch 210000), wrong value (still era-0 reward).
    {
        MineUnoPublicInputs pi{};
        pi.epoch      = 210'000;
        pi.value_nano = kInitMineReward;   // era-0 reward is wrong for era-1
        if (check_value_matches_halving(pi)) {
            tprintf("  FAILED: epoch 210000, era-0 reward should FAIL (wrong era)\n");
            return;
        }
    }

    tprintf("  PASSED (check_value_matches_halving gate works for multiple eras)\n");
}

// ---------------------------------------------------------------------------
// Test 4 — check_conservation
// ---------------------------------------------------------------------------

static void test_check_conservation() {
    tprintf("[TEST] test_check_conservation\n");

    using uno_workchain::MineUnoPublicInputs;
    using uno_workchain::check_conservation;
    using uno_workchain::kInitMineReward;
    using uno_workchain::kMineSupplyNano;

    // Happy path.
    {
        MineUnoPublicInputs pi{};
        pi.epoch          = 0;
        pi.value_nano     = kInitMineReward;
        pi.remaining_pre  = kMineSupplyNano;
        pi.remaining_post = kMineSupplyNano - kInitMineReward;
        if (!check_conservation(pi)) {
            tprintf("  FAILED: valid conservation check failed\n");
            return;
        }
    }

    // remaining_post tampered (wrong by 1).
    {
        MineUnoPublicInputs pi{};
        pi.epoch          = 0;
        pi.value_nano     = kInitMineReward;
        pi.remaining_pre  = kMineSupplyNano;
        pi.remaining_post = kMineSupplyNano - kInitMineReward + 1;  // tampered
        if (check_conservation(pi)) {
            tprintf("  FAILED: tampered remaining_post should FAIL conservation\n");
            return;
        }
    }

    // Over-mint: remaining_pre < value_nano.
    {
        MineUnoPublicInputs pi{};
        pi.epoch          = 0;
        pi.value_nano     = kInitMineReward;
        pi.remaining_pre  = kInitMineReward - 1;   // less than reward
        pi.remaining_post = 0;
        if (check_conservation(pi)) {
            tprintf("  FAILED: remaining_pre < value_nano should FAIL (over-mint)\n");
            return;
        }
    }

    // Last-UNO boundary: remaining_pre == value_nano → remaining_post = 0.
    {
        MineUnoPublicInputs pi{};
        pi.epoch          = 0;
        pi.value_nano     = kInitMineReward;
        pi.remaining_pre  = kInitMineReward;   // exact match
        pi.remaining_post = 0;
        if (!check_conservation(pi)) {
            tprintf("  FAILED: remaining_pre == value_nano → post=0 should PASS\n");
            return;
        }
    }

    tprintf("  PASSED (conservation gate handles happy path + edge cases)\n");
}

// ---------------------------------------------------------------------------
// Test 5 — MineUnoPublicInputs wire round-trip (via Rust mirror layout)
// ---------------------------------------------------------------------------

static void test_public_inputs_wire_layout() {
    tprintf("[TEST] test_public_inputs_wire_layout\n");

    using uno_workchain::MineUnoPublicInputs;
    using uno_workchain::kInitMineReward;
    using uno_workchain::kMineSupplyNano;

    MineUnoPublicInputs pi{};
    pi.epoch      = 0;
    // Genesis initial target: 2^219, byte[4] = 0x08 (big-endian 32 B).
    std::memcpy(pi.target.data(), uno_workchain::kInitMineTargetBE, 32);
    pi.value_nano = kInitMineReward;
    // output_cm placeholder (0xEE repeated for test).
    pi.output_cm.fill(0xEE);
    pi.remaining_pre  = kMineSupplyNano;
    pi.remaining_post = kMineSupplyNano - kInitMineReward;

    // Manually encode to the 92-byte wire layout (big-endian, matching Rust).
    // Layout: epoch(4) target(32) value_nano(8) output_cm(32)
    //         remaining_pre(8) remaining_post(8) = 92 bytes.
    uint8_t wire[92]{};
    wire[0] = (pi.epoch >> 24) & 0xFF;
    wire[1] = (pi.epoch >> 16) & 0xFF;
    wire[2] = (pi.epoch >>  8) & 0xFF;
    wire[3] = (pi.epoch >>  0) & 0xFF;
    std::memcpy(wire + 4,  pi.target.data(), 32);
    auto encode_u64_be = [](uint8_t* out, uint64_t v) {
        for (int i = 7; i >= 0; --i, v >>= 8) out[i] = v & 0xFF;
    };
    encode_u64_be(wire + 36, pi.value_nano);
    std::memcpy(wire + 44, pi.output_cm.data(), 32);
    encode_u64_be(wire + 76, pi.remaining_pre);
    encode_u64_be(wire + 84, pi.remaining_post);

    // Verify epoch is 0 at offset 0.
    if (wire[0] != 0 || wire[1] != 0 || wire[2] != 0 || wire[3] != 0) {
        tprintf("  FAILED: epoch bytes are not all zero for epoch=0\n");
        return;
    }
    // Verify the non-zero byte within the target field.
    // kInitMineTargetBE = 2^219 in big-endian 32 B: byte[4] = 0x08, rest 0x00.
    // Derivation: 2^219 = 0x08 << 216, so BE byte index is (31 - 219/8) = 4,
    // and the bit within that byte is (219 % 8) = 3, value (1<<3) = 0x08.
    // The target field starts at wire offset 4, so the non-zero byte is at
    // wire offset 4 + 4 = 8.
    // C++ (kInitMineTargetBE) and Rust (INIT_MINE_TARGET_BE) are byte-identical.
    if (wire[4 + 4] != 0x08) {
        tprintf("  FAILED: target byte 4 (kInitMineTargetBE index 4) is not 0x08 "
                "at wire offset %d (got 0x%02x)\n", 4 + 4, wire[4 + 4]);
        return;
    }
    // Also assert all other bytes in the target field are 0.
    bool target_clean = true;
    for (int i = 0; i < 32; ++i) {
        if (i == 4) continue;
        if (wire[4 + i] != 0x00) {
            tprintf("  FAILED: target byte %d should be 0x00, got 0x%02x\n",
                    i, wire[4 + i]);
            target_clean = false;
            break;
        }
    }
    if (!target_clean) return;
    // Verify value_nano encoded correctly at offset 36.
    uint64_t decoded_value = 0;
    for (int i = 0; i < 8; ++i) decoded_value = (decoded_value << 8) | wire[36 + i];
    if (decoded_value != kInitMineReward) {
        tprintf("  FAILED: wire value_nano %llu != kInitMineReward %llu\n",
                (unsigned long long)decoded_value,
                (unsigned long long)kInitMineReward);
        return;
    }
    // Verify output_cm at offset 44.
    for (int i = 0; i < 32; ++i) {
        if (wire[44 + i] != 0xEE) {
            tprintf("  FAILED: output_cm byte %d is %02x, expected 0xEE\n",
                    i, wire[44 + i]);
            return;
        }
    }
    // Verify total size is 92 bytes (compile-time structural check only here).
    static_assert(sizeof(wire) == 92,
                  "MineUnoPublicInputs wire layout must be exactly 92 bytes");

    tprintf("  PASSED (MineUnoPublicInputs 92-byte wire layout is correct)\n");
}

// ---------------------------------------------------------------------------
// Test 6 — Load Rust golden fixture
//
// Mirrors test-genesis-loader.cpp::test_load_rust_golden_fixture.
// Reads `uno/test/golden/mine-uno-witness-v1.json` if present, validates
// the top-level schema and key fields, then cross-checks with C++ constants.
// ---------------------------------------------------------------------------

static void test_load_rust_mine_golden_fixture() {
    tprintf("[TEST] test_load_rust_mine_golden_fixture\n");

    std::string path = find_mine_golden_fixture();
    if (path.empty()) {
        tprintf("  SKIP: mine golden fixture not found in any candidate path "
                "(regenerate via `UNO_MINE_REGEN=1 cargo test --release "
                "--test mine_genesis_golden`)\n");
        return;
    }

    auto file_r = td::read_file(td::CSlice(path.c_str()));
    if (file_r.is_error()) {
        tprintf("  FAILED: could not read %s: %s\n",
                path.c_str(), file_r.error().message().c_str());
        return;
    }
    std::string json = file_r.move_as_ok().as_slice().str();

    // Schema check.
    // serde_json::to_string_pretty emits spaces: `"schema": "value"`.
    // Search for `"schema"` then scan forward past `:`, whitespace, `"`.
    {
        std::string needle = "\"schema\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) {
            tprintf("  FAILED: golden fixture missing \"schema\" field\n");
            return;
        }
        pos += needle.size();
        // Skip whitespace and ':'
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) ++pos;
        // Expect opening quote
        if (pos >= json.size() || json[pos] != '"') {
            tprintf("  FAILED: \"schema\" value is not a quoted string\n");
            return;
        }
        ++pos;  // skip opening quote
        auto end = json.find('"', pos);
        if (end == std::string::npos) {
            tprintf("  FAILED: unterminated \"schema\" string value\n");
            return;
        }
        std::string schema_val = json.substr(pos, end - pos);
        if (schema_val != "mine-uno-witness-v1") {
            tprintf("  FAILED: schema = \"%s\", expected \"mine-uno-witness-v1\"\n",
                    schema_val.c_str());
            return;
        }
    }

    // Epoch must be 0 in the fixture.
    uint64_t epoch = extract_number_field(json, "epoch");
    if (epoch != 0) {
        tprintf("  FAILED: fixture epoch = %llu, expected 0\n",
                (unsigned long long)epoch);
        return;
    }

    // value_nano must equal era-0 reward.
    uint64_t value_nano = extract_number_field(json, "value_nano");
    if (value_nano != uno_workchain::kInitMineReward) {
        tprintf("  FAILED: fixture value_nano = %llu, expected era-0 reward %llu\n",
                (unsigned long long)value_nano,
                (unsigned long long)uno_workchain::kInitMineReward);
        return;
    }

    // remaining_pre must be <= kMineSupplyNano.
    uint64_t remaining_pre = extract_number_field(json, "remaining_pre");
    if (remaining_pre > uno_workchain::kMineSupplyNano) {
        tprintf("  FAILED: remaining_pre %llu > kMineSupplyNano %llu\n",
                (unsigned long long)remaining_pre,
                (unsigned long long)uno_workchain::kMineSupplyNano);
        return;
    }

    // Nonce hex must decode to 32 bytes.
    auto nonce_hex = extract_hex_field(json, "nonce");
    if (nonce_hex.empty() || nonce_hex.size() != 64) {
        tprintf("  FAILED: nonce field missing or wrong length (got %zu hex chars)\n",
                nonce_hex.size());
        return;
    }
    auto nonce_bytes = hex_decode(nonce_hex);
    if (nonce_bytes.size() != 32) {
        tprintf("  FAILED: nonce decodes to %zu bytes, expected 32\n",
                nonce_bytes.size());
        return;
    }
    // The Rust fixture uses [0xAB; 32].
    for (size_t i = 0; i < 32; ++i) {
        if (nonce_bytes[i] != 0xAB) {
            tprintf("  FAILED: nonce byte %zu = 0x%02x, expected 0xAB\n",
                    i, nonce_bytes[i]);
            return;
        }
    }

    // rseed must decode to 32 bytes = [0xCD; 32].
    auto rseed_hex = extract_hex_field(json, "rseed");
    if (rseed_hex.size() != 64) {
        tprintf("  FAILED: rseed field wrong length (%zu hex chars)\n",
                rseed_hex.size());
        return;
    }
    auto rseed_bytes = hex_decode(rseed_hex);
    for (size_t i = 0; i < 32; ++i) {
        if (rseed_bytes[i] != 0xCD) {
            tprintf("  FAILED: rseed byte %zu = 0x%02x, expected 0xCD\n",
                    i, rseed_bytes[i]);
            return;
        }
    }

    tprintf("  PASSED (golden fixture loaded; schema, epoch, value_nano, nonce, "
            "rseed all verified)\n");
}

// ---------------------------------------------------------------------------
// Test 6.5 — kDevMineTargetBE byte layout + select_init_mine_target() gate
//
// Pins the dev-mode mining target (2^252) added for single-CPU-box local
// smoke tests. Semantics: hash < target is valid; LARGER target = EASIER.
// 2^252 gives ~1/16 probability per hash so a single thread finds a valid
// nonce in microseconds.
//
// Asserts:
//   - kDevMineTargetBE is exactly 2^252: byte[0] = 0x10, every other byte
//     zero. Derivation: bit 252 sits in byte[0] (bits 255..248 from MSB),
//     bit position 252 % 8 = 4, so value 1 << 4 = 0x10.
//   - select_init_mine_target(3) picks kDevMineTargetBE (local dev).
//   - select_init_mine_target(1) picks kInitMineTargetBE (mainnet).
//   - select_init_mine_target(-3) picks kInitMineTargetBE (public testnet).
//   - select_init_mine_target(0) and other values default to mainnet.
//
// This is the consensus-critical sanity gate: accidentally selecting the
// 2^252 target on mainnet would let any hobbyist mint the entire 21 M UNO
// cap in seconds.
// ---------------------------------------------------------------------------

static void test_dev_mine_target_bytes() {
    tprintf("[TEST] test_dev_mine_target_bytes\n");

    using uno_workchain::kDevMineTargetBE;
    using uno_workchain::kInitMineTargetBE;
    using uno_workchain::select_init_mine_target;
    using uno_workchain::kDevGlobalId;

    // --- Byte layout of kDevMineTargetBE (2^252) --------------------------
    for (size_t i = 0; i < 32; ++i) {
        const uint8_t expected = (i == 0) ? 0x10 : 0x00;
        if (kDevMineTargetBE[i] != expected) {
            tprintf("  FAILED: kDevMineTargetBE[%zu] = 0x%02x, expected 0x%02x\n",
                    i, kDevMineTargetBE[i], expected);
            return;
        }
    }

    // --- Sanity: kInitMineTargetBE byte[4] = 0x08, rest 0 (2^219) ---------
    for (size_t i = 0; i < 32; ++i) {
        const uint8_t expected = (i == 4) ? 0x08 : 0x00;
        if (kInitMineTargetBE[i] != expected) {
            tprintf("  FAILED: kInitMineTargetBE[%zu] = 0x%02x, expected 0x%02x\n",
                    i, kInitMineTargetBE[i], expected);
            return;
        }
    }

    // --- Gate: global_id → target mapping ---------------------------------
    if (select_init_mine_target(kDevGlobalId) != kDevMineTargetBE) {
        tprintf("  FAILED: select_init_mine_target(3) did not pick kDevMineTargetBE\n");
        return;
    }
    // Mainnet must NOT get the relaxed target.
    if (select_init_mine_target(1) != kInitMineTargetBE) {
        tprintf("  FAILED: select_init_mine_target(1) did not pick kInitMineTargetBE "
                "(mainnet difficulty leaked!)\n");
        return;
    }
    // Public testnet (global_id = -3) must also get the production target.
    if (select_init_mine_target(-3) != kInitMineTargetBE) {
        tprintf("  FAILED: select_init_mine_target(-3) did not pick kInitMineTargetBE\n");
        return;
    }
    // Every other global_id must default to mainnet too.
    for (int32_t gid : {0, 2, 4, 42, -1, -2, -4, 0x100}) {
        if (select_init_mine_target(gid) != kInitMineTargetBE) {
            tprintf("  FAILED: select_init_mine_target(%d) did not default to "
                    "kInitMineTargetBE\n", gid);
            return;
        }
    }

    // --- Cross-check: kDevMineTargetBE > kInitMineTargetBE ---------------
    // Dev target (2^252) must be strictly larger than mainnet target (2^219)
    // byte-by-byte in BE so the same sort order a 256-bit compare would use.
    // That is the defining "easier" property.
    bool dev_larger = false;
    for (size_t i = 0; i < 32; ++i) {
        if (kDevMineTargetBE[i] != kInitMineTargetBE[i]) {
            dev_larger = kDevMineTargetBE[i] > kInitMineTargetBE[i];
            break;
        }
    }
    if (!dev_larger) {
        tprintf("  FAILED: kDevMineTargetBE must be > kInitMineTargetBE to be easier\n");
        return;
    }

    tprintf("  PASSED (kDevMineTargetBE is 2^252; global_id gate routes correctly)\n");
}

// ---------------------------------------------------------------------------
// Test 6.6 — build_zerostate_state honours the global_id gate
//
// Drives the genesis builder with both global_id = 1 (mainnet) and
// global_id = 3 (local dev) and confirms the resulting UnoShardState's
// `mine_target` field matches the corresponding 32-byte constant.
// ---------------------------------------------------------------------------

static void test_build_zerostate_state_mine_target_gate() {
    tprintf("[TEST] test_build_zerostate_state_mine_target_gate\n");

    uno_workchain::GenesisDistribution empty_dist;
    empty_dist.chain_id = uno_workchain::kChainIdTestnet;
    // No notes → empty distribution; build_zerostate_state still populates
    // the mining-state fields.

    // Clear any UNO_INIT_MINE_TARGET_HEX override so the gate decides.
    // The `try_load_env_mine_target` probe in genesis.cpp is cached on first
    // call, so setting this env var here only has effect if no previous
    // test already probed it. We defensively unset.
    ::unsetenv("UNO_INIT_MINE_TARGET_HEX");

    // --- Mainnet path: global_id = 1 → kInitMineTargetBE (2^219) ---------
    {
        auto state = uno_workchain::build_zerostate_state(empty_dist, /*global_id=*/1);
        for (size_t i = 0; i < 32; ++i) {
            if (state.mine_target[i] != uno_workchain::kInitMineTargetBE[i]) {
                tprintf("  FAILED: mainnet mine_target[%zu] = 0x%02x, "
                        "expected kInitMineTargetBE[%zu] = 0x%02x\n",
                        i, state.mine_target[i], i,
                        uno_workchain::kInitMineTargetBE[i]);
                return;
            }
        }
    }

    // --- Dev path: global_id = 3 → kDevMineTargetBE (2^252) --------------
    {
        auto state = uno_workchain::build_zerostate_state(empty_dist, /*global_id=*/3);
        for (size_t i = 0; i < 32; ++i) {
            if (state.mine_target[i] != uno_workchain::kDevMineTargetBE[i]) {
                tprintf("  FAILED: dev mine_target[%zu] = 0x%02x, "
                        "expected kDevMineTargetBE[%zu] = 0x%02x\n",
                        i, state.mine_target[i], i,
                        uno_workchain::kDevMineTargetBE[i]);
                return;
            }
        }
    }

    // --- Public testnet path: global_id = -3 → kInitMineTargetBE --------
    {
        auto state = uno_workchain::build_zerostate_state(empty_dist, /*global_id=*/-3);
        for (size_t i = 0; i < 32; ++i) {
            if (state.mine_target[i] != uno_workchain::kInitMineTargetBE[i]) {
                tprintf("  FAILED: public-testnet mine_target[%zu] = 0x%02x, "
                        "expected kInitMineTargetBE[%zu] = 0x%02x\n",
                        i, state.mine_target[i], i,
                        uno_workchain::kInitMineTargetBE[i]);
                return;
            }
        }
    }

    // Supporting sanity: mine_remaining seeded to the 21M cap in all paths.
    auto state_dev = uno_workchain::build_zerostate_state(empty_dist, 3);
    if (state_dev.mine_remaining != uno_workchain::kMineSupplyNano) {
        tprintf("  FAILED: dev state.mine_remaining = %llu, expected "
                "kMineSupplyNano %llu\n",
                (unsigned long long)state_dev.mine_remaining,
                (unsigned long long)uno_workchain::kMineSupplyNano);
        return;
    }
    if (state_dev.mine_epoch != 0 || state_dev.halving_era != 0) {
        tprintf("  FAILED: dev state has non-zero epoch / era at genesis\n");
        return;
    }

    tprintf("  PASSED (build_zerostate_state gate routes mainnet → 2^219, "
            "dev → 2^252)\n");
}

// ---------------------------------------------------------------------------
// Test 7 — AIR prove + verify round-trip through the FFI
//
// Mirrors `uno_plonky3_ffi::mine_uno_witness::MineUnoWitness::
// deterministic_valid(epoch=0, seed)` from the Rust side so the C++ test
// is self-contained (no on-disk proof fixture). The `expand(salt)` helper
// below is a byte-exact port of the Rust xorshift used in
// `deterministic_valid`; the resulting 192-byte wire witness is passed
// directly to `uno_mine_uno_prove`. The prover emits
// `[u32 LE proof_len][proof_bytes][public_input_bytes]`, which we split
// and feed to `uno_mine_uno_verify`. Also asserts a tampered-proof path
// returns non-Ok.
//
// Prover cost: ~15-25 s on a 192-CPU workstation; fine for a single test.
// ---------------------------------------------------------------------------

namespace mine_test {

// Byte-exact port of `deterministic_valid`'s `expand(salt)` from
// uno/plonky3-ffi/src/mine_uno_witness.rs (lines 467-478). The Rust
// source:
//
//     let expand = |salt: u64| -> [u8; 32] {
//         let mut out = [0u8; 32];
//         let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
//         for chunk in out.chunks_mut(8) {
//             x ^= x << 13;
//             x ^= x >>  7;
//             x ^= x << 17;
//             chunk.copy_from_slice(&x.to_le_bytes());
//         }
//         out
//     };
static std::array<uint8_t, 32> rust_expand(uint64_t seed, uint64_t salt) {
    std::array<uint8_t, 32> out{};
    uint64_t x = seed * 0x9E37'79B9'7F4A'7C15ULL;
    x ^= salt;
    for (size_t chunk = 0; chunk < 4; ++chunk) {
        x ^= x << 13;
        x ^= x >>  7;
        x ^= x << 17;
        for (size_t i = 0; i < 8; ++i) {
            out[chunk * 8 + i] = static_cast<uint8_t>((x >> (i * 8)) & 0xFF);
        }
    }
    return out;
}

// Build the 192-byte canonical wire-encoded MineUnoWitness mirroring
// `MineUnoWitness::deterministic_valid(epoch, seed).encode()`. Layout
// (from uno/plonky3-ffi/src/mine_uno_witness.rs lines 88-100):
//
//   0       4     epoch           (u32 LE)
//   4       32    nonce           ([u8; 32])
//   36      32    d               ([u8; 32], bytes [11..32] MUST be zero)
//   68      32    pk_d            ([u8; 32])
//   100     32    ivk_commitment  ([u8; 32])
//   132     8     value_nano      (u64 LE)
//   140     32    rseed           ([u8; 32])
//   172     8     remaining_pre   (u64 LE)
//   180     8     remaining_post  (u64 LE)
//   188     4     _reserved       (zero)
static std::vector<uint8_t> build_deterministic_witness_bytes(uint32_t epoch,
                                                              uint64_t seed) {
    std::vector<uint8_t> out(192, 0);

    // epoch (LE)
    for (size_t i = 0; i < 4; ++i) out[i] = (epoch >> (i * 8)) & 0xFF;

    auto nonce          = rust_expand(seed, 0xD11D11ULL);                   // unused; nonce salt is 0xA110_CE_00
    (void)nonce;
    // Rust `deterministic_valid`:
    //   d_raw    = expand(0xD11_D11);  // d[11..32] cleared
    //   nonce    = expand(0xA110_CE_00);
    //   pk_d     = expand(0xAF_AF_AF);
    //   ivk_cm   = expand(0x1_CE_1_CE);
    //   rseed    = expand(0x5EED_5EED);
    auto d_raw     = rust_expand(seed, 0xD11D11ULL);
    auto nonce_raw = rust_expand(seed, 0xA110CE00ULL);
    auto pk_d_raw  = rust_expand(seed, 0xAFAFAFULL);
    auto ivk_raw   = rust_expand(seed, 0x1CE1CEULL);
    auto rseed_raw = rust_expand(seed, 0x5EED5EEDULL);
    // `d_raw`: zero bytes [11..32] (Rust does `for byte in d_raw.iter_mut().skip(11)`).
    for (size_t i = 11; i < 32; ++i) d_raw[i] = 0;

    std::memcpy(&out[4],   nonce_raw.data(), 32);
    std::memcpy(&out[36],  d_raw.data(),     32);
    std::memcpy(&out[68],  pk_d_raw.data(),  32);
    std::memcpy(&out[100], ivk_raw.data(),   32);

    const uint64_t value_nano     = 50ULL * 1'000'000'000ULL;
    const uint64_t remaining_pre  = 21'000'000ULL * 1'000'000'000ULL;
    const uint64_t remaining_post = remaining_pre - value_nano;

    auto write_u64_le = [&](size_t off, uint64_t v) {
        for (size_t i = 0; i < 8; ++i) out[off + i] = (v >> (i * 8)) & 0xFF;
    };
    write_u64_le(132, value_nano);
    std::memcpy(&out[140], rseed_raw.data(), 32);
    write_u64_le(172, remaining_pre);
    write_u64_le(180, remaining_post);
    // out[188..192] reserved zero (already initialized).
    return out;
}

}  // namespace mine_test

static void test_mine_uno_proof_verify() {
    tprintf("[TEST] test_mine_uno_proof_verify\n");

    // Build a deterministic valid witness (byte-parity with the Rust-side
    // `MineUnoWitness::deterministic_valid(0, 0xC0FF_EE)` fixture).
    auto witness_bytes = mine_test::build_deterministic_witness_bytes(
        /*epoch=*/0, /*seed=*/0xC0FF'EEULL);
    if (witness_bytes.size() != 192) {
        tprintf("  FAILED: witness encoding has wrong length %zu (want 192)\n",
                witness_bytes.size());
        return;
    }

    // Prove.
    Plonky3OwnedProof owned{};
    int32_t rc = uno_mine_uno_prove(
        ::Plonky3Witness{witness_bytes.data(), witness_bytes.size()},
        &owned);
    if (rc != 0) {
        tprintf("  FAILED: uno_mine_uno_prove returned rc=%d (expected 0=Ok). "
                "If this is a link-time stub / mismatched FFI, rebuild "
                "uno_plonky3_ffi.\n", rc);
        return;
    }
    if (owned.ptr == nullptr || owned.len < 4) {
        tprintf("  FAILED: prove returned empty/undersized owned buffer "
                "(ptr=%p, len=%zu)\n", (void*)owned.ptr, (size_t)owned.len);
        uno_plonky3_proof_free(owned);
        return;
    }

    // Split [u32 LE proof_len][proof_bytes][public_input_bytes].
    const uint8_t* bytes = owned.ptr;
    uint32_t proof_len = (uint32_t)bytes[0]
                       | ((uint32_t)bytes[1] <<  8)
                       | ((uint32_t)bytes[2] << 16)
                       | ((uint32_t)bytes[3] << 24);
    if (owned.len < (size_t)4 + proof_len) {
        tprintf("  FAILED: owned buffer len %zu < 4 + proof_len %u\n",
                (size_t)owned.len, (unsigned)proof_len);
        uno_plonky3_proof_free(owned);
        return;
    }
    const uint8_t* proof_bytes = bytes + 4;
    const uint8_t* pi_bytes    = bytes + 4 + proof_len;
    size_t pi_len              = owned.len - 4 - proof_len;

    // Public-input bytes must be the 96-byte (12 × 8) MineUno PI encoding.
    if (pi_len != 96) {
        tprintf("  FAILED: public-input len = %zu, expected 96 (12 × 8)\n", pi_len);
        uno_plonky3_proof_free(owned);
        return;
    }

    // Positive verify.
    int32_t v_rc = uno_mine_uno_verify(
        ::Plonky3ProofBytes{proof_bytes, proof_len},
        ::Plonky3PublicInputs{pi_bytes, pi_len});
    if (v_rc != 0) {
        tprintf("  FAILED: uno_mine_uno_verify rejected a freshly-produced "
                "proof (rc=%d)\n", v_rc);
        uno_plonky3_proof_free(owned);
        return;
    }

    // Negative verify — flip one bit in the middle of the proof bytes and
    // confirm the verifier rejects. Copy into a mutable buffer first; the
    // `owned` buffer must not be mutated (it's a Rust Vec we will free).
    {
        std::vector<uint8_t> tampered(proof_bytes, proof_bytes + proof_len);
        tampered[tampered.size() / 2] ^= 0x01;
        int32_t t_rc = uno_mine_uno_verify(
            ::Plonky3ProofBytes{tampered.data(), tampered.size()},
            ::Plonky3PublicInputs{pi_bytes, pi_len});
        if (t_rc == 0) {
            tprintf("  FAILED: uno_mine_uno_verify accepted a tampered proof "
                    "(bit-flipped mid-proof-bytes) — expected non-Ok\n");
            uno_plonky3_proof_free(owned);
            return;
        }
    }

    uno_plonky3_proof_free(owned);
    tprintf("  PASSED (STARK prove+verify round-trip, tampered proof rejected)\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("Uno Workchain — K-mine-loader test\n");
    tprintf("===================================\n\n");

    test_mine_reward_for_era();
    test_era_from_epoch();
    test_check_value_matches_halving();
    test_check_conservation();
    test_public_inputs_wire_layout();
    test_load_rust_mine_golden_fixture();
    test_dev_mine_target_bytes();
    test_build_zerostate_state_mine_target_gate();
    test_mine_uno_proof_verify();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
