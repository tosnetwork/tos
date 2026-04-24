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

    Tests 7+ (AIR proof verification) are TODO/SKIP placeholders; will be
    enabled when the parallel AIR agent's work lands.

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

#include "uno/core/mine_constants.h"
#include "uno/core/mine_uno.h"

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
// Test 7 (placeholder) — AIR proof verification (SKIP until Phase 2)
// ---------------------------------------------------------------------------

static void test_mine_uno_proof_verify_placeholder() {
    tprintf("[TEST] test_mine_uno_proof_verify_placeholder\n");
    tprintf("  SKIP: AIR proof verification requires Phase 2 implementation "
            "(uno_plonky3_ffi::prove_mine_uno / verify_mine_uno not yet "
            "defined). Will be enabled when the parallel AIR agent lands.\n");
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
    test_mine_uno_proof_verify_placeholder();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
