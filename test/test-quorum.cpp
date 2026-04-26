/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Pin BFT-2/3 quorum semantics for the helpers in `tos/quorum.h`.
//
// Background: an early version of has_quorum() used a strict `>` against
// 2/3 (sig*3 > total*2). For N-equal-weight validators where N is divisible
// by 3 (N=3, 6, 9, ...), strict `>` requires one extra vote vs the
// canonical BFT-2/3 threshold. A 3-validator cluster could not reach
// consensus with 2/3 votes — it required all 3.
//
// Current behaviour (this test pins it):
//   has_quorum(s, t)      ::= s*3 >= t*2     (≥ 2/3, the standard)
//   quorum_threshold(t)   ::= ceil(2t/3)     (smallest s satisfying has_quorum)

#include "tos/quorum.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace {

int g_failures = 0;

#define EXPECT(cond, msg)                                                    \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "  FAIL: %s  (%s:%d)\n", (msg),             \
                         __FILE__, __LINE__);                                \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

// For each N (equal-weight validators of weight 1, total = N), verify:
//   * quorum_threshold(N) returns the expected value
//   * has_quorum(t-1, N) is false
//   * has_quorum(t, N) is true
//   * has_quorum(N, N) is true (unanimous always passes)
void check_n(uint64_t total, uint64_t expected_threshold) {
    auto t = tos::quorum_threshold(total);
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "quorum_threshold(%llu) expected %llu, got %llu",
                  (unsigned long long)total,
                  (unsigned long long)expected_threshold,
                  (unsigned long long)t);
    EXPECT(t == expected_threshold, buf);

    if (expected_threshold > 0) {
        std::snprintf(buf, sizeof(buf),
                      "has_quorum(%llu, %llu) must be false",
                      (unsigned long long)(expected_threshold - 1),
                      (unsigned long long)total);
        EXPECT(!tos::has_quorum(expected_threshold - 1, total), buf);
    }

    std::snprintf(buf, sizeof(buf),
                  "has_quorum(%llu, %llu) must be true",
                  (unsigned long long)expected_threshold,
                  (unsigned long long)total);
    EXPECT(tos::has_quorum(expected_threshold, total), buf);

    std::snprintf(buf, sizeof(buf),
                  "has_quorum(%llu, %llu) must be true (unanimous)",
                  (unsigned long long)total,
                  (unsigned long long)total);
    EXPECT(tos::has_quorum(total, total), buf);
}

void test_canonical_table() {
    std::printf("[TEST] canonical_threshold_table\n");
    // N=2 is degenerate for BFT (no fault tolerance); both must vote.
    check_n(2, 2);
    // N=3, 6, 9 — these were the broken cases under strict `>`.
    check_n(3, 2);
    check_n(6, 4);
    check_n(9, 6);
    // N=3f+1 cases: strict > and ≥ agree here.
    check_n(4, 3);
    check_n(7, 5);
    check_n(10, 7);
    // Other N values for completeness.
    check_n(5, 4);
    check_n(8, 6);
    check_n(11, 8);
    check_n(12, 8);
    if (g_failures == 0) {
        std::printf("  PASSED\n");
    }
}

void test_strict_lt_is_false() {
    std::printf("[TEST] sub_threshold_is_rejected\n");
    // Anything strictly below 2/3 must be rejected.
    EXPECT(!tos::has_quorum(0, 3), "0/3 not quorum");
    EXPECT(!tos::has_quorum(1, 3), "1/3 not quorum");
    EXPECT(!tos::has_quorum(0, 100), "0/100 not quorum");
    EXPECT(!tos::has_quorum(66, 100), "66/100 not quorum");      // 66 < 200/3
    EXPECT( tos::has_quorum(67, 100), "67/100 IS quorum (≥2/3)"); // 67*3=201 ≥ 200
    if (g_failures == 0) {
        std::printf("  PASSED\n");
    }
}

void test_unequal_weights() {
    std::printf("[TEST] unequal_weights\n");
    // Realistic non-uniform set: total=300, threshold should be ceil(600/3)=200.
    EXPECT(tos::quorum_threshold(300) == 200, "qt(300) == 200");
    EXPECT(!tos::has_quorum(199, 300), "199/300 not quorum");
    EXPECT( tos::has_quorum(200, 300), "200/300 IS quorum");
    EXPECT( tos::has_quorum(201, 300), "201/300 IS quorum");

    // total=301, threshold = ceil(602/3) = 201.
    EXPECT(tos::quorum_threshold(301) == 201, "qt(301) == 201");
    EXPECT(!tos::has_quorum(200, 301), "200/301 not quorum");
    EXPECT( tos::has_quorum(201, 301), "201/301 IS quorum");

    // total=302, threshold = ceil(604/3) = 202.
    EXPECT(tos::quorum_threshold(302) == 202, "qt(302) == 202");
    EXPECT(!tos::has_quorum(201, 302), "201/302 not quorum");
    EXPECT( tos::has_quorum(202, 302), "202/302 IS quorum");

    if (g_failures == 0) {
        std::printf("  PASSED\n");
    }
}

void test_overflow_safe_at_cap() {
    std::printf("[TEST] overflow_safe_at_cap\n");
    // Weights at the protocol cap must not overflow; quorum_threshold
    // returns a uint64.
    const auto cap = tos::kMaxTotalValidatorWeight;
    auto q = tos::quorum_threshold(cap);
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "qt(cap=%llu) returned %llu (must be <= UINT64_MAX)",
                  (unsigned long long)cap, (unsigned long long)q);
    EXPECT(q <= UINT64_MAX, buf);
    EXPECT(tos::has_quorum(q, cap), "has_quorum(qt(cap), cap) must be true");
    if (q > 0) {
        EXPECT(!tos::has_quorum(q - 1, cap),
               "has_quorum(qt(cap)-1, cap) must be false");
    }
    if (g_failures == 0) {
        std::printf("  PASSED\n");
    }
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("tos/quorum.h — BFT-2/3 helper tests\n");
    std::printf("====================================\n\n");

    test_canonical_table();
    test_strict_lt_is_false();
    test_unequal_weights();
    test_overflow_safe_at_cap();

    std::printf("\nTotal failures: %d\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
