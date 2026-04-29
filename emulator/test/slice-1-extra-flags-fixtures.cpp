/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/

// =============================================================================
// Slice 1 conformance fixtures -- extra_flags mask boundary cases.
//
// These fixtures discharge two policy obligations:
//
//   * doc/tos-message-policy.md v5 (Approved 2026-04-29) --
//     - §3.4 "Extension reservation in `extra_flags`": bits 2 and 3 are
//       reserved by this policy but currently invalid to set; the outbound
//       mask is `extra_flags & 3` and any attempt to send an outbound with
//       `extra_flags & 12 != 0` triggers `check_skip_invalid(45)`.
//     - §3.4 "Synchronized constants": the mask `3` is duplicated across
//       three sites (transaction.cpp:2948, transaction.cpp:3632, and
//       tol/extra-flags-constants.h); a Slice-4/6 PR that touches only one
//       is a hardening violation.
//     - §10.1: the canonical Slice-1 in-scope items include "an
//       `extra_flags=0b0100` rejection case".
//
//   * doc/roadmap.md Stage 1 exit criterion -- conformance fixtures
//     including an `extra_flags=0b0100` rejection case to validate the §3.4
//     synchronized-constants invariant.
//
// The named constants pulled in via tol/extra-flags-constants.h are:
//   EXTRA_FLAGS_NEW_BOUNCE       (1, bit 0)
//   EXTRA_FLAGS_FULL_BOUNCE_BODY (2, bit 1; semantically meaningful only
//                                 when bit 0 is also set -- see §10.1)
//   EXTRA_FLAGS_RICH_BOUNCE      (3, composite NEW_BOUNCE | FULL_BOUNCE_BODY)
//   EXTRA_FLAGS_VALID_MASK       (3, current valid mask)
//
// Three fixtures live in this file:
//
//   F3.1 -- accepted boundary: extra_flags in {0, 1, 2, 3} all pass the
//           `extra_flags & 3 == extra_flags` gate at transaction.cpp:2948.
//   F3.2 -- rejected boundary: extra_flags in {4, 8, 12} all fail the gate
//           and would trigger `check_skip_invalid(45)`. This is the
//           canonical Stage 1 case (`extra_flags=0b0100`).
//   F3.3 -- synchronized-constants self-check: EXTRA_FLAGS_VALID_MASK == 3
//           and the literal `td::make_refint(3)` appears at both
//           transaction.cpp sites. A drift in any of the three locations
//           breaks this fixture.
//
// The fixtures intentionally exercise the gate expression directly (the
// exact `extra_flags & td::make_refint(3) == extra_flags` predicate from
// transaction.cpp:2959) rather than driving the full transaction emulator
// for every value. This keeps the fixture targeted at the §3.4 invariant
// it is meant to defend, and makes it cheap to run in the standard test
// suite.
// =============================================================================

#include "common/refint.h"
#include "tol/extra-flags-constants.h"

#include "td/utils/PathView.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

#include <string>
#include <vector>

namespace tos_slice1_fixtures {

// Mirror of the gate expression from
// crypto/block/transaction.cpp:2959 (action-phase outbound check):
//
//     if (extra_flags.is_null() ||
//         td::cmp(extra_flags & td::make_refint(3), extra_flags) != 0) {
//       LOG(DEBUG) << "invalid extra_flags in a proposed outbound message";
//       return check_skip_invalid(45);
//     }
//
// Returns true when the value is accepted by the gate (no rejection),
// false when the gate would invoke `check_skip_invalid(45)`.
//
// We intentionally re-encode the gate predicate here verbatim. If the
// production gate changes, a Slice 4/6 PR that widens the mask must
// also update this helper -- F3.3 catches the divergence between
// transaction.cpp and tol/extra-flags-constants.h, and the body of
// F3.1/F3.2 below adapts the boundary buckets at the same time.
static bool gate_accepts(int extra_flags_value) {
  td::RefInt256 extra_flags = td::make_refint(extra_flags_value);
  if (extra_flags.is_null()) {
    return false;
  }
  return td::cmp(extra_flags & td::make_refint(3), extra_flags) == 0;
}

// Locate sibling source files relative to this file's on-disk location.
// We use this to grep for the literal `& td::make_refint(3)` at the two
// transaction.cpp sites and the named-constant declaration in
// tol/extra-flags-constants.h.
static std::string current_dir() {
  return td::PathView(td::realpath(__FILE__).move_as_ok()).parent_dir().str();
}

}  // namespace tos_slice1_fixtures

// -----------------------------------------------------------------------------
// F3.1 -- Accepted boundary.
//
// Cite: doc/tos-message-policy.md v5 §3.4 (current valid mask is `& 3`)
//       and §10.1 (named-constant introduction; note the caveat that
//       bit 1 alone has no useful v12 rich-bounce semantics, so this
//       fixture validates wire-level acceptance only, not semantic
//       correctness).
//
// Each value in {0, 1, 2, 3} is a legal v12 outbound `extra_flags`. The
// gate at transaction.cpp:2948 must accept all four; no check_skip_invalid
// is invoked.
// -----------------------------------------------------------------------------
TEST(Slice1ExtraFlagsFixtures, F3_1_accepted_boundary) {
  using namespace tos_slice1_fixtures;

  // Literal 0 -- the policy doc does not give it a named constant; senders
  // that do not opt into v12 bounce semantics simply leave extra_flags = 0.
  CHECK(gate_accepts(0));

  // Bit 0 alone: enable v12 bounce-body format (§3.4, §10.1).
  CHECK(gate_accepts(tol::EXTRA_FLAGS_NEW_BOUNCE));
  CHECK(tol::EXTRA_FLAGS_NEW_BOUNCE == 1);

  // Bit 1 alone: legal at the wire-level mask, but per §10.1 has no
  // useful v12 rich-bounce semantics because bit 0 is not set. F3.1
  // tests acceptance only.
  CHECK(gate_accepts(tol::EXTRA_FLAGS_FULL_BOUNCE_BODY));
  CHECK(tol::EXTRA_FLAGS_FULL_BOUNCE_BODY == 2);

  // Bits 0 and 1 together -- the canonical "rich bounce" composite
  // emitted by tol/send-message-api.cpp's BounceMode::RichBounce.
  CHECK(gate_accepts(tol::EXTRA_FLAGS_RICH_BOUNCE));
  CHECK(tol::EXTRA_FLAGS_RICH_BOUNCE ==
        (tol::EXTRA_FLAGS_NEW_BOUNCE | tol::EXTRA_FLAGS_FULL_BOUNCE_BODY));
  CHECK(tol::EXTRA_FLAGS_RICH_BOUNCE == 3);
}

// -----------------------------------------------------------------------------
// F3.2 -- Rejected boundary (canonical Stage 1 fixture).
//
// Cite: doc/tos-message-policy.md v5 §3.4 -- "Bits 2 and 3 are reserved by
//       this policy but **currently invalid to set**; sending an internal
//       message with `extra_flags & 12 != 0` triggers
//       `check_skip_invalid(45)`."
//
// doc/roadmap.md Stage 1 exit criterion explicitly calls out
// "an inbound message with `extra_flags = 0b0100` rejected by the `& 3`
// mask".
//
// Each value in {4, 8, 12} sets at least one bit beyond the current valid
// mask:
//   4  = 0b0100 -- bit 2 alone (the canonical Stage 1 fixture value)
//   8  = 0b1000 -- bit 3 alone
//   12 = 0b1100 -- bits 2 and 3 together
//
// The action-phase outbound check at transaction.cpp:2948 must reject all
// three. The error code is `check_skip_invalid(45)`; we verify the gate
// rejection here, and document the error code via the citation above.
// -----------------------------------------------------------------------------
TEST(Slice1ExtraFlagsFixtures, F3_2_rejected_boundary) {
  using namespace tos_slice1_fixtures;

  // 0b0100 -- the canonical Stage 1 case named in roadmap.md and §10.1.
  CHECK(!gate_accepts(0b0100));
  CHECK(!gate_accepts(4));

  // 0b1000 -- bit 3 alone (reserved for the Slice-6 supervision-link tag).
  CHECK(!gate_accepts(0b1000));
  CHECK(!gate_accepts(8));

  // 0b1100 -- bits 2 and 3 together (extra_flags & 12 != 0).
  CHECK(!gate_accepts(0b1100));
  CHECK(!gate_accepts(12));

  // Sanity: no value with any bit beyond the valid mask is accepted, even
  // when combined with a valid bit. This guards against a future
  // regression that masks the upper bits before comparing rather than
  // comparing the full value.
  CHECK(!gate_accepts(tol::EXTRA_FLAGS_NEW_BOUNCE | 4));    // 0b0101
  CHECK(!gate_accepts(tol::EXTRA_FLAGS_RICH_BOUNCE | 8));   // 0b1011
  CHECK(!gate_accepts(tol::EXTRA_FLAGS_RICH_BOUNCE | 12));  // 0b1111
}

// -----------------------------------------------------------------------------
// F3.3 -- Synchronized-constants self-check.
//
// Cite: doc/tos-message-policy.md v5 §3.4 "Synchronized constants" --
//       the mask `3` is hard-coded at three sites:
//         (1) crypto/block/transaction.cpp:2948 (action-phase outbound)
//         (2) crypto/block/transaction.cpp:3632 (prepare_bounce_phase)
//         (3) tol/extra-flags-constants.h (this header's
//             EXTRA_FLAGS_VALID_MASK)
//       A Slice-4/6 PR that touches only one is a hardening violation.
//
// Two layers of protection:
//
//   1. Compile-time `static_assert` against tol::EXTRA_FLAGS_VALID_MASK.
//      If a future PR widens the mask in tol/extra-flags-constants.h
//      without updating this fixture (and the production gate), the
//      build fails here.
//
//   2. Runtime grep of crypto/block/transaction.cpp for the literal
//      `& td::make_refint(3)` at both sites. If a Slice 4/6 PR widens
//      the production mask without updating the header, the runtime
//      check fails. (We do not require an exact line number because
//      surrounding code may move, but we do require both occurrences.)
// -----------------------------------------------------------------------------

// Compile-time invariant: this header's EXTRA_FLAGS_VALID_MASK must equal
// the literal 3 used in transaction.cpp. If a Slice 4/6 PR widens this to
// 7 (bit 2) or 15 (bit 3) without also widening the production gate, the
// runtime grep below catches the divergence. If a Slice 4/6 PR widens the
// production gate without widening this header, the static_assert here
// must be updated in lockstep.
static_assert(tol::EXTRA_FLAGS_VALID_MASK == 3,
              "Slice 1 extra_flags mask is 3 (bits 0..1). If this changes, "
              "all three synchronized-constants sites must update in lockstep "
              "-- see doc/tos-message-policy.md v5 §3.4.");

// Compile-time sanity for the named bit constants. These are not the
// synchronized-constants invariant per se, but they assert the bit
// allocation that §10.1 names.
static_assert(tol::EXTRA_FLAGS_NEW_BOUNCE == 1, "bit 0");
static_assert(tol::EXTRA_FLAGS_FULL_BOUNCE_BODY == 2, "bit 1");
static_assert(tol::EXTRA_FLAGS_RICH_BOUNCE ==
                  (tol::EXTRA_FLAGS_NEW_BOUNCE | tol::EXTRA_FLAGS_FULL_BOUNCE_BODY),
              "RICH_BOUNCE = NEW_BOUNCE | FULL_BOUNCE_BODY");
static_assert(tol::EXTRA_FLAGS_RICH_BOUNCE == 3, "composite of bits 0..1");

TEST(Slice1ExtraFlagsFixtures, F3_3_synchronized_constants_self_check) {
  using namespace tos_slice1_fixtures;

  // Re-affirm the static_assert invariants at runtime so the test report
  // shows them as a green check rather than only as a build-time gate.
  CHECK(tol::EXTRA_FLAGS_VALID_MASK == 3);
  CHECK(tol::EXTRA_FLAGS_NEW_BOUNCE == 1);
  CHECK(tol::EXTRA_FLAGS_FULL_BOUNCE_BODY == 2);
  CHECK(tol::EXTRA_FLAGS_RICH_BOUNCE == 3);

  // Locate the two sibling source files relative to the test binary's
  // build location is unreliable, so we use __FILE__ realpath. From
  // /home/tomi/tos/emulator/test/ the production sites live at
  // ../../crypto/block/transaction.cpp and the header at
  // ../../tol/extra-flags-constants.h.
  const std::string test_dir = current_dir();
  const std::string transaction_cpp_path =
      test_dir + "/../../crypto/block/transaction.cpp";
  const std::string constants_header_path =
      test_dir + "/../../tol/extra-flags-constants.h";

  // Read transaction.cpp and confirm the literal `& td::make_refint(3)`
  // appears exactly at the two synchronized-constants sites.
  auto transaction_cpp_result = td::read_file_str(transaction_cpp_path);
  CHECK(transaction_cpp_result.is_ok());
  const std::string transaction_cpp_text = transaction_cpp_result.move_as_ok();

  // Count occurrences of the synchronized-constants literal in actual
  // code (NOT comment text). T5's annotation block above each mask
  // site mentions "& td::make_refint(3)" in `//` comments; we narrow
  // the grep by requiring the surrounding `extra_flags` identifier so
  // the count reflects real call sites only.
  const std::string mask_literal = "extra_flags & td::make_refint(3)";
  size_t mask_literal_count = 0;
  for (size_t pos = 0;
       (pos = transaction_cpp_text.find(mask_literal, pos)) != std::string::npos;
       pos += mask_literal.size()) {
    ++mask_literal_count;
  }

  // §3.4 enumerates exactly two sites in transaction.cpp:
  //   line 2948 (action-phase outbound check)
  //   line 3632 (prepare_bounce_phase outbound builder)
  // If either is missing, or a third unaccounted-for occurrence appears
  // (potentially a Slice 4/6 widening that left a stray site behind), the
  // synchronized-constants invariant is broken.
  CHECK(mask_literal_count == 2);

  // Read the constants header and confirm EXTRA_FLAGS_VALID_MASK = 3.
  // We grep the literal text rather than rely solely on the static_assert
  // so that a Slice 4/6 PR that updates the header value but forgets to
  // update this fixture's expected count above does not silently slip
  // through.
  auto constants_header_result = td::read_file_str(constants_header_path);
  CHECK(constants_header_result.is_ok());
  const std::string constants_header_text =
      constants_header_result.move_as_ok();

  CHECK(constants_header_text.find("EXTRA_FLAGS_VALID_MASK       = 3") !=
        std::string::npos);
  CHECK(constants_header_text.find("EXTRA_FLAGS_NEW_BOUNCE       = 1") !=
        std::string::npos);
  CHECK(constants_header_text.find("EXTRA_FLAGS_FULL_BOUNCE_BODY = 2") !=
        std::string::npos);
  CHECK(constants_header_text.find("EXTRA_FLAGS_RICH_BOUNCE      = 3") !=
        std::string::npos);
}
