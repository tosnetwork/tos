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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cstdint>
#include <stdexcept>

#include "tos/tos-types.h"

namespace tos {

// Protocol-level cap on the total weight of a validator set. Picked so that
//   total_weight * 3 <= UINT64_MAX
// which guarantees that the 2/3 quorum check
//   sig_weight * 3 >= total_weight * 2
// and the threshold expression
//   ceil(total_weight * 2 / 3)
// cannot wrap a 64-bit unsigned integer. The cap leaves ~6.1e18 weight
// units of headroom — far beyond any realistic validator-set sizing.
//
// Enforced at validator-set load (see crypto/block/mc-config.cpp). Once
// enforced there, the helpers below are safe to use on uint64 inputs;
// they additionally widen to 128-bit as defence in depth.
inline constexpr ValidatorWeight kMaxTotalValidatorWeight = UINT64_MAX / 3;

// Returns true iff signed_weight is at least 2/3 of total_weight (≥, not
// strict >). This is the standard BFT-2/3 convention used by Tendermint /
// HotStuff / PBFT-Lite / catchain.
//
// Differs from a strict `>` check only when total_weight is divisible by 3
// — there the strict form would require one additional vote (e.g. for
// N=3 equal-weight validators it would demand all 3 to sign, while the
// canonical BFT threshold is 2/3 = 2 votes). The strict form was a
// mathematical artifact, not a safety improvement: BFT-safety claims of
// the form "f < N/3 byzantine ⇒ safe" are equally valid against the ≥
// threshold for the N=3k cases.
//
// Computed in 128-bit so the result is correct even if a future loader
// change ever lets total_weight exceed kMaxTotalValidatorWeight.
inline bool has_quorum(ValidatorWeight signed_weight, ValidatorWeight total_weight) noexcept {
  __uint128_t lhs = static_cast<__uint128_t>(signed_weight) * 3;
  __uint128_t rhs = static_cast<__uint128_t>(total_weight) * 2;
  return lhs >= rhs;
}

// Returns ceil(total_weight * 2 / 3): the smallest weight that passes
// has_quorum() above. Computed in 128-bit; throws if the 64-bit cap is
// somehow exceeded (should be impossible while the loader enforces
// kMaxTotalValidatorWeight).
//
// For N equal-weight validators:
//   N=2 → 2,  N=3 → 2,  N=4 → 3,  N=5 → 4,
//   N=6 → 4,  N=7 → 5,  N=9 → 6,  N=10 → 7
inline ValidatorWeight quorum_threshold(ValidatorWeight total_weight) {
  __uint128_t t = static_cast<__uint128_t>(total_weight);
  // ceil(2t/3) = (2t + 2) / 3 (integer division)
  __uint128_t q = (t * 2 + 2) / 3;
  if (q > UINT64_MAX) {
    throw std::overflow_error("validator quorum threshold overflow");
  }
  return static_cast<ValidatorWeight>(q);
}

// Audit #8 (2026-04-26): defence-in-depth helper for any path that
// accumulates a validator set's total weight. The primary cap lives in
// crypto/block/mc-config.cpp, but second-tier paths (ValidatorSet ctor,
// consensus bridge init, certificate voted-weight) historically used
// unchecked `total += weight`. Future paths that bypass mc-config (test
// fixtures, custom tooling, bridges) would silently re-introduce overflow.
//
// Usage: `if (!checked_add_validator_weight(acc, w)) { /* reject */ }`.
// Returns false on:
//   * w == 0 (zero-weight validators are not allowed by protocol)
//   * acc + w would exceed kMaxTotalValidatorWeight (preserves the
//     UINT64_MAX/3 invariant the quorum helpers above depend on).
inline bool checked_add_validator_weight(ValidatorWeight& acc,
                                         ValidatorWeight w) noexcept {
  if (w == 0) return false;
  if (w > kMaxTotalValidatorWeight - acc) return false;
  acc += w;
  return true;
}

}  // namespace tos
