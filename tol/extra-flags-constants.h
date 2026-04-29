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
#pragma once

// Synchronized constant set -- see doc/tos-message-policy.md §3.4 and §10.1.
//
// The extra_flags mask is duplicated across THREE sites that must be
// updated in lockstep when Slice 4 (bit 2) or Slice 6 (bit 3) widens
// the mask. The hardening grep must catch divergence between:
//   1. crypto/block/transaction.cpp:2948 (& td::make_refint(3))
//   2. crypto/block/transaction.cpp:3632 (& td::make_refint(3))
//   3. tol/extra-flags-constants.h (this file)
// and the matching Tol-stdlib constants in
//   crypto/smartcont/tol-stdlib/common.tol.

namespace tol {

constexpr int EXTRA_FLAGS_NEW_BOUNCE       = 1;  // bit 0 -- enable v12 bounce body
constexpr int EXTRA_FLAGS_FULL_BOUNCE_BODY = 2;  // bit 1 -- return whole body on bounce; meaningful only when bit 0 is also set
constexpr int EXTRA_FLAGS_RICH_BOUNCE      = 3;  // composite: NEW_BOUNCE | FULL_BOUNCE_BODY
constexpr int EXTRA_FLAGS_VALID_MASK       = 3;  // current valid mask; widens in Slice 4 (to 7) and Slice 6 (to 15)

}  // namespace tol
