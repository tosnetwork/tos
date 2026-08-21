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

// Synchronized constant set -- see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-message-policy.md §3.4 and §10.1.
//
// The extra_flags mask is owned here and consumed by transaction /
// validation code. A future Slice 4 (bit 2) or Slice 6 (bit 3)
// activation must update this constant, the matching Tol-stdlib
// constants in crypto/smartcont/tol-stdlib/common.tol, and the
// synchronized-constant fixtures together.

namespace tol {

constexpr int EXTRA_FLAGS_NEW_BOUNCE       = 1;  // bit 0 -- enable v12 bounce body
constexpr int EXTRA_FLAGS_FULL_BOUNCE_BODY = 2;  // bit 1 -- return whole body on bounce; meaningful only when bit 0 is also set
constexpr int EXTRA_FLAGS_RICH_BOUNCE      = 3;  // composite: NEW_BOUNCE | FULL_BOUNCE_BODY
constexpr int EXTRA_FLAGS_VALID_MASK       = 3;  // current valid mask; bits 2 and 3 remain reserved until a future activation

}  // namespace tol
