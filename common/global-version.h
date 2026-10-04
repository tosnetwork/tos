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

namespace tos {

// See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/GlobalVersions.md
// The ceiling this binary is capable of executing, not a switch that enables
// anything. What a network runs comes from ConfigParam 8; a configured version
// above this one is logged and then executed anyway, so raising this does not
// activate v16 and leaving it low would not have prevented it.
constexpr int SUPPORTED_VERSION = 16;

}  // namespace tos
