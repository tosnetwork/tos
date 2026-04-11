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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include "adnl/adnl-node-id.hpp"
#include "td/utils/int_types.h"
#include "tos/tos-types.h"

namespace tos {

namespace catchain {

using CatChainBlockHash = td::Bits256;
using CatChainBlockPayloadHash = td::Bits256;
using CatChainBlockHeight = td::uint32;
using CatChainSessionId = td::Bits256;

struct CatChainNode {
  adnl::AdnlNodeIdShort adnl_id;
  PublicKey pub_key;
};

}  // namespace catchain

}  // namespace tos
