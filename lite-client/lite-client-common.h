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

#include "auto/tl/lite_api.hpp"
#include "crypto/block/block.h"

namespace liteclient {

td::Result<std::unique_ptr<block::BlockProofChain>> deserialize_proof_chain(
    tos::lite_api::object_ptr<tos::lite_api::liteServer_partialBlockProof> f);

td::Ref<vm::Tuple> prepare_vm_c7(tos::UnixTime now, tos::LogicalTime lt, td::Ref<vm::CellSlice> my_addr,
                                 const block::CurrencyCollection& balance);
}  // namespace liteclient
