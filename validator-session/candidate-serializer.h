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
#include <string>

#include "auto/tl/tos_api.h"
#include "tos/tos-types.h"

namespace tos::validatorsession {

td::Result<td::BufferSlice> serialize_candidate(const tl_object_ptr<tos_api::validatorSession_candidate>& block,
                                                bool compression_enabled);
td::Result<tl_object_ptr<tos_api::validatorSession_candidate>> deserialize_candidate(td::Slice data,
                                                                                     bool compression_enabled,
                                                                                     int max_decompressed_data_size);

td::Result<td::BufferSlice> compress_candidate_data(td::Slice block, td::Slice collated_data, size_t& decompressed_size,
                                                    std::string called_from, td::Bits256 root_hash);
td::Result<std::pair<td::BufferSlice, td::BufferSlice>> decompress_candidate_data(
    td::Slice compressed, bool improved_compression, int decompressed_size, int max_decompressed_size,
    std::string called_from, td::Bits256 root_hash);

}  // namespace tos::validatorsession
