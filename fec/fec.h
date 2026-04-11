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

#include "auto/tl/tos_api.h"
#include "td/fec/fec.h"
#include "td/utils/Variant.h"

namespace tos {

namespace fec {

class FecType {
 private:
  class Empty {};
  td::Variant<Empty, td::fec::RaptorQEncoder::Parameters, td::fec::RoundRobinEncoder::Parameters,
              td::fec::OnlineEncoder::Parameters>
      type_{Empty()};

 public:
  tl_object_ptr<tos_api::fec_Type> tl() const;
  td::Result<std::unique_ptr<td::fec::Decoder>> create_decoder() const;

  // Changes parameters!
  td::Result<std::unique_ptr<td::fec::Encoder>> create_encoder(td::BufferSlice data);

  td::uint32 size() const;
  td::uint32 symbols_count() const;
  td::uint32 symbol_size() const;

  FecType() {
  }
  template <class T>
  FecType(T param) : type_(param) {
  }

  static td::Result<FecType> create(tl_object_ptr<tos_api::fec_Type> obj);
};

}  // namespace fec

}  // namespace tos
