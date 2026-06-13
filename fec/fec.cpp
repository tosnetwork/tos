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
#include "auto/tl/tos_api.hpp"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"

#include "fec.h"

namespace tos {

namespace fec {

tl_object_ptr<tos_api::fec_Type> FecType::tl() const {
  tl_object_ptr<tos_api::fec_Type> res;
  type_.visit(td::overloaded([&](const Empty &obj) { UNREACHABLE(); },
                             [&](const td::fec::RaptorQEncoder::Parameters &obj) {
                               res = create_tl_object<tos_api::fec_raptorQ>(static_cast<td::uint32>(obj.data_size),
                                                                            static_cast<td::uint32>(obj.symbol_size),
                                                                            static_cast<td::uint32>(obj.symbols_count));
                             },
                             [&](const td::fec::RoundRobinEncoder::Parameters &obj) {
                               res = create_tl_object<tos_api::fec_roundRobin>(
                                   static_cast<td::uint32>(obj.data_size), static_cast<td::uint32>(obj.symbol_size),
                                   static_cast<td::uint32>(obj.symbols_count));
                             },
                             [&](const td::fec::OnlineEncoder::Parameters &obj) {
                               res = create_tl_object<tos_api::fec_online>(static_cast<td::uint32>(obj.data_size),
                                                                           static_cast<td::uint32>(obj.symbol_size),
                                                                           static_cast<td::uint32>(obj.symbols_count));
                             }));
  return res;
}

td::Result<std::unique_ptr<td::fec::Decoder>> FecType::create_decoder() const {
  td::Result<std::unique_ptr<td::fec::Decoder>> res;
  type_.visit(td::overloaded(
      [&](const Empty &obj) { UNREACHABLE(); },
      [&](const td::fec::RaptorQEncoder::Parameters &obj) { res = td::fec::RaptorQDecoder::create(obj); },
      [&](const td::fec::RoundRobinEncoder::Parameters &obj) { res = td::fec::RoundRobinDecoder::create(obj); },
      [&](const td::fec::OnlineEncoder::Parameters &obj) { res = td::fec::OnlineDecoder::create(obj); }));
  return res;
}

td::Result<std::unique_ptr<td::fec::Encoder>> FecType::create_encoder(td::BufferSlice data) {
  std::unique_ptr<td::fec::Encoder> res;
  type_.visit(td::overloaded([&](const Empty &obj) { UNREACHABLE(); },
                             [&](const td::fec::RaptorQEncoder::Parameters &obj) {
                               auto R = td::fec::RaptorQEncoder::create(std::move(data), obj.symbol_size);
                               type_ = R->get_parameters();
                               res = std::move(R);
                             },
                             [&](const td::fec::RoundRobinEncoder::Parameters &obj) {
                               auto R = td::fec::RoundRobinEncoder::create(std::move(data), obj.symbol_size);
                               type_ = R->get_parameters();
                               res = std::move(R);
                             },
                             [&](const td::fec::OnlineEncoder::Parameters &obj) {
                               auto R = td::fec::OnlineEncoder::create(std::move(data), obj.symbol_size);
                               type_ = R->get_parameters();
                               res = std::move(R);
                             }));
  return std::move(res);
}

td::uint32 FecType::size() const {
  td::uint32 res = 0;
  type_.visit(td::overloaded([&](const Empty &obj) { UNREACHABLE(); },
                             [&](const auto &obj) { res = static_cast<td::uint32>(obj.data_size); }));
  return res;
}

td::uint32 FecType::symbols_count() const {
  td::uint32 res = 0;
  type_.visit(td::overloaded([&](const Empty &obj) { UNREACHABLE(); },
                             [&](const auto &obj) { res = static_cast<td::uint32>(obj.symbols_count); }));
  return res;
}

td::uint32 FecType::symbol_size() const {
  td::uint32 res = 0;
  type_.visit(td::overloaded([&](const Empty &obj) { UNREACHABLE(); },
                             [&](const auto &obj) { res = static_cast<td::uint32>(obj.symbol_size); }));
  return res;
}

td::Result<FecType> FecType::create(tl_object_ptr<tos_api::fec_Type> obj) {
  td::int32 data_size_int = 0, symbol_size_int = 0, symbols_count_int = 0;
  tos_api::downcast_call(*obj, td::overloaded([&](const auto &obj) {
    data_size_int = obj.data_size_;
    symbol_size_int = obj.symbol_size_;
    symbols_count_int = obj.symbols_count_;
  }));
  TRY_RESULT(data_size, td::narrow_cast_safe<size_t>(data_size_int));
  TRY_RESULT(symbol_size, td::narrow_cast_safe<size_t>(symbol_size_int));
  TRY_RESULT(symbols_count, td::narrow_cast_safe<size_t>(symbols_count_int));

  // All legitimate senders (overlay broadcast, RLDP, RLDP2) use a fixed
  // 768-byte symbol. A smaller symbol_size lets a peer inflate the symbol/
  // part count for a given data_size (up to ~16M parts at symbol_size==1),
  // bloating per-broadcast decoder state before the 60 s GC. Floor it at the
  // canonical 768 (matches upstream TON); this also subsumes the ==0 guard.
  if (symbol_size < 768) {
    return td::Status::Error("invalid fec type: symbol_size below floor (768)");
  }
  if (symbol_size > 1 << 11) {
    return td::Status::Error("invalid fec type: symbol_size is too big");
  }
  if (data_size > symbol_size * (1ull << 24)) {
    return td::Status::Error("invalid fec type: too many symbols");
  }
  if (symbols_count != (data_size + symbol_size - 1) / symbol_size) {
    return td::Status::Error("invalid fec type: wrong symbols_count");
  }
  if (obj->get_id() != tos_api::fec_raptorQ::ID) {
    return td::Status::Error("invalid fec type: only RaptorQ is allowed");
  }
  FecType T;
  T.type_ = td::fec::RaptorQEncoder::Parameters{data_size, symbol_size, symbols_count};
  return T;
}

}  // namespace fec

}  // namespace tos
