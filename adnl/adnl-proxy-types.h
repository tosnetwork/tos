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
#include "td/utils/Status.h"
#include "td/utils/buffer.h"

namespace tos {

namespace adnl {

class AdnlProxy {
 public:
  struct Packet {
    td::uint32 flags;
    td::uint32 ip;
    td::uint16 port;
    td::int32 adnl_start_time;
    td::int64 seqno;
    td::int32 date{0};
    td::BufferSlice data;
  };
  virtual ~AdnlProxy() = default;
  virtual td::BufferSlice encrypt(Packet packet) const = 0;
  virtual td::Result<Packet> decrypt(td::BufferSlice packet) const = 0;
  virtual tl_object_ptr<tos_api::adnl_Proxy> tl() const = 0;
  virtual const td::Bits256 &id() const = 0;

  static td::Result<std::shared_ptr<AdnlProxy>> create(const tos_api::adnl_Proxy &proxy_type);
};

}  // namespace adnl

}  // namespace tos
