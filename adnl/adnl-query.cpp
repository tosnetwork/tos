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
#include "common/errorcode.h"
#include "td/utils/Random.h"

#include "adnl-query.h"

namespace tos {

namespace adnl {

void AdnlQuery::alarm() {
  LOG(DEBUG) << "ADNL_EXT_QUERY client_timeout id=" << id_.to_hex()
             << " elapsed_ms=" << (debug_started_at_ ? (td::Time::now() - debug_started_at_) * 1000.0 : -1.0);
  set_error(td::Status::Error(ErrorCode::timeout, PSTRING() << "timeout for adnl query " << name_));
}
void AdnlQuery::result(td::BufferSlice data) {
  LOG(DEBUG) << "ADNL_EXT_QUERY client_complete id=" << id_.to_hex() << " outcome=answer elapsed_ms="
             << (debug_started_at_ ? (td::Time::now() - debug_started_at_) * 1000.0 : -1.0);
  promise_.set_value(std::move(data));
  stop();
}
void AdnlQuery::set_error(td::Status error) {
  promise_.set_error(std::move(error));
  stop();
}

AdnlQueryId AdnlQuery::random_query_id() {
  AdnlQueryId q_id;
  td::Random::secure_bytes(q_id.as_slice());
  return q_id;
}

}  // namespace adnl

}  // namespace tos
