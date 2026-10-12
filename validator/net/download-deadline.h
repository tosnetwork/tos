/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include "common/errorcode.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"

namespace tos::validator::fullnode {

// The deadline of one transport query sent by a download: the query's own
// bound, but never later than the download's deadline, so the transport does
// not keep a query alive for a download that has already given up. A download
// without a deadline keeps the query's own bound. A download whose deadline
// has passed gets a timeout instead and sends nothing.
inline td::Result<td::Timestamp> download_query_deadline(td::Timestamp download_deadline, double query_timeout,
                                                         td::Timestamp now = td::Timestamp::now_cached()) {
  auto query_deadline = td::Timestamp::in(query_timeout, now);
  if (!download_deadline) {
    return query_deadline;
  }
  if (download_deadline.is_in_past(now)) {
    return td::Status::Error(ErrorCode::timeout, "download deadline passed before the query was sent");
  }
  return download_deadline.at() < query_deadline.at() ? download_deadline : query_deadline;
}

}  // namespace tos::validator::fullnode
