/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <utility>

#include "td/actor/PromiseFuture.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"

namespace tos::adnl {

// A query answer with local delivery metadata. Only `data` goes on the wire;
// the metadata tells the transport that sends the answer how long it may keep
// trying.
struct AdnlQueryAnswer {
  td::BufferSlice data;
  // The latest time the answering transport may keep this answer, as an
  // absolute monotonic time. It can only shorten the transport's own rule,
  // never extend it. Unset means the transport's rule applies alone.
  td::Timestamp delivery_deadline;
};

// The earlier of a transport's own deadline for an answer and the answer's
// delivery deadline, if it has one.
inline td::Timestamp answer_delivery_deadline(td::Timestamp transport_deadline, const AdnlQueryAnswer &answer) {
  if (answer.delivery_deadline && (!transport_deadline || answer.delivery_deadline.at() < transport_deadline.at())) {
    return answer.delivery_deadline;
  }
  return transport_deadline;
}

// For a handler that answers with plain data: its answers carry no metadata.
inline td::Promise<td::BufferSlice> drop_answer_metadata(td::Promise<AdnlQueryAnswer> promise) {
  return [promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      promise.set_error(R.move_as_error());
      return;
    }
    promise.set_value(AdnlQueryAnswer{R.move_as_ok(), td::Timestamp{}});
  };
}

// For a deliverer that sends plain data: the metadata is not used.
inline td::Promise<AdnlQueryAnswer> ignore_answer_metadata(td::Promise<td::BufferSlice> promise) {
  return [promise = std::move(promise)](td::Result<AdnlQueryAnswer> R) mutable {
    if (R.is_error()) {
      promise.set_error(R.move_as_error());
      return;
    }
    promise.set_value(std::move(R.ok_ref().data));
  };
}

}  // namespace tos::adnl
