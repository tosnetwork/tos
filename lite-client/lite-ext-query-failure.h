/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <memory>

#include "adnl/adnl-ext-query-failure.h"
#include "auto/tl/lite_api.h"
#include "common/errorcode.h"
#include "tl-utils/tl-utils.hpp"

namespace liteclient {

// Encodes an external query the server cannot serve as the Lite protocol's own
// liteServer.error, answered on the original query ID. Existing Lite clients
// already parse it, so no wire change is needed. Messages are fixed strings: no
// peer address, internal state or handler text is reflected to the client.
class LiteExtQueryFailureEncoder final : public tos::adnl::ExtQueryFailureEncoder {
 public:
  static constexpr const char *kAdmissionMessage = "liteserver admission limit exceeded";
  static constexpr const char *kHandlerMessage = "liteserver query failed";
  static constexpr const char *kTooLargeMessage = "liteserver response too large";

  td::Result<td::BufferSlice> encode(const tos::adnl::ExtQueryFailure &failure) const override {
    td::int32 code = tos::ErrorCode::notready;
    const char *message = kAdmissionMessage;
    switch (failure.kind) {
      case tos::adnl::ExtQueryFailureKind::PerConnectionRateLimit:
      case tos::adnl::ExtQueryFailureKind::PerConnectionInflightLimit:
      case tos::adnl::ExtQueryFailureKind::ServerInflightLimit:
      case tos::adnl::ExtQueryFailureKind::PerIpInflightLimit:
        break;
      case tos::adnl::ExtQueryFailureKind::HandlerError:
        code = tos::ErrorCode::error;
        message = kHandlerMessage;
        break;
      case tos::adnl::ExtQueryFailureKind::ResponseTooLarge:
        code = tos::ErrorCode::error;
        message = kTooLargeMessage;
        break;
    }
    return tos::create_serialize_tl_object<tos::lite_api::liteServer_error>(code, message);
  }

  static std::shared_ptr<const tos::adnl::ExtQueryFailureEncoder> create() {
    return std::make_shared<const LiteExtQueryFailureEncoder>();
  }
};

}  // namespace liteclient
