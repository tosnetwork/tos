/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "falcon512.h"
#include "falcon512-native.h"
namespace tos::pq {
VerifyResult verify_falcon512_padded(std::string_view message, std::string_view signature,
                                   std::string_view public_key) noexcept {
  auto bytes = [](std::string_view v) { return reinterpret_cast<const uint8_t*>(v.data()); };
  switch (tos_falcon512_padded_verify(bytes(message), message.size(), bytes(signature),
                                    signature.size(), bytes(public_key), public_key.size())) {
    case 1: return VerifyResult::valid;
    case 0: return VerifyResult::invalid;
    case -1: return VerifyResult::malformed_input;
    default: return VerifyResult::backend_error;
  }
}
}
