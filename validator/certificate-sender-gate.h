/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <set>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "overlay/overlays.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/validator-transport-authority.h"

namespace tos::validator {

// Overlay certificates are pushed to a node as plain ADNL messages, and importing one costs a
// signature check. Only validators issue them, so a message whose sender is not a validator
// transport identity is dropped before any parsing or signature work.

// Adds the transport identity of every validator in `validators` to `senders`.
inline void add_validator_transport_senders(std::set<adnl::AdnlNodeIdShort> &senders,
                                            const std::vector<ValidatorDescr> &validators) {
  for (const auto &validator : validators) {
    auto root = validator_transport_root(validator);
    if (!root.is_zero()) {
      senders.emplace(root);
    }
  }
}

// A pushed fast-sync membership certificate, accepted for import only from a validator transport
// identity. The caller still checks the certificate's signature and issuer when importing it.
inline td::Result<overlay::OverlayMemberCertificate> accept_pushed_fast_sync_certificate(
    adnl::AdnlNodeIdShort src, td::BufferSlice data, const std::set<adnl::AdnlNodeIdShort> &validator_senders) {
  if (!validator_senders.contains(src)) {
    return td::Status::Error(PSTRING() << "sender " << src << " is not a validator");
  }
  TRY_RESULT_PREFIX(message, fetch_tl_object<tos_api::tosNode_newFastSyncMemberCertificate>(std::move(data), true),
                    "cannot parse certificate message: ");
  auto certificate = overlay::OverlayMemberCertificate(message->certificate_.get());
  if (certificate.empty()) {
    return td::Status::Error("empty certificate");
  }
  return certificate;
}

// Whether a pushed shard-overlay certificate may be imported from `src`: from any validator
// transport identity in accept-from-any-validator mode, otherwise only from configured senders.
inline bool shard_overlay_certificate_sender_allowed(adnl::AdnlNodeIdShort src, bool accept_from_any_validator,
                                                     const std::set<adnl::AdnlNodeIdShort> &configured_senders,
                                                     const std::set<adnl::AdnlNodeIdShort> &validator_senders) {
  return accept_from_any_validator ? validator_senders.contains(src) : configured_senders.contains(src);
}

}  // namespace tos::validator
