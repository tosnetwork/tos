/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Broadcast admission on the receive path follows the reference implementation:
// the legacy FEC and two-step receive tables are bounded only by their gc
// windows, and the per-source broadcast limiters are unconstrained by default.
// These tests pin that default and the local FEC source check.

#include "adnl/adnl-node-id.hpp"
#include "overlay/overlay.hpp"
#include "td/utils/RateLimiterWindow.h"
#include "td/utils/Time.h"
#include "td/utils/tests.h"

namespace tos::overlay {

class OverlayImplBroadcastCapacityTest {
 public:
  // The constructor turns two-step sending off without a two-step sender actor; the source check
  // only reads the option, so the test sets it directly.
  static void set_send_twostep(OverlayImpl &overlay, bool value) {
    overlay.opts_.send_twostep_broadcast_ = value;
  }
};

}  // namespace tos::overlay

// A two-step broadcast is checked by its receivers as coming from a named sender, even when the
// AnySender flag is set. The local source check before sending must use the same rule, or a source
// that the receivers accept is refused locally.
TEST(OverlayBroadcastCapacity, FecSenderCheckFollowsTheSelectedPath) {
  using tos::overlay::OverlayImpl;
  using tos::overlay::Overlays;
  auto any = Overlays::BroadcastFlagAnySender();
  auto no_twostep = Overlays::BroadcastFlagNoTwostep();
  ASSERT_TRUE(!OverlayImpl::fec_source_checked_as_any_sender(true, any));
  ASSERT_TRUE(OverlayImpl::fec_source_checked_as_any_sender(true, any | no_twostep));
  ASSERT_TRUE(OverlayImpl::fec_source_checked_as_any_sender(false, any));
  ASSERT_TRUE(!OverlayImpl::fec_source_checked_as_any_sender(true, 0));
  ASSERT_TRUE(!OverlayImpl::fec_source_checked_as_any_sender(false, 0));

  // The rule decides real eligibility: with no authorized keys, a source may send FEC broadcasts
  // up to 1 MiB as a named sender and none with AnySender.
  td::Bits256 local_bits;
  local_bits.as_slice().fill('l');
  tos::overlay::OverlayOptions options;
  options.max_neighbours_ = 0;
  options.enable_plumtree_broadcast_ = false;
  OverlayImpl overlay({}, {}, {}, {}, tos::adnl::AdnlNodeIdShort{local_bits},
                      tos::overlay::OverlayIdFull{td::BufferSlice{"fec-sender-check-test"}},
                      tos::overlay::OverlayType::Public, {}, {}, {},
                      std::make_unique<tos::overlay::Overlays::Callback>(),
                      tos::overlay::OverlayPrivacyRules{1 << 20, tos::overlay::CertificateFlags::AllowFec, {}},
                      "fec-sender-check-test", std::move(options));
  td::Bits256 source_bits;
  source_bits.as_slice().fill('s');
  tos::PublicKeyHash source{source_bits};
  ASSERT_TRUE(overlay.can_send_broadcast_fec(source, 1000, 0));
  ASSERT_TRUE(!overlay.can_send_broadcast_fec(source, 1000, any));
  // With two-step sending, the same AnySender broadcast passes, as the receivers will accept it;
  // NoTwostep keeps the plain FEC rule.
  tos::overlay::OverlayImplBroadcastCapacityTest::set_send_twostep(overlay, true);
  ASSERT_TRUE(overlay.can_send_broadcast_fec(source, 1000, any));
  ASSERT_TRUE(!overlay.can_send_broadcast_fec(source, 1000, any | no_twostep));
}

// The broadcast limiters are unconstrained unless an overlay configures them: a zero window never
// refuses. A public relay of many clients' external messages must not be throttled by a default
// count or byte window.
TEST(OverlayBroadcastCapacity, BroadcastLimitersAreUnconstrainedByDefault) {
  tos::overlay::OverlayOptions opts;
  const td::RateLimiterWindow::Params *defaults[] = {
      &opts.auth_broadcast_rate_limit_, &opts.auth_broadcast_size_rate_limit_, &opts.unauth_broadcast_rate_limit_,
      &opts.unauth_broadcast_size_rate_limit_};
  td::Timestamp now = td::Timestamp::now();
  for (const auto *params : defaults) {
    ASSERT_TRUE(params->duration == 0.0);
    td::RateLimiterWindow window{*params};
    // Well past any count or byte window a default could impose, all in one instant.
    for (int i = 0; i < 20000; i++) {
      ASSERT_TRUE(window.check(now, 1 << 20));
      window.insert(now, 1 << 20);
    }
  }
}
