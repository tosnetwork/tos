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

#include <string>

#include "adnl/adnl-node-id.hpp"
#include "fec/fec.h"
#include "keys/encryptor.h"
#include "keys/keys.hpp"
#include "overlay/broadcast-fec.hpp"
#include "overlay/overlay.hpp"
#include "td/utils/RateLimiterWindow.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/port/Clocks.h"
#include "td/utils/tests.h"
#include "tl-utils/tl-utils.hpp"

namespace tos::overlay {

class OverlayImplBroadcastCapacityTest {
 public:
  // The constructor turns two-step sending off without a two-step sender actor; the source check
  // only reads the option, so the test sets it directly.
  static void set_send_twostep(OverlayImpl &overlay, bool value) {
    overlay.opts_.send_twostep_broadcast_ = value;
  }
  static BroadcastsFec &fec(OverlayImpl &overlay) {
    return overlay.broadcasts_fec_;
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

// A short FEC part names a symbol that the receiver regenerates from its own encoder, so its seqno
// must stay inside the same bound as a full part. The broadcast is assembled through the real
// receive entry from signed full parts, then short parts probe the bound.
TEST(OverlayBroadcastCapacity, FecShortPartSeqnoIsBounded) {
  td::Bits256 local_bits;
  local_bits.as_slice().fill('l');
  tos::overlay::OverlayOptions options;
  options.max_neighbours_ = 0;
  options.enable_plumtree_broadcast_ = false;
  // Trusted unauthorized sources are Allowed, so the broadcast is delivered without an
  // application check; with no neighbours nothing is forwarded.
  tos::overlay::OverlayImpl overlay(
      {}, {}, {}, {}, tos::adnl::AdnlNodeIdShort{local_bits},
      tos::overlay::OverlayIdFull{td::BufferSlice{"fec-short-part-test"}}, tos::overlay::OverlayType::Public, {}, {},
      {}, std::make_unique<tos::overlay::Overlays::Callback>(),
      tos::overlay::OverlayPrivacyRules{
          1 << 20, tos::overlay::CertificateFlags::AllowFec | tos::overlay::CertificateFlags::Trusted, {}},
      "fec-short-part-test", std::move(options));
  auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);

  auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto source = key.compute_public_key();
  auto signer = key.create_decryptor().move_as_ok();
  td::BufferSlice data(std::string(4096, 'x'));
  auto data_hash = td::sha256_bits256(data.as_slice());
  auto data_size = static_cast<td::int32>(data.size());
  tos::fec::FecType fec_type = td::fec::RaptorQEncoder::Parameters{data.size(), 768, 0};
  auto encoder = fec_type.create_encoder(data.clone()).move_as_ok();
  encoder->prepare_more_symbols();
  auto date = static_cast<td::int32>(td::Clocks::system());
  auto broadcast_hash = tos::get_tl_object_sha_bits256(tos::create_tl_object<tos::tos_api::overlay_broadcastFec_id>(
      source.compute_short_id().tl(), tos::get_tl_object_sha_bits256(fec_type.tl()), data_hash, data_size, 0));
  td::Bits256 peer_bits;
  peer_bits.as_slice().fill('p');
  auto peer = tos::adnl::AdnlNodeIdShort{peer_bits};

  // Full parts until the receiver has decoded the broadcast and holds its encoder.
  const auto bound = static_cast<td::int32>(fec_type.symbols_count() * 2 + 4);
  ASSERT_TRUE(bound > 4);
  bool decoded = false;
  for (td::int32 seqno = 0; seqno < bound && !decoded; seqno++) {
    auto symbol = encoder->gen_symbol(static_cast<td::uint32>(seqno));
    auto part_hash = tos::get_tl_object_sha_bits256(tos::create_tl_object<tos::tos_api::overlay_broadcastFec_partId>(
        broadcast_hash, td::sha256_bits256(symbol.data.as_slice()), seqno));
    auto signature = signer
                         ->sign(tos::serialize_tl_object(
                             tos::create_tl_object<tos::tos_api::overlay_broadcast_toSign>(part_hash, date), true))
                         .move_as_ok();
    auto part = tos::create_tl_object<tos::tos_api::overlay_broadcastFec>(
        source.tl(), tos::overlay::Certificate::empty_tl(), data_hash, data_size, 0, std::move(symbol.data), seqno,
        fec_type.tl(), date, std::move(signature));
    ASSERT_TRUE(fec.process_broadcast(&overlay, peer, std::move(part)).is_ok());
    // Before decoding, a short part is refused as "not finished"; after it, it reaches later checks.
    decoded = fec.process_broadcast(&overlay, peer,
                                    tos::create_tl_object<tos::tos_api::overlay_broadcastFecShort>(
                                        source.tl(), tos::overlay::Certificate::empty_tl(), broadcast_hash,
                                        td::Bits256::zero(), 0, td::BufferSlice()))
                  .message() != td::Slice("short part of not finished broadcast");
  }
  ASSERT_TRUE(decoded);

  auto short_part = [&](td::int32 seqno) {
    return tos::create_tl_object<tos::tos_api::overlay_broadcastFecShort>(
        source.tl(), tos::overlay::Certificate::empty_tl(), broadcast_hash, td::Bits256::zero(), seqno,
        td::BufferSlice());
  };
  for (td::int32 seqno : {bound, 1 << 23, -1}) {
    auto status = fec.process_broadcast(&overlay, peer, short_part(seqno));
    ASSERT_TRUE(status.is_error());
    ASSERT_EQ(status.message(), td::Slice("too big seqno"));
  }
  // In range, the part passes the seqno check and reaches later checks instead: a symbol the
  // receiver's encoder holds reaches the data-hash check, and one just under the bound reaches the
  // encoder, which has not generated it yet.
  auto status = fec.process_broadcast(&overlay, peer, short_part(1));
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), td::Slice("wrong part data hash"));
  status = fec.process_broadcast(&overlay, peer, short_part(bound - 1));
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), td::Slice("encoder not ready"));
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
