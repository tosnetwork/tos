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

// A peer pair records each received packet seqno once. Recording the same seqno again used to
// abort the node; it is now ignored and leaves the replay window unchanged.
//
// The transport socket is IPv4-only. An IPv6 address used to get a connection actor whose first
// send aborted the process inside the IPv4 socket; it is now refused before any actor exists.

#include "adnl/adnl-address-list.hpp"
#include "adnl/adnl-peer.hpp"
#include "td/utils/tests.h"

namespace tos::adnl {

class AdnlPeerPairImplTest {
 public:
  static void add_received(AdnlPeerPairImpl &pair, td::uint64 seqno) {
    pair.add_received_packet(seqno);
  }
  static bool received(const AdnlPeerPairImpl &pair, td::uint64 seqno) {
    return pair.received_packet(seqno);
  }
};

}  // namespace tos::adnl

TEST(AdnlPeerPair, RepeatedReceivedSeqnoIsIgnored) {
  using Access = tos::adnl::AdnlPeerPairImplTest;
  td::Bits256 local_bits;
  local_bits.as_slice().fill('l');
  td::Bits256 peer_bits;
  peer_bits.as_slice().fill('p');
  tos::adnl::AdnlPeerPairImpl pair({}, {}, 0, {}, {}, tos::adnl::AdnlNodeIdShort{local_bits},
                                   tos::adnl::AdnlNodeIdShort{peer_bits});
  Access::add_received(pair, 5);
  Access::add_received(pair, 3);
  ASSERT_TRUE(Access::received(pair, 5));
  ASSERT_TRUE(Access::received(pair, 3));
  ASSERT_TRUE(!Access::received(pair, 4));

  Access::add_received(pair, 5);
  Access::add_received(pair, 3);
  ASSERT_TRUE(Access::received(pair, 5));
  ASSERT_TRUE(Access::received(pair, 3));
  ASSERT_TRUE(!Access::received(pair, 4));
  ASSERT_TRUE(!Access::received(pair, 6));
}

TEST(AdnlAddressList, Udp6AddressIsRefusedBeforeAnyConnection) {
  tos::adnl::AdnlAddressUdp6 address{td::Bits128{}, 3000};
  auto connection = address.create_connection({}, {}, nullptr);
  ASSERT_TRUE(connection.is_error());
  ASSERT_EQ(connection.error().message().str(), "ipv6 is not supported");
}
