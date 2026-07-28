#include "adnl/adnl-node-id.hpp"
#include "overlay/broadcast-plumtree.hpp"
#include "td/utils/tests.h"

TEST(Overlay, PlumtreePeerCleanup) {
  tos::overlay::BroadcastsPlumtree plumtree;
  td::Bits256 peer_bits;
  peer_bits.as_slice().fill('p');
  auto peer = tos::adnl::AdnlNodeIdShort{peer_bits};

  plumtree.add_peer_state_for_test(peer);
  ASSERT_TRUE(plumtree.has_peer_state_for_test(peer));
  plumtree.remove_peer_state_for_test(peer);
  ASSERT_TRUE(!plumtree.has_peer_state_for_test(peer));
}
