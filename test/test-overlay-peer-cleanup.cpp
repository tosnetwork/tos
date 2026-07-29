#include "adnl/adnl-node-id.hpp"
#include "overlay/broadcast-plumtree.hpp"
#include "overlay/overlay.hpp"
#include "td/utils/tests.h"

namespace tos::overlay {

class OverlayImplPeerCleanupTest {
 public:
  static void add_deletable_peer_with_plumtree_state(OverlayImpl &overlay, adnl::AdnlNodeIdShort peer_id) {
    CHECK(!overlay.peer_list_.peers_.exists(peer_id));
    overlay.peer_list_.peers_.insert(peer_id, OverlayPeer{OverlayNode{peer_id, overlay.overlay_id_, 0}});
    overlay.broadcasts_plumtree_.add_peer_state_for_test(peer_id);
  }

  static bool has_peer(const OverlayImpl &overlay, adnl::AdnlNodeIdShort peer_id) {
    return overlay.peer_list_.peers_.exists(peer_id);
  }

  static bool has_plumtree_peer_state(const OverlayImpl &overlay, adnl::AdnlNodeIdShort peer_id) {
    return overlay.broadcasts_plumtree_.has_peer_state_for_test(peer_id);
  }
};

}  // namespace tos::overlay

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

TEST(Overlay, DelPeerCleansPlumtreeState) {
  td::Bits256 local_bits;
  local_bits.as_slice().fill('l');
  auto local_id = tos::adnl::AdnlNodeIdShort{local_bits};

  td::Bits256 peer_bits;
  peer_bits.as_slice().fill('p');
  auto peer_id = tos::adnl::AdnlNodeIdShort{peer_bits};

  tos::overlay::OverlayOptions options;
  options.max_neighbours_ = 0;
  options.enable_plumtree_broadcast_ = false;
  tos::overlay::OverlayImpl overlay(
      {}, {}, {}, {}, local_id, tos::overlay::OverlayIdFull{td::BufferSlice{"peer-cleanup-test"}},
      tos::overlay::OverlayType::Public, {}, {}, {}, std::make_unique<tos::overlay::Overlays::Callback>(),
      tos::overlay::OverlayPrivacyRules{}, "peer-cleanup-test", std::move(options));

  tos::overlay::OverlayImplPeerCleanupTest::add_deletable_peer_with_plumtree_state(overlay, peer_id);
  ASSERT_TRUE(tos::overlay::OverlayImplPeerCleanupTest::has_peer(overlay, peer_id));
  ASSERT_TRUE(tos::overlay::OverlayImplPeerCleanupTest::has_plumtree_peer_state(overlay, peer_id));

  overlay.forget_peer(peer_id);
  ASSERT_TRUE(!tos::overlay::OverlayImplPeerCleanupTest::has_peer(overlay, peer_id));
  ASSERT_TRUE(!tos::overlay::OverlayImplPeerCleanupTest::has_plumtree_peer_state(overlay, peer_id));
}
