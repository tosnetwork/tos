#include <limits>

#include "adnl/adnl-node-id.hpp"
#include "overlay/broadcast-plumtree.hpp"
#include "overlay/overlay-node-version.h"
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

  static void admit(OverlayImpl &overlay, OverlayNode node) {
    overlay.add_peer(std::move(node), true);
  }
  static td::uint32 local_flags(const OverlayImpl &overlay) {
    return overlay.peer_list_.local_member_flags_;
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

namespace {
using tos::overlay::OverlayMemberFlags;
using tos::overlay::OverlayNode;

OverlayNode signed_overlay_node(const tos::PrivateKey &key, tos::overlay::OverlayIdShort overlay, td::uint32 flags,
                                td::int32 version) {
  OverlayNode node{tos::adnl::AdnlNodeIdFull{key.compute_public_key()}, overlay, flags, version, td::Slice{}};
  node.update_signature(key.create_decryptor().move_as_ok()->sign(node.to_sign().as_slice()).move_as_ok().as_slice());
  return node;
}
}  // namespace

TEST(Overlay, SignedReceivePolicy) {
  auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  tos::overlay::OverlayIdShort overlay{td::Bits256::ones()};
  for (td::uint32 flags : {0u, 1u, 2u, 3u}) {
    auto node = signed_overlay_node(key, overlay, flags, 100);
    node.check_signature().ensure();
    auto wire = tos::serialize_tl_object(node.tl(), true);
    auto parsed =
        OverlayNode::create(tos::fetch_tl_object<tos::tos_api::overlay_node>(wire.as_slice(), true).move_as_ok())
            .move_as_ok();
    ASSERT_EQ(parsed.flags(), flags);
    parsed.check_signature().ensure();
    auto tampered = node.tl();
    tampered->flags_ ^= 2;
    auto bad = OverlayNode::create(tampered).move_as_ok();
    bad.check_signature().ensure_error();
    auto db =
        tos::create_tl_object<tos::tos_api::overlay_db_nodes>(tos::create_tl_object<tos::tos_api::overlay_nodes>());
    db->nodes_->nodes_.push_back(node.tl());
    auto recovered =
        tos::fetch_tl_object<tos::tos_api::overlay_db_nodes>(tos::serialize_tl_object(db, true), true).move_as_ok();
    auto stored = OverlayNode::create(recovered->nodes_->nodes_[0]).move_as_ok();
    ASSERT_EQ(stored.flags(), flags);
    stored.check_signature().ensure();
  }
  auto unknown = signed_overlay_node(key, overlay, 4, 100).tl();
  ASSERT_TRUE(OverlayNode::create(unknown).is_error());
  unknown->flags_ = -1;
  ASSERT_TRUE(OverlayNode::create(unknown).is_error());
  unknown->flags_ = 0;
  unknown->certificate_ = nullptr;
  ASSERT_TRUE(OverlayNode::create(unknown).is_error());
}

TEST(Overlay, ReceivePolicyChangesNeedNewerSignedDescription) {
  auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  tos::overlay::OverlayIdShort overlay{td::Bits256::ones()};
  auto node = signed_overlay_node(key, overlay, 0, 100);
  node.update(signed_overlay_node(key, overlay, 2, 101));
  ASSERT_EQ(node.flags(), 2u);
  node.check_signature().ensure();
  node.update(signed_overlay_node(key, overlay, 0, 101));
  ASSERT_EQ(node.flags(), 2u);
  node.update(signed_overlay_node(key, overlay, 0, 99));
  ASSERT_EQ(node.flags(), 2u);
  node.update(signed_overlay_node(key, overlay, 0, 102));
  ASSERT_EQ(node.flags(), 0u);
  node.check_signature().ensure();
}

TEST(Overlay, PlumtreePolicyPreservesOrdinaryBroadcasts) {
  ASSERT_TRUE(OverlayMemberFlags::receives_regular(0));
  ASSERT_TRUE(OverlayMemberFlags::receives_plumtree(0));
  ASSERT_TRUE(OverlayMemberFlags::receives_regular(2));
  ASSERT_TRUE(!OverlayMemberFlags::receives_plumtree(2));
  for (auto flags : {1u, 3u, 4u, 0xffffffffu}) {
    ASSERT_TRUE(!OverlayMemberFlags::receives_regular(flags));
    ASSERT_TRUE(!OverlayMemberFlags::receives_plumtree(flags));
  }
  ASSERT_EQ(OverlayMemberFlags::public_flags(0, true, true), 2u);
  ASSERT_EQ(OverlayMemberFlags::public_flags(0, false, false), 2u);
  ASSERT_EQ(OverlayMemberFlags::public_flags(0, true, false), 0u);
  ASSERT_EQ(OverlayMemberFlags::public_flags(1, true, true), 3u);
}

TEST(Overlay, PublicPeerPolicyAdmission) {
  using Access = tos::overlay::OverlayImplPeerCleanupTest;
  auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto id = tos::adnl::AdnlNodeIdFull{key.compute_public_key()}.compute_short_id();
  tos::overlay::OverlayOptions options;
  options.max_neighbours_ = 0;
  options.enable_plumtree_broadcast_ = false;
  tos::overlay::OverlayIdFull full{td::BufferSlice{"public-policy-test"}};
  auto short_id = full.compute_short_id();
  tos::overlay::OverlayImpl overlay({}, {}, {}, {}, tos::adnl::AdnlNodeIdShort::zero(), std::move(full),
                                    tos::overlay::OverlayType::Public, {}, {}, {},
                                    std::make_unique<tos::overlay::Overlays::Callback>(),
                                    tos::overlay::OverlayPrivacyRules{}, "public-policy-test", std::move(options));
  ASSERT_EQ(Access::local_flags(overlay), 2u);
  ASSERT_TRUE(!overlay.peer_receives_plumtree_broadcasts(id));
  auto now = static_cast<td::int32>(td::Clocks::system());
  auto good = signed_overlay_node(key, short_id, 2, now);
  auto tampered = good.tl();
  tampered->flags_ = 0;
  Access::admit(overlay, OverlayNode::create(tampered).move_as_ok());
  ASSERT_TRUE(!Access::has_peer(overlay, id));
  Access::admit(overlay, std::move(good));
  ASSERT_TRUE(Access::has_peer(overlay, id));
  ASSERT_TRUE(overlay.peer_receives_broadcasts(id));
  ASSERT_TRUE(!overlay.peer_receives_plumtree_broadcasts(id));
  Access::admit(overlay, signed_overlay_node(key, short_id, 0, now + 1));
  ASSERT_TRUE(overlay.peer_receives_plumtree_broadcasts(id));
  Access::admit(overlay, signed_overlay_node(key, short_id, 2, now));
  ASSERT_TRUE(overlay.peer_receives_plumtree_broadcasts(id));
  Access::admit(overlay, signed_overlay_node(key, short_id, 2, now + 2));
  ASSERT_TRUE(!overlay.peer_receives_plumtree_broadcasts(id));
}

TEST(Overlay, LegacyNodeLayoutIsNotAProtocolFallback) {
  auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto node = signed_overlay_node(key, tos::overlay::OverlayIdShort{td::Bits256::ones()}, 0, 100);
  auto canonical = tos::serialize_tl_object(node.tl(), true);
  // Old boxed node: public key + overlay + version + signature, no flags/certificate.
  td::BufferSlice old(canonical.size() - 8);
  old.as_slice().substr(0, 72).copy_from(canonical.as_slice().substr(0, 72));
  old.as_slice().substr(72).copy_from(canonical.as_slice().substr(76, canonical.size() - 80));
  const unsigned char constructor[] = {0x83, 0x8a, 0x6b, 0xb8};
  old.as_slice().substr(0, 4).copy_from(td::Slice{constructor, 4});
  ASSERT_TRUE(tos::fetch_tl_object<tos::tos_api::overlay_node>(old.as_slice(), true).is_error());
  // The nodes constructor itself did not change: bare children must still be refused.
  auto vector = tos::create_tl_object<tos::tos_api::overlay_nodes>();
  vector->nodes_.push_back(node.tl());
  auto encoded = tos::serialize_tl_object(vector, true);
  td::BufferSlice old_vector(encoded.size() - 8);
  old_vector.as_slice().substr(0, 8).copy_from(encoded.as_slice().substr(0, 8));
  old_vector.as_slice().substr(8).copy_from(old.as_slice().substr(4));
  ASSERT_TRUE(tos::fetch_tl_object<tos::tos_api::overlay_nodes>(old_vector.as_slice(), true).is_error());
}

TEST(Overlay, DescriptorFreshnessBoundaries) {
  constexpr std::int64_t now = 1800000000;
  for (std::int32_t version : {1800000000 - 600, 1800000000, 1800000000 + 60}) {
    ASSERT_TRUE(tos::overlay::overlay_node_version_is_fresh(version, now));
  }
  for (std::int32_t version : {std::numeric_limits<std::int32_t>::min(), -1, 1800000000 - 601, 1800000000 + 61,
                               std::numeric_limits<std::int32_t>::max()}) {
    ASSERT_TRUE(!tos::overlay::overlay_node_version_is_fresh(version, now));
  }
  // Arithmetic still works at the signed wire timestamp's upper boundary.
  constexpr auto upper = std::numeric_limits<std::int32_t>::max();
  ASSERT_TRUE(tos::overlay::overlay_node_version_is_fresh(upper, upper));
  ASSERT_TRUE(!tos::overlay::overlay_node_version_is_fresh(upper - 601, upper));
}
