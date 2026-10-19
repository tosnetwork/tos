#include <limits>

#include "overlay/broadcast-plumtree-stats.hpp"
#include "td/utils/port/Clocks.h"
#include "td/utils/tests.h"

using namespace tos::overlay;

TEST(OverlayPlumtreeStats, LatencyBoundsAndReset) {
  PlumtreeLatencyStats stats;
  stats.note(std::numeric_limits<double>::quiet_NaN());
  stats.note(std::numeric_limits<double>::infinity());
  ASSERT_EQ(stats.avg_ms(10000), 0u);
  ASSERT_EQ(stats.max_ms(), 0u);
  ASSERT_EQ(stats.p99_ms(), 0u);
  stats.note(td::Clocks::system() + 60);
  ASSERT_EQ(stats.avg_ms(10000), 0u);
  ASSERT_EQ(stats.max_ms(), 0u);
  stats.note(td::Clocks::system() - 120);
  ASSERT_EQ(stats.avg_ms(10000), 10000u);
  ASSERT_TRUE(stats.max_ms() >= 120000u);
  ASSERT_EQ(stats.p99_ms(), 3000u);
  stats.reset();
  ASSERT_EQ(stats.max_ms(), 0u);
  ASSERT_EQ(stats.p99_ms(), 0u);
}

TEST(OverlayPlumtreeStats, RepairShare) {
  PlumtreeRepairStats stats;
  ASSERT_EQ(stats.percent_scaled(), 0u);
  stats.note(false);
  stats.note(true);
  ASSERT_EQ(stats.percent_scaled(), 128u);
  stats.reset();
  stats.note(true);
  ASSERT_EQ(stats.percent_scaled(), 255u);
  stats.reset();
  ASSERT_EQ(stats.percent_scaled(), 0u);
}

TEST(OverlayPlumtreeStats, PackedSlotsAndSnapshotReset) {
  PlumtreeStats stats;
  stats.note_delivered_broadcast();
  stats.note_useful_delivery(td::Clocks::system() - 120, true);
  stats.note_useful_delivery(td::Clocks::system() + 60, false);
  stats.note_part_received(true, false);
  stats.note_part_received(true, true);
  stats.note_part_received(false, true);
  stats.note_fec_parts_collected(2, 10);
  for (int i = 0; i < 99; ++i) {
    stats.note_fec_parts_collected(10, 10);
  }
  auto [delivered, parts, avg, maximum, p99] = stats.snapshot_and_reset(10);
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(parts, 10);
  ASSERT_EQ(avg, 10000 * 10001);
  ASSERT_EQ(maximum, (30000 << 16) | (128 << 8) | 255);
  ASSERT_EQ(p99, 3000 * 3001 + 1);
  auto [empty_delivered, empty_parts, empty_avg, empty_max, empty_p99] = stats.snapshot_and_reset(10);
  ASSERT_EQ(empty_delivered, 0);
  ASSERT_EQ(empty_parts, 0);
  ASSERT_EQ(empty_avg, 0);
  ASSERT_EQ(empty_max, 0);
  ASSERT_EQ(empty_p99, 0);
}
