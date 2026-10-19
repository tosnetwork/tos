#include <limits>
#include <utility>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "metrics/tl-traffic-bucket.h"
#include "td/utils/as.h"
#include "td/utils/tests.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

using namespace tos;

td::uint64 metric_value(const metrics::MetricSet &set, const std::string &family, const std::string &name) {
  for (const auto &f : set.families)
    if (f.name == family) {
      for (const auto &m : f.metrics)
        for (const auto &l : m.label_set.labels) {
          if (l.key == "tl" && l.val == name)
            return static_cast<td::uint64>(m.samples.at(0).value);
        }
    }
  return 0;
}

TEST(OverlayMetrics, ContentAndUnknownCardinality) {
  metrics::TlTrafficBucket bucket;
  auto data = create_serialize_tl_object<tos_api::dht_ping>(42);
  bucket.account(data.as_slice());
  bucket.account(tos_api::dht_ping::ID, 7);
  auto set = bucket.collect("in");
  ASSERT_EQ(metric_value(set, "overlay_broadcast_messages_total", "dht.ping"), 2u);
  ASSERT_EQ(metric_value(set, "overlay_broadcast_bytes_total", "dht.ping"), data.size() + 7u);
  for (td::int32 magic = 0; magic < 10000; ++magic)
    bucket.account(magic, 1);
  ASSERT_EQ(bucket.cells(), 2u);
  ASSERT_EQ(metric_value(bucket.collect("in"), "overlay_broadcast_messages_total", "unknown"), 10000u);
  auto delta = std::exchange(bucket, {});
  ASSERT_EQ(bucket.cells(), 1u);
  metrics::TlTrafficBucket aggregate;
  aggregate += delta;
  aggregate += bucket;
  ASSERT_EQ(metric_value(aggregate.collect("in"), "overlay_broadcast_messages_total", "dht.ping"), 2u);
  ASSERT_EQ(metric_value(aggregate.collect("in"), "overlay_broadcast_messages_total", "unknown"), 10000u);
}

TEST(OverlayMetrics, EnvelopeBoundaries) {
  auto data = create_serialize_tl_object<tos_api::dht_ping>(42);
  auto wrapped = create_serialize_tl_object<tos_api::overlay_unicast>(data.clone());
  ASSERT_EQ(metrics::resolve_tl_magic(wrapped.as_slice()), tos_api::dht_ping::ID);
  ASSERT_EQ(metrics::resolve_tl_magic(data.as_slice()), tos_api::dht_ping::ID);
  for (size_t size = 0; size < wrapped.size(); ++size) {
    auto magic = metrics::resolve_tl_magic(wrapped.as_slice().substr(0, size));
    ASSERT_EQ(magic, size < 4 ? 0 : tos_api::overlay_unicast::ID);
  }
  // A short nested bytes field must not consume its padding or the following field.
  td::BufferSlice short_content(12);
  short_content.as_slice().fill(0);
  td::as<td::int32>(short_content.as_slice().data()) = tos_api::overlay_unicast::ID;
  short_content.as_slice()[4] = 1;
  td::as<td::int32>(short_content.as_slice().data() + 8) = tos_api::dht_ping::ID;
  ASSERT_EQ(metrics::resolve_tl_magic(short_content.as_slice()), tos_api::overlay_unicast::ID);
  td::BufferSlice spill(53);
  spill.as_slice().fill(0);
  td::as<td::int32>(spill.as_slice().data()) = tos_api::overlay_unicast::ID;
  spill.as_slice()[4] = 4;
  td::as<td::int32>(spill.as_slice().data() + 5) = tos_api::overlay_query::ID;
  td::as<td::int32>(spill.as_slice().data() + 41) = tos_api::dht_ping::ID;
  ASSERT_EQ(metrics::resolve_tl_magic(spill.as_slice()), tos_api::overlay_query::ID);
  auto lite = create_serialize_tl_object<lite_api::liteServer_query>(
      create_serialize_tl_object<lite_api::liteServer_getMasterchainInfo>());
  ASSERT_EQ(metrics::resolve_tl_magic(lite.as_slice()), lite_api::liteServer_getMasterchainInfo::ID);
  ASSERT_EQ(*metrics::tl_schema_name(lite_api::liteServer_getMasterchainInfo::ID), "liteServer.getMasterchainInfo");
  ASSERT_TRUE(!metrics::tl_schema_name(1));
}
