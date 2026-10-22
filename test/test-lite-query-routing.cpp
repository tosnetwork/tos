/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// A lite server that serves a bounded history (a timed slice) is chosen for a query only when
// the requested block lies inside its [shards_from, shards_to] window.
#include <cstdio>
#include <string>
#include <vector>

#include "keys/keys.hpp"
#include "lite-client/query-utils.hpp"

namespace {

int failures = 0;

void check(const std::string& name, bool ok) {
  std::printf("LITE_ROUTING_CASE %s %s\n", name.c_str(), ok ? "PASS" : "FAIL");
  if (!ok) {
    ++failures;
  }
}

tos::tl_object_ptr<tos::tos_api::liteserver_descV2_shardInfo> shard_at(tos::WorkchainId workchain, td::int32 seqno) {
  return tos::create_tl_object<tos::tos_api::liteserver_descV2_shardInfo>(
      tos::create_tl_object<tos::tos_api::tosNode_shardId>(workchain, tos::shardIdAll), seqno, 0, 0);
}

liteclient::QueryInfo mc_seqno_query(tos::ShardIdFull shard, td::uint64 mc_seqno) {
  liteclient::QueryInfo q;
  q.shard_id = shard;
  q.type = liteclient::QueryInfo::t_mc_seqno;
  q.value = mc_seqno;
  return q;
}

}  // namespace

int main() {
  constexpr td::int32 from_seqno = 100;
  constexpr td::int32 to_seqno = 200;
  std::vector<tos::tl_object_ptr<tos::tos_api::liteserver_descV2_shardInfo>> from, to;
  // The window is given by masterchain seqnos; the basechain entries only say which shards the
  // server holds, and their own seqnos are far from the masterchain ones on purpose.
  from.push_back(shard_at(tos::masterchainId, from_seqno));
  from.push_back(shard_at(tos::basechainId, 1000));
  to.push_back(shard_at(tos::masterchainId, to_seqno));
  to.push_back(shard_at(tos::basechainId, 5000));
  std::vector<tos::tl_object_ptr<tos::tos_api::liteserver_descV2_Slice>> slices;
  slices.push_back(tos::create_tl_object<tos::tos_api::liteserver_descV2_sliceTimed>(std::move(from), std::move(to)));
  std::vector<tos::tl_object_ptr<tos::tos_api::liteserver_descV2>> servers_v2;
  servers_v2.push_back(tos::create_tl_object<tos::tos_api::liteserver_descV2>(
      tos::PublicKey{tos::pubkeys::Ed25519{td::Bits256::zero()}}.tl(), 0, 1, "127.0.0.1", std::move(slices)));
  tos::tos_api::liteclient_config_global config{{}, std::move(servers_v2), nullptr};

  auto parsed = liteclient::LiteServerConfig::parse_global_config(config);
  check("config-parsed", parsed.is_ok() && parsed.ok().size() == 1);
  if (parsed.is_error() || parsed.ok().size() != 1) {
    return 1;
  }
  const auto& server = parsed.ok()[0];

  for (auto shard : {tos::ShardIdFull{tos::masterchainId}, tos::ShardIdFull{tos::basechainId}}) {
    std::string wc = shard.is_masterchain() ? "masterchain" : "basechain";
    check(wc + "-mc-seqno-inside-window-accepted", server.accepts_query(mc_seqno_query(shard, 150)));
    check(wc + "-mc-seqno-at-window-start-accepted", server.accepts_query(mc_seqno_query(shard, from_seqno)));
    check(wc + "-mc-seqno-at-window-end-accepted", server.accepts_query(mc_seqno_query(shard, to_seqno)));
    check(wc + "-mc-seqno-before-window-refused", !server.accepts_query(mc_seqno_query(shard, from_seqno - 1)));
    check(wc + "-mc-seqno-after-window-refused", !server.accepts_query(mc_seqno_query(shard, to_seqno + 1)));
  }
  return failures ? 1 : 0;
}
