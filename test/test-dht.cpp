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

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <memory>
#include <set>

#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "dht/dht-bucket.hpp"
#include "dht/dht-in.hpp"
#include "dht/dht.h"
#include "dht/dht.hpp"
#include "td/utils/Random.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  std::string db_root_ = "tmp-dir-test-dht";
  td::rmrf(db_root_).ignore();
  td::mkdir(db_root_).ensure();

  td::set_default_failure_signal_handler().ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  std::vector<td::actor::ActorOwn<tos::dht::Dht>> dht;
  std::shared_ptr<tos::dht::DhtGlobalConfig> dht_config;

  td::actor::Scheduler scheduler({7});

  std::vector<tos::adnl::AdnlNodeIdFull> dht_ids;
  td::uint32 total_nodes = 11;
  std::atomic<td::uint32> remaining{0};
  td::actor::ActorOwn<tos::dht::DhtMember> retry_dht;
  auto retry_private_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto retry_public_key = retry_private_key.compute_public_key();
  auto retry_full_id = tos::adnl::AdnlNodeIdFull{retry_public_key};
  auto retry_short_id = retry_full_id.compute_short_id();
  std::atomic<bool> retry_key_added{false};
  bool retry_key_add_ok = false;
  std::atomic<bool> retry_initial_id_registered{false};
  bool retry_initial_id_exists = false;

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root_);
    network_manager = td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>("test net");
    adnl = tos::adnl::Adnl::create(db_root_, keyring.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager, network_manager.get());

    auto addr0 = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list(true);
    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();

    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(retry_private_key), true,
                            [&](td::Result<> result) {
                              retry_key_add_ok = result.is_ok();
                              retry_key_added = true;
                            });
    auto retry_addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, retry_full_id, std::move(retry_addr),
                            static_cast<td::uint8>(0));
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, retry_short_id, true,
                            true);
    td::actor::send_closure(adnl, &tos::adnl::Adnl::check_id_exists, retry_short_id, [&](td::Result<bool> result) {
      retry_initial_id_exists = result.is_ok() && result.ok();
      retry_initial_id_registered = true;
    });

    for (td::uint32 i = 0; i < total_nodes; i++) {
      auto pk1 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
      auto pub1 = pk1.compute_public_key();
      auto src = tos::adnl::AdnlNodeIdShort{pub1.compute_short_id()};

      if (i == 0) {
        auto obj = tos::create_tl_object<tos::tos_api::dht_node>(pub1.tl(), addr0.tl(), -1, td::BufferSlice());
        auto d = pk1.create_decryptor().move_as_ok();
        obj->signature_ = d->sign(serialize_tl_object(obj, true)).move_as_ok();

        std::vector<tos::tl_object_ptr<tos::tos_api::dht_node>> vec;
        vec.push_back(std::move(obj));
        auto nodes = tos::create_tl_object<tos::tos_api::dht_nodes>(std::move(vec));
        auto conf = tos::create_tl_object<tos::tos_api::dht_config_global>(std::move(nodes), 6, 3);
        auto dht_configR = tos::dht::Dht::create_global_config(std::move(conf));
        dht_configR.ensure();
        dht_config = dht_configR.move_as_ok();
      }
      td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk1), true, [](td::Result<>) {});
      td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub1}, addr,
                              static_cast<td::uint8>(0));
      td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, src, true, true);

      dht.push_back(tos::dht::Dht::create(src, db_root_, dht_config, keyring.get(), adnl.get()).move_as_ok());
      dht_ids.push_back(tos::adnl::AdnlNodeIdFull{pub1});
    }
    for (auto &n1 : dht_ids) {
      td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, n1.compute_short_id(), dht_ids[0], addr);
    }
  });

  auto wait_for = [&](const std::atomic<bool> &done, td::Slice operation) {
    auto timeout = td::Timestamp::in(10.0);
    while (!done.load()) {
      scheduler.run(0.1);
      if (timeout.is_in_past()) {
        LOG(FATAL) << "Timed out waiting for " << operation;
      }
    }
  };

  wait_for(retry_key_added, "DHT retry test key insertion");
  CHECK(retry_key_add_ok);
  wait_for(retry_initial_id_registered, "initial ADNL ID registration");
  CHECK(retry_initial_id_exists);

  scheduler.run_in_context([&] {
    retry_dht = tos::dht::DhtMember::create(retry_short_id, db_root_, keyring.get(), adnl.get(), -1, 6, 3, true);
  });
  auto retry_dht_started_at = td::Timestamp::in(0.5);
  while (!retry_dht_started_at.is_in_past()) {
    scheduler.run(0.05);
  }

  std::atomic<bool> retry_id_deleted{false};
  bool retry_id_delete_ok = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(adnl, &tos::adnl::Adnl::del_id, retry_short_id, [&](td::Result<td::Unit> result) {
      retry_id_delete_ok = result.is_ok();
      retry_id_deleted = true;
    });
  });
  wait_for(retry_id_deleted, "temporary ADNL ID removal");
  CHECK(retry_id_delete_ok);

  LOG(ERROR) << "testing DHT self-node error propagation and retry";
  std::atomic<bool> first_self_node_done{false};
  bool first_self_node_failed = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(retry_dht, &tos::dht::DhtMember::get_self_node, [&](td::Result<tos::dht::DhtNode> result) {
      first_self_node_failed = result.is_error();
      first_self_node_done = true;
    });
  });
  wait_for(first_self_node_done, "initial DHT self-node failure");
  CHECK(first_self_node_failed);

  std::atomic<bool> retry_id_registered{false};
  bool retry_id_exists = false;
  scheduler.run_in_context([&] {
    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, retry_full_id, std::move(addr), static_cast<td::uint8>(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::check_id_exists, retry_short_id, [&](td::Result<bool> result) {
      retry_id_exists = result.is_ok() && result.ok();
      retry_id_registered = true;
    });
  });
  wait_for(retry_id_registered, "ADNL ID registration");
  CHECK(retry_id_exists);

  std::atomic<bool> second_self_node_done{false};
  bool second_self_node_succeeded = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(retry_dht, &tos::dht::DhtMember::get_self_node, [&](td::Result<tos::dht::DhtNode> result) {
      second_self_node_succeeded = result.is_ok() && result.ok().adnl_id().compute_short_id() == retry_short_id;
      second_self_node_done = true;
    });
  });
  wait_for(second_self_node_done, "DHT self-node retry");
  CHECK(second_self_node_succeeded);
  LOG(ERROR) << "DHT self-node error propagation and retry succeeded";

  LOG(ERROR) << "testing different values";
  auto key_pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto key_pub = key_pk.compute_public_key();
  auto key_short_id = key_pub.compute_short_id();
  auto key_dec = key_pk.create_decryptor().move_as_ok();
  {
    for (td::uint32 idx = 0; idx <= tos::dht::DhtKey::max_index() + 1; idx++) {
      tos::dht::DhtKey dht_key{key_short_id, "test", idx};
      if (idx <= tos::dht::DhtKey::max_index()) {
        dht_key.check().ensure();
      } else {
        dht_key.check().ensure_error();
      }
    }
    {
      tos::dht::DhtKey dht_key{key_short_id, "test", 0};
      dht_key.check().ensure();
      dht_key = tos::dht::DhtKey{key_short_id, "", 0};
      dht_key.check().ensure_error();
      dht_key =
          tos::dht::DhtKey{key_short_id, td::BufferSlice{tos::dht::DhtKey::max_name_length()}.as_slice().str(), 0};
      dht_key.check().ensure();
      dht_key =
          tos::dht::DhtKey{key_short_id, td::BufferSlice{tos::dht::DhtKey::max_name_length() + 1}.as_slice().str(), 0};
      dht_key.check().ensure_error();
    }
    {
      tos::dht::DhtKey dht_key{key_short_id, "test", 0};
      auto dht_update_rule = tos::dht::DhtUpdateRuleSignature::create().move_as_ok();
      tos::dht::DhtKeyDescription dht_key_description{dht_key.clone(), key_pub, dht_update_rule, td::BufferSlice()};
      dht_key_description.update_signature(key_dec->sign(dht_key_description.to_sign()).move_as_ok());
      dht_key_description.check().ensure();
      dht_key_description = tos::dht::DhtKeyDescription{dht_key.clone(), key_pub, dht_update_rule, td::BufferSlice(64)};
      dht_key_description.check().ensure_error();
      dht_key_description.update_signature(key_dec->sign(dht_key_description.to_sign()).move_as_ok());
      dht_key_description.check().ensure();

      auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      dht_key_description = tos::dht::DhtKeyDescription{dht_key.clone(), pub, dht_update_rule, td::BufferSlice(64)};
      dht_key_description.update_signature(
          pk.create_decryptor().move_as_ok()->sign(dht_key_description.to_sign()).move_as_ok());
      dht_key_description.check().ensure_error();
    }
  }
  {
    tos::dht::DhtKey dht_key{key_short_id, "test", 0};
    auto dht_update_rule = tos::dht::DhtUpdateRuleSignature::create().move_as_ok();
    tos::dht::DhtKeyDescription dht_key_description{std::move(dht_key), key_pub, std::move(dht_update_rule),
                                                    td::BufferSlice()};
    dht_key_description.update_signature(key_dec->sign(dht_key_description.to_sign()).move_as_ok());

    auto ttl = static_cast<td::uint32>(td::Clocks::system() + 3600);
    tos::dht::DhtValue dht_value{dht_key_description.clone(), td::BufferSlice("value"), ttl, td::BufferSlice("")};
    dht_value.check().ensure_error();
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());
    dht_value.check().ensure();
    CHECK(!dht_value.expired());

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice(""), ttl, td::BufferSlice("")};
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());
    dht_value.check().ensure();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice(""),
                                   static_cast<td::uint32>(td::Clocks::system() - 1), td::BufferSlice("")};
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());
    dht_value.check().ensure();
    CHECK(dht_value.expired());

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice("value"), ttl, td::BufferSlice("")};
    dht_value.update_signature(td::BufferSlice{64});
    dht_value.check().ensure_error();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice(tos::dht::DhtValue::max_value_size()),
                                   ttl, td::BufferSlice("")};
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());
    dht_value.check().ensure();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(),
                                   td::BufferSlice(tos::dht::DhtValue::max_value_size() + 1), ttl, td::BufferSlice("")};
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());
    dht_value.check().ensure_error();
  }

  {
    // DhtUpdateRuleAnybody rejects Ed25519 keys (see DhtUpdateRuleAnybody::check_value),
    // so use an "unenc" key type here.
    td::BufferSlice x{64};
    td::Random::secure_bytes(x.as_slice());
    auto pk_anybody = tos::PrivateKey{tos::privkeys::Unenc{x.clone()}};
    auto pub_anybody = pk_anybody.compute_public_key();
    auto short_id_anybody = pub_anybody.compute_short_id();

    tos::dht::DhtKey dht_key{short_id_anybody, "test", 0};
    auto dht_update_rule = tos::dht::DhtUpdateRuleAnybody::create().move_as_ok();
    tos::dht::DhtKeyDescription dht_key_description{std::move(dht_key), pub_anybody, std::move(dht_update_rule),
                                                    td::BufferSlice()};
    dht_key_description.check().ensure();

    auto ttl = static_cast<td::uint32>(td::Clocks::system() + 3600);
    tos::dht::DhtValue dht_value{dht_key_description.clone(), td::BufferSlice("value"), ttl, td::BufferSlice()};
    dht_value.check().ensure();
    CHECK(!dht_value.expired());
    dht_value.update_signature(td::BufferSlice("sig"));
    dht_value.check().ensure_error();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice(), ttl, td::BufferSlice()};
    dht_value.check().ensure();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(), td::BufferSlice(tos::dht::DhtValue::max_value_size()),
                                   ttl, td::BufferSlice()};
    dht_value.check().ensure();

    dht_value = tos::dht::DhtValue{dht_key_description.clone(),
                                   td::BufferSlice(tos::dht::DhtValue::max_value_size() + 1), ttl, td::BufferSlice()};
    dht_value.check().ensure_error();
  }

  {
    // DhtUpdateRuleOverlayNodes requires an overlay key type and empty keyDescription signature.
    td::BufferSlice overlay_name{32};
    td::Random::secure_bytes(overlay_name.as_slice());
    auto overlay_pub = tos::PublicKey{tos::pubkeys::Overlay{overlay_name.clone()}};
    auto overlay_short_id = overlay_pub.compute_short_id();

    tos::dht::DhtKey dht_key{overlay_short_id, "test", 0};
    auto dht_update_rule = tos::dht::DhtUpdateRuleOverlayNodes::create().move_as_ok();
    tos::dht::DhtKeyDescription dht_key_description{std::move(dht_key), overlay_pub, std::move(dht_update_rule),
                                                    td::BufferSlice()};
    dht_key_description.check().ensure();

    auto ttl = static_cast<td::uint32>(td::Clocks::system() + 3600);
    tos::dht::DhtValue dht_value{dht_key_description.clone(), td::BufferSlice(""), ttl, td::BufferSlice()};
    dht_value.check().ensure_error();

    auto obj = tos::create_tl_object<tos::tos_api::overlay_nodes>();
    dht_value =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value.check().ensure();

    for (td::uint32 i = 0; i < 100; i++) {
      auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();

      auto date = static_cast<td::int32>(td::Clocks::system() - 10);
      //overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.node.ToSign;
      //overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node;
      auto to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
          tos::adnl::AdnlNodeIdShort{pub.compute_short_id()}.tl(), overlay_short_id.tl(), date);
      auto n = tos::create_tl_object<tos::tos_api::overlay_node>(
          pub.tl(), overlay_short_id.tl(), date,
          pk.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok());
      obj->nodes_.push_back(std::move(n));
      dht_value =
          tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
      auto size = tos::serialize_tl_object(obj, true).size();
      if (size <= tos::dht::DhtValue::max_value_size()) {
        dht_value.check().ensure();
      } else {
        dht_value.check().ensure_error();
      }
    }

    obj->nodes_.clear();
    auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub = pk.compute_public_key();

    auto date = static_cast<td::int32>(td::Clocks::system() - 10);
    //overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.node.ToSign;
    //overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node;
    auto to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
        tos::adnl::AdnlNodeIdShort{pub.compute_short_id()}.tl(), overlay_short_id.tl() ^ td::Bits256::ones(), date);
    auto n = tos::create_tl_object<tos::tos_api::overlay_node>(
        pub.tl(), overlay_short_id.tl() ^ td::Bits256::ones(), date,
        pk.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok());
    obj->nodes_.push_back(std::move(n));
    dht_value =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value.check().ensure_error();

    obj->nodes_.clear();
    to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
        tos::adnl::AdnlNodeIdShort{pub.compute_short_id()}.tl(), overlay_short_id.tl(), date);
    n = tos::create_tl_object<tos::tos_api::overlay_node>(
        pub.tl(), overlay_short_id.tl(), date,
        pk.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok());
    obj->nodes_.push_back(std::move(n));
    dht_value =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value.check().ensure();

    obj->nodes_.clear();
    //to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
    //    tos::adnl::AdnlNodeIdShort{pub.compute_short_id()}.tl(), key_short_id.tl(), date);
    n = tos::create_tl_object<tos::tos_api::overlay_node>(pub.tl(), overlay_short_id.tl(), date, td::BufferSlice{64});
    obj->nodes_.push_back(std::move(n));
    dht_value =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value.check().ensure_error();

    obj->nodes_.clear();
    to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
        tos::adnl::AdnlNodeIdShort{pub.compute_short_id()}.tl(), overlay_short_id.tl(), date);
    n = tos::create_tl_object<tos::tos_api::overlay_node>(
        pub.tl(), overlay_short_id.tl(), date,
        pk.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok());
    obj->nodes_.push_back(std::move(n));
    dht_value =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value.check().ensure();

    auto dht_value2 =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value2.check().ensure();
    dht_value.update(std::move(dht_value2)).ensure();
    CHECK(tos::fetch_tl_object<tos::tos_api::overlay_nodes>(dht_value.value().as_slice(), true)
              .move_as_ok()
              ->nodes_.size() == 1);

    obj->nodes_.clear();
    {
      td::BufferSlice x{32};
      td::Random::secure_bytes(x.as_slice());
      auto pk2 = tos::PrivateKey{tos::privkeys::Ed25519{x.clone()}};
      auto to_sign = tos::create_serialize_tl_object<tos::tos_api::overlay_node_toSign>(
          tos::adnl::AdnlNodeIdShort{pk2.compute_short_id()}.tl(), overlay_short_id.tl(), date);
      n = tos::create_tl_object<tos::tos_api::overlay_node>(
          pk2.compute_public_key().tl(), overlay_short_id.tl(), date,
          pk2.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok());
      obj->nodes_.push_back(std::move(n));
    }
    dht_value2 =
        tos::dht::DhtValue{dht_key_description.clone(), tos::serialize_tl_object(obj, true), ttl, td::BufferSlice()};
    dht_value2.check().ensure();
    dht_value.update(std::move(dht_value2)).ensure();
    CHECK(tos::fetch_tl_object<tos::tos_api::overlay_nodes>(dht_value.value().as_slice(), true)
              .move_as_ok()
              ->nodes_.size() == 2);
  }
  LOG(ERROR) << "success";

  LOG(ERROR) << "empty run";
  auto t = td::Timestamp::in(10.0);
  while (scheduler.run(1)) {
    if (t.is_in_past()) {
      break;
    }
  }

  LOG(ERROR) << "success";

  for (td::uint32 x = 0; x < 100; x++) {
    tos::dht::DhtKey dht_key{key_short_id, PSTRING() << "test-" << x, x % 8};
    auto dht_update_rule = tos::dht::DhtUpdateRuleSignature::create().move_as_ok();
    tos::dht::DhtKeyDescription dht_key_description{std::move(dht_key), key_pub, std::move(dht_update_rule),
                                                    td::BufferSlice()};
    dht_key_description.update_signature(key_dec->sign(dht_key_description.to_sign()).move_as_ok());

    auto ttl = static_cast<td::uint32>(td::Clocks::system() + 3600);
    td::uint8 v[1];
    v[0] = static_cast<td::uint8>(x);
    tos::dht::DhtValue dht_value{std::move(dht_key_description), td::BufferSlice(td::Slice(v, 1)), ttl,
                                 td::BufferSlice("")};
    dht_value.update_signature(key_dec->sign(dht_value.to_sign()).move_as_ok());

    remaining++;
    auto P = td::PromiseCreator::lambda([&](td::Result<> R) {
      R.ensure();
      remaining--;
    });

    scheduler.run_in_context([&] {
      td::actor::send_closure(dht[td::Random::fast(0, total_nodes - 1)], &tos::dht::Dht::set_value,
                              std::move(dht_value), std::move(P));
    });
  }

  LOG(ERROR) << "stores";
  t = td::Timestamp::in(60.0);
  while (scheduler.run(1)) {
    if (!remaining) {
      break;
    }
    if (t.is_in_past()) {
      LOG(FATAL) << "failed: remaining = " << remaining;
    }
  }
  LOG(ERROR) << "success";

  for (td::uint32 x = 0; x < 100; x++) {
    tos::dht::DhtKey dht_key{key_short_id, PSTRING() << "test-" << x, x % 8};

    remaining++;
    auto P = td::PromiseCreator::lambda([&, idx = x](td::Result<tos::dht::DhtValue> R) {
      R.ensure();
      auto v = R.move_as_ok();
      CHECK(v.key().key().public_key_hash() == key_short_id);
      CHECK(v.key().key().name() == (PSTRING() << "test-" << idx));
      CHECK(v.key().key().idx() == idx % 8);
      td::uint8 buf[1];
      buf[0] = static_cast<td::uint8>(idx);
      CHECK(v.value().as_slice() == td::Slice(buf, 1));
      remaining--;
    });

    scheduler.run_in_context([&] {
      td::actor::send_closure(dht[td::Random::fast(0, total_nodes - 1)], &tos::dht::Dht::get_value, dht_key,
                              std::move(P));
    });
  }

  LOG(ERROR) << "gets";
  t = td::Timestamp::in(60.0);
  while (scheduler.run(1)) {
    if (!remaining) {
      break;
    }
    if (t.is_in_past()) {
      LOG(FATAL) << "failed: remaining = " << remaining;
    }
  }
  LOG(ERROR) << "success";

  td::rmrf(db_root_).ensure();
  std::_Exit(0);
  return 0;
}
