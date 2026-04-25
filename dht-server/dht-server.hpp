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
#pragma once

#include <map>
#include <set>

#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "auto/tl/tos_api_json.h"
#include "dht/dht.h"
#include "td/actor/MultiPromise.h"
#include "tos/tos-types.h"

enum DhtServerPermissions : td::uint32 { vep_default = 1, vep_modify = 2, vep_unsafe = 4 };

using AdnlCategory = td::int8;

struct Config {
  struct Addr {
    td::IPAddress addr;

    bool operator<(const Addr &with) const {
      return addr < with.addr;
    }
  };
  struct AddrCats {
    td::IPAddress in_addr;
    std::shared_ptr<tos::adnl::AdnlProxy> proxy;
    std::set<AdnlCategory> cats;
    std::set<AdnlCategory> priority_cats;
  };
  struct Control {
    tos::PublicKeyHash key;
    std::map<tos::PublicKeyHash, td::uint32> clients;
  };

  std::map<tos::PublicKeyHash, td::uint32> keys_refcnt;
  td::uint16 out_port;
  std::map<Addr, AddrCats> addrs;
  std::map<tos::PublicKeyHash, AdnlCategory> adnl_ids;
  std::set<tos::PublicKeyHash> dht_ids;
  std::map<td::int32, Control> controls;
  std::set<tos::PublicKeyHash> gc;

  void decref(tos::PublicKeyHash key);
  void incref(tos::PublicKeyHash key) {
    keys_refcnt[key]++;
  }

  td::Result<bool> config_add_network_addr(td::IPAddress in_addr, td::IPAddress out_addr,
                                           std::shared_ptr<tos::adnl::AdnlProxy> proxy, std::vector<AdnlCategory> cats,
                                           std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_add_adnl_addr(tos::PublicKeyHash addr, AdnlCategory cat);
  td::Result<bool> config_add_dht_node(tos::PublicKeyHash id);
  td::Result<bool> config_add_control_interface(tos::PublicKeyHash key, td::int32 port);
  td::Result<bool> config_add_control_process(tos::PublicKeyHash key, td::int32 port, tos::PublicKeyHash id,
                                              td::uint32 permissions);
  td::Result<bool> config_add_gc(tos::PublicKeyHash key);
  td::Result<bool> config_del_network_addr(td::IPAddress addr, std::vector<AdnlCategory> cats,
                                           std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_del_adnl_addr(tos::PublicKeyHash addr);
  td::Result<bool> config_del_dht_node(tos::PublicKeyHash id);
  td::Result<bool> config_del_control_interface(td::int32 port);
  td::Result<bool> config_del_control_process(td::int32 port, tos::PublicKeyHash id);
  td::Result<bool> config_del_gc(tos::PublicKeyHash key);

  tos::tl_object_ptr<tos::tos_api::engine_validator_config> tl() const;

  Config();
  Config(const tos::tos_api::engine_validator_config &config);
};

class DhtServer : public td::actor::Actor {
 private:
  td::actor::ActorOwn<tos::keyring::Keyring> keyring_;
  td::actor::ActorOwn<tos::adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl_;
  std::map<tos::PublicKeyHash, td::actor::ActorOwn<tos::dht::Dht>> dht_nodes_;
  tos::PublicKeyHash default_dht_node_ = tos::PublicKeyHash::zero();
  td::actor::ActorOwn<tos::adnl::AdnlExtServer> control_ext_server_;

  std::string local_config_ = "";
  std::string global_config_ = "tos-global.config";
  std::string config_file_;
  std::string temp_config_file() const {
    return config_file_ + ".tmp";
  }

  std::string db_root_ = "/var/tos-work/db/";

  std::vector<td::IPAddress> addrs_;
  std::vector<td::IPAddress> proxy_addrs_;

  std::shared_ptr<tos::dht::DhtGlobalConfig> dht_config_;
  Config config_;

  std::set<tos::PublicKeyHash> running_gc_;

  std::map<tos::PublicKeyHash, tos::PublicKey> keys_;

  td::Promise<tos::PublicKey> get_key_promise(td::MultiPromise::InitGuard &ig);
  void got_key(tos::PublicKey key);
  void deleted_key(tos::PublicKeyHash key);

  void write_config(td::Promise<td::Unit> promise);

  std::map<td::uint32, tos::adnl::AdnlAddressList> addr_lists_;
  std::map<td::uint32, tos::adnl::AdnlAddressList> prio_addr_lists_;

  std::map<tos::PublicKeyHash, td::uint32> control_permissions_;

  bool read_config_ = false;
  bool started_keyring_ = false;
  bool started_ = false;

 public:
  static constexpr td::uint32 max_cat() {
    return 256;
  }

  void set_local_config(std::string str);
  void set_global_config(std::string str);
  void set_db_root(std::string db_root);
  void add_ip(td::IPAddress addr) {
    addrs_.push_back(addr);
  }
  void start_up() override;
  DhtServer() {
  }

  // load config
  td::Status load_global_config();
  void load_empty_local_config(td::Promise<td::Unit> promise);
  void load_local_config(td::Promise<td::Unit> promise);
  void load_config(td::Promise<td::Unit> promise);

  void start();

  void start_adnl();
  void add_addr(const Config::Addr &addr, const Config::AddrCats &cats);
  void add_adnl(tos::PublicKeyHash id, AdnlCategory cat);
  void started_adnl();

  void start_dht();
  void add_dht(td::actor::ActorOwn<tos::dht::Dht> dht, td::Promise<td::Unit> promise);
  void started_dht();

  void start_control_interface();
  void started_control_interface(td::actor::ActorOwn<tos::adnl::AdnlExtServer> control_ext_server);

  void started();

  void alarm() override;
  void run();

  void add_adnl_node(tos::PublicKey pub, AdnlCategory cat, td::Promise<td::Unit> promise);
  void add_dht_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void add_control_interface(tos::PublicKeyHash id, td::int32 port, td::Promise<td::Unit> promise);
  void add_control_process(tos::PublicKeyHash id, td::int32 port, tos::PublicKeyHash pub, td::int32 permissions,
                           td::Promise<td::Unit> promise);
  void del_adnl_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void del_dht_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);

  static td::BufferSlice create_control_query_error(td::Status error);

  void run_control_query(tos::tos_api::engine_validator_getTime &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_importPrivateKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_exportPrivateKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_exportPublicKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_generateKeyPair &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addAdnlId &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addDhtId &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getConfig &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_sign &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  template <class T>
  void run_control_query(T &query, td::BufferSlice data, tos::PublicKeyHash src, td::uint32 perm,
                         td::Promise<td::BufferSlice> promise) {
    promise.set_value(
        create_control_query_error(td::Status::Error(tos::ErrorCode::protoviolation, "query not supported")));
  }
  void process_control_query(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                             td::Promise<td::BufferSlice> promise);
};
