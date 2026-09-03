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

#include <set>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-node-id.hpp"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "auto/tl/tos_api_json.h"
#include "dht/dht.h"
#include "metrics/prometheus-exporter.h"
#include "tos/tos-types.h"
#include "json-rpc-server.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/actor/MultiPromise.h"
#include "td/actor/PromiseFuture.h"
#include "validator/full-node-master.h"
#include "validator/full-node.h"
#include "validator/manager.h"
#include "validator/validator.h"

#include "overlays.h"

enum ValidatorEnginePermissions : td::uint32 { vep_default = 1, vep_modify = 2, vep_unsafe = 4 };

using AdnlCategory = td::uint8;

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
  struct Validator {
    std::map<tos::PublicKeyHash, tos::UnixTime> temp_keys;
    std::map<tos::PublicKeyHash, tos::UnixTime> adnl_ids;
    tos::UnixTime election_date;
    tos::UnixTime expire_at;
  };
  struct Control {
    tos::PublicKeyHash key;
    std::map<tos::PublicKeyHash, td::uint32> clients;
  };
  struct FullNodeSlave {
    tos::PublicKey key;
    td::IPAddress addr;
  };
  struct FastSyncOverlayClient {
    FastSyncOverlayClient() = default;
    FastSyncOverlayClient(tos::adnl::AdnlNodeIdShort id, td::int32 slot) : id(id), slot(slot) {
    }
    tos::adnl::AdnlNodeIdShort id;
    td::int32 slot;
  };

  std::map<tos::PublicKeyHash, td::uint32> keys_refcnt;
  td::uint16 out_port;
  std::map<Addr, AddrCats> addrs;
  std::map<Addr, AddrCats> quic_addrs;
  std::map<tos::PublicKeyHash, AdnlCategory> adnl_ids;
  std::set<tos::PublicKeyHash> dht_ids;
  std::map<tos::PublicKeyHash, Validator> validators;
  std::map<tos::adnl::AdnlNodeIdShort, std::vector<tos::ShardIdFull>> collators;
  bool collator_node_whiltelist_enabled = false;
  std::set<tos::adnl::AdnlNodeIdShort> collator_node_whitelist;
  tos::PublicKeyHash full_node = tos::PublicKeyHash::zero();
  std::vector<FullNodeSlave> full_node_slaves;
  std::map<td::int32, tos::PublicKeyHash> full_node_masters;
  std::map<td::int32, tos::PublicKeyHash> liteservers;
  tos::validator::fullnode::FullNodeConfig full_node_config;
  std::map<td::int32, Control> controls;
  std::set<tos::PublicKeyHash> gc;
  std::vector<tos::ShardIdFull> shards_to_monitor;
  std::vector<FastSyncOverlayClient> fast_sync_overlay_clients;

  bool state_serializer_enabled = true;
  std::vector<std::pair<tos::adnl::AdnlNodeIdShort, tos::overlay::OverlayMemberCertificate>>
      fast_sync_member_certificates;

  void decref(tos::PublicKeyHash key);
  void incref(tos::PublicKeyHash key) {
    keys_refcnt[key]++;
  }

  td::Result<bool> config_add_network_addr(td::IPAddress in_addr, td::IPAddress out_addr,
                                           std::shared_ptr<tos::adnl::AdnlProxy> proxy, std::vector<AdnlCategory> cats,
                                           std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_add_quic_addr(td::IPAddress ip, std::vector<AdnlCategory> cats,
                                        std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_add_adnl_addr(tos::PublicKeyHash addr, AdnlCategory cat);
  td::Result<bool> config_add_dht_node(tos::PublicKeyHash id);
  td::Result<bool> config_add_validator_permanent_key(tos::PublicKeyHash id, tos::UnixTime election_date,
                                                      tos::UnixTime expire_at);
  td::Result<bool> config_add_validator_temp_key(tos::PublicKeyHash perm_key, tos::PublicKeyHash id,
                                                 tos::UnixTime expire_at);
  td::Result<bool> config_add_validator_adnl_id(tos::PublicKeyHash perm_key, tos::PublicKeyHash adnl_id,
                                                tos::UnixTime expire_at);
  td::Result<bool> config_add_collator(tos::adnl::AdnlNodeIdShort addr, tos::ShardIdFull shard);
  td::Result<bool> config_del_collator(tos::adnl::AdnlNodeIdShort addr, tos::ShardIdFull shard);
  td::Result<bool> config_add_full_node_adnl_id(tos::PublicKeyHash id);
  td::Result<bool> config_add_full_node_slave(td::IPAddress addr, tos::PublicKey id);
  td::Result<bool> config_add_full_node_master(td::int32 port, tos::PublicKeyHash id);
  td::Result<bool> config_add_lite_server(tos::PublicKeyHash key, td::int32 port);
  td::Result<bool> config_add_control_interface(tos::PublicKeyHash key, td::int32 port);
  td::Result<bool> config_add_control_process(tos::PublicKeyHash key, td::int32 port, tos::PublicKeyHash id,
                                              td::uint32 permissions);
  td::Result<bool> config_add_shard(tos::ShardIdFull shard);
  td::Result<bool> config_del_shard(tos::ShardIdFull shard);
  td::Result<bool> config_add_gc(tos::PublicKeyHash key);
  td::Result<bool> config_del_network_addr(td::IPAddress addr, std::vector<AdnlCategory> cats,
                                           std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_del_quic_addr(td::IPAddress ip, std::vector<AdnlCategory> cats,
                                        std::vector<AdnlCategory> prio_cats);
  td::Result<bool> config_del_adnl_addr(tos::PublicKeyHash addr);
  td::Result<bool> config_del_dht_node(tos::PublicKeyHash id);
  td::Result<bool> config_del_validator_permanent_key(tos::PublicKeyHash id);
  td::Result<bool> config_del_validator_temp_key(tos::PublicKeyHash perm_id, tos::PublicKeyHash id);
  td::Result<bool> config_del_validator_adnl_id(tos::PublicKeyHash perm_id, tos::PublicKeyHash adnl_id);
  td::Result<bool> config_del_full_node_adnl_id();
  td::Result<bool> config_del_lite_server(td::int32 port);
  td::Result<bool> config_del_control_interface(td::int32 port);
  td::Result<bool> config_del_control_process(td::int32 port, tos::PublicKeyHash id);
  td::Result<bool> config_del_gc(tos::PublicKeyHash key);

  tos::tl_object_ptr<tos::tos_api::engine_validator_config> tl() const;

  Config();
  Config(const tos::tos_api::engine_validator_config &config);
};

class ValidatorEngine : public td::actor::Actor {
 private:
  td::actor::ActorOwn<tos::keyring::Keyring> keyring_;
  td::actor::ActorOwn<tos::adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl_;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp2_;
  td::actor::ActorOwn<tos::quic::QuicSender> quic_;
  std::map<tos::PublicKeyHash, td::actor::ActorOwn<tos::dht::Dht>> dht_nodes_;
  tos::PublicKeyHash default_dht_node_ = tos::PublicKeyHash::zero();
  td::actor::ActorOwn<tos::overlay::Overlays> overlay_manager_;
  td::actor::ActorOwn<tos::validator::ValidatorManagerInterface> validator_manager_;
  td::actor::ActorOwn<tos::adnl::AdnlExtClient> full_node_client_;
  td::actor::ActorOwn<tos::validator::fullnode::FullNode> full_node_;
  tos::adnl::AdnlNodeIdShort full_node_id_ = tos::adnl::AdnlNodeIdShort::zero();
  std::map<td::uint16, td::actor::ActorOwn<tos::validator::fullnode::FullNodeMaster>> full_node_masters_;
  td::actor::ActorOwn<tos::adnl::AdnlExtServer> control_ext_server_;
  td::actor::ActorOwn<tos::PrometheusExporter> exporter_;
  td::actor::ActorOwn<tos::JsonRpcServer> json_rpc_server_;
  td::optional<td::IPAddress> json_rpc_addr_;
  tos::JsonRpcServer::Options json_rpc_opts_;
  std::string local_config_ = "";
  std::string global_config_ = "tos-global.config";
  std::string config_file_;
  std::string temp_config_file() const {
    return config_file_ + ".tmp";
  }

  std::string fift_dir_ = "";

  std::string db_root_ = "/var/tos-work/db/";

  std::vector<td::IPAddress> addrs_;
  std::vector<td::IPAddress> proxy_addrs_;

  tos::adnl::AdnlNodesList adnl_static_nodes_;
  std::shared_ptr<tos::dht::DhtGlobalConfig> dht_config_;
  td::Ref<tos::validator::ValidatorManagerOptions> validator_options_;
  Config config_;
  tos::tl_object_ptr<tos::tos_api::engine_validator_customOverlaysConfig> custom_overlays_config_;
  tos::tl_object_ptr<tos::tos_api::engine_validator_collatorsList> collators_list_;
  tos::tl_object_ptr<tos::tos_api::engine_validator_shardBlockVerifierConfig> shard_block_verifier_config_;
  tos::tl_object_ptr<tos::tos_api::consensus_noncriticalParamsOverrideList> noncritical_params_overrides_;

  std::set<tos::PublicKeyHash> running_gc_;

  std::map<tos::PublicKeyHash, tos::PublicKey> keys_;

  td::Ref<tos::validator::MasterchainState> state_;
  td::Ref<block::ValidatorSet> validator_set_, validator_set_prev_, validator_set_next_;
  td::Timestamp issue_fast_sync_overlay_certificates_at_ = td::Timestamp::now();
  td::Timestamp issue_shard_overlay_certificates_at_ = td::Timestamp::now();
  bool fast_sync_member_certificates_write_scheduled_ = false;
  td::Timestamp fast_sync_member_certificates_write_at_ = td::Timestamp::never();
  std::set<tos::adnl::AdnlNodeIdShort> auto_sign_adnls_;
  bool accept_shard_overlay_certificates_from_any_validator_ = false;
  std::set<tos::adnl::AdnlNodeIdShort> accept_shard_overlay_certificates_from_;

  td::Promise<tos::PublicKey> get_key_promise(td::MultiPromise::InitGuard &ig);
  void got_key(tos::PublicKey key);
  void deleted_key(tos::PublicKeyHash key);
  void got_state(td::Ref<tos::validator::MasterchainState> state);

  void write_config(td::Promise<td::Unit> promise);
  void schedule_fast_sync_member_certificates_write();
  void finish_fast_sync_member_certificate_import(td::Promise<td::Unit> promise, bool defer_write);

  std::map<td::uint32, tos::adnl::AdnlAddressList> addr_lists_;
  std::map<td::uint32, tos::adnl::AdnlAddressList> prio_addr_lists_;

  struct CI_key {
    tos::PublicKeyHash id;
    td::uint16 port;
    tos::PublicKeyHash pub;
    bool operator<(const CI_key &with) const {
      return id < with.id || (id == with.id && port < with.port) ||
             (id == with.id && port == with.port && pub < with.pub);
    }
  };
  std::map<CI_key, td::uint32> control_permissions_;

  double state_ttl_ = 0;
  size_t max_mempool_num_ = 0;
  double block_ttl_ = 0;
  double sync_ttl_ = 0;
  double archive_ttl_ = 0;
  double key_proof_ttl_ = 0;
  td::uint32 celldb_compress_depth_ = 0;
  size_t max_open_archive_files_ =
      tos::validator::ValidatorManagerOptions::default_max_open_archive_files();
  double archive_preload_period_ = 0.0;
  bool disable_rocksdb_stats_ = false;
  bool nonfinal_ls_queries_enabled_ = false;
  td::optional<td::uint64> celldb_cache_size_ = 1LL << 30;
  td::optional<td::uint64> celldb_cache_min_size_;
  td::uint64 celldb_cell_cache_max_size_{1000000};
  bool celldb_direct_io_ = false;
  bool celldb_preload_all_ = false;
  bool celldb_in_memory_ = false;
  bool celldb_disable_bloom_filter_ = false;
  bool unsynced_liteserver_ = false;
  td::optional<double> catchain_max_block_delay_, catchain_max_block_delay_slow_;
  bool read_config_ = false;
  bool started_keyring_ = false;
  bool started_ = false;
  bool dht_server_ = false;
  tos::BlockSeqno truncate_seqno_{0};
  std::string session_logs_file_;
  std::string validator_telemetry_filename_;
  bool not_all_shards_ = false;
  std::vector<tos::ShardIdFull> add_shard_cmds_;
  bool state_serializer_disabled_flag_ = false;
  double broadcast_speed_multiplier_catchain_ = 3.33;
  bool permanent_celldb_ = false;
  bool skip_key_sync_ = false;
  td::optional<tos::BlockSeqno> sync_shards_upto_;
  tos::adnl::AdnlNodeIdShort shard_block_retainer_adnl_id_ = tos::adnl::AdnlNodeIdShort::zero();
  bool shard_block_retainer_adnl_id_fullnode_ = false;
  bool parallel_validation_ = false;
  std::string db_event_fifo_path_;
  tos::validator::fullnode::FullNodeOptions full_node_options_ = {.config_ = {},
                                                                  .public_broadcast_speed_multiplier_ = 3.33,
                                                                  .private_broadcast_speed_multiplier_ = 3.33,
                                                                  .fast_sync_broadcast_speed_multiplier_ = 3.33,
                                                                  .initial_sync_delay_ = 60.0};

  std::set<tos::CatchainSeqno> unsafe_catchains_;
  std::map<tos::BlockSeqno, std::pair<tos::CatchainSeqno, td::uint32>> unsafe_catchain_rotations_;
  tos::quic::QuicServer::Options quic_options_ = {};

 public:
  static constexpr td::uint8 max_cat() {
    return 250;
  }

  void add_unsafe_catchain(tos::CatchainSeqno seq) {
    unsafe_catchains_.insert(seq);
  }
  void add_unsafe_catchain_rotation(tos::BlockSeqno b_seqno, tos::CatchainSeqno cc_seqno, td::uint32 value) {
    unsafe_catchain_rotations_.insert({b_seqno, {cc_seqno, value}});
  }
  void set_local_config(std::string str);
  void set_global_config(std::string str);
  void set_fift_dir(std::string str) {
    fift_dir_ = str;
  }
  void set_db_root(std::string db_root);
  void set_dht_server(bool value) {
    dht_server_ = value;
  }
  void set_state_ttl(double t) {
    state_ttl_ = t;
  }
  void set_max_mempool_num(size_t t) {
    max_mempool_num_ = t;
  }
  void set_block_ttl(double t) {
    block_ttl_ = t;
  }
  void set_sync_ttl(double t) {
    sync_ttl_ = t;
  }
  void set_archive_ttl(double t) {
    archive_ttl_ = t;
  }
  void set_key_proof_ttl(double t) {
    key_proof_ttl_ = t;
  }
  void set_truncate_seqno(tos::BlockSeqno seqno) {
    truncate_seqno_ = seqno;
  }
  void set_session_logs_file(std::string f) {
    session_logs_file_ = std::move(f);
  }
  void add_ip(td::IPAddress addr) {
    addrs_.push_back(addr);
  }
  void add_key_to_set(tos::PublicKey key) {
    keys_[key.compute_short_id()] = key;
  }
  void schedule_shutdown(double at);
  void set_celldb_compress_depth(td::uint32 value) {
    celldb_compress_depth_ = value;
  }
  void set_max_open_archive_files(size_t value) {
    max_open_archive_files_ = value;
  }
  void set_archive_preload_period(double value) {
    archive_preload_period_ = value;
  }
  void set_disable_rocksdb_stats(bool value) {
    disable_rocksdb_stats_ = value;
  }
  void set_nonfinal_ls_queries_enabled() {
    nonfinal_ls_queries_enabled_ = true;
  }
  void set_celldb_cache_size(td::uint64 value) {
    celldb_cache_size_ = value;
  }
  void set_celldb_cache_min_size(td::uint64 value) {
    celldb_cache_min_size_ = value;
  }
  void set_celldb_cell_cache_max_size(td::uint64 value) {
    celldb_cell_cache_max_size_ = value;
  }
  void set_celldb_direct_io(bool value) {
    celldb_direct_io_ = value;
  }
  void set_celldb_preload_all(bool value) {
    celldb_preload_all_ = value;
  }
  void set_celldb_in_memory(bool value) {
    celldb_in_memory_ = value;
  }
  void set_celldb_disable_bloom_filter(bool value) {
    celldb_disable_bloom_filter_ = value;
  }
  void set_unsynced_liteserver(bool value) {
    unsynced_liteserver_ = value;
  }
  void set_catchain_max_block_delay(double value) {
    catchain_max_block_delay_ = value;
  }
  void set_catchain_max_block_delay_slow(double value) {
    catchain_max_block_delay_slow_ = value;
  }
  void set_validator_telemetry_filename(std::string value) {
    validator_telemetry_filename_ = std::move(value);
  }
  void set_not_all_shards() {
    not_all_shards_ = true;
  }
  void add_shard_cmd(tos::ShardIdFull shard) {
    add_shard_cmds_.push_back(shard);
  }
  void set_state_serializer_disabled_flag() {
    state_serializer_disabled_flag_ = true;
  }
  void set_broadcast_speed_multiplier_catchain(double value) {
    broadcast_speed_multiplier_catchain_ = value;
  }
  void set_broadcast_speed_multiplier_public(double value) {
    full_node_options_.public_broadcast_speed_multiplier_ = value;
  }
  void set_broadcast_speed_multiplier_private(double value) {
    full_node_options_.private_broadcast_speed_multiplier_ = value;
  }
  void set_broadcast_speed_multiplier_fast_sync(double value) {
    full_node_options_.fast_sync_broadcast_speed_multiplier_ = value;
  }
  void set_permanent_celldb(bool value) {
    permanent_celldb_ = value;
  }
  void set_skip_key_sync(bool value) {
    skip_key_sync_ = value;
  }
  void set_sync_shards_upto(tos::BlockSeqno seqno) {
    sync_shards_upto_ = seqno;
  }
  void set_shard_block_retainer_adnl_id(tos::adnl::AdnlNodeIdShort id) {
    shard_block_retainer_adnl_id_ = id;
  }
  void set_shard_block_retainer_adnl_id_fullnode() {
    shard_block_retainer_adnl_id_fullnode_ = true;
  }
  void set_parallel_validation(bool value) {
    parallel_validation_ = value;
  }
  void set_db_event_fifo_path(std::string value) {
    db_event_fifo_path_ = std::move(value);
  }
  void set_initial_sync_delay(double value) {
    full_node_options_.initial_sync_delay_ = value;
  }
  void set_ratelimit_window_size(double seconds) {
    full_node_options_.ratelimit_window_size_ = seconds;
  }
  void set_ratelimit_global(size_t count) {
    full_node_options_.ratelimit_global_ = count;
  }
  void set_ratelimit_heavy(size_t count) {
    full_node_options_.ratelimit_heavy_ = count;
  }
  void set_ratelimit_medium(size_t count) {
    full_node_options_.ratelimit_medium_ = count;
  }
  void add_auto_sign_adnl(tos::adnl::AdnlNodeIdShort id) {
    LOG(INFO) << "configured auto-sign shard overlay certificates for adnl=" << id;
    auto_sign_adnls_.insert(id);
  }
  void accept_shard_overlay_certificates_from_any_validator() {
    LOG(INFO) << "configured accepting shard overlay certificates from any validator";
    accept_shard_overlay_certificates_from_any_validator_ = true;
  }
  void accept_shard_overlay_certificates_from(tos::adnl::AdnlNodeIdShort id) {
    LOG(INFO) << "configured accepting shard overlay certificates from adnl=" << id;
    accept_shard_overlay_certificates_from_.insert(id);
  }
  void set_quic_options(tos::quic::QuicServer::Options options) {
    quic_options_ = std::move(options);
  }

  void start_up() override;
  ValidatorEngine() = default;

  // load config
  td::Status load_global_config();
  void load_empty_local_config(td::Promise<td::Unit> promise);
  void load_local_config(td::Promise<td::Unit> promise);
  void load_config(td::Promise<td::Unit> promise);
  void set_shard_check_function();
  void load_collators_list();
  void load_shard_block_verifier_config();
  void load_noncritical_params_overrides();

  void start();

  void start_adnl();
  void add_addr(const Config::Addr &addr, const Config::AddrCats &cats);
  void add_quic_addr(const Config::Addr &addr, const Config::AddrCats &cats);
  void add_adnl(tos::PublicKeyHash id, AdnlCategory cat);
  void started_adnl();

  void start_dht();
  void add_dht(tos::PublicKeyHash id);
  void started_dht();

  void start_rldp();
  void started_rldp();

  void start_overlays();
  void started_overlays();

  void start_validator();
  void started_validator();
  // Crash-recovery: re-index any wc=0 block left flagged incomplete by the
  // wc0 wallet-index writer (see wallet-index.h's 0x1E marker). Fired once,
  // right after validator_manager_ exists; a pure local-db lookup, safe to
  // queue immediately (no network-sync dependency). Processes wc0_recovery_markers_
  // one at a time via recover_wc0_index_step() re-sending itself a message
  // through the actor scheduler (not a self-capturing closure) — avoids both
  // a reference cycle and unbounded concurrent lookups.
  void recover_wc0_index();
  void recover_wc0_index_step();
  std::vector<tos::BlockIdExt> wc0_recovery_markers_;
  size_t wc0_recovery_index_ = 0;

  void start_full_node();
  void started_full_node();

  void add_lite_server(tos::PublicKeyHash id, td::uint16 port);
  void start_lite_server();
  void started_lite_server();
  void start_collator();
  void started_collator();

  void add_control_interface(tos::PublicKeyHash id, td::uint16 port);
  void add_control_process(tos::PublicKeyHash id, td::uint16 port, tos::PublicKeyHash pub, td::int32 permissions);
  void start_control_interface();
  void started_control_interface(td::actor::ActorOwn<tos::adnl::AdnlExtServer> control_ext_server);

  void start_full_node_masters();
  void started_full_node_masters();

  void started();

  void alarm() override;
  void run();

  void export_metrics(td::IPAddress address);
  void serve_json_rpc(td::IPAddress address);
  void set_json_rpc_readonly(bool readonly);
  void set_json_rpc_cors_origin(std::string origin);
  void set_json_rpc_readyz_threshold(td::int32 threshold);
  void set_json_rpc_request_timeout(double seconds);
  void set_json_rpc_api_key(std::string key);
  void set_json_rpc_cache_ttl(td::int32 seconds);
  // M-01 hardening: opt-in honour of X-Forwarded-For / X-Real-IP
  // headers (only when the real TCP peer is loopback or explicitly
  // trusted via `add_json_rpc_trusted_proxy`). Default off — direct
  // public listeners attribute strictly off the real peer IP.
  void set_json_rpc_trust_proxy_headers(bool trust);
  void add_json_rpc_trusted_proxy(std::string ip);

  void get_current_validator_perm_key(td::Promise<std::pair<tos::PublicKey, size_t>> promise);

  void try_add_adnl_node(tos::PublicKeyHash pub, AdnlCategory cat, td::Promise<td::Unit> promise);
  void try_add_dht_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void try_add_validator_permanent_key(tos::PublicKeyHash key_hash, td::uint32 election_date, td::uint32 ttl,
                                       td::Promise<td::Unit> promise);
  void try_add_validator_temp_key(tos::PublicKeyHash perm_key, tos::PublicKeyHash temp_key, td::uint32 ttl,
                                  td::Promise<td::Unit> promise);
  void try_add_validator_adnl_addr(tos::PublicKeyHash perm_key, tos::PublicKeyHash adnl_id, td::uint32 ttl,
                                   td::Promise<td::Unit> promise);
  void try_add_full_node_adnl_addr(tos::PublicKeyHash id, td::Promise<td::Unit> promise);
  void try_add_liteserver(tos::PublicKeyHash id, td::int32 port, td::Promise<td::Unit> promise);
  void try_add_control_interface(tos::PublicKeyHash id, td::int32 port, td::Promise<td::Unit> promise);
  void try_add_control_process(tos::PublicKeyHash id, td::int32 port, tos::PublicKeyHash pub, td::int32 permissions,
                               td::Promise<td::Unit> promise);
  void try_del_adnl_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void try_del_dht_node(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void try_del_validator_permanent_key(tos::PublicKeyHash pub, td::Promise<td::Unit> promise);
  void try_del_validator_temp_key(tos::PublicKeyHash perm, tos::PublicKeyHash temp_key, td::Promise<td::Unit> promise);
  void try_del_validator_adnl_addr(tos::PublicKeyHash perm, tos::PublicKeyHash adnl_id, td::Promise<td::Unit> promise);

  void reload_adnl_addrs();
  void try_add_listening_port(td::uint32 ip, td::int32 port, std::vector<AdnlCategory> cats,
                              std::vector<AdnlCategory> prio_cats, td::Promise<td::Unit> promise);
  void try_del_listening_port(td::uint32 ip, td::int32 port, std::vector<AdnlCategory> cats,
                              std::vector<AdnlCategory> prio_cats, td::Promise<td::Unit> promise);
  void try_add_proxy(td::uint32 in_ip, td::int32 in_port, td::uint32 out_ip, td::int32 out_port,
                     std::shared_ptr<tos::adnl::AdnlProxy> proxy, std::vector<AdnlCategory> cats,
                     std::vector<AdnlCategory> prio_cats, td::Promise<td::Unit> promise);
  void try_del_proxy(td::uint32 ip, td::int32 port, std::vector<AdnlCategory> cats, std::vector<AdnlCategory> prio_cats,
                     td::Promise<td::Unit> promise);
  void try_add_quic_addr(td::uint32 ip, td::int32 port, std::vector<AdnlCategory> cats,
                         std::vector<AdnlCategory> prio_cats, td::Promise<td::Unit> promise);
  void try_del_quic_addr(td::uint32 ip, td::int32 port, std::vector<AdnlCategory> cats,
                         std::vector<AdnlCategory> prio_cats, td::Promise<td::Unit> promise);

  void register_fast_sync_certificate_callback();
  void register_shard_overlay_certificate_callback();
  void try_import_fast_sync_member_certificate(tos::adnl::AdnlNodeIdShort id,
                                               tos::overlay::OverlayMemberCertificate certificate,
                                               td::Promise<td::Unit> promise, bool defer_write);
  void try_import_shard_overlay_certificate(tos::adnl::AdnlNodeIdShort src, tos::ShardIdFull shard,
                                            tos::PublicKeyHash signed_key, td::int32 expire_at,
                                            std::shared_ptr<tos::overlay::Certificate> certificate,
                                            td::Promise<td::Unit> promise);

  void issue_fast_sync_overlay_certificates();
  void issue_fast_sync_overlay_certificate(tos::PublicKeyHash issue_by, tos::adnl::AdnlNodeIdShort issue_to,
                                           td::uint32 flags, td::int32 slot, td::int32 expire_at,
                                           td::Promise<tos::overlay::OverlayMemberCertificate> promise);
  void issue_shard_overlay_certificates();
  std::vector<tos::ShardIdFull> get_shards_for_overlay_certificates();
  tos::PublicKeyHash find_local_validator_for_cert_issuing();

  std::string custom_overlays_config_file() const {
    return db_root_ + "/custom-overlays.json";
  }
  std::string collator_options_file() const {
    return db_root_ + "/collator-options.json";
  }
  std::string collators_list_file() const {
    return db_root_ + "/collators-list.json";
  }
  std::string shard_block_verifier_config_file() const {
    return db_root_ + "/shard-block-verifier-config.json";
  }
  std::string noncritical_params_overrides_file() const {
    return db_root_ + "/noncritical-params-overrides.json";
  }

  void load_custom_overlays_config();
  td::Status write_custom_overlays_config();
  void add_custom_overlay_to_config(tos::tl_object_ptr<tos::tos_api::engine_validator_customOverlay> overlay,
                                    td::Promise<td::Unit> promise);
  void del_custom_overlay_from_config(std::string name, td::Promise<td::Unit> promise);
  void load_collator_options();

  void check_key(tos::PublicKeyHash id, td::Promise<td::Unit> promise);

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
  void run_control_query(tos::tos_api::engine_validator_addValidatorPermanentKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addValidatorTempKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addValidatorAdnlAddress &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_changeFullNodeAdnlAddress &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addLiteserver &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addControlInterface &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delAdnlId &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delDhtId &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delValidatorPermanentKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delValidatorTempKey &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delValidatorAdnlAddress &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addListeningPort &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delListeningPort &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addProxy &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delProxy &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addQuicAddr &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delQuicAddr &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getConfig &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_sign &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_exportAllPrivateKeys &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setVerbosity &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getStats &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_createElectionBid &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_checkDhtServers &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_createProposalVote &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_createComplaintVote &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_importCertificate &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_signShardOverlayCertificate &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_importShardOverlayCertificate &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getOverlaysStats &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getActorTextStats &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addShard &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delShard &query, td::BufferSlice data, tos::PublicKeyHash src,
                         td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addCollator &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delCollator &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getPerfTimerStats &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getShardOutQueueSize &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setExtMessagesBroadcastDisabled &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addCustomOverlay &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delCustomOverlay &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_showCustomOverlays &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setStateSerializerEnabled &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setCollatorOptionsJson &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_collatorNodeSetWhitelistedValidator &query,
                         td::BufferSlice data, tos::PublicKeyHash src, td::uint32 perm,
                         td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_collatorNodeSetWhitelistEnabled &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_showCollatorNodeWhitelist &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setCollatorsList &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_clearCollatorsList &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_showCollatorsList &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getCollationManagerStats &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_signOverlayMemberCertificate &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_importFastSyncMemberCertificate &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getCollatorOptionsJson &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getAdnlStats &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_addFastSyncClient &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_delFastSyncClient &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setShardBlockVerifierConfig &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_showShardBlockVerifierConfig &query, td::BufferSlice data,
                         tos::PublicKeyHash src, td::uint32 perm, td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_setConsensusNoncriticalParamsOverrides &query,
                         td::BufferSlice data, tos::PublicKeyHash src, td::uint32 perm,
                         td::Promise<td::BufferSlice> promise);
  void run_control_query(tos::tos_api::engine_validator_getConsensusNoncriticalParamsOverrides &query,
                         td::BufferSlice data, tos::PublicKeyHash src, td::uint32 perm,
                         td::Promise<td::BufferSlice> promise);

  template <class T>
  void run_control_query(T &query, td::BufferSlice data, tos::PublicKeyHash src, td::uint32 perm,
                         td::Promise<td::BufferSlice> promise) {
    promise.set_value(
        create_control_query_error(td::Status::Error(tos::ErrorCode::protoviolation, "query not supported")));
  }
  void process_control_query(td::uint16 port, tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst,
                             td::BufferSlice data, td::Promise<td::BufferSlice> promise);
};
