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
#include "adnl/adnl-ext-client.h"
#include "auto/tl/lite_api.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "smc-envelope/ManualDns.h"
#include "td/utils/filesystem.h"
#include "terminal/terminal.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-types.h"
#include "vm/cells.h"
#include "vm/stack.hpp"

#include "ext-client.h"

using td::Ref;

class TestNode : public td::actor::Actor {
 private:
  std::string global_config_ = "tos-global.config";
  enum {
    min_ls_version = 0x101,
    min_ls_capabilities = 1
  };  // server version >= 1.1, capabilities at least +1 = build proof chains
  td::actor::ActorOwn<liteclient::ExtClient> client_;
  td::actor::ActorOwn<td::TerminalIO> io_;
  bool ready_ = false;

  td::int32 single_liteserver_idx_ = -1;
  td::IPAddress single_remote_addr_;
  tos::PublicKey single_remote_public_key_;

  bool readline_enabled_ = true;
  int print_limit_ = 1024;

  std::string db_root_;

  int mc_server_time_ = 0;
  int mc_server_time_got_at_ = 0;
  int mc_server_version_ = 0;
  long long mc_server_capabilities_ = 0;
  bool mc_server_ok_ = false;

  tos::ZeroStateIdExt zstate_id_;
  tos::BlockIdExt mc_last_id_;

  tos::BlockIdExt last_block_id_, last_state_id_;
  td::BufferSlice last_block_data_, last_state_data_;

  tos::StdSmcAddress dns_root_, elect_addr_, config_addr_;
  bool dns_root_queried_{false}, elect_addr_queried_{false}, config_addr_queried_{false};

  std::string line_;
  const char *parse_ptr_, *parse_end_;
  td::Status error_;

  std::vector<tos::BlockIdExt> known_blk_ids_;
  std::size_t shown_blk_ids_ = 0;

  td::Timestamp fail_timeout_;
  td::uint32 running_queries_ = 0;
  bool ex_mode_ = false;
  std::vector<td::BufferSlice> ex_queries_;

  std::map<td::Bits256, Ref<vm::Cell>> cell_cache_;

  using creator_stats_func_t =
      std::function<bool(const td::Bits256&, const block::DiscountedCounter&, const block::DiscountedCounter&)>;

  struct TransId {
    tos::Bits256 acc_addr;
    tos::LogicalTime trans_lt;
    tos::Bits256 trans_hash;
    TransId(const tos::Bits256& addr_, tos::LogicalTime lt_, const tos::Bits256& hash_)
        : acc_addr(addr_), trans_lt(lt_), trans_hash(hash_) {
    }
  };

  struct BlockHdrInfo {
    tos::BlockIdExt blk_id;
    Ref<vm::Cell> proof, virt_blk_root;
    int mode;
    BlockHdrInfo() : mode(-1) {
    }
    BlockHdrInfo(const tos::BlockIdExt blk_id_, Ref<vm::Cell> proof_, Ref<vm::Cell> vroot_, int mode_)
        : blk_id(blk_id_), proof(std::move(proof_)), virt_blk_root(std::move(vroot_)), mode(mode_) {
    }
  };

  struct ConfigInfo {
    std::unique_ptr<block::Config> config;
    Ref<vm::Cell> state_proof, config_proof;
    ConfigInfo() = default;
    ConfigInfo(std::unique_ptr<block::Config> config_, Ref<vm::Cell> state_proof_, Ref<vm::Cell> config_proof_)
        : config(std::move(config_)), state_proof(std::move(state_proof_)), config_proof(std::move(config_proof_)) {
    }
  };

  struct CreatorStatsRes {
    int mode;
    bool complete{false};
    td::Bits256 last_key;
    Ref<vm::Cell> state_proof, data_proof;
    CreatorStatsRes(int mode_ = 0) : mode(mode_) {
      last_key.set_zero();
    }
    CreatorStatsRes(int mode_, const td::Bits256& key_, Ref<vm::Cell> st_proof_ = {}, Ref<vm::Cell> dproof_ = {})
        : mode(mode_), last_key(key_), state_proof(std::move(st_proof_)), data_proof(std::move(dproof_)) {
    }
  };

  struct ValidatorLoadInfo {
    tos::BlockIdExt blk_id;
    Ref<vm::Cell> state_proof, data_proof, virt_root;
    std::unique_ptr<block::Config> config;
    tos::UnixTime block_created_at{0};
    tos::UnixTime valid_since{0};
    tos::LogicalTime end_lt{0};
    tos::Bits256 vset_hash;
    Ref<vm::Cell> vset_root;
    std::shared_ptr<block::TotalValidatorSet> vset;
    std::map<tos::Bits256, int> vset_map;
    int special_idx{-1};
    std::pair<td::int64, td::int64> created_total, created_special;
    std::vector<std::pair<td::int64, td::int64>> created;
    ValidatorLoadInfo(tos::BlockIdExt blkid, Ref<vm::Cell> root, Ref<vm::Cell> root2,
                      std::unique_ptr<block::Config> cfg = {})
        : blk_id(blkid)
        , state_proof(std::move(root))
        , data_proof(std::move(root2))
        , config(std::move(cfg))
        , valid_since(0) {
    }
    td::Status unpack_vset();
    bool store_record(const td::Bits256& key, const block::DiscountedCounter& mc_cnt,
                      const block::DiscountedCounter& shard_cnt);
    bool has_data() const {
      return blk_id.is_masterchain_ext() && state_proof.not_null() && data_proof.not_null() && config;
    }
    td::Status check_header_proof(tos::UnixTime* save_utime = nullptr, tos::LogicalTime* save_lt = nullptr) const;
    td::Result<Ref<vm::Cell>> build_proof(int idx, td::Bits256* save_pubkey = nullptr) const;
    td::Result<Ref<vm::Cell>> build_producer_info(int idx, td::Bits256* save_pubkey = nullptr) const;
    td::Status init_check_proofs();
    static td::Result<std::unique_ptr<ValidatorLoadInfo>> preinit_from_producer_info(Ref<vm::Cell> prod_info);
    td::Status load_special_creator_stat(const td::Bits256& spec_pubkey, bool load_total = true);
  };

  void run_init_queries();
  char cur() const {
    return *parse_ptr_;
  }
  bool get_server_time();
  bool get_server_version(int mode = 0);
  void got_server_version(td::Result<td::BufferSlice> res, int mode);
  bool get_server_mc_block_id();
  void got_server_mc_block_id(tos::BlockIdExt blkid, tos::ZeroStateIdExt zstateid, int created_at);
  void got_server_mc_block_id_ext(tos::BlockIdExt blkid, tos::ZeroStateIdExt zstateid, int mode, int version,
                                  long long capabilities, int last_utime, int server_now);
  void set_mc_server_version(td::int32 version, td::int64 capabilities);
  void set_mc_server_time(int server_utime);
  bool request_block(tos::BlockIdExt blkid);
  bool request_state(tos::BlockIdExt blkid);
  void got_mc_block(tos::BlockIdExt blkid, td::BufferSlice data);
  void got_mc_state(tos::BlockIdExt blkid, tos::RootHash root_hash, tos::FileHash file_hash, td::BufferSlice data);
  td::Status send_ext_msg_from_filename(std::string filename);
  td::Status save_db_file(tos::FileHash file_hash, td::BufferSlice data);
  bool get_account_state(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt ref_blkid,
                         int addr_ext = 0, std::string filename = "", int mode = -1, bool prunned = false);
  void got_account_state(tos::BlockIdExt ref_blk, tos::BlockIdExt blk, tos::BlockIdExt shard_blk,
                         td::BufferSlice shard_proof, td::BufferSlice proof, td::BufferSlice state,
                         tos::WorkchainId workchain, tos::StdSmcAddress addr, std::string filename, int mode,
                         bool prunned);
  bool parse_run_method(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt ref_blkid, int addr_ext,
                        std::string method_name, bool ext_mode);
  bool after_parse_run_method(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt ref_blkid,
                              std::string method_name, std::vector<vm::StackEntry> params, bool ext_mode);
  bool start_run_method(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt ref_blkid,
                        std::string method_name, std::vector<vm::StackEntry> params, int mode,
                        td::Promise<std::vector<vm::StackEntry>> promise);
  void run_smc_method(int mode, tos::BlockIdExt ref_blk, tos::BlockIdExt blk, tos::BlockIdExt shard_blk,
                      td::BufferSlice shard_proof, td::BufferSlice proof, td::BufferSlice state,
                      tos::WorkchainId workchain, tos::StdSmcAddress addr, std::string method,
                      std::vector<vm::StackEntry> params, td::BufferSlice remote_c7, td::BufferSlice remote_libs,
                      td::BufferSlice remote_result, int remote_exit_code,
                      td::Promise<std::vector<vm::StackEntry>> promise);
  bool register_config_param(int idx, Ref<vm::Cell> value);
  bool register_config_param0(Ref<vm::Cell> value);
  bool register_config_param1(Ref<vm::Cell> value);
  bool register_config_param4(Ref<vm::Cell> value);
  bool dns_resolve_start(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt blkid, std::string domain,
                         td::Bits256 cat, int mode);
  bool dns_resolve_send(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt blkid, std::string domain,
                        std::string qdomain, td::Bits256 cat, int mode, int hops_left,
                        std::vector<std::string> resolver_path = {});
  void dns_resolve_finish(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::BlockIdExt blkid,
                          std::string domain, std::string qdomain, td::Bits256 cat, int mode, int hops_left,
                          std::vector<std::string> resolver_path, int used_bits, Ref<vm::Cell> value);
  // uniform resolver hop budget: exhausting it is reported as a distinct
  // error, never as "not found"
  static constexpr int max_dns_resolver_hops = tos::DNS_MAX_RESOLVER_HOPS;
  bool show_dns_record(std::ostream& os, td::Bits256 cat, Ref<vm::CellSlice> value, bool raw_dump);
  bool get_all_shards(std::string filename = "", bool use_last = true, tos::BlockIdExt blkid = {});
  void got_all_shards(tos::BlockIdExt blk, td::BufferSlice proof, td::BufferSlice data, std::string filename);
  bool parse_get_config_params(tos::BlockIdExt blkid, int mode = 0, std::string filename = "",
                               std::vector<int> params = {});
  bool get_config_params(tos::BlockIdExt blkid, td::Promise<std::unique_ptr<block::Config>> promise, int mode = 0,
                         std::string filename = "", std::vector<int> params = {});
  bool get_config_params_ext(tos::BlockIdExt blkid, td::Promise<ConfigInfo> promise, int mode = 0,
                             std::string filename = "", std::vector<int> params = {});
  void got_config_params(tos::BlockIdExt req_blkid, int mode, std::string filename, std::vector<int> params,
                         td::Result<td::BufferSlice> R, td::Promise<ConfigInfo> promise);
  bool get_block(tos::BlockIdExt blk, bool dump = false);
  void got_block(tos::BlockIdExt blkid, td::BufferSlice data, bool dump);
  bool get_state(tos::BlockIdExt blk, bool dump = false);
  void got_state(tos::BlockIdExt blkid, tos::RootHash root_hash, tos::FileHash file_hash, td::BufferSlice data,
                 bool dump);
  bool get_show_block_header(tos::BlockIdExt blk, int mode);
  bool get_block_header(tos::BlockIdExt blk, int mode, td::Promise<BlockHdrInfo> promise);
  bool lookup_show_block(tos::ShardIdFull shard, int mode, td::uint64 arg);
  bool lookup_block(tos::ShardIdFull shard, int mode, td::uint64 arg, td::Promise<BlockHdrInfo>);
  void got_block_header_raw(td::BufferSlice res, td::Promise<BlockHdrInfo> promise, tos::BlockIdExt req_blkid = {});
  void got_block_header(tos::BlockIdExt blkid, td::BufferSlice data, int mode);
  bool show_block_header(tos::BlockIdExt blkid, Ref<vm::Cell> root, int mode);
  bool show_state_header(tos::BlockIdExt blkid, Ref<vm::Cell> root, int mode);
  bool get_one_transaction(tos::BlockIdExt blkid, tos::WorkchainId workchain, tos::StdSmcAddress addr,
                           tos::LogicalTime lt, bool dump = false);
  void got_one_transaction(tos::BlockIdExt req_blkid, tos::BlockIdExt blkid, td::BufferSlice proof,
                           td::BufferSlice transaction, tos::WorkchainId workchain, tos::StdSmcAddress addr,
                           tos::LogicalTime trans_lt, bool dump);
  bool get_last_transactions(tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::LogicalTime lt,
                             tos::Bits256 hash, unsigned count, bool dump);
  void got_last_transactions(std::vector<tos::BlockIdExt> blkids, td::BufferSlice transactions_boc,
                             tos::WorkchainId workchain, tos::StdSmcAddress addr, tos::LogicalTime lt,
                             tos::Bits256 hash, unsigned count, bool dump);
  bool get_block_transactions(tos::BlockIdExt blkid, int mode, unsigned count, tos::Bits256 acc_addr,
                              tos::LogicalTime lt);
  void got_block_transactions(tos::BlockIdExt blkid, int mode, unsigned req_count, bool incomplete,
                              std::vector<TransId> trans,
                              std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_transactionMetadata>> metadata,
                              td::BufferSlice proof);
  bool get_block_proof(tos::BlockIdExt from, tos::BlockIdExt to, int mode);
  void got_block_proof(tos::BlockIdExt from, tos::BlockIdExt to, int mode, td::BufferSlice res);
  bool get_creator_stats(tos::BlockIdExt blkid, int mode, unsigned req_count, tos::Bits256 start_after,
                         tos::UnixTime min_utime);
  bool get_creator_stats(tos::BlockIdExt blkid, int mode, unsigned req_count, tos::Bits256 start_after,
                         tos::UnixTime min_utime, creator_stats_func_t func, td::Promise<td::Bits256> promise);
  bool get_creator_stats(tos::BlockIdExt blkid, unsigned req_count, tos::UnixTime min_utime, creator_stats_func_t func,
                         std::unique_ptr<CreatorStatsRes> state, td::Promise<std::unique_ptr<CreatorStatsRes>> promise);
  void got_creator_stats(tos::BlockIdExt req_blkid, tos::BlockIdExt blkid, int mode, tos::UnixTime min_utime,
                         td::BufferSlice state_proof, td::BufferSlice data_proof, int count, int req_count,
                         bool complete, creator_stats_func_t func, std::unique_ptr<CreatorStatsRes> state,
                         td::Promise<std::unique_ptr<CreatorStatsRes>> promise);
  bool check_validator_load(int start_time, int end_time, int mode = 0, std::string file_pfx = "");
  void continue_check_validator_load(tos::BlockIdExt blkid1, Ref<vm::Cell> root1, tos::BlockIdExt blkid2,
                                     Ref<vm::Cell> root2, int mode = 0, std::string file_pfx = "");
  void continue_check_validator_load2(std::unique_ptr<ValidatorLoadInfo> info1,
                                      std::unique_ptr<ValidatorLoadInfo> info2, int mode = 0,
                                      std::string file_pfx = "");
  void continue_check_validator_load3(std::unique_ptr<ValidatorLoadInfo> info1,
                                      std::unique_ptr<ValidatorLoadInfo> info2, int mode = 0,
                                      std::string file_pfx = "");
  void continue_check_validator_load4(std::unique_ptr<ValidatorLoadInfo> info1,
                                      std::unique_ptr<ValidatorLoadInfo> info2, int mode, std::string file_pfx,
                                      std::map<td::Bits256, td::uint64> exact_shard_shares);

  struct LoadValidatorShardSharesState {
    tos::BlockSeqno start_seqno;
    tos::BlockSeqno end_seqno;
    block::TotalValidatorSet validator_set;
    std::unique_ptr<block::CatchainValidatorsConfig> catchain_config;
    std::vector<block::ShardConfig> shard_configs;
    td::uint32 cur_idx = 0, pending = 0, loaded = 0;
    td::Promise<std::map<td::Bits256, td::uint64>> promise;
  };
  void load_validator_shard_shares(tos::BlockSeqno start_seqno, tos::BlockSeqno end_seqno,
                                   block::TotalValidatorSet validator_set,
                                   std::unique_ptr<block::CatchainValidatorsConfig> catchain_config,
                                   td::Promise<std::map<td::Bits256, td::uint64>> promise);
  void load_validator_shard_shares_cont(std::shared_ptr<LoadValidatorShardSharesState> state);
  void load_block_shard_configuration(tos::BlockSeqno seqno, td::Promise<block::ShardConfig> promise);

  td::Status write_val_create_proof(ValidatorLoadInfo& info1, ValidatorLoadInfo& info2, int idx, bool severe,
                                    std::string file_pfx, int cnt);
  bool load_creator_stats(std::unique_ptr<ValidatorLoadInfo> load_to,
                          td::Promise<std::unique_ptr<ValidatorLoadInfo>> promise, bool need_proofs);
  td::Status check_validator_load_proof(std::string filename, std::string vset_filename = "",
                                        tos::Bits256 vset_hash = tos::Bits256::zero());
  td::Status continue_check_validator_load_proof(std::unique_ptr<ValidatorLoadInfo> info1,
                                                 std::unique_ptr<ValidatorLoadInfo> info2, Ref<vm::Cell> root);
  bool get_config_addr(td::Promise<tos::StdSmcAddress> promise);
  bool get_elector_addr(td::Promise<tos::StdSmcAddress> promise);
  bool get_dns_root(td::Promise<tos::StdSmcAddress> promise);
  bool get_special_smc_addr(int addr_ext, td::Promise<tos::StdSmcAddress> promise);
  bool get_past_validator_sets();
  bool send_past_vset_query(tos::StdSmcAddress elector_addr);
  void register_past_vset_info(vm::StackEntry list);
  bool get_complaints(unsigned elect_id, std::string file_pfx);
  void send_get_complaints_query(unsigned elect_id, tos::StdSmcAddress elector_addr, std::string file_pfx);
  void save_complaints(unsigned elect_id, Ref<vm::Cell> complaints, std::string file_pfx);
  td::Status get_complaint_price(unsigned expires_in, std::string filename);
  td::Status get_complaint_price(unsigned expires_in, unsigned bits, unsigned refs,
                                 td::Bits256 chash = td::Bits256::zero(), std::string filename = "");
  void send_compute_complaint_price_query(tos::StdSmcAddress elector_addr, unsigned expires_in, unsigned bits,
                                          unsigned refs, td::Bits256 chash, std::string filename);
  bool get_msg_queue_sizes();
  void get_msg_queue_sizes_cont(tos::BlockIdExt mc_blkid, td::BufferSlice data);
  void get_msg_queue_sizes_finish(std::vector<tos::BlockIdExt> blocks, std::vector<td::uint64> sizes);
  bool get_dispatch_queue_info(tos::BlockIdExt block_id);
  bool get_dispatch_queue_info_cont(tos::BlockIdExt block_id, bool first, td::Bits256 after_addr);
  void got_dispatch_queue_info(tos::BlockIdExt block_id,
                               tos::tl_object_ptr<tos::lite_api::liteServer_dispatchQueueInfo> info);
  bool get_dispatch_queue_messages(tos::BlockIdExt block_id, tos::WorkchainId wc, tos::StdSmcAddress addr,
                                   tos::LogicalTime lt, bool one_account);
  void got_dispatch_queue_messages(tos::tl_object_ptr<tos::lite_api::liteServer_dispatchQueueMessages> msgs);
  bool cache_cell(Ref<vm::Cell> cell);
  bool list_cached_cells() const;
  bool dump_cached_cell(td::Slice hash_pfx, td::Slice type_name = {});
  // parser
  bool do_parse_line();
  bool show_help(std::string command);
  td::Slice get_word(char delim = ' ');
  td::Slice get_word_ext(const char* delims, const char* specials = nullptr);
  bool get_word_to(std::string& str, char delim = ' ');
  bool get_word_to(td::Slice& str, char delim = ' ');
  int skipspc();
  std::string get_line_tail(bool remove_spaces = true) const;
  bool eoln() const;
  bool seekeoln();
  bool set_error(td::Status error);
  bool set_error(std::string err_msg);
  void show_context() const;
  bool parse_account_addr(tos::WorkchainId& wc, tos::StdSmcAddress& addr, bool allow_none = false);
  bool parse_account_addr_ext(tos::WorkchainId& wc, tos::StdSmcAddress& addr, int& addr_ext, bool allow_none = false);
  static int parse_hex_digit(int c);
  static bool parse_hash(const char* str, tos::Bits256& hash);
  static bool parse_hash(td::Slice str, tos::Bits256& hash);
  static bool convert_uint64(td::Slice word, td::uint64& val);
  static bool convert_int64(td::Slice word, td::int64& val);
  static bool convert_uint32(td::Slice word, td::uint32& val);
  static bool convert_int32(td::Slice word, td::int32& val);
  static bool convert_shard_id(td::Slice str, tos::ShardIdFull& shard);
  static td::int64 compute_method_id(std::string method);
  bool parse_hash(tos::Bits256& hash);
  bool parse_lt(tos::LogicalTime& lt);
  bool parse_uint32(td::uint32& val);
  bool parse_int32(td::int32& val);
  bool parse_int16(int& val);
  bool parse_shard_id(tos::ShardIdFull& shard);
  bool parse_block_id_ext(tos::BlockIdExt& blkid, bool allow_incomplete = false);
  bool parse_block_id_ext(std::string blk_id_string, tos::BlockIdExt& blkid, bool allow_incomplete = false) const;
  bool register_blkid(const tos::BlockIdExt& blkid);
  bool show_new_blkids(bool all = false);
  bool complete_blkid(tos::BlockId partial_blkid, tos::BlockIdExt& complete_blkid) const;
  td::Promise<td::Unit> trivial_promise();
  template <typename T>
  td::Promise<T> trivial_promise_of() {
    return td::PromiseCreator::lambda([Self = actor_id(this)](td::Result<T> res) {
      if (res.is_error()) {
        LOG(ERROR) << "error: " << res.move_as_error();
      }
    });
  }
  static tos::UnixTime now() {
    return static_cast<td::uint32>(td::Clocks::system());
  }
  static const tlb::TypenameLookup& get_tlb_dict();

 public:
  void set_global_config(std::string str) {
    global_config_ = str;
  }
  void set_db_root(std::string db_root) {
    db_root_ = db_root;
  }
  void set_readline_enabled(bool value) {
    readline_enabled_ = value;
  }
  void set_liteserver_idx(td::int32 idx) {
    single_liteserver_idx_ = idx;
  }
  void set_remote_addr(td::IPAddress addr) {
    single_remote_addr_ = addr;
  }
  void set_public_key(td::BufferSlice file_name) {
    auto R = [&]() -> td::Result<tos::PublicKey> {
      TRY_RESULT_PREFIX(conf_data, td::read_file(file_name.as_slice().str()), "failed to read: ");
      return tos::PublicKey::import(conf_data.as_slice());
    }();

    if (R.is_error()) {
      LOG(FATAL) << "bad server public key: " << R.move_as_error();
    }
    single_remote_public_key_ = R.move_as_ok();
  }
  void decode_public_key(td::BufferSlice b64_key) {
    auto R = [&]() -> td::Result<tos::PublicKey> {
      std::string key_bytes = {(char)0xc6, (char)0xb4, (char)0x13, (char)0x48};
      key_bytes = key_bytes + td::base64_decode(b64_key.as_slice().str()).move_as_ok();
      return tos::PublicKey::import(key_bytes);
    }();

    if (R.is_error()) {
      LOG(FATAL) << "bad b64 server public key: " << R.move_as_error();
    }
    single_remote_public_key_ = R.move_as_ok();
  }
  void set_fail_timeout(td::Timestamp ts) {
    fail_timeout_ = ts;
    alarm_timestamp().relax(fail_timeout_);
  }
  void set_print_limit(int plimit) {
    if (plimit >= 0) {
      print_limit_ = plimit;
    }
  }
  void add_cmd(td::BufferSlice data) {
    ex_mode_ = true;
    ex_queries_.push_back(std::move(data));
    readline_enabled_ = false;
  }
  void alarm() override {
    if (fail_timeout_.is_in_past()) {
      std::_Exit(7);
    }
    if (ex_mode_ && !running_queries_ && ex_queries_.size() == 0) {
      std::_Exit(0);
    }
    alarm_timestamp().relax(fail_timeout_);
  }

  void start_up() override {
  }
  void tear_down() override {
    // FIXME: do not work in windows
    //td::actor::SchedulerContext::get().stop();
  }

  void got_result(td::Result<td::BufferSlice> R, td::Promise<td::BufferSlice> promise);
  void after_got_result(bool ok);
  bool envelope_send_query(td::BufferSlice query, td::Promise<td::BufferSlice> promise);
  void parse_line(td::BufferSlice data);

  TestNode() = default;

  void run();
};
