/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <map>

#include "lite-client/ext-client.h"
#include "smc-envelope/ManualDns.h"
#include "td/actor/actor.h"
#include "td/utils/CancellationToken.h"
#include "td/utils/optional.h"
#include "toslib/Config.h"
#include "toslib/ExtClient.h"
#include "toslib/ExtClientOutbound.h"
#include "toslib/KeyStorage.h"
#include "toslib/KeyValue.h"
#include "toslib/LastBlockStorage.h"

#include "ToslibCallback.h"

namespace toslib {
namespace int_api {
struct GetAccountState;
struct GetAccountStateByTransaction;
struct GetPrivateKey;
struct GetDnsResolver;
struct SendMessage;
struct RemoteRunSmcMethod;
struct RemoteRunSmcMethodReturnType;
struct ScanAndLoadGlobalLibs;

inline std::string to_string(const int_api::SendMessage&) {
  return "Send message";
}
}  // namespace int_api
class AccountState;
class Query;
class RunEmulator;

td::Result<toslib_api::object_ptr<toslib_api::dns_EntryData>> to_toslib_api(
    const tos::ManualDns::EntryData& entry_data);
td::Result<tos::ManualDns::EntryData> to_dns_entry_data(toslib_api::dns_EntryData& entry_data);
td::Result<td::Bits256> get_ext_in_msg_hash_norm(td::Ref<vm::Cell> ext_in_msg_cell);

namespace detail {
td::Status validate_liteserver_block_id(const tos::BlockIdExt& expected, const tos::BlockIdExt& actual);
td::Status validate_liteserver_transaction_page(bool incomplete, size_t transaction_count);
}  // namespace detail

class ToslibClient : public td::actor::Actor {
 public:
  template <class T>
  using object_ptr = toslib_api::object_ptr<T>;

  explicit ToslibClient(td::unique_ptr<ToslibCallback> callback);
  void request(td::uint64 id, object_ptr<toslib_api::Function> function);
  void close();
  static object_ptr<toslib_api::Object> static_request(object_ptr<toslib_api::Function> function);

  ~ToslibClient();

  struct FullConfig {
    Config config;
    bool use_callbacks_for_network;
    LastBlockState last_state;
    std::string last_state_key;
    td::uint32 wallet_id;
    td::int32 global_id{0};
    std::string rwallet_init_public_key;
  };

  template <class T, class P>
  void make_request(T&& request, P&& promise) {
    td::Promise<typename std::decay_t<T>::ReturnType> new_promise = std::move(promise);

    auto status = do_request(std::forward<T>(request), std::move(new_promise));
    if (status.is_error()) {
      new_promise.set_error(status.move_as_error());
    }
  }

 private:
  enum class State { Uninited, Running, Closed } state_ = State::Uninited;
  td::unique_ptr<ToslibCallback> callback_;

  // Config
  Config config_;
  td::uint32 config_generation_{0};
  td::uint32 wallet_id_;
  td::int32 global_id_{0};
  std::string rwallet_init_public_key_;
  std::string last_state_key_;
  bool use_callbacks_for_network_{false};

  // KeyStorage
  std::shared_ptr<KeyValue> kv_;
  KeyStorage key_storage_;
  LastBlockStorage last_block_storage_;
  struct QueryContext {
    td::optional<tos::BlockIdExt> block_id;
  };
  QueryContext query_context_;
  vm::Dictionary libraries{256};

  // network
  td::actor::ActorOwn<liteclient::ExtClient> raw_client_;
  td::actor::ActorId<ExtClientOutbound> ext_client_outbound_;
  td::actor::ActorOwn<LastBlock> raw_last_block_;
  td::actor::ActorOwn<LastConfig> raw_last_config_;
  ExtClient client_;

  td::CancellationTokenSource source_;

  std::map<td::int64, td::actor::ActorOwn<>> actors_;
  td::int64 actor_id_{1};

  ExtClientRef get_client_ref();
  void init_ext_client();
  void init_last_block(LastBlockState state);
  void init_last_config();

  bool is_closing_{false};
  td::uint32 ref_cnt_{1};
  void hangup_shared() override {
    auto it = actors_.find(get_link_token());
    if (it != actors_.end()) {
      actors_.erase(it);
    } else {
      ref_cnt_--;
    }
    try_stop();
  }
  void hangup() override;
  void try_stop() {
    if (is_closing_ && ref_cnt_ == 0 && actors_.empty()) {
      stop();
    }
  }

  void update_last_block_state(LastBlockState state, td::uint32 config_generation_);
  void update_sync_state(LastBlockSyncState state, td::uint32 config_generation);
  void on_result(td::uint64 id, object_ptr<toslib_api::Object> response);
  void on_update(object_ptr<toslib_api::Object> response);
  static bool is_static_request(td::int32 id);
  static bool is_uninited_request(td::int32 id);
  template <class T>
  static object_ptr<toslib_api::Object> do_static_request(const T& request) {
    return toslib_api::make_object<toslib_api::error>(400, "Function can't be executed synchronously");
  }
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::runTests& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::getAccountAddress& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::packAccountAddress& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::unpackAccountAddress& request);
  static object_ptr<toslib_api::Object> do_static_request(toslib_api::getBip39Hints& request);

  static object_ptr<toslib_api::Object> do_static_request(toslib_api::setLogStream& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::getLogStream& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::setLogVerbosityLevel& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::setLogTagVerbosityLevel& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::getLogVerbosityLevel& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::getLogTagVerbosityLevel& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::getLogTags& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::addLogMessage& request);

  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::encrypt& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::decrypt& request);
  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::kdf& request);

  static object_ptr<toslib_api::Object> do_static_request(const toslib_api::msg_decryptWithProof& request);

  template <class P>
  td::Status do_request(const toslib_api::runTests& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::getAccountAddress& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::packAccountAddress& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::unpackAccountAddress& request, P&&);
  template <class P>
  td::Status do_request(toslib_api::getBip39Hints& request, P&&);

  template <class P>
  td::Status do_request(toslib_api::setLogStream& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::getLogStream& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::setLogVerbosityLevel& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::setLogTagVerbosityLevel& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::getLogVerbosityLevel& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::getLogTagVerbosityLevel& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::getLogTags& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::addLogMessage& request, P&&);

  template <class P>
  td::Status do_request(const toslib_api::encrypt& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::decrypt& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::kdf& request, P&&);
  template <class P>
  td::Status do_request(const toslib_api::msg_decryptWithProof& request, P&&);

  void make_any_request(toslib_api::Function& function, QueryContext query_context,
                        td::Promise<toslib_api::object_ptr<toslib_api::Object>>&& promise);

  td::Result<FullConfig> validate_config(toslib_api::object_ptr<toslib_api::config> config);
  void set_config(FullConfig config);
  td::Status do_request(const toslib_api::init& request, td::Promise<object_ptr<toslib_api::options_info>>&& promise);
  td::Status do_request(const toslib_api::close& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(toslib_api::options_validateConfig& request,
                        td::Promise<object_ptr<toslib_api::options_configInfo>>&& promise);
  td::Status do_request(toslib_api::options_setConfig& request,
                        td::Promise<object_ptr<toslib_api::options_configInfo>>&& promise);

  td::Status do_request(const toslib_api::raw_sendMessage& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::raw_sendMessageReturnHash& request,
                        td::Promise<object_ptr<toslib_api::raw_extMessageInfo>>&& promise);
  td::Status do_request(const toslib_api::raw_createAndSendMessage& request,
                        td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::raw_createQuery& request,
                        td::Promise<object_ptr<toslib_api::query_info>>&& promise);

  td::Status do_request(toslib_api::raw_getAccountState& request,
                        td::Promise<object_ptr<toslib_api::raw_fullAccountState>>&& promise);
  td::Status do_request(toslib_api::raw_getAccountStateByTransaction& request,
                        td::Promise<object_ptr<toslib_api::raw_fullAccountState>>&& promise);
  td::Status do_request(toslib_api::raw_getTransactions& request,
                        td::Promise<object_ptr<toslib_api::raw_transactions>>&& promise);
  td::Status do_request(toslib_api::raw_getTransactionsV2& request,
                        td::Promise<object_ptr<toslib_api::raw_transactions>>&& promise);

  td::Status do_request(const toslib_api::getAccountState& request,
                        td::Promise<object_ptr<toslib_api::fullAccountState>>&& promise);
  td::Status do_request(const toslib_api::getAccountStateByTransaction& request,
                        td::Promise<object_ptr<toslib_api::fullAccountState>>&& promise);
  td::Status do_request(const toslib_api::getShardAccountCell& request,
                        td::Promise<object_ptr<toslib_api::tvm_cell>>&& promise);
  td::Status do_request(const toslib_api::getShardAccountCellByTransaction& request,
                        td::Promise<object_ptr<toslib_api::tvm_cell>>&& promise);
  td::Status do_request(toslib_api::guessAccountRevision& request,
                        td::Promise<object_ptr<toslib_api::accountRevisionList>>&& promise);
  td::Status do_request(toslib_api::guessAccount& request,
                        td::Promise<object_ptr<toslib_api::accountRevisionList>>&& promise);

  td::Status do_request(toslib_api::sync& request, td::Promise<object_ptr<toslib_api::tos_blockIdExt>>&& promise);

  td::Status do_request(const toslib_api::createNewKey& request, td::Promise<object_ptr<toslib_api::key>>&& promise);
  td::Status do_request(const toslib_api::exportKey& request,
                        td::Promise<object_ptr<toslib_api::exportedKey>>&& promise);
  td::Status do_request(const toslib_api::deleteKey& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::deleteAllKeys& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::importKey& request, td::Promise<object_ptr<toslib_api::key>>&& promise);

  td::Status do_request(const toslib_api::exportPemKey& request,
                        td::Promise<object_ptr<toslib_api::exportedPemKey>>&& promise);
  td::Status do_request(const toslib_api::importPemKey& request, td::Promise<object_ptr<toslib_api::key>>&& promise);

  td::Status do_request(const toslib_api::exportEncryptedKey& request,
                        td::Promise<object_ptr<toslib_api::exportedEncryptedKey>>&& promise);
  td::Status do_request(const toslib_api::importEncryptedKey& request,
                        td::Promise<object_ptr<toslib_api::key>>&& promise);

  td::Status do_request(const toslib_api::exportUnencryptedKey& request,
                        td::Promise<object_ptr<toslib_api::exportedUnencryptedKey>>&& promise);
  td::Status do_request(const toslib_api::importUnencryptedKey& request,
                        td::Promise<object_ptr<toslib_api::key>>&& promise);

  td::Status do_request(const toslib_api::changeLocalPassword& request,
                        td::Promise<object_ptr<toslib_api::key>>&& promise);

  td::Status do_request(const toslib_api::onLiteServerQueryResult& request,
                        td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::onLiteServerQueryError& request,
                        td::Promise<object_ptr<toslib_api::ok>>&& promise);

  td::int64 next_query_id_{0};
  std::map<td::int64, td::unique_ptr<Query>> queries_;
  td::int64 register_query(td::unique_ptr<Query> query);
  td::Result<toslib_api::object_ptr<toslib_api::query_info>> get_query_info(td::int64 id);
  void finish_create_query(td::Result<td::unique_ptr<Query>> r_query,
                           td::Promise<object_ptr<toslib_api::query_info>>&& promise);
  void query_estimate_fees(td::int64 id, bool ignore_chksig, td::Result<LastConfigState> r_state,
                           td::Promise<object_ptr<toslib_api::query_fees>>&& promise);

  td::Status do_request(const toslib_api::query_getInfo& request,
                        td::Promise<object_ptr<toslib_api::query_info>>&& promise);
  td::Status do_request(const toslib_api::query_estimateFees& request,
                        td::Promise<object_ptr<toslib_api::query_fees>>&& promise);
  td::Status do_request(const toslib_api::query_send& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(toslib_api::query_forget& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);

  td::Status do_request(toslib_api::createQuery& request, td::Promise<object_ptr<toslib_api::query_info>>&& promise);

  td::Status do_request(toslib_api::msg_decrypt& request,
                        td::Promise<object_ptr<toslib_api::msg_dataDecryptedArray>>&& promise);

  td::int64 next_smc_id_{0};
  std::map<td::int64, td::unique_ptr<AccountState>> smcs_;

  td::int64 register_smc(td::unique_ptr<AccountState> smc);
  td::Result<toslib_api::object_ptr<toslib_api::smc_info>> get_smc_info(td::int64 id);
  void finish_load_smc(td::unique_ptr<AccountState> query, td::Promise<object_ptr<toslib_api::smc_info>>&& promise);
  td::Status do_request(const toslib_api::smc_load& request, td::Promise<object_ptr<toslib_api::smc_info>>&& promise);
  td::Status do_request(const toslib_api::smc_loadByTransaction& request,
                        td::Promise<object_ptr<toslib_api::smc_info>>&& promise);
  td::Status do_request(const toslib_api::smc_forget& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);
  td::Status do_request(const toslib_api::smc_getCode& request,
                        td::Promise<object_ptr<toslib_api::tvm_cell>>&& promise);
  td::Status do_request(const toslib_api::smc_getData& request,
                        td::Promise<object_ptr<toslib_api::tvm_cell>>&& promise);
  td::Status do_request(const toslib_api::smc_getState& request,
                        td::Promise<object_ptr<toslib_api::tvm_cell>>&& promise);
  td::Status do_request(const toslib_api::smc_getRawFullAccountState& request,
                        td::Promise<object_ptr<toslib_api::raw_fullAccountState>>&& promise);

  td::Status do_request(const toslib_api::smc_runGetMethod& request,
                        td::Promise<object_ptr<toslib_api::smc_runResult>>&& promise);

  td::Status do_request(const toslib_api::smc_getLibraries& request,
                        td::Promise<object_ptr<toslib_api::smc_libraryResult>>&& promise);
  void get_libraries(tos::BlockIdExt blkid, std::vector<td::Bits256> library_list_,
                     td::Promise<object_ptr<toslib_api::smc_libraryResult>>&& promise);

  td::Status do_request(const toslib_api::smc_getLibrariesExt& request,
                        td::Promise<object_ptr<toslib_api::smc_libraryResultExt>>&& promise);

  td::Status do_request(const toslib_api::dns_resolve& request,
                        td::Promise<object_ptr<toslib_api::dns_resolved>>&& promise);

  td::Status do_request(toslib_api::pchan_signPromise& request,
                        td::Promise<object_ptr<toslib_api::pchan_promise>>&& promise);
  td::Status do_request(toslib_api::pchan_validatePromise& request, td::Promise<object_ptr<toslib_api::ok>>&& promise);

  td::Status do_request(toslib_api::pchan_packPromise& request, td::Promise<object_ptr<toslib_api::data>>&& promise);
  td::Status do_request(toslib_api::pchan_unpackPromise& request,
                        td::Promise<object_ptr<toslib_api::pchan_promise>>&& promise);

  void process_new_libraries(
      td::Result<tos::lite_api::object_ptr<tos::lite_api::liteServer_libraryResult>> r_libraries);
  void perform_smc_execution(td::Ref<tos::SmartContract> smc, tos::SmartContract::Args args,
                             td::Promise<object_ptr<toslib_api::smc_runResult>>&& promise);

  void do_dns_request(std::string name, td::Bits256 category, td::int32 ttl, td::optional<tos::BlockIdExt> block_id,
                      block::StdAddress address, td::Promise<object_ptr<toslib_api::dns_resolved>>&& promise);
  struct DnsFinishData {
    tos::BlockIdExt block_id;
    tos::SmartContract::State smc_state;
  };
  void finish_dns_resolve(std::string name, td::Bits256 category, td::int32 ttl, td::optional<tos::BlockIdExt> block_id,
                          block::StdAddress address, DnsFinishData dns_finish_data,
                          td::Promise<object_ptr<toslib_api::dns_resolved>>&& promise);

  td::Status do_request(int_api::GetAccountState request, td::Promise<td::unique_ptr<AccountState>>&&);
  td::Status do_request(int_api::GetAccountStateByTransaction request, td::Promise<td::unique_ptr<AccountState>>&&);
  td::Status do_request(int_api::GetPrivateKey request, td::Promise<KeyStorage::PrivateKey>&&);
  td::Status do_request(int_api::GetDnsResolver request, td::Promise<block::StdAddress>&&);
  td::Status do_request(int_api::RemoteRunSmcMethod request,
                        td::Promise<int_api::RemoteRunSmcMethodReturnType>&& promise);
  td::Status do_request(int_api::SendMessage request, td::Promise<td::Unit>&& promise);

  td::Status do_request(const toslib_api::liteServer_getInfo& request,
                        td::Promise<object_ptr<toslib_api::liteServer_info>>&& promise);

  td::Status do_request(toslib_api::withBlock& request, td::Promise<object_ptr<toslib_api::Object>>&& promise);

  td::Status do_request(const toslib_api::blocks_getMasterchainInfo& masterchain_info,
                        td::Promise<object_ptr<toslib_api::blocks_masterchainInfo>>&& promise);
  td::Status do_request(const toslib_api::blocks_getShards& request,
                        td::Promise<object_ptr<toslib_api::blocks_shards>>&& promise);
  td::Status do_request(const toslib_api::blocks_lookupBlock& block_header,
                        td::Promise<object_ptr<toslib_api::tos_blockIdExt>>&& promise);
  td::Status do_request(const toslib_api::blocks_getTransactions& block_data,
                        td::Promise<object_ptr<toslib_api::blocks_transactions>>&& promise);
  td::Status do_request(const toslib_api::blocks_getTransactionsExt& request,
                        td::Promise<object_ptr<toslib_api::blocks_transactionsExt>>&& promise);
  td::Status do_request(const toslib_api::blocks_getBlockHeader& request,
                        td::Promise<object_ptr<toslib_api::blocks_header>>&& promise);
  td::Status do_request(const toslib_api::blocks_getMasterchainBlockSignatures& request,
                        td::Promise<object_ptr<toslib_api::blocks_BlockSignatures>>&& promise);
  td::Status do_request(const toslib_api::blocks_getShardBlockProof& request,
                        td::Promise<object_ptr<toslib_api::blocks_shardBlockProof>>&& promise);
  td::Status do_request(const toslib_api::blocks_getOutMsgQueueSizes& request,
                        td::Promise<object_ptr<toslib_api::blocks_outMsgQueueSizes>>&& promise);

  void get_config_param(int32_t param, int32_t mode, tos::BlockIdExt block,
                        td::Promise<object_ptr<toslib_api::configInfo>>&& promise);
  td::Status do_request(const toslib_api::getConfigParam& request,
                        td::Promise<object_ptr<toslib_api::configInfo>>&& promise);
  void get_config_all(int32_t mode, tos::BlockIdExt block, td::Promise<object_ptr<toslib_api::configInfo>>&& promise);
  td::Status do_request(const toslib_api::getConfigAll& request,
                        td::Promise<object_ptr<toslib_api::configInfo>>&& promise);

  void proxy_request(td::int64 query_id, std::string data);

  void load_libs_from_disk();
  void store_libs_to_disk();

  friend class ToslibQueryActor;
  struct Target {
    bool can_be_empty{true};
    bool can_be_uninited{false};
    block::StdAddress address;
    td::optional<td::Ed25519::PublicKey> public_key;
  };

  td::Status guess_revisions(std::vector<Target> targets,
                             td::Promise<object_ptr<toslib_api::accountRevisionList>>&& promise);

  td::Status do_request(const int_api::ScanAndLoadGlobalLibs& request, td::Promise<vm::Dictionary> promise);
};
}  // namespace toslib
