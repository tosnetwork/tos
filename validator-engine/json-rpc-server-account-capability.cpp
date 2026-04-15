/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "json-rpc-server-internal.h"

#include "auto/tl/lite_api.hpp"
#include "tl/tl_object_parse.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include <limits>

namespace tos {

static std::string build_wallet_json(bool is_wallet, td::int64 balance,
                                     const std::string& account_state,
                                     const std::string& wallet_type,
                                     td::int32 seqno,
                                     td::uint64 last_lt, const std::string& last_hash_b64,
                                     td::int64 wallet_id = -1) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"ext.accounts.walletInformation\""
     << ",\"wallet\":" << (is_wallet ? "true" : "false")
     << ",\"balance\":" << td::JsonString(td::Slice(PSTRING() << balance))
     << ",\"account_state\":" << td::JsonString(td::Slice(account_state))
     << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
     << ",\"lt\":\"" << last_lt << "\""
     << ",\"hash\":" << td::JsonString(td::Slice(last_hash_b64)) << "}";
  if (is_wallet) {
    sb << ",\"wallet_type\":" << td::JsonString(td::Slice(wallet_type));
    if (seqno >= 0) {
      sb << ",\"seqno\":" << seqno;
    } else {
      sb << ",\"seqno\":null";
    }
    if (wallet_id >= 0) {
      sb << ",\"wallet_id\":" << wallet_id;
    } else {
      sb << ",\"wallet_id\":null";
    }
  } else {
    sb << ",\"wallet_type\":null,\"seqno\":null,\"wallet_id\":null";
  }
  sb << "}";
  return sb.as_cslice().str();
}

static std::string detect_wallet_type(const vm::CellHash& code_hash) {
  static const std::map<std::string, std::string> known_wallets = {
    {"89C890A6C9B5A3828B38570A93DFC93C792EE9147933DE8F21F5840AE19AB1AA", "wallet v1 r1"},
    {"27B5063EBDB6E5ECEC073F57451A4BE095EB68777496B65449B1B49FA09A43D9", "wallet v1 r2"},
    {"1F08EBE871907C8B60AA1BB9C22A54CB095D1DC0E007A3D7AF827D1C4DE23910", "wallet v1 r3"},
    {"8369FDDA46A532A8302037D955D92D7A3308422EADF0074C497CECD209832C3A", "wallet v2 r1"},
    {"9264711341AB55499665D16B4589A148ED6AB8A4AED3AE9FCF805295EEE7B927", "wallet v2 r2"},
    {"F475EC633EA8EC25B6872878B95996AEEA061198BD1C86180D3984EA7E1E6FB4", "wallet v3 r1"},
    {"09BE881BEFFE710D6BB4BD030A2506BEF85C10FF1AC44DF93B0B29282945916F", "wallet v3 r2"},
    {"6B5FD33048D2DB82650B36F47CED9714A1C0B573AA08447E23F96629364DDA2A", "wallet v4 r1"},
    {"288014A04D551904D623C826512FFEB16AD4DF6130195EA537050B35207E5FC3", "wallet v4 r2"},
    {"7AFA0EACBAF9E9EAA19AE93E61354540C9335B52F1ADD44E7A8E2D9089212B3E", "wallet v5 r1"},
    {"643A1AB8E96CB40B9CD92599EA295A591D6C12730D53CE77A447E1FC1C9A8B41", "nominator pool v1"},
    {"84DAFA449F98A6987789BA232358072BC0F76DC4524002A5D0918B9A75D2D599", "wallet v3 r2"},
    {"FEB5FF6820E2FF0D9483E7E0D62C817D846789FB4AE580C878866D959DABD5C0", "wallet v4 r2"},
    {"20834B7B72B112147E1B2FB457B84E74D1A30F04F737D4F62A668E9552D2B72F", "wallet v5 r1"},
    {"BCD75D29A1D932013CF31300C5D924A5F02EAA92CD830EC0330104FFBAD07928", "wallet v1 r1"},
    {"6C6CAAF194AF3660E7AE4C584785C1BDA0D85FAFD80E947D725105947CD11D7D", "wallet v3 r2"},
    {"E56EFC6C2C9E1DA65C36008E78BAEB9974D2779C05F29EDF4ADF39B4DBABD994", "wallet v4 r2"},
    {"E6C006F19FBABCCD0D4852C1CC4CA3C6410914DC86F6611CCF8165CDCAAFC6E0", "wallet v5 r1"},
    {"9CEC5155DCB2B37716C032C5EF85947C01E32C4405A2611EE8D1122AFFF0E0C1", "highload v1"},
    {"DE7D8832DDC838811F940EF0CECBBC95C6CD2CEF83E9D22ABCE5E1A1DBA5638A", "highload v2"},
  };
  auto hex = code_hash.to_hex();
  auto it = known_wallets.find(hex);
  return it != known_wallets.end() ? it->second : "";
}

static std::string detect_account_model(const ParsedAccountState& parsed,
                                        const std::string& wallet_type) {
  if (!wallet_type.empty()) {
    return "default.wallet.v1";
  }
  if (parsed.state_str == "uninitialized") {
    return "state.uninitialized";
  }
  if (parsed.state_str == "frozen") {
    return "state.frozen";
  }
  if (parsed.state_str == "active") {
    return parsed.code_cell.not_null() ? "advanced.unknown" : "state.active";
  }
  return "unknown";
}

static std::string detect_authorization_version(const std::string& wallet_type) {
  if (!wallet_type.empty()) {
    return "auth.external_message.ed25519.v1";
  }
  return "unknown";
}

static std::string build_account_capability_json(const std::string& address,
                                                 const ParsedAccountState& parsed,
                                                 const std::string& account_model,
                                                 const std::string& authorization_version,
                                                 bool supports_sponsorship,
                                                 bool include_sponsorship) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.capability\""
     << ",\"address\":" << td::JsonString(td::Slice(address))
     << ",\"account_model\":" << td::JsonString(td::Slice(account_model))
     << ",\"authorization_version\":" << td::JsonString(td::Slice(authorization_version))
     << ",\"supports_delegation\":false"
     << ",\"supports_sessions\":false"
     << ",\"supports_agents\":false"
     << ",\"account_state\":" << td::JsonString(td::Slice(parsed.state_str))
     << ",\"revision\":1";
  if (include_sponsorship) {
    sb << ",\"supports_sponsorship\":" << (supports_sponsorship ? "true" : "false");
  }
  sb << "}";
  return sb.as_cslice().str();
}

void JsonRpcServer::handle_getAccountCapability(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;
  auto include_experimental_r = params.get_optional_bool_field("include_experimental", false);
  bool include_experimental = include_experimental_r.is_ok() && include_experimental_r.ok();

  auto self_id = actor_id(this);
  auto do_get_account = [addr, addr_str = std::move(addr_str), include_experimental, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, addr_str = std::move(addr_str), include_experimental,
             req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise_inner.set_value(make_json_error(
                    -32603, PSTRING() << "getAccountState: " << R.error(), req_id_inner));
                return;
              }
              auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
                  R.move_as_ok(), true);
              if (F.is_error()) {
                promise_inner.set_value(make_json_error(
                    -32603, PSTRING() << "parse accountState: " << F.error(), req_id_inner));
                return;
              }
              auto f = F.move_as_ok();
              auto parsed_r = ParsedAccountState::parse(f, addr);
              if (parsed_r.is_error()) {
                promise_inner.set_value(make_json_error(
                    -32603, PSTRING() << "parse account: " << parsed_r.error(), req_id_inner));
                return;
              }
              auto parsed = parsed_r.move_as_ok();
              std::string wallet_type;
              if (parsed.code_cell.not_null()) {
                wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
              }
              auto account_model = detect_account_model(parsed, wallet_type);
              auto authorization_version = detect_authorization_version(wallet_type);
              promise_inner.set_value(make_json_ok(
                  build_account_capability_json(addr_str, parsed, account_model,
                                                authorization_version,
                                                false, include_experimental),
                  req_id_inner));
            }));
  };

  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          do_get_account(std::move(lb_r.move_as_ok()->id_), std::move(req_id), std::move(promise));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc_r.error(), req_id));
            return;
          }
          do_get_account(std::move(mc_r.move_as_ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

void JsonRpcServer::handle_getAccountDelegations(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  promise.set_value(make_json_error(
      -32603,
      "FEATURE_DEFERRED: getAccountDelegations requires frozen permission-state semantics before implementation",
      req_id));
}

void JsonRpcServer::handle_getAccountSessions(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  promise.set_value(make_json_error(
      -32603,
      "FEATURE_DEFERRED: getAccountSessions requires frozen permission-state semantics before implementation",
      req_id));
}

void JsonRpcServer::handle_getAccountAgents(td::JsonObject &params, std::string req_id,
                                            td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  promise.set_value(make_json_error(
      -32603,
      "FEATURE_DEFERRED: getAccountAgents requires frozen permission-state semantics before implementation",
      req_id));
}

void JsonRpcServer::handle_getWalletInformation(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 req_seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto saved_wc = block_id->workchain_;
    auto saved_shard = block_id->shard_;
    auto saved_seqno = block_id->seqno_;
    auto saved_root = block_id->root_hash_;
    auto saved_file = block_id->file_hash_;

    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, block_id_wc = saved_wc, block_id_shard = saved_shard,
             block_id_seqno = saved_seqno, block_id_root = saved_root,
             block_id_file = saved_file,
             req_id_inner = std::move(req_id_inner), self_id,
             promise_inner = std::move(promise_inner)](
                td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }

      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed_r = ParsedAccountState::parse(f, addr);
      if (parsed_r.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed_r.error(), req_id_inner));
        return;
      }
      auto parsed = parsed_r.move_as_ok();

      std::string wallet_type;
      if (parsed.code_cell.not_null()) {
        wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
      }
      bool is_wallet = !wallet_type.empty();

      if (!is_wallet) {
        promise_inner.set_value(make_json_ok(
            build_wallet_json(false, parsed.balance, parsed.state_str, "",
                              -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
            req_id_inner));
        return;
      }

      td::int64 method_id = (td::crc16(td::Slice("seqno")) & 0xffff) | 0x10000;
      vm::CellBuilder cb;
      vm::Stack empty_stack;
      empty_stack.serialize(cb);
      auto params_boc = vm::std_boc_serialize(cb.finalize());
      if (params_boc.is_error()) {
        promise_inner.set_value(make_json_ok(
            build_wallet_json(true, parsed.balance, parsed.state_str, wallet_type,
                              -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
            req_id_inner));
        return;
      }

      auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
          block_id_wc, block_id_shard, block_id_seqno, block_id_root, block_id_file);
      auto run_inner = tos::serialize_tl_object(
          tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
              0x04, std::move(blk),
              tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                  addr.workchain, addr.addr),
              method_id, params_boc.move_as_ok()),
          true);
      auto run_query = tos::serialize_tl_object(
          tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(run_inner)), true);

      td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
          std::move(run_query),
          td::PromiseCreator::lambda(
              [balance = parsed.balance, account_state = parsed.state_str,
               last_lt = parsed.last_trans_lt, last_hash = parsed.last_trans_hash_b64,
               wallet_type = std::move(wallet_type),
               req_id_inner = std::move(req_id_inner), promise_inner = std::move(promise_inner)](
                  td::Result<td::BufferSlice> R) mutable {
        td::int32 seqno = -1;
        if (R.is_ok()) {
          auto rr = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (rr.is_ok()) {
            auto rr_val = rr.move_as_ok();
            if (rr_val->exit_code_ == 0 && !rr_val->result_.empty()) {
              auto cell = vm::std_boc_deserialize(rr_val->result_.as_slice());
              if (cell.is_ok()) {
                auto stk = td::make_ref<vm::Stack>();
                auto result_cell = cell.move_as_ok();
                vm::CellSlice cs = vm::load_cell_slice(result_cell);
                if (stk.write().deserialize(cs) && stk->depth() > 0 && stk->at(0).is_int()) {
                  seqno = static_cast<td::int32>(stk->at(0).as_int()->to_long());
                }
              }
            }
          }
        }
        promise_inner.set_value(make_json_ok(
            build_wallet_json(true, balance, account_state, wallet_type,
                              seqno, last_lt, last_hash),
            req_id_inner));
      }));
    }));
  };

  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), req_seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc.error(), req_id));
            return;
          }
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

}  // namespace tos
