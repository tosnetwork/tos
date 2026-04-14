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

namespace tos {

// ─── getAddressInformation ──────────────────────────────────────────────

void JsonRpcServer::handle_getAddressInformation(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
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
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
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
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_address_info_json(), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
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
    // Step 1b: getMasterchainInfo to get latest block
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

void JsonRpcServer::handle_getExtendedAddressInformation(td::JsonObject &params, std::string req_id,
                                                         td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
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
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
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
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_extended_info_json(addr_str), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
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
    // Step 1b: getMasterchainInfo to get latest block
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

// ─── Wallet info JSON builder ─────────────────────────────────────────────

static std::string build_wallet_json(bool is_wallet, td::int64 balance,
                                     const std::string& account_state,
                                     const std::string& wallet_type,
                                     td::int32 seqno,
                                     td::uint64 last_lt, const std::string& last_hash_b64,
                                     td::int64 wallet_id = -1) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"query.fees\""
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

// Known wallet code hashes -> type name strings
static std::string detect_wallet_type(const vm::CellHash& code_hash) {
  static const std::map<std::string, std::string> known_wallets = {
    {"89c890a6c9b5a3828b38570a93dfc93c792ee9147933de8f21f5840ae19ab1aa", "wallet v1 r1"},
    {"27b5063ebdb6e5ecec073f57451a4be095eb68777496b65449b1b49fa09a43d9", "wallet v1 r2"},
    {"1f08ebe871907c8b60aa1bb9c22a54cb095d1dc0e007a3d7af827d1c4de23910", "wallet v1 r3"},
    {"8369fdda46a532a8302037d955d92d7a3308422eadf0074c497cecd209832c3a", "wallet v2 r1"},
    {"9264711341ab55499665d16b4589a148ed6ab8a4aed3ae9fcf805295eee7b927", "wallet v2 r2"},
    {"f475ec633ea8ec25b6872878b95996aeea061198bd1c86180d3984ea7e1e6fb4", "wallet v3 r1"},
    {"09be881beffe710d6bb4bd030a2506bef85c10ff1ac44df93b0b29282945916f", "wallet v3 r2"},
    {"6b5fd33048d2db82650b36f47ced9714a1c0b573aa08447e23f96629364dda2a", "wallet v4 r1"},
    {"288014a04d551904d623c826512ffeb16ad4df6130195ea537050b35207e5fc3", "wallet v4 r2"},
    {"7afa0eacbaf9e9eaa19ae93e61354540c9335b52f1add44e7a8e2d9089212b3e", "wallet v5 r1"},
    {"643a1ab8e96cb40b9cd92599ea295a591d6c12730d53ce77a447e1fc1c9a8b41", "nominator pool v1"},
    // tosctl verified hashes (may overlap; kept for belt-and-suspenders)
    {"84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599", "wallet v3 r2"},
    {"feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0", "wallet v4 r2"},
    {"20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f", "wallet v5 r1"},
  };
  auto hex = code_hash.to_hex();
  auto it = known_wallets.find(hex);
  return it != known_wallets.end() ? it->second : "";
}

void JsonRpcServer::handle_getWalletInformation(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 req_seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState, detect wallet, query wallet seqno
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

      // Detect wallet type from code hash
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

      // Is a wallet — query seqno via runGetMethod
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
    // Step 1a: lookupBlock to resolve seqno to full block ID
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
    // Step 1b: getMasterchainInfo to get latest block
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

// ─── getAddressBalance ──────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressBalance(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return balance
  auto do_get_account = [addr, self_id](
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
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
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
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(
          PSTRING() << "\"" << parsed.ok().balance << "\"", req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
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
    // Step 1b: getMasterchainInfo to get latest block
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

// ─── getAddressState ────────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressState(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return state string
  auto do_get_account = [addr, self_id](
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
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
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
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      auto state_json = PSTRING() << td::JsonString(td::Slice(parsed.ok().state_str));
      promise_inner.set_value(make_json_ok(state_json, req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
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
    // Step 1b: getMasterchainInfo to get latest block
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

// ─── getTokenData ──────────────────────────────────────────────────────────
// Convenience method: tries get_jetton_data, falls back to get_nft_data.

void JsonRpcServer::handle_getTokenData(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter (query token data at a specific MC block)
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  // Serialize empty stack for runSmcMethod params
  vm::CellBuilder cb;
  vm::Stack empty_stack;
  if (!empty_stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }
  auto params_boc = std::make_shared<td::BufferSlice>(params_boc_r.move_as_ok());

  // Step 2 lambda: given a resolved block, run get_jetton_data / get_nft_data
  auto do_query_token = [addr, params_boc, req_id = std::move(req_id),
                         self_id = actor_id(this), promise = std::move(promise)](
      td::int32 blk_wc, td::int64 blk_shard, td::int32 blk_seqno,
      td::Bits256 blk_root, td::Bits256 blk_file) mutable {

        auto saved_wc = blk_wc;
        auto saved_shard = blk_shard;
        auto saved_seqno = blk_seqno;
        auto saved_root = blk_root;
        auto saved_file = blk_file;

        // Step 2: try get_jetton_data
        td::int64 jetton_method_id = (td::crc16(td::Slice("get_jetton_data")) & 0xffff) | 0x10000;
        auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
            blk_wc, blk_shard, blk_seqno, blk_root, blk_file);
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(blk),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                jetton_method_id, params_boc->clone()),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, params_boc, self_id,
                 saved_wc, saved_shard, saved_seqno, saved_root, saved_file,
                 req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          // Helper: parse address from a stack slice entry
          auto parse_address_from_slice = [](const vm::StackEntry& entry) -> std::string {
            if (entry.type() != vm::StackEntry::t_slice) return "";
            auto cs = entry.as_slice();
            if (cs->size() < 2) return "";
            auto tag = cs->prefetch_ulong(2);
            if (tag == 0) return "";      // addr_none
            if (tag != 2) return "";      // not addr_std
            vm::CellSlice tmp(*cs);
            tmp.advance(2);
            if (tmp.size() < 1) return "";
            auto has_anycast = tmp.fetch_ulong(1);
            if (has_anycast) {
              if (tmp.size() < 5) return "";
              auto depth = (int)tmp.fetch_ulong(5);
              tmp.advance(depth);
            }
            if (tmp.size() < 8 + 256) return "";
            auto workchain = (td::int8)tmp.fetch_long(8);
            td::Bits256 address;
            tmp.fetch_bits_to(address.bits(), 256);
            block::StdAddress a(workchain, address);
            a.bounceable = true;
            a.testnet = false;
            return a.rserialize(true);
          };

          // Helper: serialize a cell stack entry to base64 BOC
          auto cell_to_b64 = [](const vm::StackEntry& entry) -> std::string {
            if (!entry.is_cell()) return "";
            auto boc = vm::std_boc_serialize(entry.as_cell());
            if (boc.is_error()) return "";
            return td::base64_encode(boc.ok().as_slice());
          };

          // Try to parse jetton result
          if (R.is_ok()) {
            auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R.move_as_ok(), true);
            if (F.is_ok()) {
              auto f = F.move_as_ok();
              if (f->exit_code_ == 0 && !f->result_.empty()) {
                auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
                if (cell_r.is_ok()) {
                  auto stk = td::make_ref<vm::Stack>();
                  auto result_cell = cell_r.move_as_ok();
                  vm::CellSlice cs = vm::load_cell_slice(result_cell);
                  if (stk.write().deserialize(cs) && stk->depth() >= 5) {
                    auto& total_supply_e = stk->at(0);
                    auto& mintable_e = stk->at(1);
                    auto& admin_addr_e = stk->at(2);
                    auto& content_e = stk->at(3);
                    auto& wallet_code_e = stk->at(4);

                    if (total_supply_e.is_int()) {
                      auto total_supply_str = total_supply_e.as_int()->to_dec_string();
                      bool mintable = mintable_e.is_int() && mintable_e.as_int()->to_long() != 0;
                      auto admin_addr_str = parse_address_from_slice(admin_addr_e);
                      auto content_b64 = cell_to_b64(content_e);
                      auto wallet_code_b64 = cell_to_b64(wallet_code_e);

                      td::StringBuilder sb;
                      sb << "{\"@type\":\"jetton.data\""
                         << ",\"total_supply\":" << td::JsonString(td::Slice(total_supply_str))
                         << ",\"mintable\":" << (mintable ? "true" : "false")
                         << ",\"admin_address\":" << td::JsonString(td::Slice(admin_addr_str))
                         << ",\"jetton_content\":" << td::JsonString(td::Slice(content_b64))
                         << ",\"jetton_wallet_code\":" << td::JsonString(td::Slice(wallet_code_b64))
                         << "}";
                      promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                      return;
                    }
                  }
                }
              }
            }
          }

          // Jetton failed — try get_nft_data
          auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
              saved_wc, saved_shard, saved_seqno, saved_root, saved_file);
          td::int64 nft_method_id = (td::crc16(td::Slice("get_nft_data")) & 0xffff) | 0x10000;
          auto nft_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                  0x04, std::move(blk),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  nft_method_id, params_boc->clone()),
              true);
          auto nft_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(nft_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(nft_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), promise = std::move(promise),
                   parse_address_from_slice, cell_to_b64](
                      td::Result<td::BufferSlice> R2) mutable {
            if (R2.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTokenData: both get_jetton_data and get_nft_data failed: "
                            << R2.error(), req_id));
              return;
            }
            auto F2 = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R2.move_as_ok(), true);
            if (F2.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse NFT runMethodResult: " << F2.error(), req_id));
              return;
            }
            auto f2 = F2.move_as_ok();
            if (f2->exit_code_ != 0) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTokenData: contract is neither Jetton nor NFT (get_nft_data exit_code="
                            << f2->exit_code_ << ")", req_id));
              return;
            }
            if (f2->result_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: get_nft_data returned empty result", req_id));
              return;
            }

            auto cell_r = vm::std_boc_deserialize(f2->result_.as_slice());
            if (cell_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: failed to deserialize NFT result", req_id));
              return;
            }
            auto stk = td::make_ref<vm::Stack>();
            auto result_cell = cell_r.move_as_ok();
            vm::CellSlice cs = vm::load_cell_slice(result_cell);
            if (!stk.write().deserialize(cs) || stk->depth() < 5) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: get_nft_data returned fewer than 5 stack entries", req_id));
              return;
            }

            auto& init_e = stk->at(0);
            auto& index_e = stk->at(1);
            auto& collection_e = stk->at(2);
            auto& owner_e = stk->at(3);
            auto& content_e = stk->at(4);

            bool init_val = init_e.is_int() && init_e.as_int()->to_long() != 0;
            td::int64 index_val = index_e.is_int() ? index_e.as_int()->to_long() : 0;
            auto collection_str = parse_address_from_slice(collection_e);
            auto owner_str = parse_address_from_slice(owner_e);
            auto content_b64 = cell_to_b64(content_e);

            td::StringBuilder sb;
            sb << "{\"@type\":\"nft.data\""
               << ",\"init\":" << (init_val ? "true" : "false")
               << ",\"index\":" << index_val
               << ",\"collection_address\":" << td::JsonString(td::Slice(collection_str))
               << ",\"owner_address\":" << td::JsonString(td::Slice(owner_str))
               << ",\"individual_content\":" << td::JsonString(td::Slice(content_b64))
               << "}";
            promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
          }));
        }));
  };  // end of do_query_token lambda

  // Step 1: resolve block (by seqno or latest)
  auto self_id = actor_id(this);
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            // Cannot proceed — just drop the promise (timeout will handle it)
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_query_token(lb->id_->workchain_, lb->id_->shard_, lb->id_->seqno_,
                         lb->id_->root_hash_, lb->id_->file_hash_);
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            return;
          }
          auto mc = mc_r.move_as_ok();
          do_query_token(mc->last_->workchain_, mc->last_->shard_, mc->last_->seqno_,
                         mc->last_->root_hash_, mc->last_->file_hash_);
        });
  }
}

}  // namespace tos
