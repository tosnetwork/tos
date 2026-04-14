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
#include "block/check-proof.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include <limits>

namespace tos {

// ─── ParsedAccountState implementation ─────────────────────────────────

td::Result<ParsedAccountState> ParsedAccountState::parse(
    tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
    const block::StdAddress& addr) {
  ParsedAccountState res;

  if (f->id_) {
    res.blk_workchain = f->id_->workchain_;
    res.blk_shard = f->id_->shard_;
    res.blk_seqno = f->id_->seqno_;
    res.blk_root_hash_b64 = td::base64_encode(f->id_->root_hash_.as_slice());
    res.blk_file_hash_b64 = td::base64_encode(f->id_->file_hash_.as_slice());
  }

  auto blk_id = tos::create_block_id(f->id_);
  auto shard_blk_id = tos::create_block_id(f->shardblk_);
  block::AccountState as;
  as.blk = blk_id;
  as.shard_blk = shard_blk_id;
  as.shard_proof = f->shard_proof_.clone();
  as.proof = f->proof_.clone();
  as.state = f->state_.clone();
  auto info_r = as.validate(blk_id, addr);
  if (info_r.is_ok()) {
    auto info = info_r.move_as_ok();
    res.last_trans_lt = info.last_trans_lt;
    res.last_trans_hash_b64 = td::base64_encode(info.last_trans_hash.as_slice());
    res.sync_utime = info.gen_utime;

    if (info.root.not_null()) {
      block::gen::Account::Record_account account;
      if (tlb::unpack_cell(info.root, account)) {
        block::gen::StorageInfo::Record storage_info;
        if (tlb::csr_unpack(account.storage_stat, storage_info)) {
          res.storage_last_paid = storage_info.last_paid;
          block::gen::StorageUsed::Record storage_used;
          if (tlb::csr_unpack(storage_info.used, storage_used)) {
            unsigned long long u = 0;
            u |= res.storage_used.cells = block::tlb::t_VarUInteger_7.as_uint(*storage_used.cells);
            u |= res.storage_used.bits = block::tlb::t_VarUInteger_7.as_uint(*storage_used.bits);
            if (u == std::numeric_limits<td::uint64>::max()) {
              return td::Status::Error("Failed to unpack StorageStat");
            }
          }
        }

        block::gen::AccountStorage::Record storage;
        if (tlb::csr_unpack(account.storage, storage)) {
          auto balance_cs = storage.balance.write();
          auto coins = block::tlb::t_Tomis.as_integer_skip(balance_cs);
          if (coins.not_null()) res.balance = coins->to_long();
          res.extra_currencies_cell = storage.balance->prefetch_ref();

          auto tag = block::gen::t_AccountState.get_tag(*storage.state);
          if (tag == block::gen::AccountState::account_active) {
            res.state_str = "active";
            block::gen::AccountState::Record_account_active active;
            if (tlb::csr_unpack(storage.state, active)) {
              res.state_cell = vm::CellBuilder().append_cellslice(active.x).finalize();
              block::gen::StateInit::Record si;
              if (tlb::csr_unpack(active.x, si)) {
                si.code->prefetch_maybe_ref(res.code_cell);
                si.data->prefetch_maybe_ref(res.data_cell);
                if (res.code_cell.not_null()) {
                  auto boc = vm::std_boc_serialize(res.code_cell);
                  if (boc.is_ok()) res.code_b64 = td::base64_encode(boc.ok().as_slice());
                }
                if (res.data_cell.not_null()) {
                  auto boc = vm::std_boc_serialize(res.data_cell);
                  if (boc.is_ok()) res.data_b64 = td::base64_encode(boc.ok().as_slice());
                }
              }
            }
          } else if (tag == block::gen::AccountState::account_frozen) {
            res.state_str = "frozen";
            block::gen::AccountState::Record_account_frozen frozen;
            if (tlb::csr_unpack(storage.state, frozen)) {
              res.frozen_hash = td::base64_encode(frozen.state_hash.as_slice());
            }
          }
        }
      }
    }
  }
  return res;
}

std::string ParsedAccountState::to_address_info_json() const {
  return PSTRING()
      << "{\"@type\":\"raw.fullAccountState\""
      << ",\"balance\":" << td::JsonString(td::Slice(PSTRING() << balance))
      << ",\"code\":" << td::JsonString(td::Slice(code_b64))
      << ",\"data\":" << td::JsonString(td::Slice(data_b64))
      << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
      << ",\"lt\":\"" << last_trans_lt << "\""
      << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
      << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << blk_workchain
      << ",\"shard\":\"" << blk_shard << "\""
      << ",\"seqno\":" << blk_seqno
      << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
      << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
      << ",\"sync_utime\":" << sync_utime
      << ",\"extra_currencies\":[]"
      << ",\"state\":" << td::JsonString(td::Slice(state_str))
      << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash))
      << "}";
}

std::string ParsedAccountState::to_extended_info_json(const std::string& addr_str) const {
  return PSTRING()
      << "{\"@type\":\"fullAccountState\""
      << ",\"address\":{\"@type\":\"accountAddress\",\"account_address\":"
      << td::JsonString(td::Slice(addr_str)) << "}"
      << ",\"balance\":" << balance
      << ",\"extra_currencies\":[]"
      << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
      << ",\"lt\":\"" << last_trans_lt << "\""
      << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
      << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << blk_workchain
      << ",\"shard\":\"" << blk_shard << "\""
      << ",\"seqno\":" << blk_seqno
      << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
      << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
      << ",\"sync_utime\":" << sync_utime
      << ",\"account_state\":{\"@type\":\"raw.accountState\""
      << ",\"code\":" << td::JsonString(td::Slice(code_b64))
      << ",\"data\":" << td::JsonString(td::Slice(data_b64))
      << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash)) << "}"
      << ",\"revision\":0}";
}

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

// Known wallet code hashes -> type name strings
static std::string detect_wallet_type(const vm::CellHash& code_hash) {
  static const std::map<std::string, std::string> known_wallets = {
    // TON-originated wallet code hashes (uppercase — to_hex() returns uppercase)
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
    // tosctl verified hashes
    {"84DAFA449F98A6987789BA232358072BC0F76DC4524002A5D0918B9A75D2D599", "wallet v3 r2"},
    {"FEB5FF6820E2FF0D9483E7E0D62C817D846789FB4AE580C878866D959DABD5C0", "wallet v4 r2"},
    {"20834B7B72B112147E1B2FB457B84E74D1A30F04F737D4F62A668E9552D2B72F", "wallet v5 r1"},
    // TOS-compiled wallet code hashes (from crypto/smartcont/auto/)
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
              promise.set_value(make_json_error(409,
                  "Smart contract is not a Jetton or NFT", req_id));
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
