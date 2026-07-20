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
#include "block/workchain-execution-dispatch.h"
#include "td/utils/crypto.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContract.h"
#include "vm/dict.h"
#include "vm/cellops.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "validator/impl/config.hpp"
#include <array>
#include <limits>
#include <optional>

namespace tos {

static constexpr size_t kMaxBocSize = 64 * 1024;  // 64 KiB

void JsonRpcServer::handle_sendBoc(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise) {
  auto boc_r = params.get_required_string_field("boc");
  if (boc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'boc' parameter", req_id));
    return;
  }
  auto boc_b64 = boc_r.move_as_ok();
  auto decoded_r = td::base64_decode(boc_b64);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'boc'", req_id));
    return;
  }
  if (decoded_r.ok().size() > kMaxBocSize) {
    promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
    return;
  }
  auto body = td::BufferSlice(decoded_r.move_as_ok());

  // Construct liteServer.sendMessage(body)
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(std::move(data), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(PSTRING() << "{\"status\":" << status->status_ << "}", req_id));
      });
}

static td::Result<td::Ref<vm::Cell>> parse_optional_boc_field(td::JsonObject& params, const char* name) {
  auto value_r = params.get_optional_string_field(td::Slice{name});
  if (value_r.is_error() || value_r.ok().empty()) {
    return td::Ref<vm::Cell>();
  }
  auto decoded_r = td::base64_decode(value_r.ok());
  if (decoded_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid base64 in '" << name << "'");
  }
  if (decoded_r.ok().size() > kMaxBocSize) {
    return td::Status::Error("BOC payload exceeds maximum allowed size");
  }
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded_r.ok()));
  if (cell_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid BOC in '" << name << "'");
  }
  auto cell = cell_r.move_as_ok();
  // Reject special root cells from
  // attacker-supplied BOCs at the JSON-RPC boundary. Downstream helpers
  // (GenericAccount / SmartContract / runGetMethod stack deserialize)
  // call bare `load_cell_slice_ref()` and throw on PrunedBranch /
  // Library / Merkle* cells, crashing the daemon. We probe via the
  // special-aware loader; the load itself is also caught defensively.
  if (cell.not_null()) {
    try {
      bool special = false;
      (void)vm::load_cell_slice_special(cell, special);
      if (special) {
        return td::Status::Error(PSTRING() << "BOC root in '" << name << "' is a special cell");
      }
    } catch (...) {
      return td::Status::Error(PSTRING() << "BOC root in '" << name << "' is unloadable");
    }
  }
  return cell;
}

static td::RefInt256 estimate_compute_threshold(const block::GasLimitsPrices& cfg) {
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  if (cfg.gas_limit > cfg.flat_gas_limit) {
    return td::rshift(gas_price256 * (cfg.gas_limit - cfg.flat_gas_limit), 16, 1) +
           td::make_refint(cfg.flat_gas_price);
  }
  return td::make_refint(cfg.flat_gas_price);
}

static td::uint64 estimate_gas_bought_for(td::RefInt256 nanotomis, td::RefInt256 max_gas_threshold,
                                          const block::GasLimitsPrices& cfg) {
  if (nanotomis.is_null() || sgn(nanotomis) < 0) {
    return 0;
  }
  if (nanotomis >= max_gas_threshold) {
    return cfg.gas_limit;
  }
  if (nanotomis < cfg.flat_gas_price) {
    return 0;
  }
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  auto res = td::div((std::move(nanotomis) - cfg.flat_gas_price) << 16, gas_price256);
  return res->to_long() + cfg.flat_gas_limit;
}

static td::RefInt256 estimate_compute_gas_price(td::uint64 gas_used, const block::GasLimitsPrices& cfg) {
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  return gas_used <= cfg.flat_gas_limit
             ? td::make_refint(cfg.flat_gas_price)
             : td::rshift(gas_price256 * (gas_used - cfg.flat_gas_limit), 16, 1) + cfg.flat_gas_price;
}

static vm::GasLimits estimate_compute_gas_limits(td::RefInt256 balance, const block::GasLimitsPrices& cfg) {
  vm::GasLimits res;
  res.gas_max = estimate_gas_bought_for(balance, estimate_compute_threshold(cfg), cfg);
  res.gas_credit = 0;
  res.gas_limit = estimate_gas_bought_for(td::make_refint(0), estimate_compute_threshold(cfg), cfg);
  res.gas_credit = std::min(static_cast<td::int64>(cfg.gas_credit), static_cast<td::int64>(res.gas_max));
  return res;
}

static td::Result<td::int64> estimate_calc_fwd_fees(td::Ref<vm::Cell> list, block::MsgPrices** msg_prices,
                                                    bool is_masterchain) try {
  // Structured errors handle missing next-ref and bad tags, but
  // `vm::load_cell_slice`
  // still throws on PrunedBranch / MerkleProof / MerkleUpdate / Library
  // cells (see crypto/vm/cells/CellSlice.cpp:1139). Production action
  // processing handles this with `load_cell_slice_special` (see
  // crypto/block/transaction.cpp:2295). Switch this entire function to
  // `load_cell_slice_special` + `is_special` rejects, and wrap the body
  // in a function-try-block so any remaining VmError from cell traversal
  // is converted to an RPC error rather than crashing the daemon.
  td::int64 res = 0;
  std::vector<td::Ref<vm::Cell>> actions;
  int n = 0;
  int max_actions = 20;
  while (true) {
    actions.push_back(list);
    bool special = false;
    auto cs = vm::load_cell_slice_special(std::move(list), special);
    if (special) {
      return td::Status::Error("action list invalid: traversal hit a special cell");
    }
    if (!cs.size_ext()) {
      break;
    }
    if (!cs.have_refs()) {
      return td::Status::Error("action list invalid: entry found with data but no next reference");
    }
    list = cs.prefetch_ref();
    if (++n > max_actions) {
      return td::Status::Error(PSTRING() << "action list too long: more than " << max_actions << " actions");
    }
  }
  for (int i = n - 1; i >= 0; --i) {
    bool special = false;
    vm::CellSlice cs = vm::load_cell_slice_special(actions[i], special);
    if (special) {
      return td::Status::Error("estimate_fee: action cell is special");
    }
    // The previous code asserted with
    // `CHECK(cs.fetch_ref().not_null())` and `CHECK(tag >= 0)`. Both refs
    // and tags here come from VM-produced action cells under attacker
    // control via `estimateFee` — a malformed c5 list would crash the
    // validator daemon. Mirror the defensive style of the production
    // action phase at crypto/block/transaction.cpp:2257-2330: return a
    // structured RPC error instead.
    if (cs.fetch_ref().is_null()) {
      return td::Status::Error("estimate_fee: action cell missing next-ref");
    }
    int tag = block::gen::t_OutAction.get_tag(cs);
    if (tag < 0) {
      return td::Status::Error("estimate_fee: action cell has unrecognized tag");
    }
    switch (tag) {
      case block::gen::OutAction::action_set_code:
        return td::Status::Error("estimate_fee: action_set_code unsupported");
      case block::gen::OutAction::action_send_msg: {
        block::gen::OutAction::Record_action_send_msg act_rec;
        if (!tlb::unpack_exact(cs, act_rec) || (act_rec.mode & ~0xf3) || (act_rec.mode & 0xc0) == 0xc0) {
          return td::Status::Error("estimate_fee: can't parse send_msg");
        }
        block::gen::MessageRelaxed::Record msg;
        if (!tlb::type_unpack_cell(act_rec.out_msg, block::gen::t_MessageRelaxed_Any, msg)) {
          return td::Status::Error("estimate_fee: can't parse send_msg");
        }

        bool dest_is_masterchain = false;
        if (block::gen::t_CommonMsgInfoRelaxed.get_tag(*msg.info) == block::gen::CommonMsgInfoRelaxed::int_msg_info) {
          block::gen::CommonMsgInfoRelaxed::Record_int_msg_info info;
          if (!tlb::csr_unpack(msg.info, info)) {
            return td::Status::Error("estimate_fee: can't parse send_msg");
          }
          auto dest_addr = info.dest;
          if (!dest_addr->prefetch_ulong(1)) {
            return td::Status::Error("estimate_fee: messages with external addresses are unsupported");
          }
          int addr_tag = block::gen::t_MsgAddressInt.get_tag(*dest_addr);
          if (addr_tag == block::gen::MsgAddressInt::addr_std) {
            block::gen::MsgAddressInt::Record_addr_std recs;
            if (!tlb::csr_unpack(dest_addr, recs)) {
              return td::Status::Error("estimate_fee: can't parse send_msg");
            }
            dest_is_masterchain = recs.workchain_id == tos::masterchainId;
          }
        }

        vm::CellStorageStat sstat;
        sstat.add_used_storage(msg.init, true, 3);
        sstat.add_used_storage(msg.body, true, 3);
        res += msg_prices[is_masterchain || dest_is_masterchain]->compute_fwd_fees(sstat.cells, sstat.bits);
        break;
      }
      case block::gen::OutAction::action_reserve_currency:
        continue;
    }
  }
  return res;
} catch (const vm::VmError& e) {
  // VM cell traversal can throw
  // for reasons not caught by the per-site special-cell check (e.g. a
  // CellSlice operation on a malformed cell). Convert to RPC error.
  return td::Status::Error(PSTRING() << "estimate_fee: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  return td::Status::Error(PSTRING() << "estimate_fee: exception: " << e.what());
} catch (...) {
  return td::Status::Error("estimate_fee: unknown exception during action parsing");
}

static std::string build_estimate_fee_json(td::int64 in_fwd_fee, td::int64 storage_fee,
                                           td::int64 gas_fee, td::int64 fwd_fee) {
  return PSTRING()
      << "{\"@type\":\"query.fees\""
      << ",\"source_fees\":{\"@type\":\"fees\""
      << ",\"in_fwd_fee\":" << in_fwd_fee
      << ",\"storage_fee\":" << storage_fee
      << ",\"gas_fee\":" << gas_fee
      << ",\"fwd_fee\":" << fwd_fee << "}"
      << ",\"destination_fees\":[]}";
}

struct InitialIntentInput {
  std::string address;
  std::string body_b64;
  std::string init_code_b64;
  std::string init_data_b64;
  std::string account_model;
  std::string authorization_version;
  std::string signer;
  std::string submitter;
  std::string fee_payer;
  std::string delegation_ref;
};

static std::string extract_delegation_ref(td::JsonObject& obj) {
  for (auto key : {"delegation_ref", "delegation", "delegation_grant"}) {
    auto r = obj.get_optional_string_field(td::Slice{key});
    if (r.is_ok() && !r.ok().empty()) {
      return r.ok();
    }
  }
  return "";
}

static bool has_non_delegation_permission_reference(td::JsonObject& obj) {
  static const std::array<const char*, 5> keys = {
      "session", "session_capability", "session_ref",
      "agent", "agent_capability"
  };
  for (auto key : keys) {
    if (obj.has_field(td::Slice{key})) {
      return true;
    }
  }
  return false;
}

static td::Result<std::string> get_required_address_alias(td::JsonObject &params) {
  auto from_r = params.get_optional_string_field("from");
  if (from_r.is_ok() && !from_r.ok().empty()) {
    return from_r.ok();
  }
  auto addr_r = params.get_optional_string_field("address");
  if (addr_r.is_ok() && !addr_r.ok().empty()) {
    return addr_r.ok();
  }
  return td::Status::Error("Missing 'from' or 'address'");
}

static td::Result<td::Ref<vm::Cell>> parse_optional_boc_string(const std::string& value,
                                                               const char* name) {
  if (value.empty()) {
    return td::Ref<vm::Cell>();
  }
  auto decoded_r = td::base64_decode(value);
  if (decoded_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid base64 in '" << name << "'");
  }
  if (decoded_r.ok().size() > kMaxBocSize) {
    return td::Status::Error("BOC payload exceeds maximum allowed size");
  }
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded_r.ok()));
  if (cell_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid BOC in '" << name << "'");
  }
  auto cell = cell_r.move_as_ok();
  // Mirror parse_optional_boc_field. Downstream consumers — notably
  // GenericAccount::create_ext_message and SmartContract::send_external_msg
  // (declared noexcept, called from buildTransactionIntent /
  // getSigningPayload via build_external_message_cell) — invoke bare
  // load_cell_slice_ref(body) which throws on PrunedBranch / Library /
  // Merkle* roots. A throw from a noexcept function calls std::terminate,
  // killing the validator daemon.
  if (cell.not_null()) {
    try {
      bool special = false;
      (void)vm::load_cell_slice_special(cell, special);
      if (special) {
        return td::Status::Error(PSTRING() << "BOC root in '" << name << "' is a special cell");
      }
    } catch (...) {
      return td::Status::Error(PSTRING() << "BOC root in '" << name << "' is unloadable");
    }
  }
  return cell;
}

static td::Result<InitialIntentInput> parse_initial_intent_input(td::JsonObject &params) {
  InitialIntentInput out;

  if (has_non_delegation_permission_reference(params)) {
    return td::Status::Error(
        "FEATURE_DEFERRED: session/agent references are not yet supported");
  }
  out.delegation_ref = extract_delegation_ref(params);

  auto intent_v = params.extract_field("intent");
  if (intent_v.type() == td::JsonValue::Type::Object) {
    auto &intent = intent_v.get_object();
    if (has_non_delegation_permission_reference(intent)) {
      return td::Status::Error(
          "FEATURE_DEFERRED: session/agent references are not yet supported");
    }
    if (out.delegation_ref.empty()) {
      out.delegation_ref = extract_delegation_ref(intent);
    }
    auto from_r = get_required_address_alias(intent);
    if (from_r.is_error()) {
      return from_r.move_as_error();
    }
    out.address = from_r.move_as_ok();
    auto am_r = intent.get_optional_string_field("account_model");
    if (am_r.is_ok()) out.account_model = am_r.ok();
    auto av_r = intent.get_optional_string_field("authorization_version");
    if (av_r.is_ok()) out.authorization_version = av_r.ok();

    auto action_v = intent.extract_field("action");
    if (action_v.type() == td::JsonValue::Type::Object) {
      auto &action = action_v.get_object();
      auto addr_r = action.get_optional_string_field("address");
      if (addr_r.is_ok() && !addr_r.ok().empty()) out.address = addr_r.ok();
      auto body_r = action.get_required_string_field("body");
      if (body_r.is_error()) return td::Status::Error("Missing 'body' in action");
      out.body_b64 = body_r.ok();
      auto code_r = action.get_optional_string_field("init_code");
      if (code_r.is_ok()) out.init_code_b64 = code_r.ok();
      auto data_r = action.get_optional_string_field("init_data");
      if (data_r.is_ok()) out.init_data_b64 = data_r.ok();
    } else {
      auto body_r = intent.get_required_string_field("body");
      if (body_r.is_error()) return td::Status::Error("Missing 'body'");
      out.body_b64 = body_r.ok();
      auto code_r = intent.get_optional_string_field("init_code");
      if (code_r.is_ok()) out.init_code_b64 = code_r.ok();
      auto data_r = intent.get_optional_string_field("init_data");
      if (data_r.is_ok()) out.init_data_b64 = data_r.ok();
    }

    auto roles_v = intent.extract_field("authorization_roles");
    if (roles_v.type() == td::JsonValue::Type::Object) {
      auto &roles = roles_v.get_object();
      auto signer_r = roles.get_optional_string_field("signer");
      if (signer_r.is_ok()) out.signer = signer_r.ok();
      auto submitter_r = roles.get_optional_string_field("submitter");
      if (submitter_r.is_ok()) out.submitter = submitter_r.ok();
      auto fee_payer_r = roles.get_optional_string_field("fee_payer");
      if (fee_payer_r.is_ok()) out.fee_payer = fee_payer_r.ok();
    }
  } else {
    auto addr_r = get_required_address_alias(params);
    if (addr_r.is_error()) {
      return addr_r.move_as_error();
    }
    out.address = addr_r.move_as_ok();
    auto body_r = params.get_required_string_field("body");
    if (body_r.is_error()) {
      return td::Status::Error("Missing 'body'");
    }
    out.body_b64 = body_r.ok();
    auto code_r = params.get_optional_string_field("init_code");
    if (code_r.is_ok()) out.init_code_b64 = code_r.ok();
    auto data_r = params.get_optional_string_field("init_data");
    if (data_r.is_ok()) out.init_data_b64 = data_r.ok();
    auto am_r = params.get_optional_string_field("account_model");
    if (am_r.is_ok()) out.account_model = am_r.ok();
    auto av_r = params.get_optional_string_field("authorization_version");
    if (av_r.is_ok()) out.authorization_version = av_r.ok();
    auto signer_r = params.get_optional_string_field("signer");
    if (signer_r.is_ok()) out.signer = signer_r.ok();
    auto submitter_r = params.get_optional_string_field("submitter");
    if (submitter_r.is_ok()) out.submitter = submitter_r.ok();
    auto fee_payer_r = params.get_optional_string_field("fee_payer");
    if (fee_payer_r.is_ok()) out.fee_payer = fee_payer_r.ok();
  }

  if (out.body_b64.empty()) {
    return td::Status::Error("Missing 'body'");
  }
  if (out.signer.empty()) out.signer = out.address;
  if (out.submitter.empty()) out.submitter = out.address;
  if (out.fee_payer.empty()) out.fee_payer = out.address;
  if (out.account_model.empty()) out.account_model = "unknown";
  if (out.authorization_version.empty()) out.authorization_version = "unknown";
  if (out.fee_payer != out.signer) {
    return td::Status::Error(
        "FEATURE_DEFERRED: distinct fee_payer semantics are not supported in the initial implementation");
  }
  return out;
}

static std::string build_authorization_roles_json(const std::string& signer,
                                                  const std::string& submitter,
                                                  const std::string& fee_payer) {
  return PSTRING()
      << "{\"@type\":\"account.authorizationRoles\""
      << ",\"signer\":" << td::JsonString(td::Slice(signer))
      << ",\"submitter\":" << td::JsonString(td::Slice(submitter))
      << ",\"fee_payer\":" << td::JsonString(td::Slice(fee_payer))
      << ",\"is_self_submitted\":" << (signer == submitter ? "true" : "false")
      << ",\"is_self_paid\":" << (signer == fee_payer ? "true" : "false")
      << "}";
}

static std::string build_transaction_intent_json(const InitialIntentInput& in) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"transaction.intent\""
     << ",\"from\":" << td::JsonString(td::Slice(in.address))
     << ",\"account_model\":" << td::JsonString(td::Slice(in.account_model))
     << ",\"authorization_version\":" << td::JsonString(td::Slice(in.authorization_version))
     << ",\"action\":{\"@type\":\"transaction.action.externalMessage\""
     << ",\"address\":" << td::JsonString(td::Slice(in.address))
     << ",\"body\":" << td::JsonString(td::Slice(in.body_b64))
     << ",\"init_code\":" << td::JsonString(td::Slice(in.init_code_b64))
     << ",\"init_data\":" << td::JsonString(td::Slice(in.init_data_b64))
     << "}"
     << ",\"authorization_roles\":" << build_authorization_roles_json(in.signer, in.submitter, in.fee_payer)
     << ",\"fee_intent\":{\"@type\":\"transaction.feeIntent\""
     << ",\"mode\":" << td::JsonString(td::Slice(in.fee_payer == in.address ? "self_paid" : "third_party_requested"))
     << "}"
     << ",\"replay_protection\":{\"@type\":\"transaction.replayProtection\""
     << ",\"mode\":\"contract_defined\"}";
  if (!in.delegation_ref.empty()) {
    sb << ",\"delegation_ref\":" << td::JsonString(td::Slice(in.delegation_ref));
  }
  sb << "}";
  return sb.as_cslice().str();
}

static td::Result<td::Ref<vm::Cell>> build_external_message_cell(const InitialIntentInput& in) {
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(in.address))) {
    return td::Status::Error("Invalid address");
  }
  // Round 144 MEDIUM fix: addr_std uses an int8 workchain field
  // (range [-128, 127]).  StdAddress::parse_addr accepts the
  // wider int32 form, so an address like "128:<hex>" parsed
  // successfully and then GenericAccount::create_ext_message
  // hit MsgAddressInt::pack rejection followed by
  // CHECK(res.not_null()) — turning a single crafted address
  // into a daemon abort.  Reject out-of-int8 workchains here
  // before the addr_std encode.
  if (addr.workchain < -128 || addr.workchain > 127) {
    return td::Status::Error(
        PSTRING() << "Invalid address: workchain " << addr.workchain
                  << " is out of the addr_std int8 range [-128, 127]");
  }
  auto body_r = parse_optional_boc_string(in.body_b64, "body");
  if (body_r.is_error()) return body_r.move_as_error();
  if (body_r.ok().is_null()) return td::Status::Error("Missing 'body'");
  auto init_code_r = parse_optional_boc_string(in.init_code_b64, "init_code");
  if (init_code_r.is_error()) return init_code_r.move_as_error();
  auto init_data_r = parse_optional_boc_string(in.init_data_b64, "init_data");
  if (init_data_r.is_error()) return init_data_r.move_as_error();

  td::Ref<vm::Cell> new_state;
  auto init_code = init_code_r.move_as_ok();
  auto init_data = init_data_r.move_as_ok();
  if (init_code.not_null() || init_data.not_null()) {
    new_state = tos::GenericAccount::get_init_state(init_code, init_data);
  }
  auto message = tos::GenericAccount::create_ext_message(addr, new_state, body_r.move_as_ok());
  if (message.is_null()) {
    return td::Status::Error("Failed to build external message (body or init state too large to encode)");
  }
  return message;
}

static td::Result<std::string> serialize_cell_b64(td::Ref<vm::Cell> cell) {
  auto boc_r = vm::std_boc_serialize(cell);
  if (boc_r.is_error()) {
    return td::Status::Error(PSTRING() << "BOC serialize error: " << boc_r.error());
  }
  return td::base64_encode(boc_r.ok().as_slice());
}

static td::Result<std::string> extract_signed_artifact_b64(td::JsonObject& params) {
  auto boc_r = params.get_optional_string_field("signed_message_boc");
  if (boc_r.is_ok() && !boc_r.ok().empty()) {
    return boc_r.ok();
  }
  auto alt_r = params.get_optional_string_field("boc");
  if (alt_r.is_ok() && !alt_r.ok().empty()) {
    return alt_r.ok();
  }
  auto payload_r = params.get_optional_string_field("payload");
  if (payload_r.is_ok() && !payload_r.ok().empty()) {
    auto enc_r = params.get_optional_string_field("payload_encoding");
    if (enc_r.is_ok() && !enc_r.ok().empty() && enc_r.ok() != "boc_base64") {
      return td::Status::Error("SIGNED_ARTIFACT_UNSUPPORTED: unsupported payload_encoding");
    }
    return payload_r.ok();
  }
  return td::Status::Error("Missing 'signed_message_boc', 'boc', or 'payload'");
}

static std::string build_submission_result_json(bool accepted, const std::string& hash_b64,
                                                td::int32 status,
                                                const std::string& signer,
                                                const std::string& submitter,
                                                const std::string& fee_payer) {
  return PSTRING()
      << "{\"@type\":\"transaction.submissionResult\""
      << ",\"accepted\":" << (accepted ? "true" : "false")
      << ",\"transaction_hash\":" << td::JsonString(td::Slice(hash_b64))
      << ",\"submission_id\":" << td::JsonString(td::Slice(hash_b64))
      << ",\"status\":" << status
      << ",\"authorization_roles\":" << build_authorization_roles_json(signer, submitter, fee_payer)
      << "}";
}


// ─── sendBocReturnHash ──────────────────────────────────────────────────

void JsonRpcServer::handle_sendBocReturnHash(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto boc_r = params.get_required_string_field("boc");
  if (boc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'boc' parameter", req_id));
    return;
  }
  auto boc_b64 = boc_r.move_as_ok();
  auto decoded_r = td::base64_decode(boc_b64);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'boc'", req_id));
    return;
  }
  auto decoded = decoded_r.move_as_ok();

  if (decoded.size() > kMaxBocSize) {
    promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
    return;
  }

  // Compute the external message hash before sending
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded));
  std::string msg_hash_b64;
  if (cell_r.is_ok()) {
    auto hash = cell_r.ok()->get_hash(0);
    msg_hash_b64 = td::base64_encode(hash.as_slice());
  }

  auto body = td::BufferSlice(std::move(decoded));
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), msg_hash_b64 = std::move(msg_hash_b64),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            std::move(data), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"status\":" << status->status_
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
}

void JsonRpcServer::handle_buildTransactionIntent(td::JsonObject &params, std::string req_id,
                                                  td::Promise<HttpReturn> promise) {
  auto input_r = parse_initial_intent_input(params);
  if (input_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: " << input_r.error().message(), req_id));
    return;
  }
  auto input = input_r.move_as_ok();

  // Continuation: build and return the transaction intent.  Extracted as a
  // shared lambda so both the sync and async-discovery paths converge here.
  auto do_finish = [this](InitialIntentInput input, std::string req_id,
                          td::Promise<HttpReturn> promise) mutable {
    if (!input.delegation_ref.empty()) {
      block::StdAddress addr;
      if (!addr.parse_addr(td::Slice(input.address))) {
        promise.set_value(make_json_error(-32602, "DELEGATION_UNAVAILABLE: invalid address", req_id));
        return;
      }
      auto msg_r = build_external_message_cell(input);
      if (msg_r.is_error()) {
        promise.set_value(make_json_error(-32602,
            PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: " << msg_r.error().message(), req_id));
        return;
      }
      auto intent_json = build_transaction_intent_json(input);
      validate_delegation_and_return_intent(
          addr, input.address, input.delegation_ref,
          std::move(intent_json), std::move(req_id), std::move(promise));
      return;
    }

    auto msg_r = build_external_message_cell(input);
    if (msg_r.is_error()) {
      promise.set_value(make_json_error(-32602,
          PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: " << msg_r.error().message(), req_id));
      return;
    }
    promise.set_value(make_json_ok(build_transaction_intent_json(input), req_id));
  };

  // When account_model is "unknown" (caller didn't supply it), perform async
  // capability discovery so the intent carries the correct on-chain model.
  if (input.account_model == "unknown") {
    block::StdAddress addr;
    if (!addr.parse_addr(td::Slice(input.address))) {
      promise.set_value(make_json_error(-32602,
          "TRANSACTION_INTENT_UNSUPPORTED: invalid address for capability discovery", req_id));
      return;
    }
    auto self_id = actor_id(this);
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [self_id, addr, input = std::move(input), do_finish = std::move(do_finish),
         req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: parse mcInfo: " << mc_r.error(), req_id));
            return;
          }
          auto block_id = tos::create_block_id(mc_r.ok()->last_);
          auto account_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                  tos::create_tl_lite_block_id(block_id),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr)),
              true);
          auto account_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(account_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(account_query),
              td::PromiseCreator::lambda(
                  [self_id, addr, input = std::move(input), do_finish = std::move(do_finish),
                   req_id = std::move(req_id), promise = std::move(promise)](
                      td::Result<td::BufferSlice> account_res) mutable {
                    if (account_res.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: getAccountState: " << account_res.error(), req_id));
                      return;
                    }
                    auto account_r = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
                        account_res.move_as_ok(), true);
                    if (account_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: parse accountState: " << account_r.error(), req_id));
                      return;
                    }
                    auto account = account_r.move_as_ok();
                    auto parsed_r = ParsedAccountState::parse(account, addr);
                    if (parsed_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "TRANSACTION_INTENT_UNSUPPORTED: parse account: " << parsed_r.error(), req_id));
                      return;
                    }
                    auto parsed = parsed_r.move_as_ok();

                    // Detect wallet type and account model from on-chain state
                    std::string wallet_type;
                    if (parsed.code_cell.not_null()) {
                      wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
                    }
                    input.account_model = detect_account_model(parsed, wallet_type);
                    if (input.authorization_version == "unknown") {
                      input.authorization_version = detect_authorization_version(wallet_type);
                    }

                    // Build the intent with the discovered model.
                    // do_finish captures 'this' from the member function and is
                    // invoked here inside a callback — the actor framework
                    // guarantees single-threaded execution so this is safe.
                    do_finish(std::move(input), std::move(req_id), std::move(promise));
                  }));
        });
    return;
  }

  // account_model was explicitly provided — proceed synchronously
  do_finish(std::move(input), std::move(req_id), std::move(promise));
}

void JsonRpcServer::handle_getSigningPayload(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto input_r = parse_initial_intent_input(params);
  if (input_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << input_r.error().message(), req_id));
    return;
  }
  auto input = input_r.move_as_ok();

  // Continuation: build and return the signing payload.  Extracted as a
  // shared lambda so both the sync and async-discovery paths converge here.
  auto self_id = actor_id(this);
  auto do_finish = [this, self_id](InitialIntentInput input, std::string req_id,
                                   td::Promise<HttpReturn> promise) mutable {
    if (!input.delegation_ref.empty()) {
      block::StdAddress addr;
      if (!addr.parse_addr(td::Slice(input.address))) {
        promise.set_value(make_json_error(-32602, "DELEGATION_UNAVAILABLE: invalid address", req_id));
        return;
      }
      auto msg_r = build_external_message_cell(input);
      if (msg_r.is_error()) {
        promise.set_value(make_json_error(-32602,
            PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << msg_r.error().message(), req_id));
        return;
      }
      auto payload_b64_r = serialize_cell_b64(msg_r.ok());
      if (payload_b64_r.is_error()) {
        promise.set_value(make_json_error(-32603,
            PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << payload_b64_r.error().message(), req_id));
        return;
      }
      auto intent_json = PSTRING()
          << "{\"@type\":\"transaction.signingPayload\""
          << ",\"payload_version\":1"
          << ",\"payload_encoding\":\"boc_base64\""
          << ",\"payload\":" << td::JsonString(td::Slice(payload_b64_r.ok()))
          << ",\"delegation_ref\":" << td::JsonString(td::Slice(input.delegation_ref))
          << ",\"replay_protection\":{\"@type\":\"transaction.replayProtection\""
          << ",\"mode\":\"contract_defined\"}"
          << "}";
      validate_delegation_and_return_intent(
          addr, input.address, input.delegation_ref,
          std::move(intent_json), std::move(req_id), std::move(promise));
      return;
    }

    auto msg_r = build_external_message_cell(input);
    if (msg_r.is_error()) {
      promise.set_value(make_json_error(-32602,
          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << msg_r.error().message(), req_id));
      return;
    }
    auto payload_b64_r = serialize_cell_b64(msg_r.ok());
    if (payload_b64_r.is_error()) {
      promise.set_value(make_json_error(-32603,
          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << payload_b64_r.error().message(), req_id));
      return;
    }

    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [self_id, input = std::move(input), payload_b64 = payload_b64_r.move_as_ok(),
         req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << R.error(), req_id));
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << mc_r.error(), req_id));
            return;
          }
          auto block_id = tos::create_block_id(mc_r.ok()->last_);
          auto config_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                  block::ConfigInfo::needPrevBlocks, tos::create_tl_lite_block_id(block_id)),
              true);
          auto config_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(config_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(config_query),
              td::PromiseCreator::lambda(
                  [input = std::move(input), payload_b64 = std::move(payload_b64),
                   req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> cfg_res) mutable {
                    if (cfg_res.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << cfg_res.error(), req_id));
                      return;
                    }
                    auto cfg_info_r =
                        tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(cfg_res.move_as_ok(), true);
                    if (cfg_info_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << cfg_info_r.error(), req_id));
                      return;
                    }
                    auto cfg_info = cfg_info_r.move_as_ok();
                    auto blk_id = tos::create_block_id(cfg_info->id_);
                    auto state_r = block::check_extract_state_proof(
                        blk_id, cfg_info->state_proof_.as_slice(), cfg_info->config_proof_.as_slice());
                    if (state_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << state_r.error(), req_id));
                      return;
                    }
                    auto cfg_r = block::ConfigInfo::extract_config(
                        state_r.move_as_ok(), blk_id, block::ConfigInfo::needPrevBlocks);
                    if (cfg_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: " << cfg_r.error(), req_id));
                      return;
                    }
                    auto cfg = cfg_r.move_as_ok();
                    auto chain_id = cfg->get_global_blockchain_id();
                    auto result_json = PSTRING()
                        << "{\"@type\":\"transaction.signingPayload\""
                        << ",\"payload_version\":1"
                        << ",\"payload_encoding\":\"boc_base64\""
                        << ",\"payload\":" << td::JsonString(td::Slice(payload_b64))
                        << ",\"chain_id\":" << chain_id
                        << ",\"replay_protection\":{\"@type\":\"transaction.replayProtection\""
                        << ",\"mode\":\"contract_defined\"}"
                        << "}";
                    promise.set_value(make_json_ok(result_json, req_id));
                  }));
        });
  };

  // When account_model is "unknown" (caller didn't supply it), perform async
  // capability discovery so the signing payload carries the correct on-chain model.
  if (input.account_model == "unknown") {
    block::StdAddress addr;
    if (!addr.parse_addr(td::Slice(input.address))) {
      promise.set_value(make_json_error(-32602,
          "SIGNING_PAYLOAD_UNAVAILABLE: invalid address for capability discovery", req_id));
      return;
    }
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [self_id, addr, input = std::move(input), do_finish = std::move(do_finish),
         req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: parse mcInfo: " << mc_r.error(), req_id));
            return;
          }
          auto block_id = tos::create_block_id(mc_r.ok()->last_);
          auto account_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                  tos::create_tl_lite_block_id(block_id),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr)),
              true);
          auto account_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(account_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(account_query),
              td::PromiseCreator::lambda(
                  [self_id, addr, input = std::move(input), do_finish = std::move(do_finish),
                   req_id = std::move(req_id), promise = std::move(promise)](
                      td::Result<td::BufferSlice> account_res) mutable {
                    if (account_res.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: getAccountState: " << account_res.error(), req_id));
                      return;
                    }
                    auto account_r = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
                        account_res.move_as_ok(), true);
                    if (account_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: parse accountState: " << account_r.error(), req_id));
                      return;
                    }
                    auto account = account_r.move_as_ok();
                    auto parsed_r = ParsedAccountState::parse(account, addr);
                    if (parsed_r.is_error()) {
                      promise.set_value(make_json_error(-32603,
                          PSTRING() << "SIGNING_PAYLOAD_UNAVAILABLE: parse account: " << parsed_r.error(), req_id));
                      return;
                    }
                    auto parsed = parsed_r.move_as_ok();

                    // Detect wallet type and account model from on-chain state
                    std::string wallet_type;
                    if (parsed.code_cell.not_null()) {
                      wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
                    }
                    input.account_model = detect_account_model(parsed, wallet_type);
                    if (input.authorization_version == "unknown") {
                      input.authorization_version = detect_authorization_version(wallet_type);
                    }

                    do_finish(std::move(input), std::move(req_id), std::move(promise));
                  }));
        });
    return;
  }

  // account_model was explicitly provided — proceed directly
  do_finish(std::move(input), std::move(req_id), std::move(promise));
}

// NOTE: submitSignedTransaction accepts any valid external message BOC.
// There is no server-side binding between buildTransactionIntent /
// getSigningPayload and this handler — the delegation validation in
// buildTransactionIntent is advisory only.  The on-chain smart contract
// (not the RPC layer) is the authoritative enforcer of signature and
// permission checks.
void JsonRpcServer::handle_submitSignedTransaction(td::JsonObject &params, std::string req_id,
                                                   td::Promise<HttpReturn> promise) {
  auto signed_b64_r = extract_signed_artifact_b64(params);
  if (signed_b64_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        PSTRING() << "SIGNED_ARTIFACT_INVALID: " << signed_b64_r.error().message(), req_id));
    return;
  }
  auto decoded_r = td::base64_decode(signed_b64_r.ok());
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "SIGNED_ARTIFACT_INVALID: invalid base64", req_id));
    return;
  }
  if (decoded_r.ok().size() > kMaxBocSize) {
    promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
    return;
  }
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded_r.ok()));
  if (cell_r.is_error()) {
    promise.set_value(make_json_error(-32602, "SIGNED_ARTIFACT_INVALID: invalid BOC", req_id));
    return;
  }
  auto hash_b64 = td::base64_encode(cell_r.ok()->get_hash(0).as_slice());

  auto signer_r = params.get_optional_string_field("signer");
  auto submitter_r = params.get_optional_string_field("submitter");
  auto fee_payer_r = params.get_optional_string_field("fee_payer");
  std::string signer = signer_r.is_ok() ? signer_r.ok() : "";
  std::string submitter = submitter_r.is_ok() ? submitter_r.ok() : signer;
  std::string fee_payer = fee_payer_r.is_ok() ? fee_payer_r.ok() : signer;

  auto body = td::BufferSlice(decoded_r.move_as_ok());
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), hash_b64 = std::move(hash_b64), signer = std::move(signer),
       submitter = std::move(submitter), fee_payer = std::move(fee_payer),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "SIGNED_ARTIFACT_UNSUPPORTED: " << R.error(), req_id));
          return;
        }
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            R.move_as_ok(), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "SIGNED_ARTIFACT_UNSUPPORTED: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            build_submission_result_json(true, hash_b64, status->status_,
                                         signer, submitter, fee_payer),
            req_id));
      });
}

// ─── sendQuery ──────────────────────────────────────────────────────────
// Build external message from address + body + optional init, then send

void JsonRpcServer::handle_sendQuery(td::JsonObject &params, std::string req_id,
                                     td::Promise<HttpReturn> promise) {
  // Parse destination address
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  // Round 144 MEDIUM fix: addr_std uses an int8 workchain field
  // (range [-128, 127]).  parse_address_param accepts the wider
  // int32 form, so an address like "128:<hex>" parsed and then
  // store_long(addr.workchain, 8) at the addr_std encode below
  // truncated silently — emitting a structurally malformed
  // message that downstream consensus would reject after
  // unpaid CPU work.  Reject out-of-int8 workchains here.
  if (addr.workchain < -128 || addr.workchain > 127) {
    promise.set_value(make_json_error(
        -32602,
        PSTRING() << "Invalid 'address': workchain " << addr.workchain
                  << " is out of the addr_std int8 range [-128, 127]",
        req_id));
    return;
  }

  // Parse message body (base64 BOC)
  auto body_r = params.get_required_string_field("body");
  if (body_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'body'", req_id));
    return;
  }
  auto body_decoded_r = td::base64_decode(body_r.ok());
  if (body_decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'body'", req_id));
    return;
  }
  if (body_decoded_r.ok().size() > kMaxBocSize) {
    promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
    return;
  }
  auto body_cell_r = vm::std_boc_deserialize(td::Slice(body_decoded_r.ok()));
  if (body_cell_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid BOC in 'body'", req_id));
    return;
  }
  auto body_cell = body_cell_r.move_as_ok();

  // Parse optional init_code and init_data
  td::Ref<vm::Cell> init_code, init_data;
  auto code_r = params.get_optional_string_field("init_code");
  if (code_r.is_ok() && !code_r.ok().empty()) {
    auto dec = td::base64_decode(code_r.ok());
    if (dec.is_error()) {
      promise.set_value(make_json_error(-32602, "invalid base64 in init_code", req_id));
      return;
    }
    if (dec.ok().size() > kMaxBocSize) {
      promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
      return;
    }
    auto cell = vm::std_boc_deserialize(td::Slice(dec.ok()));
    if (cell.is_error()) {
      promise.set_value(make_json_error(-32602, "invalid BOC in init_code", req_id));
      return;
    }
    init_code = cell.move_as_ok();
  }
  auto data_r = params.get_optional_string_field("init_data");
  if (data_r.is_ok() && !data_r.ok().empty()) {
    auto dec = td::base64_decode(data_r.ok());
    if (dec.is_error()) {
      promise.set_value(make_json_error(-32602, "invalid base64 in init_data", req_id));
      return;
    }
    if (dec.ok().size() > kMaxBocSize) {
      promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
      return;
    }
    auto cell = vm::std_boc_deserialize(td::Slice(dec.ok()));
    if (cell.is_error()) {
      promise.set_value(make_json_error(-32602, "invalid BOC in init_data", req_id));
      return;
    }
    init_data = cell.move_as_ok();
  }

  // Build external inbound message
  // Message = message$_ info:CommonMsgInfo init:(Maybe (Either StateInit ^StateInit)) body:(Either X ^X)
  vm::CellBuilder cb;

  // CommonMsgInfo: ext_in_msg_info$10 src:MsgAddressExt dest:MsgAddressInt import_fee:Grams
  cb.store_long(0b10, 2);    // ext_in_msg_info tag
  cb.store_long(0b00, 2);    // addr_none for src (MsgAddressExt)
  // dest: addr_std$10 anycast:(Maybe Anycast) workchain:int8 address:bits256
  cb.store_long(0b10, 2);    // addr_std tag
  cb.store_long(0, 1);       // no anycast
  cb.store_long(addr.workchain, 8);
  cb.store_bits(addr.addr.cbits(), 256);
  cb.store_long(0, 4);       // import_fee: 0 grams (VarUInteger 16, len=0)

  // init: Maybe (Either StateInit ^StateInit)
  bool has_init = init_code.not_null() || init_data.not_null();
  if (has_init) {
    cb.store_long(1, 1);     // Maybe: present
    cb.store_long(1, 1);     // Either: right (^StateInit, as ref)
    // Build StateInit cell
    vm::CellBuilder si_cb;
    si_cb.store_long(0, 1);  // split_depth: nothing
    si_cb.store_long(0, 1);  // special: nothing
    if (init_code.not_null()) {
      si_cb.store_long(1, 1);
      si_cb.store_ref(init_code);
    } else {
      si_cb.store_long(0, 1);
    }
    if (init_data.not_null()) {
      si_cb.store_long(1, 1);
      si_cb.store_ref(init_data);
    } else {
      si_cb.store_long(0, 1);
    }
    si_cb.store_long(0, 1);  // library: empty HashmapE
    cb.store_ref(si_cb.finalize());
  } else {
    cb.store_long(0, 1);     // Maybe: absent
  }

  // body: Either X ^X — store as ref to avoid overflow
  cb.store_long(1, 1);       // Either: right (^X, as ref)
  cb.store_ref(body_cell);

  auto msg_cell = cb.finalize();
  auto msg_boc_r = vm::std_boc_serialize(msg_cell);
  if (msg_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "Failed to serialize message", req_id));
    return;
  }

  // Compute message hash
  auto msg_hash_b64 = td::base64_encode(msg_cell->get_hash(0).as_slice());

  auto body_buf = td::BufferSlice(msg_boc_r.ok().as_slice());
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body_buf)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), msg_hash_b64 = std::move(msg_hash_b64),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendMessage failed: " << R.error(), req_id));
          return;
        }
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            R.move_as_ok(), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse sendMsgStatus: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"status\":" << status->status_
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
}

void JsonRpcServer::handle_estimateFee(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto body_r = parse_optional_boc_field(params, "body");
  if (body_r.is_error()) {
    promise.set_value(make_json_error(-32602, body_r.error().message().str(), req_id));
    return;
  }
  if (body_r.ok().is_null()) {
    promise.set_value(make_json_error(-32602, "Missing 'body'", req_id));
    return;
  }
  auto init_code_r = parse_optional_boc_field(params, "init_code");
  if (init_code_r.is_error()) {
    promise.set_value(make_json_error(-32602, init_code_r.error().message().str(), req_id));
    return;
  }
  auto init_data_r = parse_optional_boc_field(params, "init_data");
  if (init_data_r.is_error()) {
    promise.set_value(make_json_error(-32602, init_data_r.error().message().str(), req_id));
    return;
  }
  auto ignore_chksig_r = params.get_optional_bool_field("ignore_chksig", true);
  if (ignore_chksig_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid 'ignore_chksig'", req_id));
    return;
  }

  auto addr = addr_r.move_as_ok();
  // Round 145 MEDIUM fix: same workchain int8 range check
  // round 144 added to build_external_message_cell + handle_
  // sendQuery, applied here for handle_estimateFee.  Pre-fix
  // estimateFee accepted "128:<hex>" through parse_address_param
  // and reached GenericAccount::create_ext_message at line 1492,
  // tripping the addr_std encode CHECK and aborting the daemon.
  if (addr.workchain < -128 || addr.workchain > 127) {
    promise.set_value(make_json_error(
        -32602,
        PSTRING() << "Invalid 'address': workchain " << addr.workchain
                  << " is out of the addr_std int8 range [-128, 127]",
        req_id));
    return;
  }
  auto body_cell = body_r.move_as_ok();
  auto init_code = init_code_r.move_as_ok();
  auto init_data = init_data_r.move_as_ok();
  auto ignore_chksig = ignore_chksig_r.move_as_ok();

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [self_id, addr, body_cell = std::move(body_cell), init_code = std::move(init_code),
       init_data = std::move(init_data), ignore_chksig, req_id = std::move(req_id),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo failed: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();
        auto block_id = tos::create_block_id(mc->last_);
        auto account_inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                tos::create_tl_lite_block_id(block_id),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr)),
            true);
        auto account_query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(account_inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(account_query),
            td::PromiseCreator::lambda(
                [self_id, addr, block_id = std::move(block_id), body_cell = std::move(body_cell),
                 init_code = std::move(init_code), init_data = std::move(init_data), ignore_chksig,
                 req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> account_res) mutable {
                  if (account_res.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "getAccountState failed: " << account_res.error(), req_id));
                    return;
                  }
                  auto account_r =
                      tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(account_res.move_as_ok(), true);
                  if (account_r.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "parse accountState: " << account_r.error(), req_id));
                    return;
                  }
                  auto account = account_r.move_as_ok();
                  auto parsed_r = ParsedAccountState::parse(account, addr);
                  if (parsed_r.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "parse account proof: " << parsed_r.error(), req_id));
                    return;
                  }
                  auto parsed = parsed_r.move_as_ok();

                  td::Ref<vm::Cell> effective_code = init_code.not_null() ? init_code : parsed.code_cell;
                  td::Ref<vm::Cell> effective_data = init_data.not_null() ? init_data : parsed.data_cell;
                  td::Ref<vm::Cell> new_state;
                  if (effective_code.not_null() || effective_data.not_null()) {
                    new_state = tos::GenericAccount::get_init_state(effective_code, effective_data);
                  }
                  if (effective_code.is_null()) {
                    promise.set_value(make_json_error(-32603,
                        "estimateFee requires deploy init_code/init_data or an active account state", req_id));
                    return;
                  }

                  auto config_inner = tos::serialize_tl_object(
                      tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                          block::ConfigInfo::needPrevBlocks, tos::create_tl_lite_block_id(block_id)),
                      true);
                  auto config_query = tos::serialize_tl_object(
                      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(config_inner)), true);

                  td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(config_query),
                      td::PromiseCreator::lambda(
                          [addr, body_cell = std::move(body_cell), new_state = std::move(new_state),
                           effective_code = std::move(effective_code), effective_data = std::move(effective_data),
                           parsed = std::move(parsed), ignore_chksig, req_id = std::move(req_id),
                           promise = std::move(promise)](td::Result<td::BufferSlice> config_res) mutable {
                            if (config_res.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "getConfigAll failed: " << config_res.error(), req_id));
                              return;
                            }
                            auto config_r =
                                tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(config_res.move_as_ok(), true);
                            if (config_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "parse configInfo: " << config_r.error(), req_id));
                              return;
                            }
                            auto config_info = config_r.move_as_ok();
                            auto requested_block_id = tos::create_block_id(config_info->id_);
                            auto state_root_r = block::check_extract_state_proof(
                                requested_block_id, config_info->state_proof_.as_slice(),
                                config_info->config_proof_.as_slice());
                            if (state_root_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "config proof error: " << state_root_r.error(), req_id));
                              return;
                            }
                            auto cfg_r = block::ConfigInfo::extract_config(
                                state_root_r.move_as_ok(), requested_block_id,
                                block::ConfigInfo::needPrevBlocks | block::ConfigInfo::needCapabilities |
                                    block::ConfigInfo::needLibraries);
                            if (cfg_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "config extract error: " << cfg_r.error(), req_id));
                              return;
                            }
                            auto cfg = cfg_r.move_as_ok();
                            auto prev_blocks_r = cfg->get_prev_blocks_info();
                            if (prev_blocks_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "prev_blocks_info error: " << prev_blocks_r.error(), req_id));
                              return;
                            }

                            bool is_masterchain = addr.workchain == tos::masterchainId;
                            auto gas_limits_prices_r = cfg->get_gas_limits_prices(is_masterchain);
                            auto storage_prices_r = cfg->get_storage_prices();
                            auto masterchain_msg_prices_r = cfg->get_msg_prices(true);
                            auto basechain_msg_prices_r = cfg->get_msg_prices(false);
                            if (gas_limits_prices_r.is_error() || storage_prices_r.is_error() ||
                                masterchain_msg_prices_r.is_error() || basechain_msg_prices_r.is_error()) {
                              promise.set_value(make_json_error(-32603, "fee config unavailable", req_id));
                              return;
                            }
                            auto gas_limits_prices = gas_limits_prices_r.move_as_ok();
                            auto storage_prices = storage_prices_r.move_as_ok();
                            auto masterchain_msg_prices = masterchain_msg_prices_r.move_as_ok();
                            auto basechain_msg_prices = basechain_msg_prices_r.move_as_ok();
                            block::MsgPrices* msg_prices[2] = {&basechain_msg_prices, &masterchain_msg_prices};

                            auto storage_fee_256 = block::StoragePrices::compute_storage_fees(
                                parsed.sync_utime, storage_prices, parsed.storage_used,
                                parsed.storage_last_paid, false, is_masterchain);
                            auto storage_fee = storage_fee_256.is_null() ? 0 : storage_fee_256->to_long();

                            auto message = tos::GenericAccount::create_ext_message(addr, new_state, body_cell);
                            if (message.is_null()) {
                              promise.set_value(make_json_error(-32602,
                                  "Failed to build external message (body or init state too large to encode)",
                                  req_id));
                              return;
                            }
                            vm::CellStorageStat in_msg_stat;
                            in_msg_stat.add_used_storage(message, true, 3);
                            auto in_fwd_fee =
                                msg_prices[is_masterchain]->compute_fwd_fees(in_msg_stat.cells, in_msg_stat.bits);

                            vm::Dictionary libraries{256};
                            if (cfg->get_libraries_root().not_null()) {
                              libraries = vm::Dictionary(cfg->get_libraries_root(), 256);
                            }

                            auto prev_blocks_info = prev_blocks_r.move_as_ok();
                            auto cfg_shared = std::shared_ptr<const block::Config>(cfg.release());
                            auto smc = tos::SmartContract::create({effective_code, effective_data});
                            auto gas_limits =
                                estimate_compute_gas_limits(td::make_refint(parsed.balance), gas_limits_prices);
                            auto run_res = smc.write().send_external_message(
                                body_cell,
                                tos::SmartContract::Args()
                                    .set_limits(gas_limits)
                                    .set_balance(parsed.balance)
                                    .set_extra_currencies(parsed.extra_currencies_cell)
                                    .set_now(parsed.sync_utime)
                                    .set_ignore_chksig(ignore_chksig)
                                    .set_address(addr)
                                    .set_config(cfg_shared)
                                    .set_prev_blocks_info(prev_blocks_info)
                                    .set_libraries(std::move(libraries)));

                            td::int64 fwd_fee = 0;
                            if (run_res.success) {
                              auto fwd_fee_r = estimate_calc_fwd_fees(run_res.actions, msg_prices, is_masterchain);
                              if (fwd_fee_r.is_error()) {
                                promise.set_value(make_json_error(-32603,
                                    PSTRING() << "forward fee error: " << fwd_fee_r.error(), req_id));
                                return;
                              }
                              fwd_fee = fwd_fee_r.move_as_ok();
                            }

                            auto gas_fee = run_res.accepted
                                               ? estimate_compute_gas_price(run_res.gas_used, gas_limits_prices)->to_long()
                                               : 0;
                            promise.set_value(make_json_ok(
                                build_estimate_fee_json(in_fwd_fee, storage_fee, gas_fee, fwd_fee), req_id));
                          }));
                }));
      });
}

// ─── sendBocReturnHashNoError ────────────────────────────────────────────
// Same as sendBocReturnHash but with "ignore errors" semantics.
// If the liteserver send fails, instead of returning the raw liteserver error,
// this method returns a structured error with code -32600 (keeping the original
// error message). This matches the HTTP API behavior where
// ignore_errors=true normalizes error handling for fire-and-forget use cases.
// The hash is still computed and included even on failure.

void JsonRpcServer::handle_sendBocReturnHashNoError(td::JsonObject &params, std::string req_id,
                                                    td::Promise<HttpReturn> promise) {
  auto boc_r = params.get_required_string_field("boc");
  if (boc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'boc' parameter", req_id));
    return;
  }
  auto boc_b64 = boc_r.move_as_ok();
  auto decoded_r = td::base64_decode(boc_b64);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'boc'", req_id));
    return;
  }
  auto decoded = decoded_r.move_as_ok();

  if (decoded.size() > kMaxBocSize) {
    promise.set_value(make_json_error(-32602, "BOC payload exceeds maximum allowed size", req_id));
    return;
  }

  // Compute the external message hash before sending
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded));
  std::string msg_hash_b64;
  if (cell_r.is_ok()) {
    auto hash = cell_r.ok()->get_hash(0);
    msg_hash_b64 = td::base64_encode(hash.as_slice());
  }

  auto body = td::BufferSlice(std::move(decoded));
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), msg_hash_b64 = std::move(msg_hash_b64),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          // NoError semantics: normalize errors to code -32600 with the
          // original error message. The hash is still returned in the
          // error message so clients can track the message.
          promise.set_value(make_json_error(-32600,
              PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            std::move(data), true);
        if (status_r.is_error()) {
          // Even parse failures are normalized for NoError
          promise.set_value(make_json_error(-32600,
              PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"@type\":\"raw.extMessageInfo\""
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
}

}  // namespace tos
