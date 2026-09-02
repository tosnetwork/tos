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
#include "crypto/smc-envelope/SmartContractCode.h"
#include "vm/dict.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include <array>
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

std::string detect_wallet_type(const vm::CellHash& code_hash) {
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
    // Recognizing an account as a staking pool tells a depositor that the code
    // holding their principal is the audited contract in this repository, so
    // this entry has to stay reproducible from crypto/smartcont/nominator-pool.
    // scripts/check-nominator-pool-code-lock.sh enforces that.
    {"9A3EC14BC098F6B44064C305222CAEA2800F17DDA85EE6A8198A7095EDE10DCF", "nominator pool v1"},
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

std::string detect_account_model(const ParsedAccountState& parsed,
                                 const std::string& wallet_type) {
  if (!wallet_type.empty()) {
    if (wallet_type.rfind("wallet ", 0) == 0) {
      return "default.wallet.v1";
    }
    if (wallet_type.rfind("highload", 0) == 0) {
      return "advanced.wallet.highload";
    }
    if (wallet_type.rfind("nominator pool", 0) == 0) {
      return "contract.pool.nominator";
    }
    return "unknown.wallet";
  }
  if (parsed.code_cell.not_null()) {
    auto code_hash = parsed.code_cell->get_hash(0);
    auto multisig_hash = tos::SmartContractCode::get_code(tos::SmartContractCode::Type::Multisig)->get_hash(0);
    if (code_hash == multisig_hash) {
      return "advanced.wallet.multisig";
    }
    auto restricted_hash =
        tos::SmartContractCode::get_code(tos::SmartContractCode::Type::RestrictedWallet)->get_hash(0);
    if (code_hash == restricted_hash) {
      return "advanced.wallet.restricted";
    }
    auto session_wallet_hash =
        tos::SmartContractCode::get_code(tos::SmartContractCode::Type::SessionWallet)->get_hash(0);
    if (code_hash == session_wallet_hash) {
      return "advanced.wallet.session";
    }
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

std::string detect_authorization_version(const std::string& wallet_type) {
  if (!wallet_type.empty()) {
    return "auth.external_message.ed25519.v1";
  }
  return "unknown";
}

// AccountCapabilityContext is declared in json-rpc-server-internal.h

struct MultisigAgentView {
  int threshold_n{0};
  int threshold_k{0};
  std::vector<std::string> principals;
};

struct RestrictedDelegationView {
  std::string principal;    // "ed25519:<hex>"
  td::uint32 start_at{0};
  td::int64 available_balance{0};
  td::int64 full_balance{0};
};

struct NominatorDelegation {
  std::string principal;  // "0:<hex>" format
  td::int64 amount{0};
  td::int64 pending_deposit{0};
  bool withdraw_requested{false};
};

struct NominatorPoolDelegationView {
  std::vector<NominatorDelegation> nominators;
};

struct SessionEntry {
  td::int32 session_id{0};
  std::string principal;  // "ed25519:<hex>"
  int scope{0};           // 0=submit_only, 1=bounded_transfer, 2=bounded_contract_call
  td::uint32 created_at{0};
  td::uint32 expires_at{0};
  bool revoked{false};
};

struct SessionWalletView {
  std::vector<SessionEntry> sessions;
};

enum class PermissionKind { Delegation, Session, Agent };

enum class RequestedPermissionSourceTier { Default, Protocol, AccountStandard, Indexed, Deferred };

struct PermissionInspectionQuery {
  bool include_inactive{false};
  td::optional<std::string> status_filter;
  RequestedPermissionSourceTier source_tier{RequestedPermissionSourceTier::Default};
};

static td::Slice permission_method_name(PermissionKind kind) {
  switch (kind) {
    case PermissionKind::Delegation:
      return "getAccountDelegations";
    case PermissionKind::Session:
      return "getAccountSessions";
    case PermissionKind::Agent:
      return "getAccountAgents";
  }
  UNREACHABLE();
  return td::Slice();
}

static td::Result<PermissionInspectionQuery> parse_permission_inspection_query(td::JsonObject &params) {
  PermissionInspectionQuery query;

  auto include_inactive_r = params.get_optional_bool_field("include_inactive", false);
  if (include_inactive_r.is_error()) {
    return td::Status::Error("invalid include_inactive");
  }
  query.include_inactive = include_inactive_r.ok();

  auto status_r = params.get_optional_string_field("status");
  if (status_r.is_ok()) {
    auto status = status_r.ok();
    if (!status.empty()) {
      if (status != "active" && status != "expired" && status != "revoked" && status != "unknown") {
        return td::Status::Error("invalid status filter");
      }
      query.status_filter = std::move(status);
    }
  }

  auto source_r = params.get_optional_string_field("source_tier");
  if (source_r.is_ok()) {
    auto source = source_r.ok();
    if (!source.empty()) {
      if (source == "protocol") {
        query.source_tier = RequestedPermissionSourceTier::Protocol;
      } else if (source == "account_standard") {
        query.source_tier = RequestedPermissionSourceTier::AccountStandard;
      } else if (source == "indexed") {
        query.source_tier = RequestedPermissionSourceTier::Indexed;
      } else if (source == "deferred") {
        query.source_tier = RequestedPermissionSourceTier::Deferred;
      } else {
        return td::Status::Error("invalid source_tier");
      }
    }
  }

  return query;
}

static bool supports_account_standard_agents(const std::string& account_model) {
  return account_model == "advanced.wallet.multisig";
}

static bool supports_account_standard_delegations(const std::string& account_model) {
  return account_model == "advanced.wallet.restricted" ||
         account_model == "contract.pool.nominator";
}

static bool supports_account_standard_sessions(const std::string& account_model) {
  return account_model == "advanced.wallet.session";
}

static bool permission_state_deferred_for_account_model(const std::string& account_model) {
  return account_model == "advanced.unknown";
}

static std::string permission_source_error_prefix(const std::string& account_model) {
  return permission_state_deferred_for_account_model(account_model)
      ? "PERMISSION_SOURCE_DEFERRED"
      : "PERMISSION_SOURCE_UNSUPPORTED";
}

static std::string permission_source_error_message(const char* method_name,
                                                   const AccountCapabilityContext& ctx) {
  auto prefix = permission_source_error_prefix(ctx.account_model);
  td::StringBuilder sb;
  sb << prefix << ": " << method_name
     << " is not available for account_model=" << ctx.account_model;
  if (permission_state_deferred_for_account_model(ctx.account_model)) {
    sb << " until permission-state semantics are implemented";
  } else {
    sb << " because this account model does not expose a frozen permission-state source";
  }
  return sb.as_cslice().str();
}

// ─── Indexed freshness guarantees ──────────────────────────────────────
// When a permission surface uses the "indexed" source tier, the node must
// enforce a freshness threshold before returning results. Currently no
// canonical indexed permission source is configured, so all indexed-tier
// requests fail with INDEXED_STATE_STALE.
//
// When an indexed source is added in the future:
// - the implementation MUST document the freshness window (e.g. "within N blocks")
// - stale results MUST NOT be silently returned as current canonical truth
// - when freshness cannot be guaranteed, the query MUST fail with INDEXED_STATE_STALE
// - generic wallets SHOULD avoid treating stale indexed state as safely authorizing action
//
// Trust assumptions for indexed sources:
// - the indexed view is derived from the same on-chain state as protocol/account_standard
// - lag between on-chain state and indexed projection is bounded and documented
// - revocation and expiry observation may lag by the documented freshness window

static std::string indexed_state_stale_message(PermissionKind kind,
                                               const AccountCapabilityContext& ctx) {
  td::StringBuilder sb;
  sb << "INDEXED_STATE_STALE: " << permission_method_name(kind)
     << " has no fresh indexed permission state for account_model=" << ctx.account_model
     << " (no canonical indexed permission source is configured yet)";
  return sb.as_cslice().str();
}

static std::string forced_source_error_message(PermissionKind kind,
                                               RequestedPermissionSourceTier source_tier,
                                               const AccountCapabilityContext& ctx) {
  if (source_tier == RequestedPermissionSourceTier::Indexed) {
    return indexed_state_stale_message(kind, ctx);
  }
  if (source_tier == RequestedPermissionSourceTier::Deferred) {
    td::StringBuilder sb;
    sb << "PERMISSION_SOURCE_DEFERRED: " << permission_method_name(kind)
       << " was forced to deferred source_tier for account_model=" << ctx.account_model;
    return sb.as_cslice().str();
  }

  td::StringBuilder sb;
  sb << "PERMISSION_SOURCE_UNSUPPORTED: " << permission_method_name(kind)
     << " has no " << (source_tier == RequestedPermissionSourceTier::Protocol ? "protocol" : "account_standard")
     << " permission source for account_model=" << ctx.account_model;
  return sb.as_cslice().str();
}

// ─── Reserved permission error codes ───────────────────────────────────
// These codes are frozen for implementation per the permission error model.
// Not all are currently triggered — they are reserved so that future
// lifecycle and validation paths use consistent prefixes.
//
// Source-tier errors (currently active):
//   PERMISSION_SOURCE_DEFERRED   — no frozen source exists for the account model
//   PERMISSION_SOURCE_UNSUPPORTED — account model does not expose a permission source
//   INDEXED_STATE_STALE          — indexed permission state freshness cannot be guaranteed
//
// Permission-object errors (reserved for lifecycle/validation):
//   DELEGATION_UNAVAILABLE       — delegation cannot be resolved or inspected
//   DELEGATION_EXPIRED           — delegation exists but bounded-validity has ended
//   DELEGATION_REVOKED           — delegation has explicit revocation evidence
//   SESSION_UNAVAILABLE          — session cannot be resolved or inspected
//   SESSION_EXPIRED              — session bounded-validity has ended
//   AGENT_UNAVAILABLE            — agent capability cannot be resolved
//   AGENT_SCOPE_VIOLATION        — requested action exceeds agent's declared scope
//
// Transaction-surface errors (currently active):
//   FEATURE_DEFERRED             — requested feature is not yet implemented
//   TRANSACTION_INTENT_UNSUPPORTED — intent cannot be mapped to canonical send path
//   SIGNING_PAYLOAD_UNAVAILABLE  — signing payload cannot be derived
//   SIGNED_ARTIFACT_INVALID      — signed artifact is malformed
//   SIGNED_ARTIFACT_UNSUPPORTED  — signed artifact implies unsupported semantics

template <class SendQueryFn>
static void run_get_method_latest(SendQueryFn&& send_query, const block::StdAddress& addr,
                                  td::Slice method_name, td::Promise<td::Ref<vm::Stack>> promise) {
  auto send_query_ptr = std::make_shared<std::decay_t<SendQueryFn>>(std::forward<SendQueryFn>(send_query));
  td::int64 method_id = (td::crc16(method_name) & 0xffff) | 0x10000;

  vm::CellBuilder cb;
  vm::Stack empty_stack;
  if (!empty_stack.serialize(cb)) {
    promise.set_error(td::Status::Error("stack serialize error"));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_error(td::Status::Error("params BOC error"));
    return;
  }
  auto params_boc = params_boc_r.move_as_ok();

  auto do_run = [addr, method_id, params_boc = std::move(params_boc), send_query_ptr](
                    tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
                    td::Promise<td::Ref<vm::Stack>> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
            0x04, std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr),
            method_id, std::move(params_boc)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    (*send_query_ptr)(
        std::move(query),
        td::PromiseCreator::lambda(
            [promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise_inner.set_error(
                    td::Status::Error(PSTRING() << "runSmcMethod: " << R.error().message()));
                return;
              }
              auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                  R.move_as_ok(), true);
              if (F.is_error()) {
                promise_inner.set_error(td::Status::Error(
                    PSTRING() << "parse runMethodResult: " << F.error().message()));
                return;
              }
              auto f = F.move_as_ok();
              if (f->exit_code_ != 0) {
                promise_inner.set_error(
                    td::Status::Error(PSTRING() << "runSmcMethod exit_code=" << f->exit_code_));
                return;
              }
              promise_inner.set_result(parse_get_method_result_stack(f->result_.as_slice()));
            }));
  };

  auto mc_inner =
      tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query =
      tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
  (*send_query_ptr)(
      std::move(mc_query),
      td::PromiseCreator::lambda(
          [do_run = std::move(do_run), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_error(
                  td::Status::Error(PSTRING() << "getMasterchainInfo: " << R.error().message()));
              return;
            }
            auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
                R.move_as_ok(), true);
            if (mc_r.is_error()) {
              promise.set_error(
                  td::Status::Error(PSTRING() << "parse mcInfo: " << mc_r.error().message()));
              return;
            }
            do_run(std::move(mc_r.move_as_ok()->last_), std::move(promise));
          }));
}

template <class SendQueryFn>
static void fetch_multisig_agent_view(SendQueryFn&& send_query, const AccountCapabilityContext& ctx,
                                      td::Promise<MultisigAgentView> promise) {
  run_get_method_latest(
      send_query, ctx.addr, "get_public_keys",
      td::PromiseCreator::lambda(
          [send_query, addr = ctx.addr, promise = std::move(promise)](td::Result<td::Ref<vm::Stack>> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error());
              return;
            }

            auto public_keys_stack = R.move_as_ok();
            if (public_keys_stack->depth() == 0 || !public_keys_stack->at(0).is_cell()) {
              promise.set_error(td::Status::Error("get_public_keys returned unexpected stack"));
              return;
            }
            auto dict_root = public_keys_stack.write().pop_cell();
            // The dictionary comes from whatever data the account holds;
            // anyone can deploy the multisig code with arbitrary data.
            auto principals_r = parse_multisig_public_keys(std::move(dict_root));
            if (principals_r.is_error()) {
              promise.set_error(principals_r.move_as_error_prefix("get_public_keys returned invalid dictionary: "));
              return;
            }
            MultisigAgentView view;
            view.principals = principals_r.move_as_ok();

            run_get_method_latest(
                send_query, addr, "get_n_k",
                td::PromiseCreator::lambda(
                    [view = std::move(view), promise = std::move(promise)](
                        td::Result<td::Ref<vm::Stack>> R2) mutable {
                      if (R2.is_error()) {
                        promise.set_error(R2.move_as_error());
                        return;
                      }
                      auto nk_stack = R2.move_as_ok();
                      if (nk_stack->depth() < 2 || !nk_stack->at(0).is_int() || !nk_stack->at(1).is_int()) {
                        promise.set_error(td::Status::Error("get_n_k returned unexpected stack"));
                        return;
                      }
                      auto view2 = std::move(view);
                      try {
                        view2.threshold_k = static_cast<int>(nk_stack.write().pop_smallint_range(128));
                        view2.threshold_n = static_cast<int>(nk_stack.write().pop_smallint_range(128));
                      } catch (vm::VmError& err) {
                        view2.threshold_k = 0;
                        view2.threshold_n = 0;
                      }
                      promise.set_value(std::move(view2));
                    }));
          }));
}

template <class SendQueryFn>
static void fetch_restricted_delegation_view(SendQueryFn&& send_query, const AccountCapabilityContext& ctx,
                                             td::Promise<RestrictedDelegationView> promise) {
  run_get_method_latest(
      send_query, ctx.addr, "get_public_key",
      td::PromiseCreator::lambda(
          [send_query, ctx_addr = ctx.addr, full_balance = ctx.parsed.balance,
           promise = std::move(promise)](td::Result<td::Ref<vm::Stack>> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error());
              return;
            }

            auto pk_stack = R.move_as_ok();
            if (pk_stack->depth() == 0 || !pk_stack->at(0).is_int()) {
              promise.set_error(td::Status::Error("get_public_key returned unexpected stack"));
              return;
            }
            auto pk_int = pk_stack->at(0).as_int();
            unsigned char pk_bytes[32];
            if (!pk_int->export_bytes(pk_bytes, 32, false)) {
              promise.set_error(td::Status::Error("get_public_key: failed to export 256-bit key"));
              return;
            }
            std::string principal = "ed25519:" + td::hex_encode(td::Slice(reinterpret_cast<const char*>(pk_bytes), 32));

            run_get_method_latest(
                send_query, ctx_addr, "balance",
                td::PromiseCreator::lambda(
                    [principal = std::move(principal), full_balance,
                     promise = std::move(promise)](
                        td::Result<td::Ref<vm::Stack>> R2) mutable {
                      if (R2.is_error()) {
                        promise.set_error(R2.move_as_error());
                        return;
                      }
                      auto bal_stack = R2.move_as_ok();
                      if (bal_stack->depth() == 0 || !bal_stack->at(0).is_int()) {
                        promise.set_error(td::Status::Error("balance returned unexpected stack"));
                        return;
                      }
                      td::int64 available_balance = bal_stack->at(0).as_int()->to_long();
                      if (available_balance < 0) {
                        available_balance = 0;
                      }
                      if (available_balance > full_balance) {
                        available_balance = full_balance;
                      }

                      RestrictedDelegationView view;
                      view.principal = std::move(principal);
                      view.available_balance = available_balance;
                      view.full_balance = full_balance;
                      // start_at is set by fetch_restricted_delegation_view_with_start
                      promise.set_value(std::move(view));
                    }));
          }));
}

template <class SendQueryFn>
static void fetch_restricted_delegation_view_with_start(SendQueryFn&& send_query,
                                                        const AccountCapabilityContext& ctx,
                                                        td::Promise<RestrictedDelegationView> promise) {
  // Parse start_at from the data cell: seqno(32) + subwallet_id(32) + public_key(256) + start_at(32).
  // The data cell is attacker-controlled (the code hash alone selected this
  // account model), so the parse must not throw on an exotic root.
  auto start_at_r = parse_restricted_wallet_start_at(ctx.parsed.data_cell);
  td::uint32 start_at = start_at_r.is_ok() ? start_at_r.move_as_ok() : 0;

  fetch_restricted_delegation_view(
      std::forward<SendQueryFn>(send_query), ctx,
      td::PromiseCreator::lambda(
          [start_at, promise = std::move(promise)](td::Result<RestrictedDelegationView> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error());
              return;
            }
            auto view = R.move_as_ok();
            view.start_at = start_at;
            promise.set_value(std::move(view));
          }));
}

template <class SendQueryFn>
static void fetch_nominator_pool_delegation_view(SendQueryFn&& send_query,
                                                  const AccountCapabilityContext& ctx,
                                                  td::Promise<NominatorPoolDelegationView> promise) {
  run_get_method_latest(
      send_query, ctx.addr, "list_nominators",
      td::PromiseCreator::lambda(
          [promise = std::move(promise)](td::Result<td::Ref<vm::Stack>> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error());
              return;
            }
            auto stack = R.move_as_ok();
            NominatorPoolDelegationView view;

            if (stack->depth() == 0) {
              promise.set_value(std::move(view));
              return;
            }

            // Parse the cons-list of tuple4
            constexpr int kMaxListEntries = 10000;
            int list_count = 0;
            auto entry = stack->at(0);
            while (entry.is_tuple()) {
              if (++list_count > kMaxListEntries) break;
              auto cons = entry.as_tuple();
              if (cons->size() < 2) break;

              auto head = (*cons)[0];
              auto tail = (*cons)[1];

              if (head.is_tuple()) {
                auto elem = head.as_tuple();
                if (elem->size() >= 4 && (*elem)[0].is_int() && (*elem)[1].is_int()) {
                  NominatorDelegation nom;
                  // Address is a 256-bit integer; nominators are on workchain 0
                  auto addr_int = (*elem)[0].as_int();
                  unsigned char addr_bytes[32];
                  if (addr_int->export_bytes(addr_bytes, 32, false)) {
                    nom.principal = "0:" + td::hex_encode(td::Slice(
                        reinterpret_cast<const char*>(addr_bytes), 32));
                  }
                  {
                    auto v = (*elem)[1].as_int();
                    nom.amount = (v->sgn() >= 0 && v->fits_bits(63)) ? v->to_long() : -1;
                  }
                  {
                    if ((*elem)[2].is_int()) {
                      auto v = (*elem)[2].as_int();
                      nom.pending_deposit = (v->sgn() >= 0 && v->fits_bits(63)) ? v->to_long() : -1;
                    } else {
                      nom.pending_deposit = 0;
                    }
                  }
                  nom.withdraw_requested = (*elem)[3].is_int() && (*elem)[3].as_int()->sgn() > 0;
                  if (!nom.principal.empty()) {
                    view.nominators.push_back(std::move(nom));
                  }
                }
              }

              entry = tail;
            }

            promise.set_value(std::move(view));
          }));
}

template <class SendQueryFn>
static void fetch_session_wallet_view(SendQueryFn&& send_query,
                                      const AccountCapabilityContext& ctx,
                                      td::Promise<SessionWalletView> promise) {
  run_get_method_latest(
      send_query, ctx.addr, "get_sessions",
      td::PromiseCreator::lambda(
          [promise = std::move(promise)](td::Result<td::Ref<vm::Stack>> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error());
              return;
            }
            auto stack = R.move_as_ok();
            SessionWalletView view;

            if (stack->depth() == 0) {
              promise.set_value(std::move(view));
              return;
            }

            // Parse the cons-list of tuples (same pattern as nominator pool's list_nominators)
            constexpr int kMaxListEntries = 10000;
            int list_count = 0;
            auto entry = stack->at(0);
            while (entry.is_tuple()) {
              if (++list_count > kMaxListEntries) break;
              auto cons = entry.as_tuple();
              if (cons->size() < 2) break;

              auto head = (*cons)[0];
              auto tail = (*cons)[1];

              if (head.is_tuple()) {
                auto elem = head.as_tuple();
                // Each tuple has: [id, principal(256), scope(8), created_at(32), expires_at(32), revoked(1)]
                if (elem->size() >= 6 && (*elem)[0].is_int() && (*elem)[1].is_int()) {
                  SessionEntry se;
                  se.session_id = static_cast<td::int32>((*elem)[0].as_int()->to_long());
                  auto pk_int = (*elem)[1].as_int();
                  unsigned char pk_bytes[32];
                  if (pk_int->export_bytes(pk_bytes, 32, false)) {
                    se.principal = "ed25519:" + td::hex_encode(td::Slice(
                        reinterpret_cast<const char*>(pk_bytes), 32));
                  }
                  se.scope = (*elem)[2].is_int() ? static_cast<int>((*elem)[2].as_int()->to_long()) : 0;
                  se.created_at = (*elem)[3].is_int() ? static_cast<td::uint32>((*elem)[3].as_int()->to_long()) : 0;
                  se.expires_at = (*elem)[4].is_int() ? static_cast<td::uint32>((*elem)[4].as_int()->to_long()) : 0;
                  se.revoked = (*elem)[5].is_int() && (*elem)[5].as_int()->to_long() != 0;
                  if (!se.principal.empty()) {
                    view.sessions.push_back(std::move(se));
                  }
                }
              }

              entry = tail;
            }

            promise.set_value(std::move(view));
          }));
}

template <class SendQueryFn>
static void fetch_account_capability_context(SendQueryFn&& send_query,
                                             block::StdAddress addr, std::string addr_str,
                                             bool has_seqno, td::int32 seqno,
                                             td::Promise<AccountCapabilityContext> promise) {
  auto send_query_ptr = std::make_shared<std::decay_t<SendQueryFn>>(std::forward<SendQueryFn>(send_query));
  auto do_get_account = [addr, addr_str = std::move(addr_str), send_query_ptr](
                            tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
                            td::Promise<AccountCapabilityContext> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    (*send_query_ptr)(
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, addr_str = std::move(addr_str), promise_inner = std::move(promise_inner)](
                td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise_inner.set_error(td::Status::Error(
                    PSTRING() << "getAccountState: " << R.error().message()));
                return;
              }
              auto account_state_fetch = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
                  R.move_as_ok(), true);
              if (account_state_fetch.is_error()) {
                promise_inner.set_error(
                    td::Status::Error(PSTRING() << "parse accountState: "
                                                << account_state_fetch.error().message()));
                return;
              }
              auto f = account_state_fetch.move_as_ok();
              auto parsed_r = ParsedAccountState::parse(f, addr);
              if (parsed_r.is_error()) {
                promise_inner.set_error(
                    td::Status::Error(PSTRING() << "parse account: " << parsed_r.error().message()));
                return;
              }
              auto parsed = parsed_r.move_as_ok();
              std::string wallet_type;
              if (parsed.code_cell.not_null()) {
                wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
              }
              AccountCapabilityContext ctx;
              ctx.addr = addr;
              ctx.addr_str = std::move(addr_str);
              ctx.wallet_type = std::move(wallet_type);
              ctx.account_model = detect_account_model(parsed, ctx.wallet_type);
              ctx.authorization_version = detect_authorization_version(ctx.wallet_type);
              ctx.parsed = std::move(parsed);
              promise_inner.set_value(std::move(ctx));
            }));
  };

  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    (*send_query_ptr)(
        std::move(lookup_query),
        td::PromiseCreator::lambda(
            [do_get_account = std::move(do_get_account), promise = std::move(promise)](
                td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise.set_error(
                    td::Status::Error(PSTRING() << "lookupBlock: " << R.error().message()));
                return;
              }
              auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
                  R.move_as_ok(), true);
              if (lb_r.is_error()) {
                promise.set_error(
                    td::Status::Error(PSTRING() << "parse lookupBlock: " << lb_r.error().message()));
                return;
              }
              do_get_account(std::move(lb_r.move_as_ok()->id_), std::move(promise));
            }));
  } else {
    auto mc_inner =
        tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query =
        tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    (*send_query_ptr)(
        std::move(mc_query),
        td::PromiseCreator::lambda(
            [do_get_account = std::move(do_get_account), promise = std::move(promise)](
                td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise.set_error(
                    td::Status::Error(PSTRING() << "getMasterchainInfo: " << R.error().message()));
                return;
              }
              auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
                  R.move_as_ok(), true);
              if (mc_r.is_error()) {
                promise.set_error(
                    td::Status::Error(PSTRING() << "parse mcInfo: " << mc_r.error().message()));
                return;
              }
              do_get_account(std::move(mc_r.move_as_ok()->last_), std::move(promise));
            }));
  }
}

static td::Slice session_scope_name(int scope) {
  switch (scope) {
    case 0: return "submit_only";
    case 1: return "bounded_transfer";
    case 2: return "bounded_contract_call";
    default: return "unknown";
  }
}

static std::string build_delegation_grant_json(const std::string& account,
                                                const std::string& id,
                                                const std::string& grantor,
                                                const std::string& grantee,
                                                const std::string& scope,
                                                const std::string& constraints_json,
                                                const std::string& constraints_extensions_json,
                                                bool has_created_at, td::uint32 created_at,
                                                bool has_expires_at, td::uint32 expires_at,
                                                bool revocable,
                                                const std::string& status,
                                                bool projected = false) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.delegationGrant\""
     << ",\"account\":" << td::JsonString(td::Slice(account))
     << ",\"id\":" << td::JsonString(td::Slice(id))
     << ",\"grantor\":" << td::JsonString(td::Slice(grantor))
     << ",\"grantee\":" << td::JsonString(td::Slice(grantee))
     << ",\"scope\":" << td::JsonString(td::Slice(scope))
     << ",\"constraints\":" << constraints_json;
  if (!constraints_extensions_json.empty()) {
    sb << ",\"constraints_extensions\":" << constraints_extensions_json;
  }
  sb << ",\"created_at\":" << (has_created_at ? PSTRING() << created_at : "null")
     << ",\"expires_at\":" << (has_expires_at ? PSTRING() << expires_at : "null")
     << ",\"revoked_at\":null"
     << ",\"revocable\":" << (revocable ? "true" : "false")
     << ",\"revocation_reference\":null"
     << ",\"status\":" << td::JsonString(td::Slice(status));
  if (projected) {
    sb << ",\"projected\":true";
  }
  sb << "}";
  return sb.as_cslice().str();
}

static std::string build_session_capability_json(const std::string& account,
                                                  const std::string& session_id,
                                                  const std::string& principal,
                                                  const std::string& scope,
                                                  const std::string& constraints_json,
                                                  const std::string& constraints_extensions_json,
                                                  td::uint32 created_at,
                                                  td::uint32 expires_at,
                                                  bool revocable,
                                                  const std::string& status) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.sessionCapability\""
     << ",\"account\":" << td::JsonString(td::Slice(account))
     << ",\"session_id\":" << td::JsonString(td::Slice(session_id))
     << ",\"principal\":" << td::JsonString(td::Slice(principal))
     << ",\"scope\":" << td::JsonString(td::Slice(scope))
     << ",\"constraints\":" << constraints_json;
  if (!constraints_extensions_json.empty()) {
    sb << ",\"constraints_extensions\":" << constraints_extensions_json;
  }
  sb << ",\"created_at\":" << created_at
     << ",\"expires_at\":" << expires_at
     << ",\"revoked_at\":null"
     << ",\"revocable\":" << (revocable ? "true" : "false")
     << ",\"status\":" << td::JsonString(td::Slice(status))
     << "}";
  return sb.as_cslice().str();
}

static std::string build_agent_capability_json(const std::string& account,
                                                const std::string& agent_id,
                                                const std::string& principal,
                                                const std::string& scope,
                                                const std::string& constraints_json,
                                                const std::string& constraints_extensions_json,
                                                bool revocable,
                                                const std::string& status) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.agentCapability\""
     << ",\"account\":" << td::JsonString(td::Slice(account))
     << ",\"agent_id\":" << td::JsonString(td::Slice(agent_id))
     << ",\"principal\":" << td::JsonString(td::Slice(principal))
     << ",\"scope\":" << td::JsonString(td::Slice(scope))
     << ",\"constraints\":" << constraints_json;
  if (!constraints_extensions_json.empty()) {
    sb << ",\"constraints_extensions\":" << constraints_extensions_json;
  }
  sb << ",\"created_at\":null"
     << ",\"expires_at\":null"
     << ",\"revoked_at\":null"
     << ",\"revocable\":" << (revocable ? "true" : "false")
     << ",\"status\":" << td::JsonString(td::Slice(status))
     << "}";
  return sb.as_cslice().str();
}

static std::string build_account_capability_json(const std::string& address,
                                                 const ParsedAccountState& parsed,
                                                 const std::string& account_model,
                                                 const std::string& authorization_version,
                                                 bool supports_sponsorship,
                                                 bool include_sponsorship) {
  bool supports_agents = supports_account_standard_agents(account_model);
  bool supports_delegation = supports_account_standard_delegations(account_model);
  bool supports_sessions = supports_account_standard_sessions(account_model);
  bool has_real_permission_source = supports_agents || supports_delegation || supports_sessions;
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.capability\""
     << ",\"address\":" << td::JsonString(td::Slice(address))
     << ",\"account_model\":" << td::JsonString(td::Slice(account_model))
     << ",\"authorization_version\":" << td::JsonString(td::Slice(authorization_version))
     << ",\"supports_delegation\":" << (supports_delegation ? "true" : "false")
     << ",\"supports_sessions\":" << (supports_sessions ? "true" : "false")
     << ",\"supports_agents\":" << (supports_agents ? "true" : "false")
     << ",\"delegation_source\":" << td::JsonString(td::Slice(supports_delegation ? "account_standard" : "deferred"))
     << ",\"session_source\":" << td::JsonString(td::Slice(supports_sessions ? "account_standard" : "deferred"))
     << ",\"agent_source\":" << td::JsonString(td::Slice(supports_agents ? "account_standard" : "deferred"))
     << ",\"capability_maturity\":" << td::JsonString(td::Slice(has_real_permission_source ? "supported" : "initial"))
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

  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> promise_inner) {
    this->send_liteserver_query(std::move(query), std::move(promise_inner));
  };
  fetch_account_capability_context(
      send_query, addr, std::move(addr_str), has_seqno, seqno,
      td::PromiseCreator::lambda(
          [include_experimental, req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            promise.set_value(make_json_ok(
                build_account_capability_json(ctx.addr_str, ctx.parsed, ctx.account_model,
                                              ctx.authorization_version, false,
                                              include_experimental),
                req_id));
          }));
}

void JsonRpcServer::handle_getAccountDelegations(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto query_r = parse_permission_inspection_query(params);
  if (query_r.is_error()) {
    promise.set_value(make_json_error(-32602, query_r.move_as_error().message().str(), req_id));
    return;
  }
  auto query_opts = query_r.move_as_ok();

  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> promise_inner) {
    this->send_liteserver_query(std::move(query), std::move(promise_inner));
  };
  auto self_id = actor_id(this);
  fetch_account_capability_context(
      send_query, addr, std::move(addr_str), false, 0,
      td::PromiseCreator::lambda(
          [self_id, query_opts = std::move(query_opts), req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (supports_account_standard_delegations(ctx.account_model)) {
              if (query_opts.source_tier == RequestedPermissionSourceTier::Protocol ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Indexed ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Deferred) {
                promise.set_value(make_json_error(
                    -32603,
                    forced_source_error_message(PermissionKind::Delegation, query_opts.source_tier, ctx),
                    req_id));
                return;
              }

              auto send_query = [self_id](td::BufferSlice query,
                                          td::Promise<td::BufferSlice> promise_inner) mutable {
                td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                                        std::move(query), std::move(promise_inner));
              };

              if (ctx.account_model == "contract.pool.nominator") {
                fetch_nominator_pool_delegation_view(
                    send_query, ctx,
                    td::PromiseCreator::lambda(
                        [ctx = std::move(ctx), query_opts = std::move(query_opts),
                         req_id = std::move(req_id), promise = std::move(promise)](
                            td::Result<NominatorPoolDelegationView> R2) mutable {
                          if (R2.is_error()) {
                            promise.set_value(make_json_error(
                                -32603, PSTRING() << "getAccountDelegations: " << R2.error().message(), req_id));
                            return;
                          }
                          auto view = R2.move_as_ok();

                          // Status materialization: nominator pool can materialize both
                          // "active" and "revoked" statuses. A nominator with
                          // withdraw_requested=true has initiated withdrawal, which is
                          // treated as revocation evidence.
                          td::StringBuilder sb;
                          sb << "[";
                          bool first = true;
                          for (size_t i = 0; i < view.nominators.size(); i++) {
                            const auto& nom = view.nominators[i];
                            std::string status = nom.withdraw_requested ? "revoked" : "active";
                            if (query_opts.status_filter) {
                              if (query_opts.status_filter.value() != status) {
                                continue;
                              }
                            } else if (!query_opts.include_inactive &&
                                       (status == "expired" || status == "revoked")) {
                              continue;
                            }
                            if (!first) {
                              sb << ",";
                            }
                            first = false;
                            std::string constraints_json = PSTRING()
                                << "{\"max_value\":\"" << nom.amount << "\"}";
                            std::string extensions_json = PSTRING()
                                << "{\"account_model\":\"contract.pool.nominator\""
                                << ",\"pending_deposit\":\"" << nom.pending_deposit << "\""
                                << ",\"withdraw_requested\":" << (nom.withdraw_requested ? "true" : "false")
                                << "}";
                            sb << build_delegation_grant_json(
                                ctx.addr_str,
                                PSTRING() << ctx.addr_str << ":nominator-stake:" << nom.principal,
                                nom.principal,
                                ctx.addr_str,
                                "bounded_transfer",
                                constraints_json,
                                extensions_json,
                                false, 0,
                                false, 0,
                                true,
                                status);
                          }
                          sb << "]";
                          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                        }));
                return;
              }

              fetch_restricted_delegation_view_with_start(
                  send_query, ctx,
                  td::PromiseCreator::lambda(
                      [ctx = std::move(ctx), query_opts = std::move(query_opts),
                       req_id = std::move(req_id), promise = std::move(promise)](
                          td::Result<RestrictedDelegationView> R2) mutable {
                        if (R2.is_error()) {
                          promise.set_value(make_json_error(
                              -32603, PSTRING() << "getAccountDelegations: " << R2.error().message(), req_id));
                          return;
                        }
                        auto view = R2.move_as_ok();

                        // Status materialization: the restricted wallet vesting expires when
                        // the full balance is released (reserve reaches 0). At that point
                        // the restriction no longer applies and the delegation is "expired".
                        // When the reserve is still positive the delegation is "active".
                        // Filtering by revoked/unknown correctly returns empty because this
                        // source genuinely cannot produce those states.
                        std::string materialized_status;
                        if (view.available_balance >= view.full_balance) {
                          materialized_status = "expired";
                        } else {
                          materialized_status = "active";
                        }
                        if (query_opts.status_filter) {
                          if (query_opts.status_filter.value() != materialized_status) {
                            promise.set_value(make_json_ok("[]", req_id));
                            return;
                          }
                        } else if (!query_opts.include_inactive &&
                                   (materialized_status == "expired" || materialized_status == "revoked")) {
                          promise.set_value(make_json_ok("[]", req_id));
                          return;
                        }

                        td::int64 reserve = view.full_balance - view.available_balance;
                        if (reserve < 0) {
                          reserve = 0;
                        }
                        // Canonical constraints: only frozen vocabulary fields
                        std::string constraints_json = PSTRING()
                            << "{\"max_value\":\"" << view.available_balance << "\""
                            << ",\"not_before\":" << (view.start_at > 0 ? PSTRING() << view.start_at : "null")
                            << "}";
                        // Account-model-specific extensions (not part of the canonical vocabulary)
                        std::string extensions_json = PSTRING()
                            << "{\"account_model\":\"advanced.wallet.restricted\""
                            << ",\"vesting_start\":" << view.start_at
                            << ",\"reserved_balance\":\"" << reserve << "\"}";
                        auto grant = build_delegation_grant_json(
                            ctx.addr_str,
                            PSTRING() << ctx.addr_str << ":restricted-vesting:0",
                            "deployer",
                            view.principal,
                            "bounded_transfer",
                            constraints_json,
                            extensions_json,
                            true, view.start_at,
                            false, 0,
                            false,
                            materialized_status);
                        promise.set_value(make_json_ok(PSTRING() << "[" << grant << "]", req_id));
                      }));
              return;
            }
            if (query_opts.source_tier != RequestedPermissionSourceTier::Default) {
              promise.set_value(make_json_error(
                  -32603,
                  forced_source_error_message(PermissionKind::Delegation, query_opts.source_tier, ctx),
                  req_id));
              return;
            }
            promise.set_value(make_json_error(
                -32603, permission_source_error_message("getAccountDelegations", ctx), req_id));
          }));
}

void JsonRpcServer::handle_getAccountSessions(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto query_r = parse_permission_inspection_query(params);
  if (query_r.is_error()) {
    promise.set_value(make_json_error(-32602, query_r.move_as_error().message().str(), req_id));
    return;
  }
  auto query_opts = query_r.move_as_ok();

  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();
  auto self_id = actor_id(this);
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> promise_inner) {
    this->send_liteserver_query(std::move(query), std::move(promise_inner));
  };
  fetch_account_capability_context(
      send_query, addr, std::move(addr_str), false, 0,
      td::PromiseCreator::lambda(
          [self_id, query_opts = std::move(query_opts), req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (supports_account_standard_sessions(ctx.account_model)) {
              if (query_opts.source_tier == RequestedPermissionSourceTier::Protocol ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Indexed ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Deferred) {
                promise.set_value(make_json_error(
                    -32603,
                    forced_source_error_message(PermissionKind::Session, query_opts.source_tier, ctx),
                    req_id));
                return;
              }

              auto send_query = [self_id](td::BufferSlice query,
                                          td::Promise<td::BufferSlice> promise_inner) mutable {
                td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                                        std::move(query), std::move(promise_inner));
              };

              fetch_session_wallet_view(
                  send_query, ctx,
                  td::PromiseCreator::lambda(
                      [ctx = std::move(ctx), query_opts = std::move(query_opts),
                       req_id = std::move(req_id), promise = std::move(promise)](
                          td::Result<SessionWalletView> R2) mutable {
                        if (R2.is_error()) {
                          promise.set_value(make_json_error(
                              -32603, PSTRING() << "getAccountSessions: " << R2.error().message(), req_id));
                          return;
                        }
                        auto view = R2.move_as_ok();

                        // Status materialization per frozen rules:
                        // revoked > expired > active > unknown
                        td::StringBuilder sb;
                        sb << "[";
                        bool first = true;
                        for (size_t i = 0; i < view.sessions.size(); i++) {
                          const auto& se = view.sessions[i];
                          std::string status;
                          if (se.revoked) {
                            status = "revoked";
                          } else if (se.expires_at > 0 && ctx.parsed.sync_utime >= se.expires_at) {
                            status = "expired";
                          } else {
                            status = "active";
                          }
                          if (query_opts.status_filter) {
                            if (query_opts.status_filter.value() != status) {
                              continue;
                            }
                          } else if (!query_opts.include_inactive &&
                                     (status == "expired" || status == "revoked")) {
                            continue;
                          }
                          if (!first) {
                            sb << ",";
                          }
                          first = false;
                          std::string scope_str = session_scope_name(se.scope).str();
                          std::string constraints_json = PSTRING()
                              << "{\"not_before\":" << (se.created_at > 0 ? PSTRING() << se.created_at : "null")
                              << ",\"expires_at\":" << (se.expires_at > 0 ? PSTRING() << se.expires_at : "null")
                              << "}";
                          std::string extensions_json = PSTRING()
                              << "{\"account_model\":\"advanced.wallet.session\""
                              << ",\"scope_int\":" << se.scope
                              << "}";
                          sb << build_session_capability_json(
                              ctx.addr_str,
                              PSTRING() << ctx.addr_str << ":session:" << se.session_id,
                              se.principal,
                              scope_str,
                              constraints_json,
                              extensions_json,
                              se.created_at,
                              se.expires_at,
                              true,
                              status);
                        }
                        sb << "]";
                        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                      }));
              return;
            }
            if (query_opts.source_tier != RequestedPermissionSourceTier::Default) {
              promise.set_value(make_json_error(
                  -32603,
                  forced_source_error_message(PermissionKind::Session, query_opts.source_tier, ctx),
                  req_id));
              return;
            }
            promise.set_value(make_json_error(
                -32603, permission_source_error_message("getAccountSessions", ctx), req_id));
          }));
}

void JsonRpcServer::handle_getAccountAgents(td::JsonObject &params, std::string req_id,
                                            td::Promise<HttpReturn> promise) {
  auto query_r = parse_permission_inspection_query(params);
  if (query_r.is_error()) {
    promise.set_value(make_json_error(-32602, query_r.move_as_error().message().str(), req_id));
    return;
  }
  auto query_opts = query_r.move_as_ok();

  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();
  auto self_id = actor_id(this);
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> promise_inner) {
    this->send_liteserver_query(std::move(query), std::move(promise_inner));
  };
  fetch_account_capability_context(
      send_query, addr, std::move(addr_str), false, 0,
      td::PromiseCreator::lambda(
          [self_id, query_opts = std::move(query_opts), req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (supports_account_standard_agents(ctx.account_model)) {
              if (query_opts.source_tier == RequestedPermissionSourceTier::Protocol ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Indexed ||
                  query_opts.source_tier == RequestedPermissionSourceTier::Deferred) {
                promise.set_value(make_json_error(
                    -32603,
                    forced_source_error_message(PermissionKind::Agent, query_opts.source_tier, ctx),
                    req_id));
                return;
              }

              auto send_query = [self_id](td::BufferSlice query,
                                          td::Promise<td::BufferSlice> promise_inner) mutable {
                td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                                        std::move(query), std::move(promise_inner));
              };
              fetch_multisig_agent_view(
                  send_query, ctx,
                  td::PromiseCreator::lambda(
                      [ctx = std::move(ctx), query_opts = std::move(query_opts),
                       req_id = std::move(req_id), promise = std::move(promise)](
                          td::Result<MultisigAgentView> R2) mutable {
                        if (R2.is_error()) {
                          promise.set_value(make_json_error(
                              -32603, PSTRING() << "getAccountAgents: " << R2.error().message(), req_id));
                          return;
                        }
                        auto view = R2.move_as_ok();

                        // Status materialization: multisig owner list has no on-chain
                        // revocation or expiration evidence. The only status this source
                        // can materialize is "active".
                        std::string materialized_status = "active";
                        if (query_opts.status_filter) {
                          if (query_opts.status_filter.value() != materialized_status) {
                            promise.set_value(make_json_ok("[]", req_id));
                            return;
                          }
                        } else if (!query_opts.include_inactive &&
                                   (materialized_status == "expired" || materialized_status == "revoked")) {
                          promise.set_value(make_json_ok("[]", req_id));
                          return;
                        }
                        td::StringBuilder sb;
                        sb << "[";
                        for (size_t i = 0; i < view.principals.size(); i++) {
                          if (i > 0) {
                            sb << ",";
                          }
                          // Canonical constraints: empty — multisig threshold semantics do not
                          // map to any frozen canonical constraint field. threshold_k is a
                          // per-action co-signature requirement, not a use-count limit.
                          std::string constraints_json = "{}";
                          // Account-model-specific extensions carry the real threshold semantics
                          std::string extensions_json = PSTRING()
                              << "{\"account_model\":\"advanced.wallet.multisig\""
                              << ",\"threshold_n\":" << view.threshold_n
                              << ",\"threshold_k\":" << view.threshold_k << "}";
                          sb << build_agent_capability_json(
                              ctx.addr_str,
                              PSTRING() << ctx.addr_str << ":multisig-owner:" << i,
                              view.principals[i],
                              "agent_execution",
                              constraints_json,
                              extensions_json,
                              false,
                              materialized_status);
                        }
                        sb << "]";
                        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                      }));
              return;
            }
            if (query_opts.source_tier != RequestedPermissionSourceTier::Default) {
              promise.set_value(make_json_error(
                  -32603,
                  forced_source_error_message(PermissionKind::Agent, query_opts.source_tier, ctx),
                  req_id));
              return;
            }
            promise.set_value(make_json_error(
                -32603, permission_source_error_message("getAccountAgents", ctx), req_id));
          }));
}

// ─── Delegation reference validation for transaction intents ──────────────────

void JsonRpcServer::validate_delegation_and_return_intent(
    block::StdAddress addr, std::string addr_str,
    std::string delegation_ref,
    std::string intent_json,
    std::string req_id,
    td::Promise<HttpReturn> promise) {
  auto self_id = actor_id(this);
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, std::move(addr_str), false, 0,
      td::PromiseCreator::lambda(
          [self_id, delegation_ref = std::move(delegation_ref),
           intent_json = std::move(intent_json),
           req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (!supports_account_standard_delegations(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "DELEGATION_UNAVAILABLE: account_model=" << ctx.account_model
                      << " does not support delegation inspection", req_id));
              return;
            }

            auto send_query = [self_id](td::BufferSlice query,
                                        td::Promise<td::BufferSlice> p) mutable {
              td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                                      std::move(query), std::move(p));
            };

            if (ctx.account_model == "advanced.wallet.restricted") {
              fetch_restricted_delegation_view_with_start(
                  send_query, ctx,
                  td::PromiseCreator::lambda(
                      [ctx = std::move(ctx), delegation_ref = std::move(delegation_ref),
                       intent_json = std::move(intent_json),
                       req_id = std::move(req_id), promise = std::move(promise)](
                          td::Result<RestrictedDelegationView> R2) mutable {
                        if (R2.is_error()) {
                          promise.set_value(make_json_error(-32603,
                              PSTRING() << "DELEGATION_UNAVAILABLE: " << R2.error().message(), req_id));
                          return;
                        }
                        auto view = R2.move_as_ok();
                        auto expected_id = PSTRING() << ctx.addr_str << ":restricted-vesting:0";
                        if (delegation_ref != expected_id) {
                          promise.set_value(make_json_error(-32603,
                              PSTRING() << "DELEGATION_UNAVAILABLE: delegation_ref=" << delegation_ref
                                  << " does not match the restricted delegation id", req_id));
                          return;
                        }
                        if (view.available_balance >= view.full_balance) {
                          promise.set_value(make_json_error(-32603,
                              "DELEGATION_EXPIRED: the restricted wallet vesting has fully released", req_id));
                          return;
                        }
                        // Validate not_before: if start_at > 0 and sync_utime < start_at
                        if (view.start_at > 0 && ctx.parsed.sync_utime < view.start_at) {
                          promise.set_value(make_json_error(-32603,
                              PSTRING() << "DELEGATION_SCOPE_VIOLATION: not_before constraint not met"
                                  << " (vesting_start=" << view.start_at
                                  << ", current_time=" << ctx.parsed.sync_utime << ")", req_id));
                          return;
                        }
                        // Delegation is active and constraints are met
                        promise.set_value(make_json_ok(intent_json, req_id));
                      }));
              return;
            }

            if (ctx.account_model == "contract.pool.nominator") {
              fetch_nominator_pool_delegation_view(
                  send_query, ctx,
                  td::PromiseCreator::lambda(
                      [ctx = std::move(ctx), delegation_ref = std::move(delegation_ref),
                       intent_json = std::move(intent_json),
                       req_id = std::move(req_id), promise = std::move(promise)](
                          td::Result<NominatorPoolDelegationView> R2) mutable {
                        if (R2.is_error()) {
                          promise.set_value(make_json_error(-32603,
                              PSTRING() << "DELEGATION_UNAVAILABLE: " << R2.error().message(), req_id));
                          return;
                        }
                        auto view = R2.move_as_ok();
                        // Find the delegation matching the ref
                        bool found = false;
                        for (size_t i = 0; i < view.nominators.size(); i++) {
                          auto expected_id = PSTRING() << ctx.addr_str << ":nominator-stake:" << view.nominators[i].principal;
                          if (delegation_ref == expected_id) {
                            found = true;
                            if (view.nominators[i].withdraw_requested) {
                              promise.set_value(make_json_error(-32603,
                                  "DELEGATION_REVOKED: the nominator has submitted a withdraw request", req_id));
                              return;
                            }
                            break;
                          }
                        }
                        if (!found) {
                          promise.set_value(make_json_error(-32603,
                              PSTRING() << "DELEGATION_UNAVAILABLE: delegation_ref=" << delegation_ref
                                  << " not found in pool", req_id));
                          return;
                        }
                        promise.set_value(make_json_ok(intent_json, req_id));
                      }));
              return;
            }

            // Shouldn't reach here if supports_account_standard_delegations is correct
            promise.set_value(make_json_error(-32603,
                "DELEGATION_UNAVAILABLE: unhandled account model", req_id));
          }));
}

// ─── Lifecycle mutation helpers ─────────────────────────────────────────────

static std::string lifecycle_unsupported_message(const char* method, const AccountCapabilityContext& ctx) {
  return PSTRING() << "PERMISSION_SOURCE_UNSUPPORTED: " << method
      << " is not supported for account_model=" << ctx.account_model;
}

static std::string lifecycle_immutable_message(const char* method, const AccountCapabilityContext& ctx) {
  return PSTRING() << "LIFECYCLE_IMMUTABLE: " << method
      << " cannot modify permissions for account_model=" << ctx.account_model
      << " because permissions are fixed at deployment";
}

static bool account_model_has_immutable_delegations(const std::string& model) {
  return model == "advanced.wallet.restricted";
}

static bool account_model_has_immutable_agents(const std::string& model) {
  return model == "advanced.wallet.multisig";
}

static bool account_model_supports_delegation_lifecycle(const std::string& model) {
  return model == "contract.pool.nominator";
}

// ─── Lifecycle request parsers ──────────────────────────────────────────

static const std::array<const char*, 5> CANONICAL_SCOPES = {
    "submit_only", "bounded_transfer", "bounded_contract_call",
    "session_issuance", "agent_execution"
};

static const std::array<const char*, 5> CANONICAL_CONSTRAINT_FIELDS = {
    "target_allowlist", "max_value", "max_uses", "not_before", "expires_at"
};

static bool is_canonical_scope(const std::string& scope) {
  for (auto s : CANONICAL_SCOPES) {
    if (scope == s) return true;
  }
  return false;
}

struct GrantRequest {
  std::string address;
  std::string grantee;
  std::string scope;
  std::string constraints_json;  // raw JSON string
  td::uint32 expires_at{0};
  bool has_expires_at{false};
  bool revocable{true};
};

struct RevokeRequest {
  std::string address;
  std::string permission_id;
};

static td::Result<td::Unit> validate_nominator_lifecycle_grant(const GrantRequest& grant) {
  if (grant.scope != "bounded_transfer") {
    return td::Status::Error(
        "DELEGATION_SCOPE_VIOLATION: contract.pool.nominator only supports bounded_transfer");
  }
  if (grant.constraints_json != "{}") {
    return td::Status::Error(
        "INVALID_CONSTRAINTS: contract.pool.nominator does not support caller-supplied constraints");
  }
  if (grant.has_expires_at) {
    return td::Status::Error(
        "INVALID_CONSTRAINTS: contract.pool.nominator does not support expires_at");
  }
  return td::Unit();
}

static td::Result<GrantRequest> parse_grant_request(td::JsonObject &params) {
  GrantRequest req;

  // address (required)
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) {
    return td::Status::Error("MISSING_FIELD: 'address' is required");
  }
  req.address = addr_r.ok();

  // grantee (required)
  auto grantee_r = params.get_required_string_field("grantee");
  if (grantee_r.is_error()) {
    return td::Status::Error("MISSING_GRANTEE: 'grantee' is required for grant operations");
  }
  req.grantee = grantee_r.ok();
  if (req.grantee.empty()) {
    return td::Status::Error("MISSING_GRANTEE: 'grantee' must not be empty");
  }

  // scope (required, must be canonical)
  auto scope_r = params.get_required_string_field("scope");
  if (scope_r.is_error()) {
    return td::Status::Error("INVALID_SCOPE: 'scope' is required for grant operations");
  }
  req.scope = scope_r.ok();
  if (!is_canonical_scope(req.scope)) {
    return td::Status::Error(PSTRING() << "INVALID_SCOPE: '" << req.scope
        << "' is not a canonical scope value");
  }

  // constraints (optional object — validate known fields if present)
  auto constraints_v = params.extract_field("constraints");
  if (constraints_v.type() == td::JsonValue::Type::Object) {
    auto &cobj = constraints_v.get_object();
    // Validate that only canonical constraint fields are present
    for (auto &field : cobj.field_values_) {
      bool found = false;
      for (auto cf : CANONICAL_CONSTRAINT_FIELDS) {
        if (field.first == td::Slice{cf}) {
          found = true;
          break;
        }
      }
      if (!found) {
        return td::Status::Error(PSTRING() << "INVALID_CONSTRAINTS: unrecognized constraint field '"
            << field.first << "'; only canonical fields are allowed");
      }
    }
    // Serialize constraints back to JSON string
    td::StringBuilder sb;
    sb << "{";
    bool first = true;
    for (auto &field : cobj.field_values_) {
      if (!first) sb << ",";
      first = false;
      sb << td::JsonString(td::Slice(field.first)) << ":";
      if (field.second.type() == td::JsonValue::Type::String) {
        sb << td::JsonString(td::Slice(field.second.get_string()));
      } else if (field.second.type() == td::JsonValue::Type::Number) {
        sb << field.second.get_number();
      } else if (field.second.type() == td::JsonValue::Type::Boolean) {
        sb << (field.second.get_boolean() ? "true" : "false");
      } else if (field.second.type() == td::JsonValue::Type::Null) {
        sb << "null";
      } else {
        return td::Status::Error(PSTRING() << "INVALID_CONSTRAINTS: field '" << field.first
            << "' must be a scalar or null value");
      }
    }
    sb << "}";
    req.constraints_json = sb.as_cslice().str();
  } else {
    req.constraints_json = "{}";
  }

  // expires_at (optional)
  auto expires_r = params.get_optional_int_field("expires_at");
  if (expires_r.is_ok() && expires_r.ok() > 0) {
    if (expires_r.ok() > static_cast<td::int64>(std::numeric_limits<td::uint32>::max())) {
      return td::Status::Error("INVALID_EXPIRES_AT: value out of uint32 range");
    }
    req.expires_at = static_cast<td::uint32>(expires_r.ok());
    req.has_expires_at = true;
  }

  // revocable (optional, default true)
  auto revocable_r = params.get_optional_bool_field("revocable", true);
  if (revocable_r.is_ok()) {
    req.revocable = revocable_r.ok();
  }

  return req;
}

static td::Result<RevokeRequest> parse_revoke_request(td::JsonObject &params) {
  RevokeRequest req;

  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) {
    return td::Status::Error("MISSING_FIELD: 'address' is required");
  }
  req.address = addr_r.ok();

  auto pid_r = params.get_required_string_field("permission_id");
  if (pid_r.is_error()) {
    return td::Status::Error("MISSING_PERMISSION_ID: 'permission_id' is required for revoke operations");
  }
  req.permission_id = pid_r.ok();
  if (req.permission_id.empty()) {
    return td::Status::Error("MISSING_PERMISSION_ID: 'permission_id' must not be empty");
  }

  return req;
}

// ─── Lifecycle response builder ───────────────────────────────────────────

static std::string build_mutation_result_json(const std::string& method,
                                                const std::string& account_model,
                                                const std::string& mutation_intent_json,
                                                const std::string& affected_preview_json,
                                                const std::string& preview_note = "") {
  td::StringBuilder sb;
  sb << "{\"@type\":\"lifecycle.mutationResult\""
     << ",\"method\":" << td::JsonString(td::Slice(method))
     << ",\"account_model\":" << td::JsonString(td::Slice(account_model))
     << ",\"accepted\":true"
     << ",\"mutation_intent\":" << mutation_intent_json
     << ",\"affected_object_preview\":" << affected_preview_json;
  if (!preview_note.empty()) {
    sb << ",\"preview_note\":" << td::JsonString(td::Slice(preview_note));
  }
  sb << "}";
  return sb.as_cslice().str();
}

// ─── Lifecycle mutation RPC handlers ────────────────────────────────────────

void JsonRpcServer::handle_grantAccountDelegation(td::JsonObject &params, std::string req_id,
                                                    td::Promise<HttpReturn> promise) {
  auto grant_r = parse_grant_request(params);
  if (grant_r.is_error()) {
    promise.set_value(make_json_error(-32602, grant_r.move_as_error().message().str(), req_id));
    return;
  }
  auto grant = grant_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(grant.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, grant.address, false, 0,
      td::PromiseCreator::lambda(
          [grant = std::move(grant), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (account_model_has_immutable_delegations(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_immutable_message("grantAccountDelegation", ctx), req_id));
              return;
            }
            if (!account_model_supports_delegation_lifecycle(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_unsupported_message("grantAccountDelegation", ctx), req_id));
              return;
            }
            auto validation_r = validate_nominator_lifecycle_grant(grant);
            if (validation_r.is_error()) {
              promise.set_value(make_json_error(
                  -32602, validation_r.move_as_error().message().str(), req_id));
              return;
            }

            // Nominator pool: deposit is a standard wallet transfer with text comment "d"
            // grantor = the nominator (grant.grantee from request), grantee = the pool
            std::string intent_json = PSTRING()
                << "{\"type\":\"internal_transfer\""
                << ",\"destination\":" << td::JsonString(td::Slice(ctx.addr_str))
                << ",\"body_comment\":\"d\"}";

            auto preview = build_delegation_grant_json(
                ctx.addr_str,
                PSTRING() << ctx.addr_str << ":nominator-stake:pending",
                grant.grantee,
                ctx.addr_str,
                grant.scope,
                "{}",
                "",
                false, 0,
                false, 0,
                true,
                "active",
                true);

            auto result = build_mutation_result_json(
                "grantAccountDelegation", ctx.account_model,
                intent_json, preview,
                "projected: principal is derived from request grantee, not from on-chain state");
            promise.set_value(make_json_ok(result, req_id));
          }));
}

void JsonRpcServer::handle_revokeAccountDelegation(td::JsonObject &params, std::string req_id,
                                                     td::Promise<HttpReturn> promise) {
  auto revoke_r = parse_revoke_request(params);
  if (revoke_r.is_error()) {
    promise.set_value(make_json_error(-32602, revoke_r.move_as_error().message().str(), req_id));
    return;
  }
  auto revoke = revoke_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(revoke.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  auto self_id = actor_id(this);
  fetch_account_capability_context(
      send_query, addr, revoke.address, false, 0,
      td::PromiseCreator::lambda(
          [self_id, revoke = std::move(revoke), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (account_model_has_immutable_delegations(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_immutable_message("revokeAccountDelegation", ctx), req_id));
              return;
            }
            if (!account_model_supports_delegation_lifecycle(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_unsupported_message("revokeAccountDelegation", ctx), req_id));
              return;
            }
            auto send_query2 = [self_id](td::BufferSlice query, td::Promise<td::BufferSlice> p) mutable {
              td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                                      std::move(query), std::move(p));
            };
            fetch_nominator_pool_delegation_view(
                send_query2, ctx,
                td::PromiseCreator::lambda(
                    [ctx = std::move(ctx), revoke = std::move(revoke),
                     req_id = std::move(req_id), promise = std::move(promise)](
                        td::Result<NominatorPoolDelegationView> R2) mutable {
                      if (R2.is_error()) {
                        promise.set_value(make_json_error(
                            -32603, PSTRING() << "DELEGATION_UNAVAILABLE: " << R2.error().message(), req_id));
                        return;
                      }
                      auto view = R2.move_as_ok();
                      const NominatorDelegation* matched = nullptr;
                      for (size_t i = 0; i < view.nominators.size(); i++) {
                        auto expected_id = PSTRING() << ctx.addr_str << ":nominator-stake:" << view.nominators[i].principal;
                        if (revoke.permission_id == expected_id) {
                          matched = &view.nominators[i];
                          break;
                        }
                      }
                      if (!matched) {
                        promise.set_value(make_json_error(
                            -32603,
                            PSTRING() << "DELEGATION_UNAVAILABLE: permission_id=" << revoke.permission_id
                                      << " not found in pool",
                            req_id));
                        return;
                      }
                      if (matched->withdraw_requested) {
                        promise.set_value(make_json_error(
                            -32603,
                            "DELEGATION_REVOKED: the nominator has already submitted a withdraw request",
                            req_id));
                        return;
                      }

                      std::string intent_json = PSTRING()
                          << "{\"type\":\"internal_transfer\""
                          << ",\"destination\":" << td::JsonString(td::Slice(ctx.addr_str))
                          << ",\"body_comment\":\"w\"}";
                      std::string constraints_json = PSTRING()
                          << "{\"max_value\":\"" << matched->amount << "\"}";
                      std::string extensions_json = PSTRING()
                          << "{\"account_model\":\"contract.pool.nominator\""
                          << ",\"pending_deposit\":\"" << matched->pending_deposit << "\""
                          << ",\"withdraw_requested\":true"
                          << "}";
                      auto preview = build_delegation_grant_json(
                          ctx.addr_str,
                          PSTRING() << ctx.addr_str << ":nominator-stake:" << matched->principal,
                          matched->principal,
                          ctx.addr_str,
                          "bounded_transfer",
                          constraints_json,
                          extensions_json,
                          false, 0,
                          false, 0,
                          true,
                          "revoked");

                      auto result = build_mutation_result_json(
                          "revokeAccountDelegation", ctx.account_model,
                          intent_json, preview);
                      promise.set_value(make_json_ok(result, req_id));
                    }));
          }));
}

void JsonRpcServer::handle_grantAccountSession(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  // Validate grant request fields BEFORE checking account model
  auto grant_r = parse_grant_request(params);
  if (grant_r.is_error()) {
    promise.set_value(make_json_error(-32602, grant_r.move_as_error().message().str(), req_id));
    return;
  }
  auto grant = grant_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(grant.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, grant.address, false, 0,
      td::PromiseCreator::lambda(
          [grant = std::move(grant), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            // No account model currently supports session lifecycle
            promise.set_value(make_json_error(-32603,
                lifecycle_unsupported_message("grantAccountSession", ctx), req_id));
          }));
}

void JsonRpcServer::handle_revokeAccountSession(td::JsonObject &params, std::string req_id,
                                                   td::Promise<HttpReturn> promise) {
  // Validate revoke request fields BEFORE checking account model
  auto revoke_r = parse_revoke_request(params);
  if (revoke_r.is_error()) {
    promise.set_value(make_json_error(-32602, revoke_r.move_as_error().message().str(), req_id));
    return;
  }
  auto revoke = revoke_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(revoke.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, revoke.address, false, 0,
      td::PromiseCreator::lambda(
          [revoke = std::move(revoke), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            // No account model currently supports session lifecycle
            promise.set_value(make_json_error(-32603,
                lifecycle_unsupported_message("revokeAccountSession", ctx), req_id));
          }));
}

void JsonRpcServer::handle_grantAccountAgent(td::JsonObject &params, std::string req_id,
                                               td::Promise<HttpReturn> promise) {
  // Validate grant request fields BEFORE checking account model
  auto grant_r = parse_grant_request(params);
  if (grant_r.is_error()) {
    promise.set_value(make_json_error(-32602, grant_r.move_as_error().message().str(), req_id));
    return;
  }
  auto grant = grant_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(grant.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, grant.address, false, 0,
      td::PromiseCreator::lambda(
          [grant = std::move(grant), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (account_model_has_immutable_agents(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_immutable_message("grantAccountAgent", ctx), req_id));
              return;
            }
            // No account model currently supports agent lifecycle beyond immutable
            promise.set_value(make_json_error(-32603,
                lifecycle_unsupported_message("grantAccountAgent", ctx), req_id));
          }));
}

void JsonRpcServer::handle_revokeAccountAgent(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  // Validate revoke request fields BEFORE checking account model
  auto revoke_r = parse_revoke_request(params);
  if (revoke_r.is_error()) {
    promise.set_value(make_json_error(-32602, revoke_r.move_as_error().message().str(), req_id));
    return;
  }
  auto revoke = revoke_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(revoke.address))) {
    promise.set_value(make_json_error(-32602, "invalid address", req_id));
    return;
  }
  auto send_query = [this](td::BufferSlice query, td::Promise<td::BufferSlice> p) {
    this->send_liteserver_query(std::move(query), std::move(p));
  };
  fetch_account_capability_context(
      send_query, addr, revoke.address, false, 0,
      td::PromiseCreator::lambda(
          [revoke = std::move(revoke), req_id = std::move(req_id),
           promise = std::move(promise)](td::Result<AccountCapabilityContext> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, R.move_as_error().message().str(), req_id));
              return;
            }
            auto ctx = R.move_as_ok();
            if (account_model_has_immutable_agents(ctx.account_model)) {
              promise.set_value(make_json_error(-32603,
                  lifecycle_immutable_message("revokeAccountAgent", ctx), req_id));
              return;
            }
            // No account model currently supports agent lifecycle beyond immutable
            promise.set_value(make_json_error(-32603,
                lifecycle_unsupported_message("revokeAccountAgent", ctx), req_id));
          }));
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
              auto stk_r = parse_get_method_result_stack(rr_val->result_.as_slice());
              if (stk_r.is_ok()) {
                auto stk = stk_r.move_as_ok();
                if (stk->depth() > 0 && stk->at(0).is_int()) {
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
