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

// Internal to the JSON-RPC server: the account-capability views that read a
// restricted wallet through liteserver queries. The getAccountDelegations and
// transaction-intent handlers call these functions and only wrap the result;
// test/test-json-rpc-account-capability.cpp instantiates the same templates
// with a fake query function. Included by json-rpc-server-account-capability.cpp
// and that test only.
#pragma once

#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "auto/tl/lite_api.hpp"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl/tl_object_parse.h"
#include "vm/stack.hpp"

#include "json-rpc-server-internal.h"

namespace tos {

struct RestrictedDelegationView {
  std::string principal;  // "ed25519:<hex>"
  td::uint32 start_at{0};
  td::int64 available_balance{0};
  td::int64 full_balance{0};
};

enum class RequestedPermissionSourceTier { Default, Protocol, AccountStandard, Indexed, Deferred };

struct PermissionInspectionQuery {
  bool include_inactive{false};
  td::optional<std::string> status_filter;
  RequestedPermissionSourceTier source_tier{RequestedPermissionSourceTier::Default};
};

template <class SendQueryFn>
void run_get_method_latest(SendQueryFn&& send_query, const block::StdAddress& addr, td::Slice method_name,
                           td::Promise<td::Ref<vm::Stack>> promise) {
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
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr), method_id,
            std::move(params_boc)),
        true);
    auto query =
        tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    (*send_query_ptr)(
        std::move(query),
        td::PromiseCreator::lambda([promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise_inner.set_error(td::Status::Error(PSTRING() << "runSmcMethod: " << R.error().message()));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(R.move_as_ok(), true);
          if (F.is_error()) {
            promise_inner.set_error(td::Status::Error(PSTRING() << "parse runMethodResult: " << F.error().message()));
            return;
          }
          auto f = F.move_as_ok();
          if (f->exit_code_ != 0) {
            promise_inner.set_error(td::Status::Error(PSTRING() << "runSmcMethod exit_code=" << f->exit_code_));
            return;
          }
          promise_inner.set_result(parse_get_method_result_stack(f->result_.as_slice()));
        }));
  };

  auto mc_inner = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query =
      tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
  (*send_query_ptr)(
      std::move(mc_query), td::PromiseCreator::lambda([do_run = std::move(do_run), promise = std::move(promise)](
                                                          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_error(td::Status::Error(PSTRING() << "getMasterchainInfo: " << R.error().message()));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_error(td::Status::Error(PSTRING() << "parse mcInfo: " << mc_r.error().message()));
          return;
        }
        do_run(std::move(mc_r.move_as_ok()->last_), std::move(promise));
      }));
}

template <class SendQueryFn>
void fetch_restricted_delegation_view(SendQueryFn&& send_query, const AccountCapabilityContext& ctx,
                                      td::Promise<RestrictedDelegationView> promise) {
  run_get_method_latest(
      send_query, ctx.addr, "get_public_key",
      td::PromiseCreator::lambda([send_query, ctx_addr = ctx.addr, full_balance = ctx.parsed.balance,
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
            td::PromiseCreator::lambda([principal = std::move(principal), full_balance,
                                        promise = std::move(promise)](td::Result<td::Ref<vm::Stack>> R2) mutable {
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
void fetch_restricted_delegation_view_with_start(SendQueryFn&& send_query, const AccountCapabilityContext& ctx,
                                                 td::Promise<RestrictedDelegationView> promise) {
  // Parse start_at from the data cell: seqno(32) + subwallet_id(32) + public_key(256) + start_at(32).
  // The data cell is attacker-controlled (the code hash alone selected this
  // account model), so the parse must not throw on an exotic root. A root that
  // cannot be read at all (null or exotic) refuses the view before any query:
  // reporting start 0 there would answer a vesting-locked wallet as unlocked.
  // A readable cell too short to hold start_at reports 0.
  auto start_at_r = parse_restricted_wallet_start_at(ctx.parsed.data_cell);
  if (start_at_r.is_error()) {
    promise.set_error(td::Status::Error(PSTRING() << "DELEGATION_UNAVAILABLE: cannot read restricted wallet start_at: "
                                                  << start_at_r.error().message()));
    return;
  }
  td::uint32 start_at = start_at_r.move_as_ok();

  fetch_restricted_delegation_view(std::forward<SendQueryFn>(send_query), ctx,
                                   td::PromiseCreator::lambda([start_at, promise = std::move(promise)](
                                                                  td::Result<RestrictedDelegationView> R) mutable {
                                     if (R.is_error()) {
                                       promise.set_error(R.move_as_error());
                                       return;
                                     }
                                     auto view = R.move_as_ok();
                                     view.start_at = start_at;
                                     promise.set_value(std::move(view));
                                   }));
}

inline std::string build_delegation_grant_json(const std::string& account, const std::string& id,
                                               const std::string& grantor, const std::string& grantee,
                                               const std::string& scope, const std::string& constraints_json,
                                               const std::string& constraints_extensions_json, bool has_created_at,
                                               td::uint32 created_at, bool has_expires_at, td::uint32 expires_at,
                                               bool revocable, const std::string& status, bool projected = false) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"account.delegationGrant\""
     << ",\"account\":" << td::JsonString(td::Slice(account)) << ",\"id\":" << td::JsonString(td::Slice(id))
     << ",\"grantor\":" << td::JsonString(td::Slice(grantor)) << ",\"grantee\":" << td::JsonString(td::Slice(grantee))
     << ",\"scope\":" << td::JsonString(td::Slice(scope)) << ",\"constraints\":" << constraints_json;
  if (!constraints_extensions_json.empty()) {
    sb << ",\"constraints_extensions\":" << constraints_extensions_json;
  }
  sb << ",\"created_at\":" << (has_created_at ? PSTRING() << created_at : "null")
     << ",\"expires_at\":" << (has_expires_at ? PSTRING() << expires_at : "null") << ",\"revoked_at\":null"
     << ",\"revocable\":" << (revocable ? "true" : "false") << ",\"revocation_reference\":null"
     << ",\"status\":" << td::JsonString(td::Slice(status));
  if (projected) {
    sb << ",\"projected\":true";
  }
  sb << "}";
  return sb.as_cslice().str();
}

// The getAccountDelegations result for an advanced.wallet.restricted account:
// a JSON array with the single vesting delegation, or empty when the filter
// excludes it. The context is moved into shared ownership once, in its own
// statement, so the view query and its continuation both read the live
// context rather than a moved-from one.
template <class SendQueryFn>
void restricted_delegations_json(SendQueryFn send_query, AccountCapabilityContext ctx,
                                 const PermissionInspectionQuery& query_opts, td::Promise<std::string> promise) {
  auto shared_ctx = std::make_shared<const AccountCapabilityContext>(std::move(ctx));
  fetch_restricted_delegation_view_with_start(
      std::move(send_query), *shared_ctx,
      td::PromiseCreator::lambda(
          [shared_ctx, query_opts, promise = std::move(promise)](td::Result<RestrictedDelegationView> R) mutable {
            if (R.is_error()) {
              promise.set_error(R.move_as_error_prefix("getAccountDelegations: "));
              return;
            }
            const AccountCapabilityContext& ctx = *shared_ctx;
            auto view = R.move_as_ok();

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
                promise.set_value("[]");
                return;
              }
            } else if (!query_opts.include_inactive &&
                       (materialized_status == "expired" || materialized_status == "revoked")) {
              promise.set_value("[]");
              return;
            }

            td::int64 reserve = view.full_balance - view.available_balance;
            if (reserve < 0) {
              reserve = 0;
            }
            // Canonical constraints: only frozen vocabulary fields
            std::string constraints_json =
                PSTRING() << "{\"max_value\":\"" << view.available_balance << "\""
                          << ",\"not_before\":" << (view.start_at > 0 ? PSTRING() << view.start_at : "null") << "}";
            // Account-model-specific extensions (not part of the canonical vocabulary)
            std::string extensions_json = PSTRING() << "{\"account_model\":\"advanced.wallet.restricted\""
                                                    << ",\"vesting_start\":" << view.start_at
                                                    << ",\"reserved_balance\":\"" << reserve << "\"}";
            auto grant =
                build_delegation_grant_json(ctx.addr_str, PSTRING() << ctx.addr_str << ":restricted-vesting:0",
                                            "deployer", view.principal, "bounded_transfer", constraints_json,
                                            extensions_json, true, view.start_at, false, 0, false, materialized_status);
            promise.set_value(PSTRING() << "[" << grant << "]");
          }));
}

// Whether a transaction intent may use delegation_ref on an
// advanced.wallet.restricted account now. Succeeds only for the account's own
// vesting delegation while it is active and its not_before constraint is met;
// every refusal carries its DELEGATION_* code. The context is shared as in
// restricted_delegations_json.
template <class SendQueryFn>
void check_restricted_delegation_ref(SendQueryFn send_query, AccountCapabilityContext ctx, std::string delegation_ref,
                                     td::Promise<td::Unit> promise) {
  auto shared_ctx = std::make_shared<const AccountCapabilityContext>(std::move(ctx));
  fetch_restricted_delegation_view_with_start(
      std::move(send_query), *shared_ctx,
      td::PromiseCreator::lambda([shared_ctx, delegation_ref = std::move(delegation_ref),
                                  promise = std::move(promise)](td::Result<RestrictedDelegationView> R) mutable {
        if (R.is_error()) {
          auto error = R.move_as_error();
          if (td::begins_with(error.message(), "DELEGATION_UNAVAILABLE:")) {
            promise.set_error(std::move(error));
          } else {
            promise.set_error(error.move_as_error_prefix("DELEGATION_UNAVAILABLE: "));
          }
          return;
        }
        const AccountCapabilityContext& ctx = *shared_ctx;
        auto view = R.move_as_ok();
        auto expected_id = PSTRING() << ctx.addr_str << ":restricted-vesting:0";
        if (delegation_ref != expected_id) {
          promise.set_error(td::Status::Error(PSTRING() << "DELEGATION_UNAVAILABLE: delegation_ref=" << delegation_ref
                                                        << " does not match the restricted delegation id"));
          return;
        }
        if (view.available_balance >= view.full_balance) {
          promise.set_error(td::Status::Error("DELEGATION_EXPIRED: the restricted wallet vesting has fully released"));
          return;
        }
        // Validate not_before: if start_at > 0 and sync_utime < start_at
        if (view.start_at > 0 && ctx.parsed.sync_utime < view.start_at) {
          promise.set_error(td::Status::Error(PSTRING() << "DELEGATION_SCOPE_VIOLATION: not_before constraint not met"
                                                        << " (vesting_start=" << view.start_at
                                                        << ", current_time=" << ctx.parsed.sync_utime << ")"));
          return;
        }
        // Delegation is active and constraints are met
        promise.set_value(td::Unit());
      }));
}

}  // namespace tos
