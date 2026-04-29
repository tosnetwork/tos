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
*/
#include "ast.h"
#include "ast-visitor.h"
#include "compilation-errors.h"
#include "compiler-state.h"
#include "type-system.h"

#include <vector>

/*
 *   This pipe enforces the §4.4 query_id propagation rule from
 *   doc/tos-message-policy.md (v6):
 *
 *     - Every handler that returns a reply propagates the inbound
 *       query_id (or explicitly disclaims it via the
 *       `disclaim_query_id()` stdlib helper).
 *     - Every send-with-reply call produces a query_id and reserves
 *       a table slot.
 *
 *   Diagnostics are emitted with `error_collector.collect(...)`
 *   (warnings, not errors). Per §4.4 the pass is wired into
 *   `tol/tol.cpp` in the band:
 *
 *     after  pipeline_check_serialized_fields()      (line 83)
 *     before G.error_collector = nullptr;            (line 102)
 *
 *   Moving the pass past the error-collector teardown would NPE
 *   inside `.collect()`. The injection-point constraint is
 *   sign-off-blocking per v6.
 *
 *   Algorithm (syntactic, intentionally conservative — false
 *   positives on unusual propagation idioms are tolerated, false
 *   negatives on missing propagation are not):
 *
 *     for each onInternalMessage handler `fun_ref`:
 *       walk its AST body, tracking
 *         - inbound_envelope_local: the LocalVar bound by
 *           `val msg = lazy <Struct>.fromSlice(in.body)`
 *         - inbound_envelope_struct: the type behind that lazy
 *           bind, IF it has a `queryId` field
 *         - disclaimed: did the handler call `disclaim_query_id()`?
 *         - saw_reply_emit: every `createMessage({...body: ...})`
 *           site, paired with whether the body literal sources
 *           `queryId` from `<msg>.queryId`
 *
 *       at end-of-handler:
 *         - if envelope has `queryId` and !disclaimed and no
 *           replies — warn at the function;
 *         - for each reply that is not propagating — warn at the
 *           call site.
 *
 *   The "propagated" check is purely syntactic: the `queryId:`
 *   field initializer in the reply body literal must be an
 *   `ast_dot_access` reading `<envelope_local>.queryId`. Anything
 *   else (computed expressions, `0`, calls, etc.) falls through
 *   to "not propagated".
 */

namespace tol {

// detect `onInternalMessage` with a single `InMessage` parameter.
// duplicated from pipe-transform-on-message.cpp (the original is static there;
// once that predicate is exposed in a shared header, this copy can be retired).
static bool is_onInternalMessage(FunctionPtr fun_ref) {
  if (fun_ref->is_entrypoint() && (fun_ref->name == "main" || fun_ref->name == "onInternalMessage")) {
    if (fun_ref->get_num_params() == 1) {
      const auto* t_param = fun_ref->get_param(0).declared_type->try_as<TypeDataStruct>();
      return t_param && t_param->struct_ref->name == "InMessage";
    }
  }
  return false;
}

// is `expr` syntactically `<param_ref>.body`? we deliberately look at
// (a) ast_dot_access with field name "body"
// (b) whose obj is an ast_reference whose sym is `param_ref`.
// this runs BEFORE pipeline_transform_onInternalMessage, so `in.body`
// is still unwritten as a regular dot-access.
static bool is_in_dot_body(AnyExprV expr, LocalVarPtr param_ref) {
  if (expr->kind != ast_dot_access) {
    return false;
  }
  auto v_dot = expr->as<ast_dot_access>();
  if (v_dot->get_field_name() != "body") {
    return false;
  }
  if (v_dot->get_obj()->kind != ast_reference) {
    return false;
  }
  return v_dot->get_obj()->as<ast_reference>()->sym == param_ref;
}

// is `expr` syntactically `<envelope_local>.queryId`?
// used to recognize the propagation pattern in a reply body literal.
static bool is_envelope_dot_queryId(AnyExprV expr, LocalVarPtr envelope_local) {
  if (!envelope_local) {
    return false;
  }
  if (expr->kind != ast_dot_access) {
    return false;
  }
  auto v_dot = expr->as<ast_dot_access>();
  if (v_dot->get_field_name() != "queryId") {
    return false;
  }
  if (v_dot->get_obj()->kind != ast_reference) {
    return false;
  }
  return v_dot->get_obj()->as<ast_reference>()->sym == envelope_local;
}

// extract the underlying expression from an ast_argument wrapper.
static AnyExprV unwrap_argument(AnyExprV expr) {
  if (expr->kind == ast_argument) {
    return expr->as<ast_argument>()->get_expr();
  }
  return expr;
}

class CheckQueryIdPropagationVisitor final : public ASTVisitorFunctionBody {
  // per-handler state, reset in on_enter_function
  LocalVarPtr in_param_ref = nullptr;       // the `in: InMessage` parameter
  StructPtr inbound_envelope_struct = nullptr;
  LocalVarPtr inbound_envelope_local = nullptr;
  bool disclaimed = false;

  struct ReplySite {
    AnyV at;             // call site for diagnostic anchoring
    bool propagated;     // true iff queryId: <envelope>.queryId
  };
  std::vector<ReplySite> saw_reply_emit;

  // Detect `val msg = lazy <Struct>.fromSlice(in.body)`.
  // The AST shape is:
  //   ast_assign
  //     lhs: ast_local_vars_declaration -> ast_local_var_lhs
  //     rhs: ast_lazy_operator
  //            -> ast_function_call (callee: <Struct>.fromSlice, arg: in.body)
  void visit(V<ast_assign> v) override {
    parent::visit(v);

    if (inbound_envelope_local || !in_param_ref) {
      return;        // already bound, or we have no `in` to compare against
    }

    // unwrap `var x = ...` lhs
    AnyExprV lhs = v->get_lhs();
    if (lhs->kind == ast_local_vars_declaration) {
      lhs = lhs->as<ast_local_vars_declaration>()->get_expr();
    }
    if (lhs->kind != ast_local_var_lhs) {
      return;
    }
    LocalVarPtr lhs_var = lhs->as<ast_local_var_lhs>()->var_ref;
    if (!lhs_var) {
      return;
    }

    // rhs must be `lazy <call>`
    AnyExprV rhs = v->get_rhs();
    if (rhs->kind != ast_lazy_operator) {
      return;
    }
    AnyExprV inner = rhs->as<ast_lazy_operator>()->get_expr();
    if (inner->kind != ast_function_call) {
      return;
    }
    auto v_call = inner->as<ast_function_call>();

    // callee must be a generic instantiation of `T.fromSlice`
    FunctionPtr fun_ref = v_call->fun_maybe;
    if (!fun_ref || !fun_ref->is_builtin() || !fun_ref->is_instantiation_of_generic_function()) {
      return;
    }
    if (!fun_ref->base_fun_ref || fun_ref->base_fun_ref->name != "T.fromSlice") {
      return;
    }

    // arg 0 must be `in.body`
    if (v_call->get_num_args() < 1) {
      return;
    }
    AnyExprV arg0 = unwrap_argument(v_call->get_arg(0));
    if (!is_in_dot_body(arg0, in_param_ref)) {
      return;
    }

    // bound type: the rvalue's inferred type, or the receiver type of the
    // T.fromSlice instantiation. Either way, drill to TypeDataStruct.
    TypePtr bound_type = rhs->inferred_type;
    if (!bound_type) {
      return;
    }
    const auto* t_struct = bound_type->unwrap_alias()->try_as<TypeDataStruct>();
    if (!t_struct) {
      return;
    }
    StructPtr struct_ref = t_struct->struct_ref;
    if (!struct_ref) {
      return;
    }

    // only of interest if the envelope carries queryId.
    if (!struct_ref->find_field("queryId")) {
      return;
    }

    inbound_envelope_struct = struct_ref;
    inbound_envelope_local = lhs_var;
  }

  // Detect:
  //   - explicit `disclaim_query_id()` call
  //   - `createMessage({ body: <BodyStruct> { queryId: ..., ... } })` reply emits
  void visit(V<ast_function_call> v) override {
    parent::visit(v);

    FunctionPtr fun_ref = v->fun_maybe;
    if (!fun_ref) {
      return;
    }

    // disclaim_query_id() is a top-level builtin: name matches directly
    if (fun_ref->name == "disclaim_query_id") {
      disclaimed = true;
      return;
    }

    // createMessage<TBody>(options): the instantiated function's
    // base_fun_ref->name is "createMessage". Top-level builtin, not a method.
    if (!fun_ref->base_fun_ref || fun_ref->base_fun_ref->name != "createMessage") {
      return;
    }
    if (v->get_num_args() < 1) {
      return;
    }

    AnyExprV options_arg = unwrap_argument(v->get_arg(0));
    // expected: ast_object_literal (CreateMessageOptions { ... }).
    if (options_arg->kind != ast_object_literal) {
      // non-literal options argument — record reply but cannot prove propagation
      saw_reply_emit.push_back({v, /*propagated=*/false});
      return;
    }
    auto v_options_lit = options_arg->as<ast_object_literal>();
    auto v_options_body = v_options_lit->get_body();

    // locate `body:` field of the CreateMessageOptions
    AnyExprV body_init = nullptr;
    for (int i = 0, n = v_options_body->get_num_fields(); i < n; ++i) {
      auto v_field = v_options_body->get_field(i);
      if (v_field->get_field_name() == "body") {
        body_init = v_field->get_init_val();
        break;
      }
    }
    if (!body_init) {
      // no body field at all — empty body, nothing to propagate.
      // not a reply for §4.4 purposes; skip.
      return;
    }

    // body initializer must be an object literal whose struct has a
    // queryId field for the propagation check to apply.
    if (body_init->kind != ast_object_literal) {
      // shorthand `body: someVar` or `body: <expr>` — cannot prove
      // propagation syntactically. Conservative: warn unless the
      // body's struct type does not even have a queryId.
      TypePtr body_type = body_init->inferred_type;
      if (body_type) {
        const auto* t_struct = body_type->unwrap_alias()->try_as<TypeDataStruct>();
        if (t_struct && t_struct->struct_ref && !t_struct->struct_ref->find_field("queryId")) {
          // body has no queryId — outbound on a non-query opcode, not a reply
          return;
        }
      }
      saw_reply_emit.push_back({v, /*propagated=*/false});
      return;
    }
    auto v_body_lit = body_init->as<ast_object_literal>();

    // determine struct type of the reply body
    StructPtr reply_struct = v_body_lit->struct_ref;
    if (!reply_struct) {
      if (TypePtr body_type = body_init->inferred_type) {
        if (const auto* t_struct = body_type->unwrap_alias()->try_as<TypeDataStruct>()) {
          reply_struct = t_struct->struct_ref;
        }
      }
    }
    if (!reply_struct || !reply_struct->find_field("queryId")) {
      // outbound body has no queryId — not a reply that needs propagation.
      return;
    }

    // walk the literal's fields, find `queryId:`, check its rhs.
    bool propagated = false;
    auto v_body_obj = v_body_lit->get_body();
    for (int i = 0, n = v_body_obj->get_num_fields(); i < n; ++i) {
      auto v_field = v_body_obj->get_field(i);
      if (v_field->get_field_name() != "queryId") {
        continue;
      }
      AnyExprV init_val = v_field->get_init_val();
      if (is_envelope_dot_queryId(init_val, inbound_envelope_local)) {
        propagated = true;
      }
      break;
    }

    saw_reply_emit.push_back({v, propagated});
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function()
        && !fun_ref->is_generic_function()
        && is_onInternalMessage(fun_ref);
  }

  void on_enter_function(V<ast_function_declaration> v_function) override {
    (void)v_function;
    in_param_ref = &cur_f->parameters[0];
    inbound_envelope_struct = nullptr;
    inbound_envelope_local = nullptr;
    disclaimed = false;
    saw_reply_emit.clear();
  }

  void on_exit_function(V<ast_function_declaration> v_function) override {
    // only diagnose if we positively identified an envelope with queryId
    if (!inbound_envelope_struct || !inbound_envelope_local) {
      return;
    }
    if (disclaimed) {
      return;
    }

    if (saw_reply_emit.empty()) {
      err("inbound envelope carries `queryId` but the handler emits no reply — "
          "call `disclaim_query_id()` to acknowledge fire-and-forget. "
          "See doc/tos-message-policy.md \xc2\xa7""4.4.")
        .warning(v_function, cur_f);
      return;
    }

    for (const ReplySite& site : saw_reply_emit) {
      if (!site.propagated) {
        err("reply does not propagate inbound `queryId` — "
            "set `body.queryId = <envelope>.queryId` or call "
            "`disclaim_query_id()`. "
            "See doc/tos-message-policy.md \xc2\xa7""4.4.")
          .warning(site.at, cur_f);
      }
    }
  }
};

void pipeline_check_query_id_propagation() {
  CheckQueryIdPropagationVisitor visitor;
  visit_ast_of_all_functions(visitor);
}

} // namespace tol
