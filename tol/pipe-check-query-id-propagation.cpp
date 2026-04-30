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
 *   doc/tos-message-policy.md (v6) AND the per-receiver scope rule
 *   from doc/tos-language-syntax-policy.md §3.2.1 (v3, codex security
 *   review v2 closure):
 *
 *     - Every handler that returns a reply propagates the inbound
 *       query_id (or explicitly disclaims it via the
 *       `disclaim_query_id()` stdlib helper).
 *     - Every send-with-reply call produces a query_id and reserves
 *       a table slot.
 *     - In a Slice 2 contract, each receiver scope is independent:
 *       receiver A's `@disclaim_query_id` must NOT silence reply
 *       diagnostics emitted from receiver B. The lowering pass
 *       (`tol/pipe-lower-contract.cpp`) tags each lowered if-arm with
 *       a synthetic `ast_receiver_scope_marker` whose entry/exit
 *       this pass keys off.
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
 *       maintain a stack of ScopeRecord, each tracking
 *         - inbound_envelope_local: the LocalVar bound by
 *           `val msg = lazy <Struct>.fromSlice(in.body)` inside
 *           THIS scope
 *         - inbound_envelope_struct: the type behind that lazy
 *           bind, IF it has a `queryId` field
 *         - inbound_query_id_local: the LocalVar bound by the
 *           manual parse sequence
 *             `val body = in.body; body.loadUint(32); val q = body.loadUint(64)`
 *         - disclaimed: did the scope call `disclaim_query_id()`?
 *         - saw_reply_emit: every `createMessage({...body: ...})`
 *           site, paired with whether the body literal sources
 *           `queryId` from `<msg>.queryId` or the manual local
 *
 *       initial scope (function level) covers a legacy
 *       `onInternalMessage` body (no marker present). When entering
 *       an `ast_receiver_scope_marker`, push a fresh ScopeRecord.
 *       Receiver scopes do not inherit query_id sources from the
 *       function-level dispatch preamble: opcode dispatch and
 *       request/reply correlation are separate semantics.
 *
 *       at scope exit:
 *         - if envelope has `queryId` and !disclaimed and no
 *           replies — warn at the scope's source range;
 *         - for each reply that is not propagating — warn at the
 *           call site.
 *
 *   The "propagated" check is purely syntactic: the `queryId:`
 *   field initializer in the reply body literal must be an
 *   `ast_dot_access` reading `<envelope_local>.queryId` or an
 *   `ast_reference` to the manual queryId local. Anything else
 *   (computed expressions, `0`, calls, etc.) falls through to
 *   "not propagated".
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

// is `expr` syntactically a reference to a known local?
static bool is_reference_to_local(AnyExprV expr, LocalVarPtr local_var) {
  if (!local_var) {
    return false;
  }
  if (expr->kind != ast_reference) {
    return false;
  }
  return expr->as<ast_reference>()->sym == local_var;
}

// extract the underlying expression from an ast_argument wrapper.
static AnyExprV unwrap_argument(AnyExprV expr) {
  if (expr->kind == ast_argument) {
    return expr->as<ast_argument>()->get_expr();
  }
  return expr;
}

static bool is_int_literal_value(AnyExprV expr, int expected) {
  expr = unwrap_argument(expr);
  if (expr->kind != ast_int_const) {
    return false;
  }
  auto v_int = expr->as<ast_int_const>();
  return !v_int->intval.is_null() && v_int->intval->to_long() == expected;
}

static bool is_slice_loadUint_from_local(AnyExprV expr, LocalVarPtr slice_local, int width) {
  if (!slice_local || expr->kind != ast_function_call) {
    return false;
  }
  auto v_call = expr->as<ast_function_call>();
  FunctionPtr fun_ref = v_call->fun_maybe;
  if (!fun_ref || fun_ref->name != "slice.loadUint" || !v_call->get_self_obj()) {
    return false;
  }
  if (!is_reference_to_local(v_call->get_self_obj(), slice_local)) {
    return false;
  }
  return v_call->get_num_args() == 1 && is_int_literal_value(v_call->get_arg(0), width);
}

class CheckQueryIdPropagationVisitor final : public ASTVisitorFunctionBody {
  // Per-scope analysis record. Each receiver-scope marker pushes a new
  // ScopeRecord; the function entry pushes the implicit top-level scope.
  // §3.2.1: receiver A's `@disclaim_query_id` MUST NOT silence warnings
  // emitted from receiver B in the same contract.
  struct ScopeRecord {
    StructPtr inbound_envelope_struct = nullptr;
    LocalVarPtr inbound_envelope_local = nullptr;
    LocalVarPtr inbound_body_slice_local = nullptr;
    bool manual_opcode_loaded = false;
    LocalVarPtr inbound_query_id_local = nullptr;
    bool disclaimed = false;

    bool is_marker_scope = false;
    std::string_view contract_name;        // empty for function-level scope
    std::string_view message_struct_name;  // empty for function-level scope

    struct ReplySite {
      AnyV at;             // call site for diagnostic anchoring
      bool propagated;     // true iff queryId: <envelope>.queryId
    };
    std::vector<ReplySite> saw_reply_emit;

    bool has_query_id_source() const {
      return (inbound_envelope_struct && inbound_envelope_local) || inbound_query_id_local;
    }
  };

  LocalVarPtr in_param_ref = nullptr;       // the `in: InMessage` parameter
  std::vector<ScopeRecord> scope_stack;
  // Set when any `ast_receiver_scope_marker` is encountered inside the current
  // function. The marker presence signals a Slice 2 lowered `onInternalMessage`
  // synthesized by `pipeline_lower_contracts`; in that case the synthesized
  // dispatch preamble (opcode parse, loadData) at the
  // function-level scope is NOT a receiver and must not produce any
  // function-level diagnostic — every reply/disclaim attribution belongs to
  // a per-receiver marker scope. Legacy hand-written `onInternalMessage`
  // (e.g. crypto/smartcont/wallet-v5.tol) has no markers, so this flag stays
  // false and the function-level scope is diagnosed as it was in Slice 1.
  bool saw_any_receiver_marker = false;

  ScopeRecord& cur_scope() {
    return scope_stack.back();
  }

  void diagnose_scope_at_exit(const ScopeRecord& scope, AnyV anchor) {
    if (!scope.has_query_id_source()) {
      return;
    }
    if (scope.disclaimed) {
      return;
    }

    if (scope.saw_reply_emit.empty()) {
      err("inbound envelope carries `queryId` but the receiver emits no reply — "
          "call `disclaim_query_id()` to acknowledge fire-and-forget. "
          "See doc/tos-message-policy.md \xc2\xa7""4.4 / "
          "doc/tos-language-syntax-policy.md \xc2\xa7""3.2.1.")
        .warning(anchor, cur_f);
      return;
    }

    for (const ScopeRecord::ReplySite& site : scope.saw_reply_emit) {
      if (!site.propagated) {
        err("reply does not propagate inbound `queryId` — "
            "set `body.queryId` from the inbound queryId or call "
            "`disclaim_query_id()`. "
            "See doc/tos-message-policy.md \xc2\xa7""4.4 / "
            "doc/tos-language-syntax-policy.md \xc2\xa7""3.2.1.")
          .warning(site.at, cur_f);
      }
    }
  }

  // Entering a receiver-scope marker: push a fresh ScopeRecord. The receiver's
  // only valid inbound query_id source is discovered inside this scope from
  // `val msg = lazy T.fromSlice(in.body)` (or from a legacy manual parse within
  // the same scope). A function-level queryId local must not be inherited:
  // opcode dispatch and request/reply correlation are separate semantics.
  // Disclaim flag, reply sites, and aliases are likewise local to the receiver
  // scope (§3.2.1).
  void visit(V<ast_receiver_scope_marker> v) override {
    saw_any_receiver_marker = true;
    ScopeRecord new_scope;
    new_scope.is_marker_scope = true;
    new_scope.contract_name = v->contract_name;
    new_scope.message_struct_name = v->message_struct_name;
    scope_stack.push_back(std::move(new_scope));
    visit_children(v);
    ScopeRecord finished = std::move(scope_stack.back());
    scope_stack.pop_back();
    diagnose_scope_at_exit(finished, v);
  }

  // Detect `val msg = lazy <Struct>.fromSlice(in.body)`.
  // The AST shape is:
  //   ast_assign
  //     lhs: ast_local_vars_declaration -> ast_local_var_lhs
  //     rhs: ast_lazy_operator
  //            -> ast_function_call (callee: <Struct>.fromSlice, arg: in.body)
  void visit(V<ast_assign> v) override {
    parent::visit(v);

    if (!in_param_ref || scope_stack.empty()) {
      return;
    }
    ScopeRecord& s = cur_scope();

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

    AnyExprV rhs = v->get_rhs();

    if (!s.inbound_envelope_local && !s.inbound_query_id_local) {
      if (!s.inbound_body_slice_local && is_in_dot_body(rhs, in_param_ref)) {
        s.inbound_body_slice_local = lhs_var;
        return;
      }
      if (s.inbound_body_slice_local && !s.manual_opcode_loaded && is_slice_loadUint_from_local(rhs, s.inbound_body_slice_local, 32)) {
        s.manual_opcode_loaded = true;
        return;
      }
      if (s.inbound_body_slice_local && s.manual_opcode_loaded && is_slice_loadUint_from_local(rhs, s.inbound_body_slice_local, 64)) {
        s.inbound_query_id_local = lhs_var;
        return;
      }
    }

    if (s.inbound_envelope_local) {
      return;        // already bound
    }

    // rhs must be `lazy <call>`
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

    s.inbound_envelope_struct = struct_ref;
    s.inbound_envelope_local = lhs_var;
  }

  // Detect:
  //   - explicit `disclaim_query_id()` call
  //   - `createMessage({ body: <BodyStruct> { queryId: ..., ... } })` reply emits
  void visit(V<ast_function_call> v) override {
    parent::visit(v);

    if (scope_stack.empty()) {
      return;
    }
    ScopeRecord& s = cur_scope();

    FunctionPtr fun_ref = v->fun_maybe;
    if (!fun_ref) {
      return;
    }

    // disclaim_query_id() is a top-level builtin: name matches directly.
    // Per §3.2.1 the disclaim flag is per-scope: only the topmost scope is set.
    if (fun_ref->name == "disclaim_query_id") {
      s.disclaimed = true;
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
      s.saw_reply_emit.push_back({v, /*propagated=*/false});
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
      s.saw_reply_emit.push_back({v, /*propagated=*/false});
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
      if (is_envelope_dot_queryId(init_val, s.inbound_envelope_local) || is_reference_to_local(init_val, s.inbound_query_id_local)) {
        propagated = true;
      }
      break;
    }

    s.saw_reply_emit.push_back({v, propagated});
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
    scope_stack.clear();
    saw_any_receiver_marker = false;
    // Function-level scope: covers a legacy `onInternalMessage` body without any
    // marker (e.g. crypto/smartcont/wallet-v5.tol). When the function is the
    // synthesized `onInternalMessage` from `pipeline_lower_contracts`, this scope
    // owns the dispatch preamble (opcode parse, loadData,
    // future `@deploy` branch); per §3.2.1 those statements belong to the
    // synthesized function, not any single receiver. Each per-receiver marker
    // pushes its own ScopeRecord on top; only the receiver scope's diagnostics
    // fire at marker-exit, while the outer function-level scope's diagnostic
    // fires at function-exit (legacy single-scope semantics preserved).
    ScopeRecord top_level;
    top_level.is_marker_scope = false;
    scope_stack.push_back(std::move(top_level));
  }

  void on_exit_function(V<ast_function_declaration> v_function) override {
    if (scope_stack.empty()) {
      return;
    }
    ScopeRecord top_level = std::move(scope_stack.back());
    scope_stack.pop_back();
    // Skip the function-level diagnostic when any receiver-scope marker was
    // seen in the body — that means this is a synthesized lowered
    // `onInternalMessage` and the dispatch preamble (which the function-level
    // scope owns) is NOT a receiver. Per §3.2.1 only per-receiver markers
    // diagnose their own replies/disclaims. Legacy hand-written
    // `onInternalMessage` files emit no markers and keep Slice 1 single-flag
    // semantics.
    if (saw_any_receiver_marker) {
      return;
    }
    diagnose_scope_at_exit(top_level, v_function);
  }
};

void pipeline_check_query_id_propagation() {
  // Slice 2 §10.1 hardening (codex security review v2 closure):
  // pipeline_lower_contracts() MUST run BEFORE this pass so that every
  // `contract` declaration has been replaced with the synthesized
  // `onInternalMessage` and per-receiver `ast_receiver_scope_marker`s.
  // Without that ordering, this pass's per-receiver scope tracking degrades
  // back to the pre-Slice-2 single-flag behavior — and a future refactor
  // could silently reorder these passes. Assert at runtime.
  for (const SrcFile* file : G.all_src_files) {
    auto v_file = file->ast->as<ast_tol_file>();
    for (AnyV declaration : v_file->get_toplevel_declarations()) {
      if (declaration->kind == ast_contract_declaration) {
        err("internal: pipeline order violation: pipeline_check_query_id_propagation ran before pipeline_lower_contracts (contract `{}` still present at top level). See doc/tos-language-syntax-policy.md §10.1.",
            declaration->as<ast_contract_declaration>()->get_identifier()->name)
          .fire(declaration);
      }
    }
  }

  CheckQueryIdPropagationVisitor visitor;
  visit_ast_of_all_functions(visitor);
}

} // namespace tol
