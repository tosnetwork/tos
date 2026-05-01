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
//
// Slice 2 Stage 3 — `@on(State1, State2)` field scoping plus expression-level taint analysis.
// See doc/tos-language-syntax-policy.md §3.4 (rules) and §5 (taint propagation requirements).
//
// This pass runs in the policy-mandated band, immediately AFTER
// pipeline_check_state_reachability() and BEFORE pipeline_lower_contracts().
// At this point, contract receiver bodies have NOT been resolved into a real FunctionPtr,
// so the analysis is purely structural over the receive-block AST: storage accesses are
// detected by name, exactly as pipe-check-state-reachability.cpp does.
//
// What is enforced:
//   1. `@on(...)` is permitted only on storage struct fields of state-bearing contracts.
//   2. Every state listed in `@on(...)` must appear in the contract's `states:` declaration.
//   3. Reading `storage.<field>` of an `@on(...)`-annotated field inside a receiver whose
//      `on State` is not in the field's state-set is a compile error.
//   4. Local-binding alias propagation (`val foo = storage.payoutsRemaining;`): the local
//      inherits the field's state-set; reading the local in an out-of-scope state errors.
//   5. Tuple/pattern destructure (`val (a, b) = (storage.x, storage.y)`): each binding
//      inherits the corresponding part's state-set. A combined value carries the union.
//   6. Passing a tainted local to a free function (`helper(foo)`) is rejected as a
//      conservative Stage 3 approximation; Slice 3 will refine.
//   7. Direct c4 serialisation escape inside a state-bearing receiver is rejected:
//      `storage.toCell()`, `contract.getData()`, `(storage as Cell)`.
//

#include "ast.h"
#include "ast-visitor.h"
#include "compilation-errors.h"
#include "compiler-state.h"
#include "pipeline.h"
#include "symtable.h"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace tol {

namespace {

// ---------- per-receiver mutable state ----------

struct FieldScopingContext {
  // points back to the contract for diagnostics
  V<ast_contract_declaration> contract = nullptr;
  // set of state names declared in `states:` (for membership checks against @on() lists)
  std::unordered_set<std::string> declared_states;
  // storage struct (may be nullptr if unresolved); used to look up @on() annotations on fields
  StructPtr storage_struct = nullptr;
  // the state being analysed for this receiver, or empty if non-state-bearing receiver
  std::string current_state;
  // true while analysing an @deploy body, which runs before c4/storage exists
  bool in_deploy_receiver = false;
  // map: local-var name -> the @on(...) state-set tainting that name
  // a value of {} (empty vector) means "untainted". We only insert entries for tainted vars.
  // shadowing within nested blocks is approximated by assignment (Stage 3 conservative).
  std::unordered_map<std::string, std::vector<std::string>> tainted_locals;
};

static std::string format_state_list(const std::vector<std::string>& states) {
  std::string out;
  for (size_t i = 0; i < states.size(); ++i) {
    if (i) {
      out += ", ";
    }
    out += states[i];
  }
  return out;
}

static bool state_in_list(const std::vector<std::string>& list, const std::string& state) {
  for (const std::string& s : list) {
    if (s == state) {
      return true;
    }
  }
  return false;
}

// ---------- AST shape helpers ----------

static bool is_storage_reference(AnyExprV expr) {
  if (auto ref = expr->try_as<ast_reference>()) {
    return ref->get_name() == "storage";
  }
  return false;
}

static bool is_contract_reference(AnyExprV expr) {
  if (auto ref = expr->try_as<ast_reference>()) {
    return ref->get_name() == "contract";
  }
  return false;
}

static bool expr_references_storage(AnyExprV expr) {
  if (is_storage_reference(expr)) {
    return true;
  }
  switch (expr->kind) {
    case ast_dot_access:
      return expr_references_storage(expr->as<ast_dot_access>()->get_obj());
    case ast_argument:
      return expr_references_storage(expr->as<ast_argument>()->get_expr());
    case ast_cast_as_operator:
      return expr_references_storage(expr->as<ast_cast_as_operator>()->get_expr());
    case ast_not_null_operator:
      return expr_references_storage(expr->as<ast_not_null_operator>()->get_expr());
    case ast_lazy_operator:
      return expr_references_storage(expr->as<ast_lazy_operator>()->get_expr());
    case ast_unary_operator:
      return expr_references_storage(expr->as<ast_unary_operator>()->get_rhs());
    case ast_binary_operator:
      return expr_references_storage(expr->as<ast_binary_operator>()->get_lhs()) ||
             expr_references_storage(expr->as<ast_binary_operator>()->get_rhs());
    default:
      return false;
  }
}

// True if `dot_access` is `storage.<some_field>` (NOT `storage.method(...)` shape).
// Caller still has to look up the field on the storage struct.
static bool is_storage_field_dot(V<ast_dot_access> dot) {
  return is_storage_reference(dot->get_obj());
}

// ---------- forward decls ----------

static std::vector<std::string> compute_taint_of_expr(AnyExprV expr, FieldScopingContext& ctx);
static void check_expr(AnyExprV expr, FieldScopingContext& ctx);
static void check_statement(AnyV statement, FieldScopingContext& ctx);
static void check_block(V<ast_block_statement> block, FieldScopingContext& ctx);

// ---------- escape-hatch detection ----------

static bool asm_command_mentions_c4(std::string_view command) {
  return command.find("c4") != std::string_view::npos ||
         command.find("C4") != std::string_view::npos ||
         command.find("PUSHROOT") != std::string_view::npos ||
         command.find("POPROOT") != std::string_view::npos;
}

static bool asm_function_uses_c4_register(FunctionPtr fun_ref) {
  if (!fun_ref || !fun_ref->ast_root) {
    return false;
  }
  auto v_fun = fun_ref->ast_root->try_as<ast_function_declaration>();
  if (!v_fun) {
    return false;
  }
  auto v_asm = v_fun->get_body()->try_as<ast_asm_body>();
  if (!v_asm) {
    return false;
  }
  for (AnyV command : v_asm->get_asm_commands()) {
    if (auto v_str = command->try_as<ast_string_const>()) {
      if (asm_command_mentions_c4(v_str->str_val)) {
        return true;
      }
    }
  }
  return false;
}

static FunctionPtr resolve_called_function(V<ast_function_call> fc) {
  if (fc->fun_maybe) {
    return fc->fun_maybe;
  }
  AnyExprV callee = fc->get_callee();
  if (auto ref = callee->try_as<ast_reference>()) {
    if (FunctionPtr fun_ref = ref->sym ? ref->sym->try_as<FunctionPtr>() : nullptr) {
      return fun_ref;
    }
    const Symbol* sym = G.symtable.lookup(ref->get_name());
    return sym ? sym->try_as<FunctionPtr>() : nullptr;
  }
  if (auto dot = callee->try_as<ast_dot_access>()) {
    if (dot->is_target_fun_ref()) {
      return std::get<FunctionPtr>(dot->target);
    }
  }
  return nullptr;
}

static bool function_body_uses_c4_escape(FunctionPtr fun_ref, std::unordered_set<FunctionPtr>& seen);

class C4EscapeScanner final : public ASTVisitorFunctionBody {
  std::unordered_set<FunctionPtr>& seen_;

  void visit(V<ast_dot_access> v) override {
    if (is_contract_reference(v->get_obj())) {
      std::string_view method = v->get_field_name();
      if (method == "getData" || method == "rawData" || method == "loadData") {
        found = true;
      }
    }
    parent::visit(v);
  }

  void visit(V<ast_function_call> v) override {
    if (FunctionPtr called_fun = resolve_called_function(v)) {
      if (asm_function_uses_c4_register(called_fun) || function_body_uses_c4_escape(called_fun, seen_)) {
        found = true;
      }
    }
    if (auto ref = v->get_callee()->try_as<ast_reference>()) {
      std::string_view name = ref->get_name();
      if (name == "currentData" || name == "getContractData" || name == "rawC4Push" || name == "rawC4Pop") {
        found = true;
      }
    }
    parent::visit(v);
  }

public:
  explicit C4EscapeScanner(std::unordered_set<FunctionPtr>& seen)
    : seen_(seen) {}

  bool found = false;

  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function() && !fun_ref->is_generic_function();
  }
};

static bool function_body_uses_c4_escape(FunctionPtr fun_ref, std::unordered_set<FunctionPtr>& seen) {
  if (!fun_ref || !fun_ref->ast_root || !fun_ref->is_code_function() || fun_ref->is_generic_function()) {
    return false;
  }
  if (!seen.insert(fun_ref).second) {
    return false;
  }
  auto v_fun = fun_ref->ast_root->try_as<ast_function_declaration>();
  if (!v_fun || !v_fun->get_body()->try_as<ast_block_statement>()) {
    return false;
  }
  C4EscapeScanner scanner(seen);
  scanner.start_visiting_function(fun_ref, v_fun);
  return scanner.found;
}

// `storage.toCell()` / `storage.toSlice()` / `(storage as Cell)` / `contract.getData()`
// are explicit c4 serialisation escapes; §5 forbids them inside state-bearing contract receivers.
static bool detect_c4_serialisation_escape(AnyExprV expr, FieldScopingContext& ctx) {
  if (auto fc = expr->try_as<ast_function_call>()) {
    FunctionPtr called_fun = resolve_called_function(fc);
    if (asm_function_uses_c4_register(called_fun)) {
      err("c4 serialization escapes `@on` scoping; asm function `{}` uses c4 and is not permitted inside a state-bearing receiver. "
          "See doc/tos-language-syntax-policy.md §5.", called_fun->name)
        .collect(expr);
    } else if (called_fun) {
      std::unordered_set<FunctionPtr> seen;
      if (function_body_uses_c4_escape(called_fun, seen)) {
        err("c4 serialization escapes `@on` scoping; helper function `{}` reaches c4 and is not permitted inside a state-bearing receiver. "
            "See doc/tos-language-syntax-policy.md §5.", called_fun->name)
          .collect(expr);
      }
    }
    AnyExprV callee = fc->get_callee();
    if (auto dot = callee->try_as<ast_dot_access>()) {
      std::string_view method = dot->get_field_name();
      if (is_storage_reference(dot->get_obj())) {
        if (method == "toCell" || method == "toSlice" || method == "asCell" || method == "asSlice") {
          err("c4 serialization escapes `@on` scoping; `storage.{}()` is not permitted inside a state-bearing receiver. "
              "See doc/tos-language-syntax-policy.md §5.", method)
            .collect(expr);
        }
      }
      if (is_contract_reference(dot->get_obj())) {
        if (method == "getData" || method == "rawData" || method == "loadData") {
          err("c4 serialization escapes `@on` scoping; `contract.{}()` is not permitted inside a state-bearing receiver. "
              "See doc/tos-language-syntax-policy.md §5.", method)
            .collect(expr);
        }
      }
    }
    if (auto ref = callee->try_as<ast_reference>()) {
      std::string_view name = ref->get_name();
      // free-fun escape hatches (`currentData()` style wrappers around `c4 PUSH`)
      if (name == "currentData" || name == "getContractData" || name == "rawC4Push" || name == "rawC4Pop") {
        err("c4 serialization escapes `@on` scoping; `{}()` is not permitted inside a state-bearing receiver. "
            "See doc/tos-language-syntax-policy.md §5.", name)
          .collect(expr);
      }
    }
    return false;
  }
  // `storage as Cell`
  if (auto cast = expr->try_as<ast_cast_as_operator>()) {
    if (is_storage_reference(cast->get_expr())) {
      err("c4 serialization escapes `@on` scoping; casting `storage` to a cell/slice is not permitted "
          "inside a state-bearing receiver. See doc/tos-language-syntax-policy.md §5.")
        .collect(expr);
    }
  }
  return false;
}

// ---------- @on(field) read enforcement ----------

// For every storage.<field> read inside a state-bearing receiver: if the struct field has a
// non-empty @on(...) state-set that does NOT include the receiver's state, error.
// Returns the field's @on() state-set (empty if no annotation), so callers can taint locals.
static std::vector<std::string> check_storage_field_access(V<ast_dot_access> dot, FieldScopingContext& ctx) {
  if (!is_storage_field_dot(dot)) {
    return {};
  }
  if (!ctx.storage_struct) {
    return {};
  }
  std::string_view field_name = dot->get_field_name();
  // skip compiler-reserved fields (already diagnosed by pipe-check-state-reachability.cpp)
  if (field_name == "__state") {
    return {};
  }
  StructFieldPtr field = ctx.storage_struct->find_field(field_name);
  if (!field) {
    return {};
  }
  if (ctx.in_deploy_receiver) {
    err("storage field `{}` may not be read inside an `@deploy receive(...)` body "
        "because deployment runs before storage exists. See doc/tos-language-syntax-policy.md §3.6.",
        field_name)
      .collect(dot);
    return field->has_on_states_annotation() ? field->on_states : std::vector<std::string>{};
  }
  if (!field->has_on_states_annotation()) {
    return {};
  } else if (!ctx.current_state.empty() && !state_in_list(field->on_states, ctx.current_state)) {
    err("storage field `{}` is annotated `@on({})` and may not be read inside a `receive(...) on {}` body. "
        "See doc/tos-language-syntax-policy.md §3.4.",
        field_name, format_state_list(field->on_states), ctx.current_state)
      .collect(dot);
  }
  return field->on_states;
}

// ---------- taint inference ----------

// Compute the @on() state-set carried by an expression. Empty vector = untainted.
// This walks expressions that *produce* the value being assigned to a binding.
// Used both at val-decls and to flag tainted-arg-to-call.
static std::vector<std::string> compute_taint_of_expr(AnyExprV expr, FieldScopingContext& ctx) {
  switch (expr->kind) {
    case ast_dot_access: {
      auto dot = expr->as<ast_dot_access>();
      // direct `storage.<field>` read
      if (is_storage_field_dot(dot) && ctx.storage_struct) {
        StructFieldPtr field = ctx.storage_struct->find_field(dot->get_field_name());
        if (field && field->has_on_states_annotation()) {
          return field->on_states;
        }
      }
      // chained `storage.field.subfield` — keep the root field's @on; we conservatively treat
      // the whole subtree as tainted with the root's set.
      return compute_taint_of_expr(dot->get_obj(), ctx);
    }
    case ast_reference: {
      auto ref = expr->as<ast_reference>();
      if (is_storage_reference(expr) && ctx.in_deploy_receiver) {
        return {"@deploy"};
      }
      auto it = ctx.tainted_locals.find(static_cast<std::string>(ref->get_name()));
      if (it != ctx.tainted_locals.end()) {
        return it->second;
      }
      return {};
    }
    case ast_tensor: {
      // a tensor literal's combined taint is the union of element taints (per §5).
      std::vector<std::string> result;
      std::unordered_set<std::string> seen;
      for (AnyExprV item : expr->as<ast_tensor>()->get_items()) {
        for (const std::string& s : compute_taint_of_expr(item, ctx)) {
          if (seen.insert(s).second) {
            result.push_back(s);
          }
        }
      }
      return result;
    }
    case ast_square_brackets: {
      std::vector<std::string> result;
      std::unordered_set<std::string> seen;
      for (AnyExprV item : expr->as<ast_square_brackets>()->get_items()) {
        for (const std::string& s : compute_taint_of_expr(item, ctx)) {
          if (seen.insert(s).second) {
            result.push_back(s);
          }
        }
      }
      return result;
    }
    case ast_argument:
      return compute_taint_of_expr(expr->as<ast_argument>()->get_expr(), ctx);
    case ast_artificial_aux_vertex:
      return compute_taint_of_expr(expr->as<ast_artificial_aux_vertex>()->get_wrapped_expr(), ctx);
    case ast_braced_yield_result:
      return compute_taint_of_expr(expr->as<ast_braced_yield_result>()->get_expr(), ctx);
    case ast_cast_as_operator:
      return compute_taint_of_expr(expr->as<ast_cast_as_operator>()->get_expr(), ctx);
    case ast_not_null_operator:
      return compute_taint_of_expr(expr->as<ast_not_null_operator>()->get_expr(), ctx);
    case ast_lazy_operator:
      return compute_taint_of_expr(expr->as<ast_lazy_operator>()->get_expr(), ctx);
    case ast_unary_operator:
      return compute_taint_of_expr(expr->as<ast_unary_operator>()->get_rhs(), ctx);
    case ast_binary_operator: {
      auto bin = expr->as<ast_binary_operator>();
      std::vector<std::string> result = compute_taint_of_expr(bin->get_lhs(), ctx);
      std::unordered_set<std::string> seen(result.begin(), result.end());
      for (const std::string& s : compute_taint_of_expr(bin->get_rhs(), ctx)) {
        if (seen.insert(s).second) {
          result.push_back(s);
        }
      }
      return result;
    }
    case ast_ternary_operator: {
      auto t = expr->as<ast_ternary_operator>();
      std::vector<std::string> result = compute_taint_of_expr(t->get_when_true(), ctx);
      std::unordered_set<std::string> seen(result.begin(), result.end());
      for (const std::string& s : compute_taint_of_expr(t->get_when_false(), ctx)) {
        if (seen.insert(s).second) {
          result.push_back(s);
        }
      }
      return result;
    }
    case ast_null_coalesce_operator: {
      auto nc = expr->as<ast_null_coalesce_operator>();
      std::vector<std::string> result = compute_taint_of_expr(nc->get_lhs(), ctx);
      std::unordered_set<std::string> seen(result.begin(), result.end());
      for (const std::string& s : compute_taint_of_expr(nc->get_rhs(), ctx)) {
        if (seen.insert(s).second) {
          result.push_back(s);
        }
      }
      return result;
    }
    default:
      return {};
  }
}

// Assign `taint` to a leaf binding lhs. Handles ast_local_var_lhs (declared name) and
// ast_reference (reassignment to an existing local). Empty taint clears the entry.
static void assign_taint_to_leaf(AnyExprV leaf, const std::vector<std::string>& taint, FieldScopingContext& ctx) {
  std::string_view name;
  if (auto var_lhs = leaf->try_as<ast_local_var_lhs>()) {
    name = var_lhs->get_name();
  } else if (auto var_decl = leaf->try_as<ast_local_vars_declaration>()) {
    if (auto inner_var_lhs = var_decl->get_expr()->try_as<ast_local_var_lhs>()) {
      name = inner_var_lhs->get_name();
    }
  } else if (auto ref = leaf->try_as<ast_reference>()) {
    name = ref->get_name();
  }
  if (name.empty()) {
    return;
  }
  std::string key(name);
  if (taint.empty()) {
    ctx.tainted_locals.erase(key);
  } else {
    ctx.tainted_locals[std::move(key)] = taint;
  }
}

// Take the taint-set of an rhs expression and propagate it through a binding lhs
// (`val x = rhs`, `val (a, b) = rhs`, etc.). Tuples/brackets distribute element-wise
// when the rhs is also a tensor literal of matching arity; otherwise the whole rhs taint
// is assigned to every leaf binding (conservative fan-out for §5 union semantics).
static void propagate_taint_through_binding(AnyExprV lhs_expr, AnyExprV rhs_expr, FieldScopingContext& ctx) {
  // Step through the `ast_local_vars_declaration` wrapper that `val ... = ...` uses.
  if (auto var_decl = lhs_expr->try_as<ast_local_vars_declaration>()) {
    propagate_taint_through_binding(var_decl->get_expr(), rhs_expr, ctx);
    return;
  }

  // Element-wise distribution for shape-matching tuples and bracketed tuples.
  if (auto lhs_tensor = lhs_expr->try_as<ast_tensor>()) {
    auto rhs_tensor = rhs_expr->try_as<ast_tensor>();
    if (rhs_tensor && rhs_tensor->size() == lhs_tensor->size()) {
      for (int i = 0; i < lhs_tensor->size(); ++i) {
        propagate_taint_through_binding(lhs_tensor->get_item(i), rhs_tensor->get_item(i), ctx);
      }
      return;
    }
    // shape mismatch / non-tensor rhs -> compute combined rhs taint and broadcast it
    std::vector<std::string> rhs_taint = compute_taint_of_expr(rhs_expr, ctx);
    for (int i = 0; i < lhs_tensor->size(); ++i) {
      assign_taint_to_leaf(lhs_tensor->get_item(i), rhs_taint, ctx);
    }
    return;
  }
  if (auto lhs_brackets = lhs_expr->try_as<ast_square_brackets>()) {
    auto rhs_brackets = rhs_expr->try_as<ast_square_brackets>();
    if (rhs_brackets && rhs_brackets->size() == lhs_brackets->size()) {
      for (int i = 0; i < lhs_brackets->size(); ++i) {
        propagate_taint_through_binding(lhs_brackets->get_item(i), rhs_brackets->get_item(i), ctx);
      }
      return;
    }
    std::vector<std::string> rhs_taint = compute_taint_of_expr(rhs_expr, ctx);
    for (int i = 0; i < lhs_brackets->size(); ++i) {
      assign_taint_to_leaf(lhs_brackets->get_item(i), rhs_taint, ctx);
    }
    return;
  }

  // Leaf binding (val x, x = rhs, or one element of a tensor destructure).
  std::vector<std::string> rhs_taint = compute_taint_of_expr(rhs_expr, ctx);
  assign_taint_to_leaf(lhs_expr, rhs_taint, ctx);
}

// ---------- taint-into-callee enforcement ----------

// Walk a call's argument list. If any argument carries a non-empty taint set, error.
// `callee_for_diag` is purely for the message.
static void check_call_arguments(V<ast_function_call> call, FieldScopingContext& ctx, std::string_view callee_for_diag) {
  auto args = call->get_arg_list();
  for (int i = 0; i < args->size(); ++i) {
    AnyExprV arg_expr = args->get_arg(i)->get_expr();
    if (ctx.in_deploy_receiver && expr_references_storage(arg_expr)) {
      err("`storage` may not be forwarded across function boundary inside an `@deploy receive(...)` body "
          "because deployment runs before storage exists. Inline the initialization value instead. "
          "See doc/tos-language-syntax-policy.md §3.6.")
        .collect(arg_expr);
      continue;
    }
    std::vector<std::string> taint = compute_taint_of_expr(arg_expr, ctx);
    if (!taint.empty()) {
      err("forwarding `@on({})` field across function boundary not yet supported; inline the use site at "
          "`{}(...)`. See doc/tos-language-syntax-policy.md §5.",
          format_state_list(taint), callee_for_diag)
        .collect(arg_expr);
    }
  }
}

// ---------- expression / statement walkers ----------

static void check_expr(AnyExprV expr, FieldScopingContext& ctx) {
  switch (expr->kind) {
    case ast_empty_expression:
    case ast_int_const:
    case ast_string_const:
    case ast_bool_const:
    case ast_null_keyword:
    case ast_underscore:
      return;
    case ast_reference: {
      // a bare read of a tainted local in this state = error
      auto ref = expr->as<ast_reference>();
      if (is_storage_reference(expr) && ctx.in_deploy_receiver) {
        err("`storage` may not be read inside an `@deploy receive(...)` body because deployment runs before storage exists. "
            "See doc/tos-language-syntax-policy.md §3.6.")
          .collect(expr);
        return;
      }
      auto it = ctx.tainted_locals.find(static_cast<std::string>(ref->get_name()));
      if (it != ctx.tainted_locals.end()) {
        if (!ctx.current_state.empty() && !state_in_list(it->second, ctx.current_state)) {
          err("local `{}` was tainted by an `@on({})` storage field and may not be read inside a "
              "`receive(...) on {}` body. See doc/tos-language-syntax-policy.md §5.",
              ref->get_name(), format_state_list(it->second), ctx.current_state)
            .collect(ref);
        }
      }
      return;
    }
    case ast_braced_expression:
      return check_block(expr->as<ast_braced_expression>()->get_block_statement(), ctx);
    case ast_braced_yield_result:
      return check_expr(expr->as<ast_braced_yield_result>()->get_expr(), ctx);
    case ast_artificial_aux_vertex:
      return check_expr(expr->as<ast_artificial_aux_vertex>()->get_wrapped_expr(), ctx);
    case ast_tensor:
      for (AnyExprV item : expr->as<ast_tensor>()->get_items()) {
        check_expr(item, ctx);
      }
      return;
    case ast_square_brackets:
      for (AnyExprV item : expr->as<ast_square_brackets>()->get_items()) {
        check_expr(item, ctx);
      }
      return;
    case ast_argument:
      return check_expr(expr->as<ast_argument>()->get_expr(), ctx);
    case ast_argument_list:
      for (AnyExprV arg : expr->as<ast_argument_list>()->get_arguments()) {
        check_expr(arg, ctx);
      }
      return;
    case ast_dot_access: {
      auto dot = expr->as<ast_dot_access>();
      check_storage_field_access(dot, ctx);
      return check_expr(dot->get_obj(), ctx);
    }
    case ast_function_call: {
      auto fc = expr->as<ast_function_call>();
      // first reject explicit c4 serialisation escapes
      detect_c4_serialisation_escape(fc, ctx);
      // determine callee diagnostic string
      std::string callee_str = "<call>";
      AnyExprV callee = fc->get_callee();
      if (auto ref = callee->try_as<ast_reference>()) {
        callee_str = static_cast<std::string>(ref->get_name());
      } else if (auto dot = callee->try_as<ast_dot_access>()) {
        std::string obj_part;
        if (auto ref_obj = dot->get_obj()->try_as<ast_reference>()) {
          obj_part = static_cast<std::string>(ref_obj->get_name()) + ".";
        }
        callee_str = obj_part + static_cast<std::string>(dot->get_field_name());
      }
      // method calls on a tainted receiver (e.g. `foo.someMethod()`) — flag the receiver too.
      // We allow `<obj>.method(...)` whose obj is `storage.<field>`-rooted only if the field is in scope;
      // check_storage_field_access has already done that on the dot-access of the callee.
      // We now still need to scrutinise arguments AND scrutinise the callee's expression tree.
      check_expr(callee, ctx);
      check_call_arguments(fc, ctx, callee_str);
      return;
    }
    case ast_assign: {
      auto a = expr->as<ast_assign>();
      // first inspect the rhs (so c4-escapes/tainted reads are caught even in assignments)
      check_expr(a->get_rhs(), ctx);
      // do not visit lhs as an expression — it is a binding, not a read
      // propagate taint into the binding
      propagate_taint_through_binding(a->get_lhs(), a->get_rhs(), ctx);
      return;
    }
    case ast_set_assign: {
      auto a = expr->as<ast_set_assign>();
      check_expr(a->get_lhs(), ctx);
      check_expr(a->get_rhs(), ctx);
      // a += b with tainted b carries combined taint into a
      std::vector<std::string> rhs_taint = compute_taint_of_expr(a->get_rhs(), ctx);
      if (auto ref = a->get_lhs()->try_as<ast_reference>()) {
        if (!rhs_taint.empty()) {
          auto& cur = ctx.tainted_locals[static_cast<std::string>(ref->get_name())];
          std::unordered_set<std::string> seen(cur.begin(), cur.end());
          for (std::string& s : rhs_taint) {
            if (seen.insert(s).second) {
              cur.push_back(std::move(s));
            }
          }
        }
      }
      return;
    }
    case ast_unary_operator:
      return check_expr(expr->as<ast_unary_operator>()->get_rhs(), ctx);
    case ast_binary_operator:
      check_expr(expr->as<ast_binary_operator>()->get_lhs(), ctx);
      return check_expr(expr->as<ast_binary_operator>()->get_rhs(), ctx);
    case ast_ternary_operator:
      check_expr(expr->as<ast_ternary_operator>()->get_cond(), ctx);
      check_expr(expr->as<ast_ternary_operator>()->get_when_true(), ctx);
      return check_expr(expr->as<ast_ternary_operator>()->get_when_false(), ctx);
    case ast_null_coalesce_operator:
      check_expr(expr->as<ast_null_coalesce_operator>()->get_lhs(), ctx);
      return check_expr(expr->as<ast_null_coalesce_operator>()->get_rhs(), ctx);
    case ast_cast_as_operator:
      detect_c4_serialisation_escape(expr, ctx);
      return check_expr(expr->as<ast_cast_as_operator>()->get_expr(), ctx);
    case ast_is_type_operator:
      return check_expr(expr->as<ast_is_type_operator>()->get_expr(), ctx);
    case ast_not_null_operator:
      return check_expr(expr->as<ast_not_null_operator>()->get_expr(), ctx);
    case ast_lazy_operator:
      return check_expr(expr->as<ast_lazy_operator>()->get_expr(), ctx);
    case ast_match_expression: {
      auto match = expr->as<ast_match_expression>();
      for (AnyExprV child : match->get_all_children()) {
        check_expr(child, ctx);
      }
      return;
    }
    case ast_match_arm:
      check_expr(expr->as<ast_match_arm>()->get_pattern_expr(), ctx);
      return check_expr(expr->as<ast_match_arm>()->get_body(), ctx);
    case ast_object_field:
      return check_expr(expr->as<ast_object_field>()->get_init_val(), ctx);
    case ast_object_body:
      for (int i = 0; i < expr->as<ast_object_body>()->get_num_fields(); ++i) {
        check_expr(expr->as<ast_object_body>()->get_field(i), ctx);
      }
      return;
    case ast_object_literal:
      return check_expr(expr->as<ast_object_literal>()->get_body(), ctx);
    case ast_lambda_fun:
      return check_block(expr->as<ast_lambda_fun>()->get_body(), ctx);
    default:
      return;
  }
}

static void check_statement(AnyV statement, FieldScopingContext& ctx) {
  switch (statement->kind) {
    case ast_block_statement:
      return check_block(statement->as<ast_block_statement>(), ctx);
    case ast_return_statement:
      return check_expr(statement->as<ast_return_statement>()->get_return_value(), ctx);
    case ast_if_statement: {
      auto if_stmt = statement->as<ast_if_statement>();
      check_expr(if_stmt->get_cond(), ctx);
      // Stage 3 conservative: do not branch-merge tainted_locals; just visit each arm with
      // the entry state. This is sound because any binding introduced inside an arm goes out
      // of scope at arm-end, and §3.4 mandates `become`/`keep_state` tail-position so any
      // post-`become` continuation is unreachable anyway. We still must restore on exit.
      auto saved = ctx.tainted_locals;
      check_block(if_stmt->get_if_body(), ctx);
      ctx.tainted_locals = saved;
      check_block(if_stmt->get_else_body(), ctx);
      ctx.tainted_locals = std::move(saved);
      return;
    }
    case ast_repeat_statement:
      check_expr(statement->as<ast_repeat_statement>()->get_cond(), ctx);
      return check_block(statement->as<ast_repeat_statement>()->get_body(), ctx);
    case ast_while_statement:
      check_expr(statement->as<ast_while_statement>()->get_cond(), ctx);
      return check_block(statement->as<ast_while_statement>()->get_body(), ctx);
    case ast_do_while_statement:
      check_block(statement->as<ast_do_while_statement>()->get_body(), ctx);
      return check_expr(statement->as<ast_do_while_statement>()->get_cond(), ctx);
    case ast_throw_statement: {
      auto t = statement->as<ast_throw_statement>();
      check_expr(t->get_thrown_code(), ctx);
      if (t->has_thrown_arg()) {
        check_expr(t->get_thrown_arg(), ctx);
      }
      return;
    }
    case ast_assert_statement:
      check_expr(statement->as<ast_assert_statement>()->get_cond(), ctx);
      return check_expr(statement->as<ast_assert_statement>()->get_thrown_code(), ctx);
    case ast_try_catch_statement: {
      auto saved = ctx.tainted_locals;
      check_block(statement->as<ast_try_catch_statement>()->get_try_body(), ctx);
      ctx.tainted_locals = saved;
      check_block(statement->as<ast_try_catch_statement>()->get_catch_body(), ctx);
      ctx.tainted_locals = std::move(saved);
      return;
    }
    case ast_become_statement:
    case ast_keep_state_statement:
    case ast_empty_statement:
      return;
    default:
      return check_expr(reinterpret_cast<AnyExprV>(statement), ctx);
  }
}

static void check_block(V<ast_block_statement> block, FieldScopingContext& ctx) {
  for (AnyV item : block->get_items()) {
    check_statement(item, ctx);
  }
}

// ---------- per-contract entry ----------

static StructPtr resolve_storage_struct(V<ast_contract_declaration> contract) {
  auto leaf = contract->storage_type_node->try_as<ast_type_leaf_text>();
  if (!leaf) {
    return nullptr;
  }
  const Symbol* sym = G.symtable.lookup(leaf->text);
  return sym ? sym->try_as<StructPtr>() : nullptr;
}

static void validate_on_states_against_declared(StructPtr storage_struct, FieldScopingContext& ctx) {
  if (!storage_struct) {
    return;
  }
  for (StructFieldPtr field : storage_struct->fields) {
    if (!field->has_on_states_annotation()) {
      continue;
    }
    for (const std::string& referenced : field->on_states) {
      if (ctx.declared_states.find(referenced) == ctx.declared_states.end()) {
        err("`@on(...)` references state `{}`, which is not declared in `states:`. "
            "See doc/tos-language-syntax-policy.md §3.4.", referenced)
          .collect(field->ident_anchor);
      }
    }
  }
}

static void check_state_contract(V<ast_contract_declaration> contract) {
  FieldScopingContext ctx;
  ctx.contract = contract;
  for (int i = 0; i < contract->get_num_states(); ++i) {
    ctx.declared_states.emplace(contract->get_state(i)->name);
  }
  ctx.storage_struct = resolve_storage_struct(contract);
  validate_on_states_against_declared(ctx.storage_struct, ctx);

  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    if (!receive->has_state_clause()) {
      if (receive->is_deploy) {
        ctx.current_state.clear();
        ctx.in_deploy_receiver = true;
        ctx.tainted_locals.clear();
        check_block(receive->get_body(), ctx);
        ctx.in_deploy_receiver = false;
      }
      continue;     // already diagnosed by pipe-check-state-reachability
    }
    ctx.current_state = static_cast<std::string>(receive->state_identifier->name);
    ctx.in_deploy_receiver = false;
    ctx.tainted_locals.clear();
    check_block(receive->get_body(), ctx);
  }
}

static void check_non_state_contract(V<ast_contract_declaration> contract) {
  StructPtr storage_struct = resolve_storage_struct(contract);
  if (!storage_struct) {
    return;
  }
  for (StructFieldPtr field : storage_struct->fields) {
    if (field->has_on_states_annotation()) {
      err("`@on(...)` requires a `states:` declaration on the surrounding contract. "
          "See doc/tos-language-syntax-policy.md §3.4.")
        .collect(field->ident_anchor);
    }
  }
}

// ---------- standalone-struct sweep ----------

// A struct that is NOT a state-bearing contract's storage may not bear `@on(...)` on any field.
// Authors must not sprinkle the annotation outside the §3.4 rule's scope.
static std::unordered_set<StructPtr> collect_state_storage_structs() {
  std::unordered_set<StructPtr> result;
  for (const SrcFile* file : G.all_src_files) {
    auto v_file = file->ast->as<ast_tol_file>();
    for (AnyV declaration : v_file->get_toplevel_declarations()) {
      if (auto contract = declaration->try_as<ast_contract_declaration>()) {
        if (!contract->has_state_machine()) {
          continue;
        }
        if (StructPtr s = resolve_storage_struct(contract)) {
          result.insert(s);
        }
      }
    }
  }
  return result;
}

static void check_free_struct_fields_have_no_on_annotation(const std::unordered_set<StructPtr>& state_storage_structs) {
  for (StructPtr s : G.all_structs) {
    if (state_storage_structs.find(s) != state_storage_structs.end()) {
      continue;
    }
    for (StructFieldPtr field : s->fields) {
      if (field->has_on_states_annotation()) {
        err("`@on(...)` is only permitted on storage struct fields of a state-bearing contract; "
            "struct `{}` is not used as such. See doc/tos-language-syntax-policy.md §3.4.", s->name)
          .collect(field->ident_anchor);
      }
    }
  }
}

}  // namespace

void pipeline_check_field_scoping() {
  std::unordered_set<StructPtr> state_storage_structs = collect_state_storage_structs();
  check_free_struct_fields_have_no_on_annotation(state_storage_structs);

  for (const SrcFile* file : G.all_src_files) {
    auto v_file = file->ast->as<ast_tol_file>();
    for (AnyV declaration : v_file->get_toplevel_declarations()) {
      if (auto contract = declaration->try_as<ast_contract_declaration>()) {
        if (contract->has_state_machine()) {
          check_state_contract(contract);
        } else {
          check_non_state_contract(contract);
        }
      }
    }
  }
}

}  // namespace tol
