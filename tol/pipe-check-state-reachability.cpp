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
#include "compilation-errors.h"
#include "compiler-state.h"
#include "symtable.h"

#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tol {

struct StateCheckInfo {
  V<ast_contract_declaration> contract;
  std::vector<std::string> states;
  std::unordered_map<std::string, int> state_to_idx;
  std::vector<std::unordered_set<int>> edges;
  int initial_idx = -1;
};

struct StatementFlow {
  bool terminates = false;
  bool via_state_tail = false;
};

static std::string to_string(std::string_view value) {
  return static_cast<std::string>(value);
}

static StructPtr resolve_storage_struct(V<ast_contract_declaration> contract) {
  auto leaf = contract->storage_type_node->try_as<ast_type_leaf_text>();
  if (!leaf) {
    return nullptr;
  }
  const Symbol* sym = G.symtable.lookup(leaf->text);
  return sym ? sym->try_as<StructPtr>() : nullptr;
}

static int require_declared_state(StateCheckInfo& info, V<ast_identifier> state_identifier, std::string_view role) {
  std::string state_name = to_string(state_identifier->name);
  auto it = info.state_to_idx.find(state_name);
  if (it == info.state_to_idx.end()) {
    err("{} `{}` is not declared in `states:`; see doc/tos-language-syntax-policy.md §3.4", role, state_name)
      .fire(state_identifier);
  }
  return it->second;
}

static bool is_storage_state_read(V<ast_dot_access> dot_access) {
  if (dot_access->get_field_name() != "__state") {
    return false;
  }
  auto obj_ref = dot_access->get_obj()->try_as<ast_reference>();
  return obj_ref && obj_ref->get_name() == "storage";
}

static void scan_hidden_state_expr(AnyExprV expr);
static void scan_hidden_state_statement(AnyV statement);

static void scan_hidden_state_block(V<ast_block_statement> block) {
  for (AnyV item : block->get_items()) {
    scan_hidden_state_statement(item);
  }
}

static void scan_hidden_state_expr(AnyExprV expr) {
  switch (expr->kind) {
    case ast_empty_expression:
    case ast_int_const:
    case ast_string_const:
    case ast_bool_const:
    case ast_null_keyword:
    case ast_reference:
    case ast_underscore:
      return;
    case ast_braced_expression:
      return scan_hidden_state_block(expr->as<ast_braced_expression>()->get_block_statement());
    case ast_braced_yield_result:
      return scan_hidden_state_expr(expr->as<ast_braced_yield_result>()->get_expr());
    case ast_artificial_aux_vertex:
      return scan_hidden_state_expr(expr->as<ast_artificial_aux_vertex>()->get_wrapped_expr());
    case ast_tensor:
      for (AnyExprV item : expr->as<ast_tensor>()->get_items()) {
        scan_hidden_state_expr(item);
      }
      return;
    case ast_square_brackets:
      for (AnyExprV item : expr->as<ast_square_brackets>()->get_items()) {
        scan_hidden_state_expr(item);
      }
      return;
    case ast_argument:
      return scan_hidden_state_expr(expr->as<ast_argument>()->get_expr());
    case ast_argument_list:
      for (AnyExprV arg : expr->as<ast_argument_list>()->get_arguments()) {
        scan_hidden_state_expr(arg);
      }
      return;
    case ast_dot_access:
      if (is_storage_state_read(expr->as<ast_dot_access>())) {
        err("receiver code may not read compiler-reserved `storage.__state`; use `become` or `keep_state`. See doc/tos-language-syntax-policy.md §3.4.")
          .fire(expr);
      }
      return scan_hidden_state_expr(expr->as<ast_dot_access>()->get_obj());
    case ast_function_call:
      scan_hidden_state_expr(expr->as<ast_function_call>()->get_callee());
      return scan_hidden_state_expr(expr->as<ast_function_call>()->get_arg_list());
    case ast_assign:
      scan_hidden_state_expr(expr->as<ast_assign>()->get_lhs());
      return scan_hidden_state_expr(expr->as<ast_assign>()->get_rhs());
    case ast_set_assign:
      scan_hidden_state_expr(expr->as<ast_set_assign>()->get_lhs());
      return scan_hidden_state_expr(expr->as<ast_set_assign>()->get_rhs());
    case ast_unary_operator:
      return scan_hidden_state_expr(expr->as<ast_unary_operator>()->get_rhs());
    case ast_binary_operator:
      scan_hidden_state_expr(expr->as<ast_binary_operator>()->get_lhs());
      return scan_hidden_state_expr(expr->as<ast_binary_operator>()->get_rhs());
    case ast_ternary_operator:
      scan_hidden_state_expr(expr->as<ast_ternary_operator>()->get_cond());
      scan_hidden_state_expr(expr->as<ast_ternary_operator>()->get_when_true());
      return scan_hidden_state_expr(expr->as<ast_ternary_operator>()->get_when_false());
    case ast_null_coalesce_operator:
      scan_hidden_state_expr(expr->as<ast_null_coalesce_operator>()->get_lhs());
      return scan_hidden_state_expr(expr->as<ast_null_coalesce_operator>()->get_rhs());
    case ast_cast_as_operator:
      return scan_hidden_state_expr(expr->as<ast_cast_as_operator>()->get_expr());
    case ast_is_type_operator:
      return scan_hidden_state_expr(expr->as<ast_is_type_operator>()->get_expr());
    case ast_not_null_operator:
      return scan_hidden_state_expr(expr->as<ast_not_null_operator>()->get_expr());
    case ast_lazy_operator:
      return scan_hidden_state_expr(expr->as<ast_lazy_operator>()->get_expr());
    case ast_match_expression: {
      auto match = expr->as<ast_match_expression>();
      for (AnyExprV child : match->get_all_children()) {
        scan_hidden_state_expr(child);
      }
      return;
    }
    case ast_match_arm:
      scan_hidden_state_expr(expr->as<ast_match_arm>()->get_pattern_expr());
      return scan_hidden_state_expr(expr->as<ast_match_arm>()->get_body());
    case ast_object_field:
      return scan_hidden_state_expr(expr->as<ast_object_field>()->get_init_val());
    case ast_object_body:
      for (int i = 0; i < expr->as<ast_object_body>()->get_num_fields(); ++i) {
        scan_hidden_state_expr(expr->as<ast_object_body>()->get_field(i));
      }
      return;
    case ast_object_literal:
      return scan_hidden_state_expr(expr->as<ast_object_literal>()->get_body());
    case ast_lambda_fun:
      return scan_hidden_state_block(expr->as<ast_lambda_fun>()->get_body());
    default:
      return;
  }
}

static void scan_hidden_state_statement(AnyV statement) {
  switch (statement->kind) {
    case ast_block_statement:
      return scan_hidden_state_block(statement->as<ast_block_statement>());
    case ast_return_statement:
      return scan_hidden_state_expr(statement->as<ast_return_statement>()->get_return_value());
    case ast_if_statement:
      scan_hidden_state_expr(statement->as<ast_if_statement>()->get_cond());
      scan_hidden_state_block(statement->as<ast_if_statement>()->get_if_body());
      return scan_hidden_state_block(statement->as<ast_if_statement>()->get_else_body());
    case ast_repeat_statement:
      scan_hidden_state_expr(statement->as<ast_repeat_statement>()->get_cond());
      return scan_hidden_state_block(statement->as<ast_repeat_statement>()->get_body());
    case ast_while_statement:
      scan_hidden_state_expr(statement->as<ast_while_statement>()->get_cond());
      return scan_hidden_state_block(statement->as<ast_while_statement>()->get_body());
    case ast_do_while_statement:
      scan_hidden_state_block(statement->as<ast_do_while_statement>()->get_body());
      return scan_hidden_state_expr(statement->as<ast_do_while_statement>()->get_cond());
    case ast_throw_statement:
      scan_hidden_state_expr(statement->as<ast_throw_statement>()->get_thrown_code());
      if (statement->as<ast_throw_statement>()->has_thrown_arg()) {
        scan_hidden_state_expr(statement->as<ast_throw_statement>()->get_thrown_arg());
      }
      return;
    case ast_assert_statement:
      scan_hidden_state_expr(statement->as<ast_assert_statement>()->get_cond());
      return scan_hidden_state_expr(statement->as<ast_assert_statement>()->get_thrown_code());
    case ast_try_catch_statement:
      scan_hidden_state_block(statement->as<ast_try_catch_statement>()->get_try_body());
      return scan_hidden_state_block(statement->as<ast_try_catch_statement>()->get_catch_body());
    case ast_become_statement:
    case ast_keep_state_statement:
    case ast_empty_statement:
      return;
    default:
      return scan_hidden_state_expr(reinterpret_cast<AnyExprV>(statement));
  }
}

static StatementFlow analyze_block(V<ast_block_statement> block, StateCheckInfo& info, int current_state);

static StatementFlow analyze_statement(AnyV statement, StateCheckInfo& info, int current_state) {
  scan_hidden_state_statement(statement);

  switch (statement->kind) {
    case ast_become_statement: {
      int target_idx = require_declared_state(info, statement->as<ast_become_statement>()->get_identifier(), "`become` target state");
      info.edges[current_state].insert(target_idx);
      return {true, true};
    }
    case ast_keep_state_statement:
      return {true, true};
    case ast_block_statement:
      return analyze_block(statement->as<ast_block_statement>(), info, current_state);
    case ast_if_statement: {
      StatementFlow if_flow = analyze_block(statement->as<ast_if_statement>()->get_if_body(), info, current_state);
      StatementFlow else_flow = analyze_block(statement->as<ast_if_statement>()->get_else_body(), info, current_state);
      return {if_flow.terminates && else_flow.terminates, if_flow.via_state_tail || else_flow.via_state_tail};
    }
    case ast_repeat_statement:
      analyze_block(statement->as<ast_repeat_statement>()->get_body(), info, current_state);
      return {};
    case ast_while_statement:
      analyze_block(statement->as<ast_while_statement>()->get_body(), info, current_state);
      return {};
    case ast_do_while_statement:
      analyze_block(statement->as<ast_do_while_statement>()->get_body(), info, current_state);
      return {};
    case ast_try_catch_statement: {
      StatementFlow try_flow = analyze_block(statement->as<ast_try_catch_statement>()->get_try_body(), info, current_state);
      StatementFlow catch_flow = analyze_block(statement->as<ast_try_catch_statement>()->get_catch_body(), info, current_state);
      return {try_flow.terminates && catch_flow.terminates, try_flow.via_state_tail || catch_flow.via_state_tail};
    }
    case ast_return_statement:
      err("state-bearing receivers must end with `become` or `keep_state`, not `return`; see doc/tos-language-syntax-policy.md §3.4")
        .fire(statement);
    case ast_throw_statement:
      return {true, false};
    default:
      return {};
  }
}

static StatementFlow analyze_block(V<ast_block_statement> block, StateCheckInfo& info, int current_state) {
  StatementFlow flow;
  for (AnyV item : block->get_items()) {
    if (flow.terminates) {
      if (flow.via_state_tail) {
        err("statements after `become` or `keep_state` are not permitted in the same control-flow path; see doc/tos-language-syntax-policy.md §3.4")
          .fire(item);
      }
      return flow;
    }
    flow = analyze_statement(item, info, current_state);
  }
  return flow;
}

static bool contains_state_tail_statement(AnyV statement) {
  switch (statement->kind) {
    case ast_become_statement:
    case ast_keep_state_statement:
      return true;
    case ast_block_statement:
      for (AnyV item : statement->as<ast_block_statement>()->get_items()) {
        if (contains_state_tail_statement(item)) {
          return true;
        }
      }
      return false;
    case ast_if_statement:
      return contains_state_tail_statement(statement->as<ast_if_statement>()->get_if_body()) ||
             contains_state_tail_statement(statement->as<ast_if_statement>()->get_else_body());
    case ast_repeat_statement:
      return contains_state_tail_statement(statement->as<ast_repeat_statement>()->get_body());
    case ast_while_statement:
      return contains_state_tail_statement(statement->as<ast_while_statement>()->get_body());
    case ast_do_while_statement:
      return contains_state_tail_statement(statement->as<ast_do_while_statement>()->get_body());
    case ast_try_catch_statement:
      return contains_state_tail_statement(statement->as<ast_try_catch_statement>()->get_try_body()) ||
             contains_state_tail_statement(statement->as<ast_try_catch_statement>()->get_catch_body());
    default:
      return false;
  }
}

static bool contains_state_tail_statement(V<ast_block_statement> block) {
  for (AnyV item : block->get_items()) {
    if (contains_state_tail_statement(item)) {
      return true;
    }
  }
  return false;
}

static StateCheckInfo build_state_info(V<ast_contract_declaration> contract) {
  StateCheckInfo info;
  info.contract = contract;
  info.states.reserve(contract->get_num_states());
  info.edges.resize(contract->get_num_states());

  for (int i = 0; i < contract->get_num_states(); ++i) {
    std::string state_name = to_string(contract->get_state(i)->name);
    auto [it, inserted] = info.state_to_idx.emplace(state_name, i);
    if (!inserted) {
      err("duplicate state `{}` in `states:` declaration; see doc/tos-language-syntax-policy.md §3.4", state_name)
        .fire(contract->get_state(i));
    }
    info.states.push_back(std::move(state_name));
  }

  if (!contract->get_initial_state_identifier()) {
    err("state-bearing contract must declare exactly one `@initial state <State>`; see doc/tos-language-syntax-policy.md §3.4")
      .fire(contract->get_identifier());
  }
  info.initial_idx = require_declared_state(info, contract->get_initial_state_identifier(), "`@initial` state");
  return info;
}

static void check_storage_reserved_state_field(V<ast_contract_declaration> contract) {
  StructPtr storage_struct = resolve_storage_struct(contract);
  if (!storage_struct) {
    return;
  }
  if (StructFieldPtr field = storage_struct->find_field("__state")) {
    err("state-bearing contract storage struct may not declare compiler-reserved field `__state`; see doc/tos-language-syntax-policy.md §3.4")
      .fire(field->ident_anchor);
  }
}

static void check_reachability(StateCheckInfo& info) {
  std::vector<bool> reachable(info.states.size(), false);
  std::queue<int> q;
  reachable[info.initial_idx] = true;
  q.push(info.initial_idx);

  while (!q.empty()) {
    int cur = q.front();
    q.pop();
    for (int next : info.edges[cur]) {
      if (!reachable[next]) {
        reachable[next] = true;
        q.push(next);
      }
    }
  }

  for (int i = 0; i < static_cast<int>(info.states.size()); ++i) {
    if (!reachable[i]) {
      err("state `{}` is unreachable from `@initial`; see doc/tos-language-syntax-policy.md §3.4", info.states[i])
        .fire(info.contract->get_state(i));
    }
  }
}

static void check_state_contract(V<ast_contract_declaration> contract) {
  StateCheckInfo info = build_state_info(contract);
  check_storage_reserved_state_field(contract);

  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    if (!receive->has_state_clause()) {
      err("state-bearing contract receiver must declare `on <State>`; see doc/tos-language-syntax-policy.md §3.4")
        .fire(receive);
    }
    int current_state = require_declared_state(info, receive->state_identifier, "receiver state");
    StatementFlow flow = analyze_block(receive->get_body(), info, current_state);
    if (!flow.terminates) {
      err("state-bearing receiver must end every successful control-flow path with `become` or `keep_state`; see doc/tos-language-syntax-policy.md §3.4")
        .fire(receive->get_body());
    }
  }

  check_reachability(info);
}

static void check_non_state_contract(V<ast_contract_declaration> contract) {
  if (contract->get_initial_state_identifier()) {
    err("`@initial state` requires a `states:` declaration; see doc/tos-language-syntax-policy.md §3.4")
      .fire(contract->get_initial_state_identifier());
  }
  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    if (receive->has_state_clause()) {
      err("`receive(...) on <State>` requires a `states:` declaration; see doc/tos-language-syntax-policy.md §3.4")
        .fire(receive->state_identifier);
    }
    if (contains_state_tail_statement(receive->get_body())) {
      err("`become` and `keep_state` require a state-bearing contract; see doc/tos-language-syntax-policy.md §3.4")
        .fire(receive->get_body());
    }
  }
}

void pipeline_check_state_reachability() {
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

} // namespace tol
