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
#include "pipeline.h"
#include "type-system.h"

#include <unordered_map>

namespace tol {

static V<ast_identifier> make_ident(SrcRange range, std::string_view name) {
  return createV<ast_identifier>(range, name);
}

static AnyTypeV make_type(SrcRange range, std::string_view name) {
  return createV<ast_type_leaf_text>(range, name);
}

static AnyExprV make_ref(SrcRange range, std::string_view name) {
  return createV<ast_reference>(range, make_ident(range, name), nullptr);
}

static AnyExprV make_int(SrcRange range, int64_t value) {
  return createV<ast_int_const>(range, td::make_refint(value), "");
}

static AnyExprV make_dot(SrcRange range, AnyExprV obj, std::string_view field) {
  return createV<ast_dot_access>(range, obj, make_ident(range, field), nullptr);
}

static AnyExprV make_arg(SrcRange range, AnyExprV expr) {
  return createV<ast_argument>(range, expr, false);
}

static V<ast_argument_list> make_args(SrcRange range, std::vector<AnyExprV>&& args) {
  return createV<ast_argument_list>(range, std::move(args));
}

static AnyExprV make_call(SrcRange range, AnyExprV callee, std::vector<AnyExprV>&& args = {}) {
  return createV<ast_function_call>(range, callee, make_args(range, std::move(args)));
}

static AnyExprV make_method_call(SrcRange range, AnyExprV obj, std::string_view method, std::vector<AnyExprV>&& args = {}) {
  return make_call(range, make_dot(range, obj, method), std::move(args));
}

static AnyExprV make_in_body(SrcRange range) {
  return make_dot(range, make_ref(range, "in"), "body");
}

static AnyV make_return_void(SrcRange range) {
  return createV<ast_return_statement>(range, createV<ast_empty_expression>(SrcRange::empty_at_end(range)));
}

static AnyV make_return_expr(SrcRange range, AnyExprV expr) {
  return createV<ast_return_statement>(range, expr);
}

static AnyV make_local_decl(SrcRange range, std::string_view name, AnyExprV rhs, bool immutable, AnyTypeV type_node = nullptr) {
  auto lhs = createV<ast_local_var_lhs>(range, make_ident(range, name), type_node, immutable, false);
  auto decl = createV<ast_local_vars_declaration>(range, lhs);
  return createV<ast_assign>(range, decl, rhs);
}

static AnyExprV make_storage_from_c4(SrcRange range, std::string_view storage_type) {
  AnyExprV contract_get_data = make_method_call(range, make_ref(range, "contract"), "getData");
  return make_method_call(range, make_ref(range, storage_type), "fromCell", {make_arg(range, contract_get_data)});
}

static AnyExprV make_to_cell(SrcRange range, std::string_view var_name) {
  return make_method_call(range, make_ref(range, var_name), "toCell");
}

static StructPtr resolve_struct_type(AnyTypeV type_node, const char* role) {
  auto leaf = type_node->try_as<ast_type_leaf_text>();
  if (!leaf) {
    err("{} must be a simple struct type identifier", role).fire(type_node);
  }

  const Symbol* sym = G.symtable.lookup(leaf->text);
  StructPtr struct_ref = sym ? sym->try_as<StructPtr>() : nullptr;
  if (!struct_ref) {
    err("{} `{}` is not a struct", role, leaf->text).fire(type_node);
  }
  return struct_ref;
}

static void check_receive_opcode_prefix(V<ast_receive_block> receive, StructPtr message_struct) {
  int prefix_len = message_struct->opcode.prefix_len;
  if (prefix_len != 32) {
    err("contract receive message type `{}` must declare exactly a 32-bit opcode prefix; actual prefix length is {}. See doc/tos-language-syntax-policy.md §3.2.",
        message_struct->name, prefix_len)
      .collect(receive->message_type_node);
  }
}

static V<ast_function_declaration> make_load_data_function(V<ast_contract_declaration> contract, StructPtr storage_struct) {
  SrcRange range = contract->range;
  auto name = make_ident(range, "loadData");
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{});
  AnyExprV loaded = make_storage_from_c4(range, storage_struct->name);
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{make_return_expr(range, loaded)});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, storage_struct->name), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static V<ast_function_declaration> make_save_function(V<ast_contract_declaration> contract, StructPtr storage_struct) {
  SrcRange range = contract->range;
  auto name = make_ident(range, "save");
  auto param = createV<ast_parameter>(
      range, make_ident(range, "storage"), make_type(range, storage_struct->name), nullptr, false);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{param});
  AnyExprV set_data = make_method_call(
      range, make_ref(range, "contract"), "setData", {make_arg(range, make_to_cell(range, "storage"))});
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{set_data});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, "void"), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static AnyV make_msg_decode_decl(SrcRange range, V<ast_receive_block> receive) {
  auto type_leaf = receive->message_type_node->as<ast_type_leaf_text>();
  AnyExprV from_slice = make_method_call(range, make_ref(range, type_leaf->text), "fromSlice", {make_arg(range, make_in_body(range))});
  return make_local_decl(range, receive->get_param_name(), createV<ast_lazy_operator>(range, from_slice), true);
}

static AnyV make_receive_branch(V<ast_receive_block> receive, StructPtr message_struct) {
  SrcRange range = receive->range;
  AnyExprV cond = createV<ast_binary_operator>(
      range, range, "==", tok_eq, make_ref(range, "op"), make_int(range, message_struct->opcode.pack_prefix));

  std::vector<AnyV> body_items;
  body_items.reserve(2 + receive->get_body()->get_items().size());
  body_items.push_back(make_msg_decode_decl(range, receive));
  for (AnyV item : receive->get_body()->get_items()) {
    body_items.push_back(item);
  }
  body_items.push_back(make_return_void(range));

  auto if_body = createV<ast_block_statement>(range, std::move(body_items));
  auto else_body = createV<ast_block_statement>(SrcRange::empty_at_end(range), std::vector<AnyV>{});
  return createV<ast_if_statement>(range, false, cond, if_body, else_body);
}

static AnyV make_query_id_preflight_guard(SrcRange range) {
  // Keep the 64-bit query_id preflight live even before per-receiver query handling exists.
  AnyExprV cond = createV<ast_binary_operator>(
      range, range, "!=", tok_neq, make_ref(range, "queryId"), make_ref(range, "queryId"));
  auto if_body = createV<ast_block_statement>(range, std::vector<AnyV>{make_return_void(range)});
  auto else_body = createV<ast_block_statement>(SrcRange::empty_at_end(range), std::vector<AnyV>{});
  return createV<ast_if_statement>(range, false, cond, if_body, else_body);
}

static V<ast_function_declaration> make_on_internal_function(V<ast_contract_declaration> contract, const std::vector<StructPtr>& message_structs) {
  SrcRange range = contract->range;

  auto name = make_ident(range, "onInternalMessage");
  auto param = createV<ast_parameter>(range, make_ident(range, "in"), make_type(range, "InMessage"), nullptr, false);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{param});

  std::vector<AnyV> items;
  AnyExprV body_empty = make_method_call(range, make_in_body(range), "isEmpty");
  auto return_body = createV<ast_block_statement>(range, std::vector<AnyV>{make_return_void(range)});
  auto empty_else = createV<ast_block_statement>(SrcRange::empty_at_end(range), std::vector<AnyV>{});
  items.push_back(createV<ast_if_statement>(range, false, body_empty, return_body, empty_else));

  items.push_back(make_local_decl(range, "header", make_in_body(range), false));
  items.push_back(make_local_decl(
      range, "op", make_method_call(range, make_ref(range, "header"), "loadUint", {make_arg(range, make_int(range, 32))}), true));
  items.push_back(make_local_decl(
      range, "queryId", make_method_call(range, make_ref(range, "header"), "loadUint", {make_arg(range, make_int(range, 64))}), true));
  items.push_back(make_query_id_preflight_guard(range));
  items.push_back(make_local_decl(range, "storage", make_call(range, make_ref(range, "loadData")), true));

  for (int i = 0; i < contract->get_num_receives(); ++i) {
    items.push_back(make_receive_branch(contract->get_receive(i), message_structs[i]));
  }
  items.push_back(make_return_void(range));

  auto body = createV<ast_block_statement>(range, std::move(items));
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, nullptr, nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, FunctionData::flagIsEntrypoint, FunctionInlineMode::notCalculated);
}

static std::vector<AnyV> lower_contract(V<ast_contract_declaration> contract) {
  StructPtr storage_struct = resolve_struct_type(contract->storage_type_node, "contract storage type");

  std::vector<StructPtr> message_structs;
  message_structs.reserve(contract->get_num_receives());
  std::unordered_map<int64_t, V<ast_receive_block>> seen_opcodes;
  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    StructPtr message_struct = resolve_struct_type(receive->message_type_node, "contract receive message type");
    check_receive_opcode_prefix(receive, message_struct);
    if (message_struct->opcode.prefix_len == 32) {
      auto [it, inserted] = seen_opcodes.emplace(message_struct->opcode.pack_prefix, receive);
      if (!inserted) {
        err("duplicate contract receive opcode `{}`; first receiver with this opcode was declared at {}",
            std::to_string(message_struct->opcode.pack_prefix), it->second->range.stringify_start_location(false))
          .collect(receive->message_type_node);
      }
    }
    message_structs.push_back(message_struct);
  }

  return {
    make_load_data_function(contract, storage_struct),
    make_save_function(contract, storage_struct),
    make_on_internal_function(contract, message_structs),
  };
}

static void analyze_generated_function(FunctionPtr fun_ref) {
  pipeline_resolve_identifiers_and_assign_symbols(fun_ref);
  pipeline_resolve_types_and_aliases(fun_ref);
  pipeline_calculate_rvalue_lvalue(fun_ref);
  pipeline_infer_types_and_calls_and_fields(fun_ref);
}

void pipeline_lower_contracts() {
  std::vector<V<ast_function_declaration>> generated_functions;

  for (const SrcFile* file : G.all_src_files) {
    auto v_file = file->ast->as<ast_tol_file>();
    std::vector<AnyV> lowered_declarations;
    bool changed = false;

    for (AnyV declaration : v_file->get_toplevel_declarations()) {
      if (auto contract = declaration->try_as<ast_contract_declaration>()) {
        changed = true;
        std::vector<AnyV> generated = lower_contract(contract);
        for (AnyV generated_decl : generated) {
          lowered_declarations.push_back(generated_decl);
          generated_functions.push_back(generated_decl->as<ast_function_declaration>());
        }
      } else {
        lowered_declarations.push_back(declaration);
      }
    }

    if (changed) {
      v_file->mutate()->assign_new_children(std::move(lowered_declarations));
    }
  }

  if (generated_functions.empty()) {
    return;
  }

  std::vector<FunctionPtr> generated_refs;
  generated_refs.reserve(generated_functions.size());
  for (V<ast_function_declaration> generated_function : generated_functions) {
    generated_refs.push_back(pipeline_register_instantiated_generic_function(
        nullptr, generated_function, std::string{}, nullptr));
  }
  for (FunctionPtr fun_ref : generated_refs) {
    analyze_generated_function(fun_ref);
  }

  pipeline_check_inferred_types();
  pipeline_refine_lvalue_for_mutate_arguments();
  pipeline_check_rvalue_lvalue();
  pipeline_check_private_fields_usage();
  pipeline_check_pure_impure_operations();
  pipeline_check_constant_expressions();
  pipeline_mini_borrow_checker_for_mutate();
  pipeline_optimize_boolean_expressions();
  pipeline_detect_inline_in_place();
  pipeline_check_serialized_fields();
}

} // namespace tol
