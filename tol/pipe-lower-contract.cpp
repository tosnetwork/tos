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
#include "pipeline.h"
#include "symtable.h"
#include "type-system.h"

#include <cstdio>
#include <unordered_map>
#include <utility>

namespace tol {

static std::string_view keep_generated_string(std::string_view name) {
  return *new std::string(name);
}

static V<ast_identifier> make_ident(SrcRange range, std::string_view name) {
  return createV<ast_identifier>(range, keep_generated_string(name));
}

static AnyTypeV make_type(SrcRange range, std::string_view name) {
  return createV<ast_type_leaf_text>(range, keep_generated_string(name));
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

static AnyExprV make_enum_member(SrcRange range, std::string_view enum_name, std::string_view member_name) {
  return make_dot(range, make_ref(range, enum_name), member_name);
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

static AnyV make_throw(SrcRange range, int64_t code) {
  return createV<ast_throw_statement>(
      range, make_int(range, code), createV<ast_empty_expression>(SrcRange::empty_at_end(range)));
}

static AnyV make_local_decl(SrcRange range, std::string_view name, AnyExprV rhs, bool immutable, AnyTypeV type_node = nullptr) {
  auto lhs = createV<ast_local_var_lhs>(range, make_ident(range, name), type_node, immutable, false);
  auto decl = createV<ast_local_vars_declaration>(range, lhs);
  return createV<ast_assign>(range, decl, rhs);
}

static V<ast_object_field> make_object_field(SrcRange range, std::string_view name, AnyExprV value) {
  return createV<ast_object_field>(range, make_ident(range, name), value);
}

static AnyExprV make_object_literal(SrcRange range, std::string_view type_name, std::vector<std::pair<std::string, AnyExprV>>&& fields) {
  std::vector<AnyExprV> object_fields;
  object_fields.reserve(fields.size());
  for (auto& [name, value] : fields) {
    object_fields.push_back(make_object_field(range, name, value));
  }
  auto body = createV<ast_object_body>(range, std::move(object_fields));
  return createV<ast_object_literal>(range, make_type(range, type_name), body);
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

struct StateLoweringContext {
  bool enabled = false;
  std::string enum_name;
  std::string data_name;
  std::string load_state_data_name;
  std::string load_state_name;
  std::string save_state_name;
  V<ast_enum_declaration> enum_decl = nullptr;
  V<ast_struct_declaration> data_decl = nullptr;
  StructPtr data_struct = nullptr;
};

static std::string make_contract_private_name(V<ast_contract_declaration> contract, std::string_view suffix) {
  std::string name = "__";
  name += contract->get_identifier()->name;
  name += suffix;
  return name;
}

static EnumDefPtr register_generated_enum(V<ast_enum_declaration> decl) {
  auto body = decl->get_enum_body();
  std::vector<EnumMemberPtr> members;
  members.reserve(body->get_num_members());
  for (int i = 0; i < body->get_num_members(); ++i) {
    auto member = body->get_member(i);
    members.emplace_back(new EnumMemberData(
        static_cast<std::string>(member->get_identifier()->name), member->get_identifier(), i, member->init_value));
  }

  EnumDefData* enum_ref = new EnumDefData(
      static_cast<std::string>(decl->get_identifier()->name), decl->get_identifier(), decl->colon_type, std::move(members));
  G.symtable.add_global_symbol(enum_ref);
  G.all_enums.push_back(enum_ref);
  decl->mutate()->assign_enum_ref(enum_ref);
  return enum_ref;
}

static StructPtr register_generated_struct(V<ast_struct_declaration> decl) {
  auto body = decl->get_struct_body();
  std::vector<StructFieldPtr> fields;
  fields.reserve(body->get_num_fields());
  for (int i = 0; i < body->get_num_fields(); ++i) {
    auto field = body->get_field(i);
    fields.emplace_back(new StructFieldData(
        static_cast<std::string>(field->get_identifier()->name), field->get_identifier(), i,
        field->is_private, field->is_readonly, field->type_node, field->default_value));
  }

  StructData* struct_ref = new StructData(
      static_cast<std::string>(decl->get_identifier()->name), decl->get_identifier(), std::move(fields),
      StructData::PackOpcode(0, 0), decl->overflow1023_policy, nullptr, nullptr, decl);
  G.symtable.add_global_symbol(struct_ref);
  G.all_structs.push_back(struct_ref);
  decl->mutate()->assign_struct_ref(struct_ref);
  return struct_ref;
}

static StateLoweringContext make_state_lowering_context(V<ast_contract_declaration> contract, StructPtr storage_struct) {
  StateLoweringContext ctx;
  if (!contract->has_state_machine()) {
    return ctx;
  }

  SrcRange range = contract->range;
  ctx.enabled = true;
  ctx.enum_name = make_contract_private_name(contract, "State");
  ctx.data_name = make_contract_private_name(contract, "StateData");
  ctx.load_state_data_name = make_contract_private_name(contract, "LoadStateData");
  ctx.load_state_name = make_contract_private_name(contract, "LoadState");
  ctx.save_state_name = make_contract_private_name(contract, "SaveState");

  std::vector<AnyV> enum_members;
  enum_members.reserve(contract->get_num_states());
  for (int i = 0; i < contract->get_num_states(); ++i) {
    enum_members.push_back(createV<ast_enum_member>(
        contract->get_state(i)->range, make_ident(contract->get_state(i)->range, contract->get_state(i)->name), nullptr));
  }
  auto enum_body = createV<ast_enum_body>(range, std::move(enum_members));
  ctx.enum_decl = createV<ast_enum_declaration>(range, make_ident(range, ctx.enum_name), nullptr, enum_body);
  register_generated_enum(ctx.enum_decl);

  std::vector<AnyV> fields;
  fields.push_back(createV<ast_struct_field>(
      range, make_ident(range, "__state"), false, false, nullptr, make_type(range, ctx.enum_name)));
  fields.push_back(createV<ast_struct_field>(
      range, make_ident(range, "storage"), false, false, nullptr, make_type(range, storage_struct->name)));
  auto struct_body = createV<ast_struct_body>(range, std::move(fields));
  ctx.data_decl = createV<ast_struct_declaration>(
      range, make_ident(range, ctx.data_name), nullptr, StructData::Overflow1023Policy::not_specified,
      createV<ast_empty_expression>(SrcRange::empty_at_start(range)), struct_body);
  ctx.data_struct = register_generated_struct(ctx.data_decl);
  pipeline_resolve_types_and_aliases(ctx.data_struct);

  return ctx;
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

static V<ast_function_declaration> make_state_load_data_function(
    V<ast_contract_declaration> contract, StructPtr storage_struct, const StateLoweringContext& state_ctx) {
  SrcRange range = contract->range;
  auto name = make_ident(range, "loadData");
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{});
  auto state_data_decl = make_local_decl(range, "stateData", make_call(range, make_ref(range, state_ctx.load_state_data_name)), true);
  AnyExprV storage_expr = make_dot(range, make_ref(range, "stateData"), "storage");
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{state_data_decl, make_return_expr(range, storage_expr)});
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

static AnyExprV make_state_data_literal_preserving_state(SrcRange range, const StateLoweringContext& state_ctx, AnyExprV storage_expr) {
  return make_object_literal(range, state_ctx.data_name, {
      {"__state", make_dot(range, make_ref(range, "stateData"), "__state")},
      {"storage", storage_expr},
  });
}

static V<ast_function_declaration> make_state_save_function(
    V<ast_contract_declaration> contract, StructPtr storage_struct, const StateLoweringContext& state_ctx) {
  SrcRange range = contract->range;
  auto name = make_ident(range, "save");
  auto param = createV<ast_parameter>(
      range, make_ident(range, "storage"), make_type(range, storage_struct->name), nullptr, false);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{param});
  AnyV state_data_decl = make_local_decl(range, "stateData", make_call(range, make_ref(range, state_ctx.load_state_data_name)), true);
  AnyExprV data_literal = make_state_data_literal_preserving_state(range, state_ctx, make_ref(range, "storage"));
  AnyExprV set_data = make_method_call(
      range, make_ref(range, "contract"), "setData", {make_arg(range, make_method_call(range, data_literal, "toCell"))});
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{state_data_decl, set_data});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, "void"), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static V<ast_function_declaration> make_load_state_data_function(
    V<ast_contract_declaration> contract, const StateLoweringContext& state_ctx) {
  SrcRange range = contract->range;
  auto name = make_ident(range, state_ctx.load_state_data_name);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{});
  AnyExprV loaded = make_storage_from_c4(range, state_ctx.data_name);
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{make_return_expr(range, loaded)});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, state_ctx.data_name), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static V<ast_function_declaration> make_load_state_function(
    V<ast_contract_declaration> contract, const StateLoweringContext& state_ctx) {
  SrcRange range = contract->range;
  auto name = make_ident(range, state_ctx.load_state_name);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{});
  AnyExprV state_expr = make_dot(range, make_call(range, make_ref(range, state_ctx.load_state_data_name)), "__state");
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{make_return_expr(range, state_expr)});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, state_ctx.enum_name), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static V<ast_function_declaration> make_save_state_function(
    V<ast_contract_declaration> contract, const StateLoweringContext& state_ctx) {
  SrcRange range = contract->range;
  auto name = make_ident(range, state_ctx.save_state_name);
  auto param = createV<ast_parameter>(
      range, make_ident(range, "state"), make_type(range, state_ctx.enum_name), nullptr, false);
  auto params = createV<ast_parameter_list>(range, std::vector<AnyV>{param});
  AnyV state_data_decl = make_local_decl(range, "stateData", make_call(range, make_ref(range, state_ctx.load_state_data_name)), true);
  AnyExprV data_literal = make_object_literal(range, state_ctx.data_name, {
      {"__state", make_ref(range, "state")},
      {"storage", make_dot(range, make_ref(range, "stateData"), "storage")},
  });
  AnyExprV set_data = make_method_call(
      range, make_ref(range, "contract"), "setData", {make_arg(range, make_method_call(range, data_literal, "toCell"))});
  auto body = createV<ast_block_statement>(range, std::vector<AnyV>{state_data_decl, set_data});
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, make_type(range, "void"), nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, 0, FunctionInlineMode::notCalculated);
}

static AnyV make_msg_decode_decl(SrcRange range, V<ast_receive_block> receive) {
  auto type_leaf = receive->message_type_node->as<ast_type_leaf_text>();
  AnyExprV from_slice = make_method_call(range, make_ref(range, type_leaf->text), "fromSlice", {make_arg(range, make_in_body(range))});
  return make_local_decl(range, receive->get_param_name(), createV<ast_lazy_operator>(range, from_slice), true);
}

static AnyV make_state_guard(SrcRange range, V<ast_receive_block> receive, const StateLoweringContext& state_ctx) {
  AnyExprV cond = createV<ast_binary_operator>(
      range, range, "!=", tok_neq,
      make_call(range, make_ref(range, state_ctx.load_state_name)),
      make_enum_member(range, state_ctx.enum_name, receive->get_state_name()));
  auto if_body = createV<ast_block_statement>(range, std::vector<AnyV>{make_throw(range, 1024)});
  auto else_body = createV<ast_block_statement>(SrcRange::empty_at_end(range), std::vector<AnyV>{});
  return createV<ast_if_statement>(range, false, cond, if_body, else_body);
}

static std::vector<AnyV> lower_state_statement(AnyV item, const StateLoweringContext& state_ctx);

static V<ast_block_statement> lower_state_block(V<ast_block_statement> block, const StateLoweringContext& state_ctx) {
  std::vector<AnyV> lowered_items;
  for (AnyV item : block->get_items()) {
    std::vector<AnyV> lowered = lower_state_statement(item, state_ctx);
    lowered_items.insert(lowered_items.end(), lowered.begin(), lowered.end());
  }
  return createV<ast_block_statement>(block->range, std::move(lowered_items));
}

static std::vector<AnyV> lower_state_statement(AnyV item, const StateLoweringContext& state_ctx) {
  SrcRange range = item->range;
  switch (item->kind) {
    case ast_become_statement: {
      auto become = item->as<ast_become_statement>();
      AnyExprV state_expr = make_enum_member(range, state_ctx.enum_name, become->get_state_name());
      AnyExprV save_state = make_call(range, make_ref(range, state_ctx.save_state_name), {make_arg(range, state_expr)});
      return {save_state, make_return_void(range)};
    }
    case ast_keep_state_statement:
      return {make_return_void(range)};
    case ast_block_statement:
      return {lower_state_block(item->as<ast_block_statement>(), state_ctx)};
    case ast_if_statement: {
      auto if_stmt = item->as<ast_if_statement>();
      auto if_body = lower_state_block(if_stmt->get_if_body(), state_ctx);
      auto else_body = lower_state_block(if_stmt->get_else_body(), state_ctx);
      return {createV<ast_if_statement>(range, false, if_stmt->get_cond(), if_body, else_body)};
    }
    case ast_repeat_statement: {
      auto repeat = item->as<ast_repeat_statement>();
      return {createV<ast_repeat_statement>(range, repeat->get_cond(), lower_state_block(repeat->get_body(), state_ctx))};
    }
    case ast_while_statement: {
      auto while_stmt = item->as<ast_while_statement>();
      return {createV<ast_while_statement>(range, while_stmt->get_cond(), lower_state_block(while_stmt->get_body(), state_ctx))};
    }
    case ast_do_while_statement: {
      auto do_while = item->as<ast_do_while_statement>();
      return {createV<ast_do_while_statement>(range, lower_state_block(do_while->get_body(), state_ctx), do_while->get_cond())};
    }
    case ast_try_catch_statement: {
      auto try_catch = item->as<ast_try_catch_statement>();
      return {createV<ast_try_catch_statement>(
          range, lower_state_block(try_catch->get_try_body(), state_ctx),
          try_catch->get_catch_expr(), lower_state_block(try_catch->get_catch_body(), state_ctx))};
    }
    default:
      return {item};
  }
}

static AnyV make_receive_branch(V<ast_receive_block> receive, StructPtr message_struct, const StateLoweringContext& state_ctx) {
  SrcRange range = receive->range;
  AnyExprV cond = createV<ast_binary_operator>(
      range, range, "==", tok_eq, make_ref(range, "op"), make_int(range, message_struct->opcode.pack_prefix));

  std::vector<AnyV> body_items;
  body_items.reserve(3 + receive->get_body()->get_items().size());
  body_items.push_back(make_msg_decode_decl(range, receive));
  if (state_ctx.enabled) {
    body_items.push_back(make_state_guard(range, receive, state_ctx));
    for (AnyV item : receive->get_body()->get_items()) {
      std::vector<AnyV> lowered = lower_state_statement(item, state_ctx);
      body_items.insert(body_items.end(), lowered.begin(), lowered.end());
    }
  } else {
    for (AnyV item : receive->get_body()->get_items()) {
      body_items.push_back(item);
    }
    body_items.push_back(make_return_void(range));
  }

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

static V<ast_function_declaration> make_on_internal_function(
    V<ast_contract_declaration> contract, const std::vector<StructPtr>& message_structs, const StateLoweringContext& state_ctx) {
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
    items.push_back(make_receive_branch(contract->get_receive(i), message_structs[i], state_ctx));
  }
  items.push_back(make_return_void(range));

  auto body = createV<ast_block_statement>(range, std::move(items));
  return createV<ast_function_declaration>(
      range, name, params, body, nullptr, nullptr, nullptr, nullptr,
      FunctionData::EMPTY_TVM_METHOD_ID, FunctionData::flagIsEntrypoint, FunctionInlineMode::notCalculated);
}

// Names that mutate persistent storage / emit c5 actions.
// `get fun` bodies must be free of these per doc/tos-language-syntax-policy.md §3.5
// (the get-method execution path has no commit() and must not produce actions).
static bool is_forbidden_in_get_fun_top_level(std::string_view name) {
  return name == "save" || name == "saveData" || name == "commitContractDataAndActions"
      || name == "sendRawMessage" || name == "setData" || name == "setCodePostponed"
      || name == "reserveBalance" || name == "reserveExtraBalance";
}

static bool is_forbidden_in_get_fun_method(std::string_view receiver_name, std::string_view method_name) {
  if (receiver_name == "contract" && (method_name == "setData" || method_name == "setCodePostponed")) {
    return true;
  }
  if (method_name == "send" || method_name == "sendAndEstimateFee") {
    // OutMessage.send / message.send / etc. — any send-like method
    return true;
  }
  return false;
}

// Walks a get-fun body and reports `err(...).fire()` if it contains a forbidden side-effecting call.
// Stops at the first violation (fire() throws).
class GetFunBodySideEffectChecker final : public ASTVisitorFunctionBody {
  std::string_view get_fun_name;

protected:
  void visit(V<ast_function_call> v) override {
    AnyExprV callee = v->get_callee();
    if (auto v_ref = callee->try_as<ast_reference>()) {
      std::string_view name = v_ref->get_name();
      if (is_forbidden_in_get_fun_top_level(name)) {
        err("`{}(...)` is not permitted in `get fun {}`; the get-method execution path is read-only and may not emit actions or commit storage; see doc/tos-language-syntax-policy.md §3.5",
            name, get_fun_name).fire(v);
      }
    } else if (auto v_dot = callee->try_as<ast_dot_access>()) {
      auto field_name = v_dot->get_identifier()->name;
      std::string_view obj_name;
      if (auto obj_ref = v_dot->get_obj()->try_as<ast_reference>()) {
        obj_name = obj_ref->get_name();
      }
      if (is_forbidden_in_get_fun_method(obj_name, field_name)) {
        err("`{}.{}(...)` is not permitted in `get fun {}`; the get-method execution path is read-only and may not emit actions or commit storage; see doc/tos-language-syntax-policy.md §3.5",
            obj_name.empty() ? std::string("<expr>") : std::string(obj_name), field_name, get_fun_name).fire(v);
      }
    }
    parent::visit(v);
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    static_cast<void>(fun_ref);
    return false;   // we drive visit() manually on the get-fun body
  }

  void check(V<ast_get_fun_block> get_fun) {
    get_fun_name = get_fun->get_name();
    // dispatch through the kind-switching overload (defined in ASTVisitorFunctionBody)
    ASTVisitorFunctionBody::visit(static_cast<AnyV>(get_fun->get_body()));
  }
};

// Generate a top-level `fun X(...): T { let storage = loadData(); <body> }`
// for each get-fun block in the contract. The synthesized function carries
// flagContractGetter so the existing tvm_method_id pipeline assigns
// crc16(name) | 0x10000 (or the @method_id override) per §3.5.
static V<ast_function_declaration> make_get_fun_lowering(V<ast_get_fun_block> get_fun, StructPtr storage_struct) {
  SrcRange range = get_fun->range;
  auto name = make_ident(range, get_fun->get_name());
  auto v_param_list = get_fun->get_param_list();
  AnyTypeV ret_type = get_fun->return_type_node;

  // body: prepend `let storage = loadData();` (read-only; §3.5)
  // (void) storage_struct here — we rely on type inference, mirroring make_on_internal_function.
  static_cast<void>(storage_struct);
  std::vector<AnyV> body_items;
  body_items.reserve(1 + get_fun->get_body()->get_items().size());
  body_items.push_back(make_local_decl(range, "storage", make_call(range, make_ref(range, "loadData")), true));
  for (AnyV item : get_fun->get_body()->get_items()) {
    body_items.push_back(item);
  }
  auto body = createV<ast_block_statement>(get_fun->get_body()->range, std::move(body_items));

  int flags = FunctionData::flagContractGetter | get_fun->extra_fun_flags;
  return createV<ast_function_declaration>(
      range, name, v_param_list, body, nullptr, ret_type, nullptr,
      get_fun->tvm_method_id_expr,
      FunctionData::EMPTY_TVM_METHOD_ID,
      flags,
      get_fun->inline_mode);
}

// Map from a synthesized contract-getter function (lowered ast_function_declaration,
// keyed by the AST node pointer) to the source contract name that produced it.
// Populated during lowering, consumed by the per-contract method_id collision
// detector. Per doc §3.5: cross-contract auto-derived ID sharing is NOT a collision,
// so we MUST group by contract origin.
static std::unordered_map<AnyV, std::string> g_contract_getter_origin;

std::string_view contract_origin_of_getter(FunctionPtr fun_ref) {
  if (!fun_ref || !fun_ref->ast_root) {
    return {};
  }
  auto it = g_contract_getter_origin.find(fun_ref->ast_root);
  if (it == g_contract_getter_origin.end()) {
    return {};
  }
  return it->second;
}

static std::vector<AnyV> lower_contract(V<ast_contract_declaration> contract) {
  StructPtr storage_struct = resolve_struct_type(contract->storage_type_node, "contract storage type");
  StateLoweringContext state_ctx = make_state_lowering_context(contract, storage_struct);

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

  // Validate get_fun bodies: §3.5 forbids any side-effecting builtins.
  // Also ensure we don't shadow the synthesized `loadData` / `save` / generated state helpers
  // with a get_fun of the same name.
  std::unordered_map<std::string_view, V<ast_get_fun_block>> get_fun_by_name;
  for (int i = 0; i < contract->get_num_get_funs(); ++i) {
    V<ast_get_fun_block> get_fun = contract->get_get_fun(i);
    std::string_view name = get_fun->get_name();
    if (name == "loadData" || name == "save" || name == "onInternalMessage") {
      err("`get fun {}` shadows a contract-internal function generated by the lowering; pick a different name; see doc/tos-language-syntax-policy.md §3.5",
          name).fire(get_fun->get_identifier());
    }
    auto [it, inserted] = get_fun_by_name.emplace(name, get_fun);
    if (!inserted) {
      err("duplicate `get fun {}` in contract `{}`; first declared at {}",
          name, contract->get_identifier()->name, it->second->range.stringify_start_location(false))
        .fire(get_fun->get_identifier());
    }
    GetFunBodySideEffectChecker checker;
    checker.check(get_fun);
  }

  std::vector<AnyV> generated;
  if (state_ctx.enabled) {
    generated.push_back(state_ctx.enum_decl);
    generated.push_back(state_ctx.data_decl);
    generated.push_back(make_load_state_data_function(contract, state_ctx));
    generated.push_back(make_load_state_function(contract, state_ctx));
    generated.push_back(make_save_state_function(contract, state_ctx));
    generated.push_back(make_state_load_data_function(contract, storage_struct, state_ctx));
    generated.push_back(make_state_save_function(contract, storage_struct, state_ctx));
  } else {
    generated.push_back(make_load_data_function(contract, storage_struct));
    generated.push_back(make_save_function(contract, storage_struct));
  }
  generated.push_back(make_on_internal_function(contract, message_structs, state_ctx));

  // Synthesize a top-level `fun X(): T { let storage = loadData(); <body> }` per get_fun block.
  // Track origin so the per-contract collision detector can group these correctly.
  std::string contract_name = static_cast<std::string>(contract->get_identifier()->name);
  for (int i = 0; i < contract->get_num_get_funs(); ++i) {
    V<ast_get_fun_block> get_fun = contract->get_get_fun(i);
    V<ast_function_declaration> lowered = make_get_fun_lowering(get_fun, storage_struct);
    g_contract_getter_origin.emplace(static_cast<AnyV>(lowered), contract_name);
    generated.push_back(lowered);
  }
  return generated;
}

// Per-contract method_id collision detector.
// Runs at pre-emission time (after all const-expr resolution is done).
// Groups contract getters by origin contract name, then for each group reports
// the SECOND offender so the diff is small. Legacy file-scope getters (origin = "")
// share a single global group, preserving the existing behaviour.
// See doc/tos-language-syntax-policy.md §3.5 / §10.1.
void check_contract_method_id_collisions() {
  // group: contract_name (or "" for file-scope) -> [(method_id, FunctionPtr)]
  std::unordered_map<std::string, std::unordered_map<int, FunctionPtr>> seen_per_contract;
  for (FunctionPtr fun_ref : G.all_functions) {
    if (!fun_ref->is_contract_getter() || !fun_ref->has_tvm_method_id()) {
      continue;
    }
    std::string origin{contract_origin_of_getter(fun_ref)};
    auto& seen = seen_per_contract[origin];
    auto [it, inserted] = seen.emplace(fun_ref->tvm_method_id, fun_ref);
    if (inserted) continue;
    FunctionPtr first = it->second;
    if (origin.empty()) {
      // legacy file-scope path: keep prior wording, no §3.5 reference
      err("GET methods hash collision: `{}` and `{}` produce the same method_id={}. Consider renaming one of these functions.",
          first, fun_ref, fun_ref->tvm_method_id).fire(fun_ref->ident_anchor);
    } else {
      char id_buf[16];
      std::snprintf(id_buf, sizeof(id_buf), "0x%x", static_cast<unsigned>(fun_ref->tvm_method_id));
      err("method_id collision: get fun `{}` (method_id {}) collides with get fun `{}` in contract `{}`; rename one or pin via @method_id(N); see doc/tos-language-syntax-policy.md §3.5",
          fun_ref->name, std::string(id_buf), first->name, origin).fire(fun_ref->ident_anchor);
    }
  }
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
          if (auto generated_function = generated_decl->try_as<ast_function_declaration>()) {
            generated_functions.push_back(generated_function);
          }
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
