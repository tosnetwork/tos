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
#include "type-system.h"
#include "constant-evaluator.h"
#include "td/utils/crypto.h"

/*
 *   This pipe checks that expressions expected to be constant, are actually constant.
 *   For example, `const a = 2 + 3` is okay, but `const a = foo()` is not.
 *   For example, field defaults and parameters defaults are also required to be constant.
 *
 *   Also, this pipe calculates and assigns values for every `enum` members.
 */

namespace tol {

static ConstValExpression unwrap_const_cast_local(ConstValExpression val) {
  while (const ConstValCastToType* val_cast = std::get_if<ConstValCastToType>(&val)) {
    val = val_cast->inner.front();
  }
  return val;
}

static int get_fixed_width_for_struct_opcode(AnyExprV v_opcode) {
  if (auto v_lit = v_opcode->try_as<ast_int_const>()) {
    std::string_view prefix_str = v_lit->orig_str;
    if (prefix_str.starts_with("0x")) {
      return static_cast<int>(prefix_str.size() - 2) * 4;
    }
    if (prefix_str.starts_with("0b")) {
      return static_cast<int>(prefix_str.size() - 2);
    }
    err("struct opcode literal must use `0x...` or `0b...`").fire(v_opcode);
  }

  TypePtr opcode_type = v_opcode->inferred_type ? v_opcode->inferred_type->unwrap_alias() : nullptr;
  if (const auto* t_intN = opcode_type ? opcode_type->try_as<TypeDataIntN>() : nullptr) {
    if (!t_intN->is_variadic) {
      return t_intN->n_bits;
    }
  }
  if (const auto* t_enum = opcode_type ? opcode_type->try_as<TypeDataEnum>() : nullptr) {
    TypePtr enum_storage = t_enum->enum_ref->colon_type ? t_enum->enum_ref->colon_type->unwrap_alias() : nullptr;
    if (const auto* t_intN = enum_storage ? enum_storage->try_as<TypeDataIntN>() : nullptr) {
      if (!t_intN->is_variadic) {
        return t_intN->n_bits;
      }
    }
  }

  err("struct opcode constant must have fixed-width type; use `OP as uint32` or declare `const OP: uint32 = ...`").fire(v_opcode);
}

static void resolve_struct_opcode_constant(StructPtr struct_ref) {
  auto v_struct = struct_ref->ast_root->as<ast_struct_declaration>();
  if (!v_struct->has_opcode()) {
    return;
  }

  AnyExprV v_opcode = v_struct->get_opcode();
  int prefix_len = get_fixed_width_for_struct_opcode(v_opcode);
  ConstValExpression opcode_val = unwrap_const_cast_local(eval_expression_if_const_or_fire(v_opcode));
  const ConstValInt* opcode_int = std::get_if<ConstValInt>(&opcode_val);
  if (!opcode_int) {
    err("struct opcode constant must be an integer").fire(v_opcode);
  }
  if (prefix_len <= 0 || prefix_len > 48) {
    err("opcode must not exceed 2^48").fire(v_opcode);
  }
  if (opcode_int->int_val < 0 || !opcode_int->int_val->unsigned_fits_bits(prefix_len)) {
    err("struct opcode constant does not fit into {} bits", prefix_len).fire(v_opcode);
  }
  struct_ref->mutate()->opcode = StructData::PackOpcode(opcode_int->int_val->to_long(), prefix_len);
}

static int calculate_method_id_from_name(std::string_view method_name) {
  unsigned int crc = td::crc16(static_cast<std::string>(method_name));
  return static_cast<int>(crc & 0xffff) | 0x10000;
}

static void resolve_function_method_id_constant(FunctionPtr fun_ref) {
  auto v_func = fun_ref->ast_root->as<ast_function_declaration>();
  if (!v_func->has_tvm_method_id_expr()) {
    return;
  }

  AnyExprV v_method_id = v_func->get_tvm_method_id_expr();
  ConstValExpression method_id_val = unwrap_const_cast_local(eval_expression_if_const_or_fire(v_method_id));
  if (const ConstValInt* method_id_int = std::get_if<ConstValInt>(&method_id_val)) {
    if (method_id_int->int_val.is_null() || !method_id_int->int_val->signed_fits_bits(32)) {
      err("invalid integer constant").fire(v_method_id);
    }
    fun_ref->mutate()->tvm_method_id = static_cast<int>(method_id_int->int_val->to_long());
    return;
  }
  if (const ConstValString* method_id_str = std::get_if<ConstValString>(&method_id_val)) {
    fun_ref->mutate()->tvm_method_id = calculate_method_id_from_name(method_id_str->str_val);
    return;
  }

  err("@method_id expects an integer constant or a string method name").fire(v_method_id);
}

class ConstantExpressionsChecker final : public ASTVisitorFunctionBody {

  void visit(V<ast_function_call> v) override {
    // check `tos("0.05")` and others for correctness (not `tos(local_var)`, etc.)
    if (v->fun_maybe && v->fun_maybe->is_compile_time_const_val()) {
      // on invalid usage, this call will fire
      eval_expression_if_const_or_fire(v);
      // note that in AST tree, it's still left as `tos("0.05")`, `stringCrc32("...")`, etc.
      // later, when transforming to IR, such compile-time functions are handled specially
    }

    parent::visit(v);
  }

 void visit(V<ast_match_arm> v) override {
    // check `2 + 3 => ...` (before =>)
    // non-constant expressions like `foo() => ...` fire an error here
    if (v->pattern_kind == MatchArmKind::const_expression) {
      check_expression_is_constant_or_fire(v->get_pattern_expr());
    }

    parent::visit(v);
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function() && !fun_ref->is_generic_function();
  }
};

void pipeline_check_constant_expressions() {
  // here (after type inferring) check that `const a = 2 + 3` is a valid constant expression
  // non-constant expressions like `const a = foo()` fire an error here
  for (GlobalConstPtr const_ref : get_all_declared_constants()) {
    eval_and_cache_const_init_val(const_ref);
  }
  // do the same for default values of struct fields, they must be constant expressions
  for (StructPtr struct_ref : get_all_declared_structs()) {
    for (StructFieldPtr field_ref : struct_ref->fields) {
      if (field_ref->has_default_value() && !struct_ref->is_generic_struct()) {
        check_expression_is_constant_or_fire(field_ref->default_value);
      }
    }
  }
  // Parameter defaults are evaluated at the call site, after identifier
  // resolution and type inference. They may call helper functions (for example,
  // a fixture address constructor) and therefore are intentionally not part of
  // the compile-time-constant surface.
  
  // assign `enum` members values (either auto-compute sequentially or use manual initializers)
  for (EnumDefPtr enum_ref : get_all_declared_enums()) {
    std::vector<td::RefInt256> values = calculate_enum_members_with_values(enum_ref);
    for (EnumMemberPtr member_ref : enum_ref->members) {
      member_ref->mutate()->assign_computed_value(values[member_ref->member_idx]);
    }
  }

  for (StructPtr struct_ref : get_all_declared_structs()) {
    if (!struct_ref->is_generic_struct()) {
      resolve_struct_opcode_constant(struct_ref);
    }
  }
  for (FunctionPtr fun_ref : get_all_not_builtin_functions()) {
    if (!fun_ref->is_generic_function()) {
      resolve_function_method_id_constant(fun_ref);
    }
  }

  ConstantExpressionsChecker visitor;
  visit_ast_of_all_functions(visitor);
}

} // namespace tol
