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
#include "type-system.h"

namespace tol {

namespace {

static bool is_slice3_pending_reply_table_type(TypePtr type) {
  if (!type) {
    return false;
  }
  const auto* t_struct = type->unwrap_alias()->try_as<TypeDataStruct>();
  return t_struct && t_struct->struct_ref && t_struct->struct_ref->name == "Slice3PendingReplyTable";
}

static bool is_allowed_slice3_pending_reply_helper(FunctionPtr fun_ref) {
  if (!fun_ref) {
    return false;
  }
  return fun_ref->name == "Slice3PendingReplyTable.reserve" ||
         fun_ref->name == "Slice3PendingReplyTable.consume" ||
         fun_ref->name == "Slice3PendingReplyTable.ignoreDuplicate";
}

class CheckSlice3ReplyCorrelationVisitor final : public ASTVisitorFunctionBody {
protected:
  void visit(V<ast_dot_access> v) override {
    if (v->get_field_name() == "entries" &&
        is_slice3_pending_reply_table_type(v->get_obj()->inferred_type) &&
        !is_allowed_slice3_pending_reply_helper(cur_f)) {
      err("direct access to `Slice3PendingReplyTable.entries` bypasses `(expected_responder, query_id)` reply binding "
          "and duplicate-reply consumption. Use `Slice3PendingReplyTable.reserve(...)`, `.consume(...)`, or `.ignoreDuplicate(...)` "
          "so Slice 3 manifest-backed reply APIs delete or mark a reply before user-visible side effects. "
          "See doc/tos-message-policy.md §4.4 / doc/tos-language-syntax-policy.md §5.")
        .collect(v, cur_f);
    }
    parent::visit(v);
  }

  void visit(V<ast_function_call> v) override {
    FunctionPtr fun_ref = v->fun_maybe;
    if (fun_ref && fun_ref->name == "slice3PendingReplyKeyHash" &&
        !is_allowed_slice3_pending_reply_helper(cur_f)) {
      err("raw Slice 3 reply-key construction is warning-only for legacy code; manifest-backed stdlib reply APIs must use "
          "`Slice3PendingReplyTable.reserve(...)` / `.consume(...)` so the key includes `(expected_responder, query_id)` "
          "and optional `expected_reply_opcode`. See doc/tos-message-policy.md §4.4 / doc/tos-language-syntax-policy.md §5.")
        .warning(v, cur_f);
    }
    parent::visit(v);
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function() && !fun_ref->is_generic_function();
  }
};

} // namespace

void pipeline_check_slice3_reply_correlation() {
  CheckSlice3ReplyCorrelationVisitor visitor;
  visit_ast_of_all_functions(visitor);
}

} // namespace tol
