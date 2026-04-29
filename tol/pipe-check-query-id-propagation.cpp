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

/*
 *   This pipe enforces the §4.4 query_id propagation rule from
 *   doc/tos-message-policy.md (v4):
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
 *   sign-off-blocking per v4.
 *
 *   Slice 1 ships this skeleton wired in; the actual propagation
 *   analysis is a follow-up (TODO at the visit site).
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

class CheckQueryIdPropagationVisitor final : public ASTVisitorFunctionBody {

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function()
        && !fun_ref->is_generic_function()
        && is_onInternalMessage(fun_ref);
  }

  void on_enter_function(V<ast_function_declaration> v_function) override {
    // TODO(slice-1): implement query_id propagation check per
    // doc/tos-message-policy.md §4.4. Skeleton-only for now —
    // `error_collector.collect(...)` wiring is in place
    // (G.error_collector is non-null at this pipeline stage),
    // and no diagnostics are emitted yet.
    (void)v_function;
  }
};

void pipeline_check_query_id_propagation() {
  CheckQueryIdPropagationVisitor visitor;
  visit_ast_of_all_functions(visitor);
}

} // namespace tol
