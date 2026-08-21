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
#include "ast-replacer.h"
#include "compilation-errors.h"
#include "compiler-state.h"
#include "pipeline.h"
#include "symtable.h"
#include "type-system.h"

#include <cstdio>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

/*
 *   Slice 2 Stage 6 — `require(...)` auto-numbering pass.
 *   See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.7 / §10.1.
 *
 *   Input AST (post-pipeline_lower_contracts):
 *     - 2-arg form: `require(cond, ErrorClass.X)` — auto-numbered here.
 *     - 3-arg form: `require(cond, ErrorClass.X, customCode)` — passes
 *       through unchanged (this is the explicit-code escape hatch).
 *
 *   Encoding (per task instruction, first-principles):
 *     - 24-bit derived error code packed into a 32-bit `__throw` operand.
 *     - top 8 bits = ErrorClass tag (matches the existing `enum ErrorClass: uint8`
 *       constants in `crypto/smartcont/tol-stdlib/common.tol`).
 *     - bottom 16 bits = per-(contract, ErrorClass) site index, source-order.
 *     - first occurrence of a class within a contract → site_index 0.
 *     - the formula is `(class << 16) | site_index`.
 *     - the lower-1024 reservation in `https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-message-policy.md §5.2` is
 *       respected: any non-Ok class tag (>=1) puts the resulting code at
 *       >= 0x10000, which is far above 1023.
 *
 *   The pass is registered after `pipeline_lower_contracts()` so it sees
 *   the synthesized `onInternalMessage` / `onExternalMessage` bodies, and
 *   before `pipeline_check_query_id_propagation()` so the query-id pass
 *   sees the final form.
 *
 *   Debug manifest: a textual side-table is built and emitted as a
 *   `;; require_site_table` comment in the generated Fif by
 *   `pipe-generate-fif-output.cpp`. Each entry is
 *     (contract_name, ErrorClass tag name, site_index, derived_code, source_location)
 *   so external dev tooling (`tonscan`, bounce-replay scripts) can recover
 *   which of two same-class sites in the same contract actually fired.
 */

namespace tol {

// Singleton manifest (definition is in pipeline.h). Populated by the pass;
// consumed (read-only) by `pipe-generate-fif-output.cpp` to emit the
// `;; require_site_table` comment.
static std::vector<RequireSiteEntry> g_require_site_manifest;

const std::vector<RequireSiteEntry>& get_require_site_manifest() {
  return g_require_site_manifest;
}

namespace {

// Bucket key: (contract_name, error_class_tag).
// Per-bucket counter is the next site_index to assign in source order.
struct BucketKey {
  std::string contract;
  int tag;
  bool operator==(const BucketKey& o) const { return tag == o.tag && contract == o.contract; }
};
struct BucketKeyHash {
  size_t operator()(const BucketKey& k) const noexcept {
    return std::hash<std::string>{}(k.contract) ^ (static_cast<size_t>(k.tag) * 1099511628211ULL);
  }
};

// Look up the integer value of an `ErrorClass.X` enum-member dot-access. Returns -1
// if the expression is not a recognized enum-member reference.
static int extract_error_class_tag(AnyExprV expr, std::string* class_name_out) {
  // unwrap ast_argument
  if (expr->kind == ast_argument) {
    expr = expr->as<ast_argument>()->get_expr();
  }
  if (expr->kind != ast_dot_access) {
    return -1;
  }
  auto v_dot = expr->as<ast_dot_access>();
  if (v_dot->get_obj()->kind != ast_reference) {
    return -1;
  }
  auto v_ref = v_dot->get_obj()->as<ast_reference>();
  if (v_ref->get_name() != "ErrorClass") {
    return -1;
  }
  std::string_view member = v_dot->get_field_name();
  // Look up the symbol -> EnumDefPtr -> member by name.
  const Symbol* sym = G.symtable.lookup("ErrorClass");
  if (!sym) {
    return -1;
  }
  EnumDefPtr enum_ref = sym->try_as<EnumDefPtr>();
  if (!enum_ref) {
    return -1;
  }
  for (EnumMemberPtr m : enum_ref->members) {
    if (m->name == member) {
      if (class_name_out) {
        *class_name_out = static_cast<std::string>(member);
      }
      // ErrorClass declares explicit integer values 0..5; computed_value carries the resolved
      // integer regardless of whether the source used `Red = 1` or implicit indexing.
      if (!m->computed_value.is_null()) {
        return static_cast<int>(m->computed_value->to_long());
      }
      return m->member_idx;
    }
  }
  return -1;
}

// Build a new ast_argument wrapping an int literal whose inferred_type is Int.
// The wrapper itself also gets inferred_type = Int (matches what type inference
// would assign to a literal argument). The SrcRange anchors the literal to the
// `require(...)` call site so source-mapping in the codegen output matches.
static V<ast_argument> make_int_argument(SrcRange range, int64_t value) {
  auto v_int = createV<ast_int_const>(range, td::make_refint(value), "");
  v_int->mutate()->assign_inferred_type(TypeDataInt::create());
  auto v_arg = createV<ast_argument>(range, static_cast<AnyExprV>(v_int), false);
  v_arg->mutate()->assign_inferred_type(TypeDataInt::create());
  return v_arg;
}

class AssignRequireCodesReplacer final : public ASTReplacerInFunctionBody {
  std::unordered_map<BucketKey, int, BucketKeyHash> next_site_index;
  std::string current_contract_name;   // origin of cur_f, "" for non-synthesized
  std::string current_function_name;

protected:
  AnyExprV replace(V<ast_function_call> v) override {
    // descend first so nested calls are processed in source order; the
    // outer call's third-argument int literal is built from already-known
    // metadata, so children rewrites don't perturb the bucket index for
    // the outer call. replace_children mutates in-place and returns v.
    replace_children(v);
    auto v_call = v;
    FunctionPtr fun_ref = v_call->fun_maybe;
    if (!fun_ref || fun_ref->name != "require") {
      return v_call;
    }

    int n_args = v_call->get_num_args();
    // 2-arg form: rewrite to 3-arg with the auto-numbered code.
    // 3-arg form: register manifest entry but leave AST alone.
    auto v_arg_ec = v_call->get_arg(1);
    std::string class_name;
    int tag = extract_error_class_tag(v_arg_ec, &class_name);
    if (tag < 0) {
      // Not a recognizable ErrorClass.X; leave the call alone (typechecker
      // already accepted whatever was passed). This keeps the pass benign
      // on hand-rolled enum aliases.
      return v_call;
    }

    if (n_args >= 3) {
      // 3-arg form: pass through, but record in manifest for tooling.
      RequireSiteEntry entry;
      entry.contract_name = current_contract_name;
      entry.function_name = current_function_name;
      entry.error_class_name = class_name;
      entry.error_class_tag = tag;
      entry.site_index = -1;
      entry.derived_code = -1;
      entry.source_location = v_call->range.stringify_start_location(false);
      entry.explicit_code = true;
      entry.explicit_code_value = -1;
      auto v_arg_code = v_call->get_arg(2);
      AnyExprV code_expr = v_arg_code->kind == ast_argument
          ? v_arg_code->as<ast_argument>()->get_expr()
          : v_arg_code;
      if (code_expr->kind == ast_int_const) {
        auto v_int = code_expr->as<ast_int_const>();
        if (!v_int->intval.is_null()) {
          entry.explicit_code_value = static_cast<int>(v_int->intval->to_long());
        }
      }
      g_require_site_manifest.push_back(std::move(entry));
      return v_call;
    }

    // 2-arg form: derive code, build new arg list, build new call.
    BucketKey key{current_contract_name, tag};
    int site_index = next_site_index[key]++;
    int64_t derived_code = (static_cast<int64_t>(tag) << 16) | static_cast<int64_t>(site_index & 0xFFFF);

    std::vector<AnyExprV> new_args;
    new_args.reserve(3);
    new_args.push_back(v_call->get_arg(0));
    new_args.push_back(v_call->get_arg(1));
    new_args.push_back(make_int_argument(v_call->range, derived_code));

    auto v_arg_list = v_call->get_arg_list();
    auto new_arg_list = createV<ast_argument_list>(v_arg_list->range, std::move(new_args));
    new_arg_list->mutate()->assign_inferred_type(v_arg_list->inferred_type);

    auto new_call = createV<ast_function_call>(v_call->range, v_call->get_callee(), new_arg_list);
    new_call->mutate()->assign_fun_ref(fun_ref, v_call->dot_obj_is_self);
    new_call->mutate()->assign_inferred_type(v_call->inferred_type);

    RequireSiteEntry entry;
    entry.contract_name = current_contract_name;
    entry.function_name = current_function_name;
    entry.error_class_name = class_name;
    entry.error_class_tag = tag;
    entry.site_index = site_index;
    entry.derived_code = static_cast<int>(derived_code);
    entry.source_location = v_call->range.stringify_start_location(false);
    entry.explicit_code = false;
    entry.explicit_code_value = 0;
    g_require_site_manifest.push_back(std::move(entry));

    return new_call;
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    // Visit every non-builtin function; require() may appear anywhere.
    // Free functions outside contracts get bucket "" — their codes are still
    // unique within that bucket, and a downstream tool can disambiguate by
    // (function_name, source_location) via the manifest.
    if (fun_ref->is_builtin() || fun_ref->is_asm_function()) {
      return false;
    }
    return true;
  }

  void on_enter_function(V<ast_function_declaration> v_function) override {
    current_function_name = static_cast<std::string>(cur_f->name);
    std::string_view origin = contract_origin_of_synthesized_function(cur_f);
    current_contract_name = static_cast<std::string>(origin);
  }
};

} // namespace

void pipeline_assign_require_codes() {
  AssignRequireCodesReplacer replacer;
  replace_ast_of_all_functions(replacer);
}

} // namespace tol
