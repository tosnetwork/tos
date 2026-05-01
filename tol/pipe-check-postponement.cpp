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

#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tol {

namespace {

static std::string_view canonical_function_name(FunctionPtr fun_ref) {
  if (!fun_ref) {
    return {};
  }
  if (fun_ref->base_fun_ref && !fun_ref->base_fun_ref->name.empty()) {
    return fun_ref->base_fun_ref->name;
  }
  return fun_ref->name;
}

static bool is_struct_type(TypePtr type, std::string_view struct_name) {
  if (!type) {
    return false;
  }
  const auto* t_struct = type->unwrap_alias()->try_as<TypeDataStruct>();
  return t_struct && t_struct->struct_ref && t_struct->struct_ref->name == struct_name;
}

static bool is_postponed_queue_type(TypePtr type) {
  return is_struct_type(type, "PostponedQueue");
}

static bool is_postponed_item_type(TypePtr type) {
  return is_struct_type(type, "PostponedItem");
}

static bool is_raw_postponed_item_map_type(TypePtr type) {
  if (!type) {
    return false;
  }
  const auto* t_map = type->unwrap_alias()->try_as<TypeDataMapKV>();
  return t_map && is_postponed_item_type(t_map->TValue);
}

static bool is_postponed_queue_internal_field(std::string_view field_name) {
  return field_name == "nextNonce" ||
         field_name == "count" ||
         field_name == "totalBodyBits" ||
         field_name == "totalBodyRefs" ||
         field_name == "lastMeasuredCellDepth" ||
         field_name == "items" ||
         field_name == "queryIndex";
}

static bool is_postponed_queue_private_map_field(std::string_view field_name) {
  return field_name == "items" || field_name == "queryIndex";
}

static bool is_allowed_postponement_helper(FunctionPtr fun_ref) {
  const std::string_view name = canonical_function_name(fun_ref);
  return name == "slice4NewPostponedQueue" ||
         name == "slice4BuildPostponedItem" ||
         name == "PostponedQueue.requireCandidateDepth" ||
         name == "PostponedQueue.enqueue" ||
         name == "PostponedQueue.enqueueWithQueryId" ||
         name == "PostponedQueue.enqueueWithAuthorKey" ||
         name == "PostponedQueue.dropNonce" ||
         name == "PostponedQueue.peekFirst" ||
         name == "PostponedQueue.expireFirst" ||
         name == "PostponedQueue.drain";
}

static bool is_postponement_enqueue(FunctionPtr fun_ref) {
  const std::string_view name = canonical_function_name(fun_ref);
  return name == "PostponedQueue.enqueue" ||
         name == "PostponedQueue.enqueueWithQueryId" ||
         name == "PostponedQueue.enqueueWithAuthorKey";
}

static bool is_map_mutator(FunctionPtr fun_ref) {
  const std::string_view name = canonical_function_name(fun_ref);
  return name == "map<K,V>.set" ||
         name == "map<K,V>.setAndGetPrevious" ||
         name == "map<K,V>.replaceIfExists" ||
         name == "map<K,V>.replaceAndGetPrevious" ||
         name == "map<K,V>.addIfNotExists" ||
         name == "map<K,V>.addOrGetExisting" ||
         name == "map<K,V>.delete" ||
         name == "map<K,V>.deleteAndGetDeleted";
}

static V<ast_dot_access> as_dot_access(AnyExprV expr) {
  if (!expr) {
    return nullptr;
  }
  return expr->try_as<ast_dot_access>();
}

class CheckPostponementVisitor final : public ASTVisitorFunctionBody {
  std::unordered_map<FunctionPtr, std::vector<FunctionPtr>> call_graph;
  std::unordered_map<FunctionPtr, std::vector<V<ast_function_call>>> enqueue_sites;
  std::vector<FunctionPtr> external_entrypoints;

  void check_queue_field_write(AnyExprV lhs) {
    V<ast_dot_access> dot = as_dot_access(lhs);
    if (!dot) {
      return;
    }
    if (!is_postponed_queue_type(dot->get_obj()->inferred_type)) {
      return;
    }
    const std::string_view field_name = dot->get_field_name();
    if (!is_postponed_queue_internal_field(field_name) || is_allowed_postponement_helper(cur_f)) {
      return;
    }
    err("direct write to `PostponedQueue.{}` bypasses Slice 4 bounded-postponement accounting. "
        "Use `@stdlib/postponement` helpers (`enqueue*`, `dropNonce`, `expireFirst`, or `drain`) "
        "so item count, total body footprint, duplicate keys, and cell-depth budgets remain synchronized. "
        "See doc/tos-postponement-policy.md §8.", field_name)
      .collect(dot, cur_f);
  }

protected:
  void visit(V<ast_dot_access> v) override {
    const std::string_view field_name = v->get_field_name();
    if (is_postponed_queue_private_map_field(field_name) &&
        is_postponed_queue_type(v->get_obj()->inferred_type) &&
        !is_allowed_postponement_helper(cur_f)) {
      err("direct access to `PostponedQueue.{}` bypasses Slice 4 duplicate-key, FIFO, expiry, and budget accounting. "
          "Use `@stdlib/postponement` helpers instead. See doc/tos-postponement-policy.md §8.", field_name)
        .collect(v, cur_f);
    }
    parent::visit(v);
  }

  void visit(V<ast_assign> v) override {
    check_queue_field_write(v->get_lhs());
    parent::visit(v);
  }

  void visit(V<ast_set_assign> v) override {
    check_queue_field_write(v->get_lhs());
    parent::visit(v);
  }

  void visit(V<ast_function_call> v) override {
    FunctionPtr fun_ref = v->fun_maybe;
    if (cur_f && fun_ref && fun_ref->is_code_function()) {
      call_graph[cur_f].emplace_back(fun_ref);
    }
    if (cur_f && is_postponement_enqueue(fun_ref) && !is_allowed_postponement_helper(cur_f)) {
      enqueue_sites[cur_f].emplace_back(v);
    }

    AnyExprV self_obj = v->get_self_obj();
    if (is_map_mutator(fun_ref) &&
        self_obj &&
        is_raw_postponed_item_map_type(self_obj->inferred_type) &&
        !is_allowed_postponement_helper(cur_f)) {
      err("raw map-based postponement is warning-only for legacy code; stdlib/generated Slice 4 contracts must use "
          "`PostponedQueue.enqueue*`, `.dropNonce`, `.expireFirst`, or `.drain` so budgets, FIFO order, duplicate keys, "
          "and expiry accounting are enforced. See doc/tos-postponement-policy.md §8.")
        .warning(v, cur_f);
    }
    parent::visit(v);
  }

public:
  bool should_visit_function(FunctionPtr fun_ref) override {
    return fun_ref->is_code_function() && !fun_ref->is_generic_function();
  }

  void on_enter_function(V<ast_function_declaration> v_function) override {
    call_graph[cur_f] = {};
    if (cur_f->name == "onExternalMessage") {
      external_entrypoints.emplace_back(cur_f);
    }
    parent::on_enter_function(v_function);
  }

  void report_external_enqueue_paths() const {
    std::unordered_set<FunctionPtr> reachable;
    std::vector<FunctionPtr> stack = external_entrypoints;
    while (!stack.empty()) {
      FunctionPtr current = stack.back();
      stack.pop_back();
      if (!reachable.insert(current).second) {
        continue;
      }
      auto edge_it = call_graph.find(current);
      if (edge_it == call_graph.end()) {
        continue;
      }
      for (FunctionPtr next : edge_it->second) {
        if (next && !reachable.count(next)) {
          stack.emplace_back(next);
        }
      }
    }

    for (FunctionPtr fun_ref : reachable) {
      auto site_it = enqueue_sites.find(fun_ref);
      if (site_it == enqueue_sites.end()) {
        continue;
      }
      for (V<ast_function_call> site : site_it->second) {
        err("external-message postponement is not permitted in Slice 4 Stage 2; external signed bodies must be handled "
            "or rejected in the current transaction, not stored as postponed internal work. "
            "This check follows helper calls reachable from `onExternalMessage`. "
            "See doc/tos-postponement-policy.md §2 / §8.")
          .collect(site, fun_ref);
      }
    }
  }
};

} // namespace

void pipeline_check_postponement() {
  CheckPostponementVisitor visitor;
  visit_ast_of_all_functions(visitor);
  visitor.report_external_enqueue_paths();
}

} // namespace tol
