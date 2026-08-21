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

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tol {

namespace {

static std::string to_string(std::string_view value) {
  return static_cast<std::string>(value);
}

static bool is_unknown_opcode_type_node(AnyTypeV type_node) {
  auto leaf = type_node ? type_node->try_as<ast_type_leaf_text>() : nullptr;
  return leaf && leaf->text == "UnknownOpcode";
}

static StructPtr resolve_struct_type_or_null(AnyTypeV type_node) {
  auto leaf = type_node ? type_node->try_as<ast_type_leaf_text>() : nullptr;
  if (!leaf) {
    return nullptr;
  }
  const Symbol* sym = G.symtable.lookup(leaf->text);
  return sym ? sym->try_as<StructPtr>() : nullptr;
}

static bool is_visible_unknown_policy(V<ast_contract_declaration> contract) {
  return contract->unknown_mode == ContractUnknownMode::silent_drop ||
         contract->unknown_mode == ContractUnknownMode::throw_code ||
         contract->unknown_mode == ContractUnknownMode::catch_all_receiver;
}

static std::string suppression_key(const std::string& message_name, const std::string& state_name) {
  return message_name + "\n" + state_name;
}

static void warn_implicit_unknown_policy(V<ast_contract_declaration> contract) {
  if (is_visible_unknown_policy(contract)) {
    return;
  }
  err("contract `{}` has no visible unknown-opcode policy; opcodes outside the declared receive map use the implicit Protocol throw. "
      "Declare `@unknown_throw(...)`, `@unknown_silent_drop`, or `receive(msg: UnknownOpcode)` to make Slice 3 receive exhaustiveness explicit. "
      "See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5 / https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tol.tex.",
      contract->get_identifier()->name)
    .warning(contract->get_identifier());
}

static void check_state_cross_product(V<ast_contract_declaration> contract) {
  struct MessageCoverage {
    std::string message_name;
    V<ast_receive_block> first_receive = nullptr;
    std::unordered_set<std::string> handled_states;
  };

  std::unordered_map<std::string, MessageCoverage> coverage_by_message;
  std::vector<std::string> message_order;
  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    if (receive->is_deploy || receive->is_unknown_opcode_catch_all || is_unknown_opcode_type_node(receive->message_type_node)) {
      continue;
    }
    StructPtr message_struct = resolve_struct_type_or_null(receive->message_type_node);
    if (!message_struct) {
      continue;
    }
    std::string message_name = message_struct->name;
    auto [it, inserted] = coverage_by_message.emplace(message_name, MessageCoverage{message_name, receive, {}});
    if (inserted) {
      message_order.push_back(message_name);
    }
    if (receive->has_state_clause()) {
      it->second.handled_states.insert(to_string(receive->get_state_name()));
    }
  }

  if (contract->implicit_protocol_default) {
    return;
  }

  std::unordered_set<std::string> suppressed_pairs;
  for (const ContractImplicitProtocolFor& suppression : contract->implicit_protocol_for) {
    suppressed_pairs.insert(suppression_key(suppression.message_name, suppression.state_name));
  }

  for (const std::string& message_name : message_order) {
    MessageCoverage& coverage = coverage_by_message.at(message_name);
    for (int state_i = 0; state_i < contract->get_num_states(); ++state_i) {
      std::string state_name = to_string(contract->get_state(state_i)->name);
      if (coverage.handled_states.count(state_name)) {
        continue;
      }
      if (suppressed_pairs.count(suppression_key(coverage.message_name, state_name))) {
        continue;
      }
      err("receive exhaustiveness warning: contract `{}` does not declare `receive(msg: {}) on {}`; "
          "the known opcode is accepted by the dispatch table but reaches the synthesized state guard and throws 1024 in that state. "
          "Add an explicit receiver, `@implicit_protocol_for({}, {});`, or `@implicit_protocol_default;` to document the implicit Protocol path. "
          "See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5 / https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tol.tex.",
          contract->get_identifier()->name, coverage.message_name, state_name, coverage.message_name, state_name)
        .warning(coverage.first_receive);
    }
  }
}

static void validate_implicit_protocol_suppressions(V<ast_contract_declaration> contract) {
  if (!contract->implicit_protocol_default && contract->implicit_protocol_for.empty()) {
    return;
  }
  if (!contract->has_state_machine()) {
    if (contract->implicit_protocol_default) {
      err("`@implicit_protocol_default` requires a state-bearing contract; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5")
        .fire(contract->implicit_protocol_default_range);
    }
    for (const ContractImplicitProtocolFor& suppression : contract->implicit_protocol_for) {
      err("`@implicit_protocol_for({}, {})` requires a state-bearing contract; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5",
          suppression.message_name, suppression.state_name)
        .fire(suppression.range);
    }
    return;
  }

  std::unordered_set<std::string> declared_states;
  for (int state_i = 0; state_i < contract->get_num_states(); ++state_i) {
    declared_states.insert(to_string(contract->get_state(state_i)->name));
  }

  std::unordered_set<std::string> declared_messages;
  for (int i = 0; i < contract->get_num_receives(); ++i) {
    V<ast_receive_block> receive = contract->get_receive(i);
    if (receive->is_deploy || receive->is_unknown_opcode_catch_all || is_unknown_opcode_type_node(receive->message_type_node)) {
      continue;
    }
    StructPtr message_struct = resolve_struct_type_or_null(receive->message_type_node);
    if (message_struct) {
      declared_messages.insert(message_struct->name);
    }
  }

  std::unordered_set<std::string> seen_pairs;
  for (const ContractImplicitProtocolFor& suppression : contract->implicit_protocol_for) {
    if (!declared_messages.count(suppression.message_name)) {
      err("`@implicit_protocol_for({}, {})` references message type `{}` that is not declared by any `receive(msg: ...)` in contract `{}`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5",
          suppression.message_name, suppression.state_name, suppression.message_name, contract->get_identifier()->name)
        .fire(suppression.range);
    }
    if (!declared_states.count(suppression.state_name)) {
      err("`@implicit_protocol_for({}, {})` references state `{}` that is not declared in contract `{}`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5",
          suppression.message_name, suppression.state_name, suppression.state_name, contract->get_identifier()->name)
        .fire(suppression.range);
    }
    std::string key = suppression_key(suppression.message_name, suppression.state_name);
    if (!seen_pairs.insert(key).second) {
      err("duplicate `@implicit_protocol_for({}, {})` suppression; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5",
          suppression.message_name, suppression.state_name)
        .fire(suppression.range);
    }
  }
}

static void check_contract(V<ast_contract_declaration> contract) {
  warn_implicit_unknown_policy(contract);
  validate_implicit_protocol_suppressions(contract);
  if (contract->has_state_machine()) {
    check_state_cross_product(contract);
  }
}

} // namespace

void pipeline_check_receive_exhaustiveness() {
  for (const SrcFile* file : G.all_src_files) {
    auto v_file = file->ast->as<ast_tol_file>();
    for (AnyV declaration : v_file->get_toplevel_declarations()) {
      if (auto contract = declaration->try_as<ast_contract_declaration>()) {
        check_contract(contract);
      }
    }
  }
}

} // namespace tol
