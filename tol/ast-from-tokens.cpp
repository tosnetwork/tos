/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "ast.h"
#include "compilation-errors.h"
#include "type-system.h"
#include "tol-version.h"

/*
 *   Here we construct AST for a tol file.
 *   While constructing, no global state is modified.
 *   Historically, in FunC, there was no AST: while lexing, symbols were registered, types were inferred, and so on.
 * There was no way to perform any more or less semantic analysis.
 *   Implementing AST gives a giant advance for future modifications and stability.
 */

namespace tol {

// given a token, determine whether it's <, or >, or similar
static bool is_comparison_binary_op(TokenType tok) {
  return tok == tok_lt || tok == tok_gt || tok == tok_leq || tok == tok_geq || tok == tok_eq || tok == tok_neq || tok == tok_spaceship;
}

// same as above, but to detect bitwise operators: & | ^
static bool is_bitwise_binary_op(TokenType tok) {
  return tok == tok_bitwise_and || tok == tok_bitwise_or || tok == tok_bitwise_xor;
}

// same as above, but to detect logical operators: && ||
static bool is_logical_binary_op(TokenType tok) {
  return tok == tok_logical_and || tok == tok_logical_or;
}

// same as above, but to detect addition/subtraction
static bool is_add_or_sub_binary_op(TokenType tok) {
  return tok == tok_plus || tok == tok_minus;
}

// make an error for a case "flags & 0xFF != 0" (equivalent to "flags & 1", probably unexpected)
// it would better be a warning, but we decided to make it a strict error
static Error err_lower_precedence(std::string_view op_lower, std::string_view op_higher) {
  return err("{} has lower precedence than {}"
              ", probably this code won't work as you expected.  "
              "Use parentheses: either (... {} ...) to evaluate it first, or (... {} ...) to suppress this error.",
              op_lower, op_higher, op_lower, op_higher);
}

// make an error for a case "arg1 & arg2 | arg3"
static Error err_mix_and_or_no_parenthesis(std::string_view op1, std::string_view op2) {
  return err("mixing {} with {} without parentheses may lead to accidental errors.  "
              "Use parentheses to emphasize operator precedence.",
              op1, op2);
}

// make an error "Tol does not have ++i operator"
static Error err_no_increment_operator() {
  return err("Tol has no increment operator\n""hint: use `i += 1`, not `i++`");
}

// make an error "Tol does not have --i operator"
static Error err_no_decrement_operator() {
  return err("Tol has no decrement operator\n""hint: use `i -= 1`, not `i--`");
}

// diagnose when bitwise operators are used in a probably wrong way due to tricky precedence
// example: "flags & 0xFF != 0" is equivalent to "flags & 1", most likely it's unexpected
// the only way to suppress this error for the programmer is to use parentheses
// (how do we detect presence of parentheses? by checking `vertex->was_parenthesized` flag)
static void diagnose_bitwise_precedence(SrcRange range, std::string_view operator_name, AnyExprV lhs, AnyExprV rhs) {
  // handle "flags & 0xFF != 0" (rhs = "0xFF != 0")
  if (auto rhs_op = rhs->try_as<ast_binary_operator>(); rhs_op && !rhs->was_parenthesized) {
    if (is_comparison_binary_op(rhs_op->tok)) {
      err_lower_precedence(operator_name, rhs_op->operator_name).fire(range);
    }
  }

  // handle "0 != flags & 0xFF" (lhs = "0 != flags")
  if (auto lhs_op = lhs->try_as<ast_binary_operator>(); lhs_op && !lhs->was_parenthesized) {
    if (is_comparison_binary_op(lhs_op->tok)) {
      err_lower_precedence(operator_name, lhs_op->operator_name).fire(range);
    }
  }
}

// similar to above, but detect potentially invalid usage of && and ||
// since anyway, using parentheses when both && and || occur in the same expression,
// && and || have equal operator precedence in Tol
static void diagnose_and_or_precedence(SrcRange range, AnyExprV lhs, TokenType rhs_tok, std::string_view rhs_operator_name) {
  if (auto lhs_op = lhs->try_as<ast_binary_operator>(); lhs_op && !lhs->was_parenthesized) {
    // handle "arg1 & arg2 | arg3" (lhs = "arg1 & arg2")
    if (is_bitwise_binary_op(lhs_op->tok) && is_bitwise_binary_op(rhs_tok) && lhs_op->tok != rhs_tok) {
      err_mix_and_or_no_parenthesis(lhs_op->operator_name, rhs_operator_name).fire(range);
    }

    // handle "arg1 && arg2 || arg3" (lhs = "arg1 && arg2")
    if (is_logical_binary_op(lhs_op->tok) && is_logical_binary_op(rhs_tok) && lhs_op->tok != rhs_tok) {
      err_mix_and_or_no_parenthesis(lhs_op->operator_name, rhs_operator_name).fire(range);
    }
  }
}

// diagnose "a << 8 + 1" (equivalent to "a << 9", probably unexpected)
static void diagnose_addition_in_bitshift(SrcRange range, std::string_view bitshift_operator_name, AnyExprV rhs) {
  if (auto rhs_op = rhs->try_as<ast_binary_operator>(); rhs_op && !rhs->was_parenthesized) {
    if (is_add_or_sub_binary_op(rhs_op->tok)) {
      err_lower_precedence(bitshift_operator_name, rhs_op->operator_name).fire(range);
    }
  }
}

// replace (a == null) and similar to ast_is_type_operator(a, null) (as if `a is null` was written)
static AnyExprV maybe_replace_eq_null_with_isNull_check(V<ast_binary_operator> v) {
  bool lhs_is_null = v->get_lhs()->kind == ast_null_keyword;
  bool rhs_is_null = v->get_rhs()->kind == ast_null_keyword;
  bool replace = (lhs_is_null || rhs_is_null) && (v->tok == tok_eq || v->tok == tok_neq);
  if (!replace) {
    return v;
  }

  AnyExprV v_null_kw = lhs_is_null ? v->get_lhs() : v->get_rhs();
  AnyExprV v_nullable = lhs_is_null ? v->get_rhs() : v->get_lhs();
  AnyTypeV rhs_null_type = createV<ast_type_leaf_text>(v_null_kw->range, "null");
  return createV<ast_is_type_operator>(v->range, v_nullable, rhs_null_type, v->tok == tok_neq);
}

static std::string strip_numeric_separators(std::string_view text) {
  std::string result;
  result.reserve(text.size());
  for (char c : text) {
    if (c != '_') {
      result += c;
    }
  }
  return result;
}

// parse `123` / `0xFF` / `0b10001` to td::RefInt256
static td::RefInt256 parse_tok_int_const(std::string_view text, SrcRange cur_range) {
  bool bin = text.size() >= 2 && text[0] == '0' && text[1] == 'b';
  if (!bin) {
    // this function parses decimal and hex numbers
    td::RefInt256 intval = td::string_to_int256(strip_numeric_separators(text));
    if (intval.is_null() || !intval->signed_fits_bits(257)) {
      err("invalid integer constant").fire(cur_range);
    }
    return intval;
  }
  // parse a binary number; to make it simpler, don't allow too long numbers, it's impractical
  uint64_t result = 0;
  int n_digits = 0;
  for (char c : text.substr(2)) { // skip "0b"
    if (c == '_') {
      continue;
    }
    ++n_digits;
    if (n_digits > 64) {
      err("invalid binary integer").fire(cur_range);
    }
    result = (result << 1) | static_cast<uint64_t>(c - '0');
  }
  if (n_digits == 0) {
    err("invalid binary integer").fire(cur_range);
  }
  return td::make_refint(result);
}

// parse and un-escape a string token; for text `"with\"quotes"`, return `with"quotes`: just contents
static std::string parse_tok_string_const(std::string_view text, SrcRange cur_range) {
  // trim surrounding quotes
  int trim_n = text.starts_with(R"(""")") ? 3 : 1;    // multi-line literal: 3 quotes outside
  text = text.substr(trim_n, text.size() - 2 * trim_n);
  if (text.size() >= 32768) {
    err("too long string literal").fire(cur_range);
  }
  // unescape contents within
  std::string unescaped;
  unescaped.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '\r' && text[i + 1] == '\n') {   // normalize CRLF line endings to LF
      unescaped += '\n';
      ++i;
      continue;
    }
    if (text[i] != '\\') {
      unescaped += text[i];
      continue;
    }
    switch (text[++i]) {
      case 'n':  unescaped += '\n'; break;
      case 'r':  unescaped += '\r'; break;
      case 't':  unescaped += '\t'; break;
      case '\\': unescaped += '\\'; break;
      case '\'': unescaped += '\''; break;
      case '"':  unescaped += '"';  break;
      default:
        err("invalid escape sequence \\{}", std::string_view(&text[i], 1)).fire(cur_range);
    }
  }
  return unescaped;
}

// when we meet `(expr)` in parentheses, we keep `expr` in AST,
// but mark it with a boolean flag `was_parenthesized` (used for precedence diagnostics)
// and extend its range to include outer parentheses (for underline in error messages)
// (previously we had ast_parenthesized_expression which caused bugs when forgotten to handle)
static AnyExprV create_parenthesized_expression(SrcRange parens_range, AnyExprV v_in_parens) {
  // okay to use const_cast — we inject into existing vertex instead of creating a new one
  const_cast<SrcRange&>(v_in_parens->mutate()->range) = parens_range;
  v_in_parens->mutate()->was_parenthesized = true;
  return v_in_parens;
}



// --------------------------------------------
//    parsing type from tokens
//
// here we implement parsing types (mostly after colon) to AnyTypeV
// example: `var v: int` is leaf "int"
// example: `var v: (User?, [cell])` is tensor(nullable(leaf "User"), brackets(leaf "cell"))
//
// later, after all symbols are registered, types are resolved to TypePtr, see pipe-resolve-types.cpp
//

static AnyTypeV parse_type_expression(Lexer& lex);

static std::vector<AnyTypeV> parse_nested_type_list(Lexer& lex, TokenType tok_op, const char* s_op, TokenType tok_cl, const char* s_cl, SrcRange& out_range) {
  lex.expect(tok_op, s_op);
  std::vector<AnyTypeV> sub_types;
  while (true) {
    if (lex.tok() == tok_cl) {  // empty lists allowed
      out_range.end(lex.cur_range());
      lex.next();
      break;
    }

    sub_types.emplace_back(parse_type_expression(lex));
    if (lex.tok() == tok_comma) {
      lex.next();
    } else if (lex.tok() != tok_cl) {
      // overcome the `>>` problem, like `Wrapper<Wrapper<int>>`:
      // treat token `>>` like two `>`; consume one here doing nothing (break) and leave the second `>` in a lexer
      if (tok_cl == tok_gt && lex.tok() == tok_rshift) {
        lex.hack_replace_rshift_with_one_triangle();
        out_range.end(lex.cur_range());
        break;
      }
      lex.unexpected(s_cl);
    }
  }
  return sub_types;
}

static AnyTypeV parse_simple_type(Lexer& lex) {
  switch (lex.tok()) {
    case tok_self:
    case tok_identifier:
    case tok_contract:
    case tok_receive:
    case tok_receive_external:
    case tok_storage:
    case tok_null: {
      SrcRange range = lex.cur_range();
      std::string_view text = lex.cur_str();
      lex.next();
      return createV<ast_type_leaf_text>(range, text);
    }
    case tok_oppar: {
      SrcRange range = lex.range_start();
      std::vector tensor_items = parse_nested_type_list(lex, tok_oppar, "`(`", tok_clpar, "`)` or `,`", range);
      return createV<ast_type_parenthesis_tensor>(range, std::move(tensor_items));
    }
    case tok_opbracket: {
      SrcRange range = lex.range_start();
      std::vector shaped_items = parse_nested_type_list(lex, tok_opbracket, "`[`", tok_clbracket, "`]` or `,`", range);
      return createV<ast_type_brackets_shape>(range, std::move(shaped_items));
    }
    default:
      lex.unexpected("<type>");
  }
}

static AnyTypeV parse_type_nullable(Lexer& lex) {
  AnyTypeV result = parse_simple_type(lex);

  if (lex.tok() == tok_lt) {    // T1<T2, T3, ...>
    SrcRange range = SrcRange::empty_at_start(result->range);
    auto args = parse_nested_type_list(lex, tok_lt, "`<`", tok_gt, "`>` or `,`", range);
    std::vector<AnyTypeV> outer_and_args;
    outer_and_args.reserve(1 + args.size());
    outer_and_args.push_back(result);
    outer_and_args.insert(outer_and_args.end(), args.begin(), args.end());
    result = createV<ast_type_triangle_args>(range, std::move(outer_and_args));
  }

  if (lex.tok() == tok_question) {
    SrcRange range = SrcRange::overlap(result->range, lex.cur_range());
    lex.next();
    result = createV<ast_type_question_nullable>(range, result);
  }

  return result;
}

static AnyTypeV parse_type_expression(Lexer& lex) {
  if (lex.tok() == tok_bitwise_or) {    // allow leading `|`, like in TypeScript
    lex.next();
  }
  AnyTypeV result = parse_type_nullable(lex);

  if (lex.tok() == tok_bitwise_or) {  // `int | slice`, `Pair2 | (Pair3 | null)`
    std::vector<AnyTypeV> items;
    items.emplace_back(result);
    while (lex.tok() == tok_bitwise_or) {
      lex.next();
      items.emplace_back(parse_type_nullable(lex));
    }
    SrcRange range = SrcRange::overlap(items.front()->range, items.back()->range);
    result = createV<ast_type_vertical_bar_union>(range, std::move(items));
  }

  if (lex.tok() == tok_arrow) {   // `int -> int`, `(cell, slice) -> void`, `int -> int -> int`, `int | cell -> void`
    lex.next();
    std::vector<AnyTypeV> params_and_return;
    if (auto p_tensor = result->try_as<ast_type_parenthesis_tensor>()) {
      params_and_return.reserve(p_tensor->get_items().size());
      params_and_return.insert(params_and_return.begin(), p_tensor->get_items().begin(), p_tensor->get_items().end());
    } else {
      params_and_return.reserve(2);
      params_and_return.push_back(result);
    }
    params_and_return.push_back(parse_type_expression(lex));
    SrcRange range = SrcRange::overlap(params_and_return.front()->range, params_and_return.back()->range);
    result = createV<ast_type_arrow_callable>(range, std::move(params_and_return));
  }

  return result;
}

static AnyTypeV parse_type_from_tokens(Lexer& lex) {
  return parse_type_expression(lex);
}



// --------------------------------------------
//    parsing expressions and statements
//


AnyExprV parse_expr(Lexer& lex);
AnyV parse_statement(Lexer& lex, bool in_contract_receive = false);

static bool is_identifier_like(TokenType tok) {
  return tok == tok_identifier || tok == tok_contract || tok == tok_receive || tok == tok_receive_external || tok == tok_storage;
}

static V<ast_identifier> parse_identifier(Lexer& lex, const char* str_expected) {
  if (!is_identifier_like(lex.tok())) {
    lex.unexpected(str_expected);
  }
  SrcRange range = lex.cur_range();
  std::string_view name = lex.cur_str();
  lex.next();
  return createV<ast_identifier>(range, name);
}

static V<ast_genericsT_item> parse_genericsT_item(Lexer& lex) {
  lex.check(tok_identifier, "T");
  SrcRange rangeT = lex.cur_range();
  std::string_view nameT = lex.cur_str();
  lex.next();
  AnyTypeV default_type = nullptr;
  if (lex.tok() == tok_assign) {          // <T = int?>
    lex.next();
    default_type = parse_type_expression(lex);
    rangeT.end(default_type->range);
  }
  return createV<ast_genericsT_item>(rangeT, nameT, default_type);
}

static V<ast_genericsT_list> parse_genericsT_list(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_lt, "`<`");
  std::vector<AnyV> genericsT_items(1, parse_genericsT_item(lex));
  while (lex.tok() == tok_comma) {
    lex.next();
    if (lex.tok() == tok_gt) {   // trailing comma
      break;
    }
    genericsT_items.push_back(parse_genericsT_item(lex));
  }

  lex.check(tok_gt, "`>`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_genericsT_list>(range, std::move(genericsT_items));
}

static AnyV parse_parameter(Lexer& lex, AnyTypeV self_type, bool in_lambda) {
  SrcRange range = lex.range_start();

  // optional keyword `mutate` meaning that a function will mutate a passed argument (like passed by reference)
  bool declared_as_mutate = false;
  if (lex.tok() == tok_mutate) {
    if (in_lambda) {
      lex.error("`mutate` is not available in lambdas");
    }
    lex.next();
    declared_as_mutate = true;
  }

  // parameter name (or underscore for an unnamed parameter)
  V<ast_identifier> v_ident = nullptr;
  bool is_self = false;
  if (is_identifier_like(lex.tok())) {
    v_ident = parse_identifier(lex, "parameter name");
  } else if (lex.tok() == tok_self) {
    if (!self_type) {
      lex.error("`self` can only be the first parameter of a method");
    }
    is_self = true;
    v_ident = createV<ast_identifier>(lex.cur_range(), "self");
    lex.next();
  } else if (lex.tok() == tok_underscore) {
    v_ident = createV<ast_identifier>(lex.cur_range(), "");
    lex.next();
  } else {
    lex.unexpected("parameter name");
  }
  range.end(v_ident->range);

  // parameter type after colon is mandatory in declarations, but optional for lambdas
  AnyTypeV param_type = self_type;
  if (lex.tok() == tok_colon) {
    if (is_self) {
      err("`self` parameter should not have a type").fire(v_ident);
    }
    lex.next();
    param_type = parse_type_from_tokens(lex);
    range.end(param_type->range);
  } else if (!is_self && !in_lambda) {
    err("specify a type for a parameter: `{}: <type>`", v_ident->name).fire(v_ident);
  }

  // optional default value
  AnyExprV default_value = nullptr;
  if (lex.tok() == tok_assign && !is_self) {      // `a: int = 0`
    if (declared_as_mutate) {
      lex.error("`mutate` parameter can't have a default value");
    }
    lex.next();
    default_value = parse_expr(lex);
    range.end(default_value->range);
  }

  return createV<ast_parameter>(range, v_ident, param_type, default_value, declared_as_mutate);
}

static AnyV parse_global_var_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.range_start();
  lex.expect(tok_global, "`global`");
  auto v_ident = parse_identifier(lex, "global variable name");
  lex.expect(tok_colon, "`:`");
  AnyTypeV declared_type = parse_type_from_tokens(lex);
  range.end(declared_type->range);
  if (lex.tok() == tok_comma) {
    lex.error("multiple declarations are not allowed, split globals on separate lines");
  }
  if (lex.tok() == tok_assign) {
    lex.error("assigning to a global is not allowed at declaration");
  }

  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::custom:
        break;
      default:
        err("this annotation is not applicable to global").fire(v_annotation);
    }
  }

  return createV<ast_global_var_declaration>(range, v_ident, declared_type);
}

static AnyV parse_constant_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.range_start();
  lex.expect(tok_const, "`const`");
  auto v_ident = parse_identifier(lex, "constant name");
  AnyTypeV declared_type = nullptr;
  if (lex.tok() == tok_colon) {
    lex.next();
    declared_type = parse_type_from_tokens(lex);
  }
  lex.expect(tok_assign, "`=`");
  AnyExprV init_value = parse_expr(lex);
  if (lex.tok() == tok_comma) {
    lex.error("multiple declarations are not allowed, split constants on separate lines");
  }

  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::custom:
        break;
      default:
        err("this annotation is not applicable to constant").fire(v_annotation);
    }
  }

  range.end(init_value->range);
  return createV<ast_constant_declaration>(range, v_ident, declared_type, init_value);
}

static AnyV parse_type_alias_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.range_start();
  lex.expect(tok_type, "`type`");
  auto v_ident = parse_identifier(lex, "type name");

  V<ast_genericsT_list> genericsT_list = nullptr;
  if (lex.tok() == tok_lt) {    // 'type Response<TResult, TError>'
    genericsT_list = parse_genericsT_list(lex);
  }

  lex.expect(tok_assign, "`=`");
  if (lex.tok() == tok_builtin) {   // type map<K, V> = builtin
    range.end(lex.cur_range());
    lex.next();
    return createV<ast_empty_statement>(range);
  }

  AnyTypeV underlying_type = parse_type_from_tokens(lex);
  range.end(underlying_type->range);

  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::custom:
        break;
      default:
        err("this annotation is not applicable to type alias").fire(v_annotation);
    }
  }

  return createV<ast_type_alias_declaration>(range, v_ident, genericsT_list, underlying_type);
}

static AnyExprV parse_var_declaration_lhs(Lexer& lex, bool is_immutable, bool allow_lateinit) {
  if (lex.tok() == tok_oppar) {
    SrcRange range = lex.range_start();
    lex.next();
    AnyExprV first = parse_var_declaration_lhs(lex, is_immutable, false);
    if (lex.tok() == tok_clpar) {
      lex.next();
      return first;
    }
    std::vector<AnyExprV> args(1, first);
    while (lex.tok() == tok_comma) {
      lex.next();
      if (lex.tok() == tok_clpar) {     // trailing comma
        break;
      }
      args.push_back(parse_var_declaration_lhs(lex, is_immutable, false));
    }
    lex.check(tok_clpar, "`)`");
    range.end(lex.cur_range());
    lex.next();
    return createV<ast_tensor>(range, std::move(args));
  }
  if (lex.tok() == tok_opbracket) {
    SrcRange range = lex.range_start();
    lex.next();
    std::vector<AnyExprV> args(1, parse_var_declaration_lhs(lex, is_immutable, false));
    while (lex.tok() == tok_comma) {
      lex.next();
      if (lex.tok() == tok_clbracket) {     // trailing comma
        break;
      }
      args.push_back(parse_var_declaration_lhs(lex, is_immutable, false));
    }
    lex.check(tok_clbracket, "`]`");
    range.end(lex.cur_range());
    lex.next();
    return createV<ast_square_brackets>(range, std::move(args), nullptr);
  }
  if (is_identifier_like(lex.tok())) {
    SrcRange range = lex.range_start();
    auto v_ident = parse_identifier(lex, "variable name");
    range.end(v_ident->range);
    AnyTypeV declared_type = nullptr;
    bool is_lateinit = false;
    if (lex.tok() == tok_colon) {
      lex.next();
      declared_type = parse_type_from_tokens(lex);
      range.end(declared_type->range);
    }
    if (lex.tok() == tok_semicolon && allow_lateinit) {
      if (declared_type == nullptr) {
        lex.error("provide a type for a variable, because its default value is omitted:\n> var " + static_cast<std::string>(v_ident->name) + ": <type>;");
      }
      is_lateinit = true;
    }
    return createV<ast_local_var_lhs>(range, v_ident, declared_type, is_immutable, is_lateinit);
  }
  if (lex.tok() == tok_underscore) {
    SrcRange range = lex.cur_range();
    AnyTypeV declared_type = nullptr;
    lex.next();
    if (lex.tok() == tok_colon) {
      lex.next();
      declared_type = parse_type_from_tokens(lex);
      range.end(declared_type->range);
    }
    return createV<ast_local_var_lhs>(range, createV<ast_identifier>(range, ""), declared_type, true, false);
  }
  lex.unexpected("variable name");
}

static AnyExprV parse_local_vars_declaration(Lexer& lex, bool allow_lateinit) {
  SrcRange range = lex.range_start();
  bool is_immutable = lex.tok() == tok_val;
  lex.next();

  AnyExprV lhs = parse_var_declaration_lhs(lex, is_immutable, allow_lateinit);
  if (lex.tok() != tok_assign) {
    if (auto lhs_var = lhs->try_as<ast_local_var_lhs>(); lhs_var && lhs_var->is_lateinit) {
      return lhs;   // just ast_local_var_lhs inside AST tree
    }
    lex.error("variables declaration must be followed by assignment: `var xxx = ...`");
  }
  lex.next();
  AnyExprV rhs = parse_expr(lex);

  if (lex.tok() == tok_comma) {
    lex.error("multiple declarations are not allowed, split variables on separate lines");
  }
  range.end(rhs->range);
  return createV<ast_assign>(range, createV<ast_local_vars_declaration>(range, lhs), rhs);
}

// "parameters" are at function declaration: `fun f(param1: int, mutate param2: slice)`
// for methods like `fun builder.storeUint(self, i: int)`, receiver_type = builder (type of self)
static V<ast_parameter_list> parse_parameter_list(Lexer& lex, AnyTypeV receiver_type, bool in_lambda) {
  SrcRange range = lex.range_start();
  std::vector<AnyV> params;
  lex.expect(tok_oppar, "parameter list");
  if (lex.tok() != tok_clpar) {
    params.push_back(parse_parameter(lex, receiver_type, in_lambda));
    while (lex.tok() == tok_comma) {
      lex.next();
      if (lex.tok() == tok_clpar) {     // trailing comma
        break;
      }
      params.push_back(parse_parameter(lex, nullptr, in_lambda));
    }
  }
  lex.check(tok_clpar, "`)`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_parameter_list>(range, std::move(params));
}

// "arguments" are at function call: `f(arg1, mutate arg2)`
static AnyExprV parse_argument(Lexer& lex) {
  SrcRange range = lex.range_start();

  // keyword `mutate` is necessary when a parameter is declared `mutate` (to make mutation obvious for the reader)
  bool passed_as_mutate = false;
  if (lex.tok() == tok_mutate) {
    lex.next();
    passed_as_mutate = true;
  }

  AnyExprV expr = parse_expr(lex);
  range.end(expr->range);
  return createV<ast_argument>(range, expr, passed_as_mutate);
}

static V<ast_argument_list> parse_argument_list(Lexer& lex) {
  SrcRange range = lex.range_start();
  std::vector<AnyExprV> args;
  lex.expect(tok_oppar, "`(`");
  if (lex.tok() != tok_clpar) {
    args.push_back(parse_argument(lex));
    while (lex.tok() == tok_comma) {
      lex.next();
      if (lex.tok() == tok_clpar) {   // trailing comma
        break;
      }
      args.push_back(parse_argument(lex));
    }
  }

  lex.check(tok_clpar, "`)`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_argument_list>(range, std::move(args));
}

static V<ast_instantiationT_list> parse_maybe_instantiationTs_after_identifier(Lexer& lex) {
  lex.check(tok_lt, "`<`");
  Lexer::SavedPositionForLookahead backup = lex.save_parsing_position();
  try {
    SrcRange range = lex.range_start();
    lex.next();
    std::vector<AnyV> instantiationTs;
    AnyTypeV type_node = parse_type_from_tokens(lex);
    instantiationTs.push_back(createV<ast_instantiationT_item>(type_node->range, type_node));
    while (lex.tok() == tok_comma) {
      lex.next();
      type_node = parse_type_from_tokens(lex);
      instantiationTs.push_back(createV<ast_instantiationT_item>(type_node->range, type_node));
    }
    lex.check(tok_gt, "`>`");
    range.end(lex.cur_range());
    lex.next();
    return createV<ast_instantiationT_list>(range, std::move(instantiationTs));
  } catch (const ThrownParseError&) {
    lex.restore_position(backup);
    return nullptr;
  }
}

static V<ast_block_statement> parse_block_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_opbrace, "`{`");
  std::vector<AnyV> items;
  while (lex.tok() != tok_clbrace) {
    AnyV v = parse_statement(lex, in_contract_receive);
    items.push_back(v);
    if (lex.tok() == tok_clbrace) {
      break;
    }
    bool does_end_with_brace =
             v->kind == ast_if_statement || v->kind == ast_while_statement || v->kind == ast_match_expression
          || v->kind == ast_try_catch_statement || v->kind == ast_repeat_statement || v->kind == ast_block_statement;
    if (!does_end_with_brace) {
      lex.expect(tok_semicolon, "`;`");
    }
  }
  lex.check(tok_clbrace, "`}`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_block_statement>(range, std::move(items));
}

static V<ast_object_field> parse_object_field(Lexer& lex) {
  SrcRange range = lex.range_start();
  if (lex.tok() == tok_ellipsis) {
    lex.next();
    AnyExprV spread_expr = parse_expr(lex);
    range.end(spread_expr->range);
    return createV<ast_object_field>(range, spread_expr);
  }

  auto v_ident = parse_identifier(lex, "field name");
  range.end(v_ident->range);

  if (lex.tok() == tok_comma || lex.tok() == tok_clbrace) {
    auto v_same_ident = createV<ast_identifier>(v_ident->range, v_ident->name);
    auto v_same_expr = createV<ast_reference>(v_ident->range, v_same_ident, nullptr);
    return createV<ast_object_field>(range, v_ident, v_same_expr);
  }

  lex.expect(tok_colon, "`:`");
  AnyExprV init_val = parse_expr(lex);
  range.end(init_val->range);
  return createV<ast_object_field>(range, v_ident, init_val);
}

static V<ast_object_body> parse_object_body(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_opbrace, "`{`");

  std::vector<AnyExprV> fields;
  while (lex.tok() != tok_clbrace) {
    fields.push_back(parse_object_field(lex));
    if (lex.tok() == tok_comma) {
      lex.next();
    } else if (lex.tok() != tok_clbrace) {
      lex.unexpected("`,`");
    }
  }

  lex.check(tok_clbrace, "`}`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_object_body>(range, std::move(fields));
}

static V<ast_square_brackets> parse_square_brackets(Lexer& lex, AnyTypeV type_node) {
  SrcRange range = lex.range_start();
  lex.next();
  if (lex.tok() == tok_clbracket) {
    range.end(lex.cur_range());
    lex.next();
    return createV<ast_square_brackets>(range, {}, type_node);
  }

  std::vector<AnyExprV> items(1, parse_expr(lex));
  while (lex.tok() == tok_comma) {
    lex.next();
    if (lex.tok() == tok_clbracket) {   // trailing comma
      break;
    }
    items.emplace_back(parse_expr(lex));
  }
  lex.check(tok_clbracket, "`]`");

  range.end(lex.cur_range());
  lex.next();
  return createV<ast_square_brackets>(range, std::move(items), type_node);
}

// `throw code` / `throw (code)` / `throw (code, arg)`
// it's technically a statement (can't occur "in any place of expression"),
// but inside `match` arm it can appear without semicolon: `pattern => throw 123`
static AnyV parse_throw_expression(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_throw, "`throw`");

  AnyExprV thrown_code, thrown_arg;
  if (lex.tok() == tok_oppar) {   // throw (code) or throw (code, arg)
    lex.next();
    thrown_code = parse_expr(lex);
    if (lex.tok() == tok_comma) {
      lex.next();
      thrown_arg = parse_expr(lex);
    } else {
      thrown_arg = createV<ast_empty_expression>(SrcRange::empty_at_start(range));
    }
    lex.check(tok_clpar, "`)`");
    range.end(lex.cur_range());
    lex.next();
  } else {   // throw code
    thrown_code = parse_expr(lex);
    range.end(thrown_code->range);
    thrown_arg = createV<ast_empty_expression>(SrcRange::empty_at_start(range));
  }

  return createV<ast_throw_statement>(range, thrown_code, thrown_arg);
}

// `pattern => body` inside `match`
static V<ast_match_arm> parse_match_arm(Lexer& lex) {
  SrcRange range = lex.range_start();
  MatchArmKind pattern_kind = static_cast<MatchArmKind>(-1);
  AnyTypeV exact_type = nullptr;
  AnyExprV pattern_expr = nullptr;

  Lexer::SavedPositionForLookahead backup = lex.save_parsing_position();
  try {
    exact_type = parse_type_from_tokens(lex);
    pattern_kind = MatchArmKind::exact_type;
  } catch (const ThrownParseError&) {
  }
  if (!exact_type || lex.tok() != tok_double_arrow) {
    exact_type = nullptr;
    pattern_kind = static_cast<MatchArmKind>(-1);
    lex.restore_position(backup);
    try {
      pattern_expr = parse_expr(lex);
      pattern_kind = MatchArmKind::const_expression;    // any expr at parsing, should result in const int/bool
    } catch (const ThrownParseError&) {
    }
  }
  if (!exact_type && !pattern_expr && lex.tok() == tok_else) {
    lex.next();
    pattern_kind = MatchArmKind::else_branch;
  }

  if (pattern_kind == static_cast<MatchArmKind>(-1)) {
    lex.restore_position(backup);
    lex.error("expected <type> or <expression> in `match` before `=>`");
  }
  lex.expect(tok_double_arrow, "`=>`");

  V<ast_block_statement> v_block = nullptr;
  if (lex.tok() == tok_opbrace) {       // `1 => { ... }`
    v_block = parse_block_statement(lex);
  } else try {                          // `1 => x + y` and other expressions
    AnyExprV inner_expr = parse_expr(lex);
    v_block = createV<ast_block_statement>(inner_expr->range, {createV<ast_braced_yield_result>(inner_expr->range, inner_expr)});
  } catch (const ThrownParseError&) {   // `1 => throw 123` and other statements (without semicolon!)
    AnyV inner_stmt = parse_statement(lex);
    v_block = createV<ast_block_statement>(inner_stmt->range, {inner_stmt});
  }
  auto body = createV<ast_braced_expression>(v_block->range, v_block);

  range.end(body->range);
  if (pattern_expr == nullptr) {  // for match by type / default case, empty vertex, not nullptr
    pattern_expr = createV<ast_empty_expression>(SrcRange::span(range, 4));
  }
  return createV<ast_match_arm>(range, pattern_kind, exact_type, pattern_expr, body);
}

static V<ast_match_expression> parse_match_expression(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_match, "`match`");

  lex.expect(tok_oppar, "`(`");
  AnyExprV subject = lex.tok() == tok_var || lex.tok() == tok_val       // `match (var x = rhs)`
                ? parse_local_vars_declaration(lex, false)
                : parse_expr(lex);
  lex.expect(tok_clpar, "`)`");

  std::vector<AnyExprV> subject_and_arms = {subject};
  lex.expect(tok_opbrace, "`{`");
  while (lex.tok() != tok_clbrace) {
    auto v_arm = parse_match_arm(lex);
    subject_and_arms.push_back(v_arm);

    // after `pattern => { ... }` comma is optional, after `pattern => expr` mandatory
    bool was_comma = lex.tok() == tok_comma;    // trailing comma is allowed always
    bool was_unbraced = v_arm->get_body()->get_block_statement()->size() == 1 && v_arm->get_body()->get_block_statement()->get_item(0)->kind == ast_braced_yield_result;
    if (was_comma) {
      lex.next();
    }
    if (lex.tok() == tok_clbrace) {
      break;
    }
    if (!was_comma && was_unbraced) {
      lex.unexpected("`,`");
    }
  }

  lex.check(tok_clbrace, "`}`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_match_expression>(range, std::move(subject_and_arms));
}

static V<ast_lambda_fun> parse_lambda_fun_expression(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_fun, "`fun`");
  
  V<ast_parameter_list> v_param_list = parse_parameter_list(lex, nullptr, true);

  AnyTypeV ret_type = nullptr;
  if (lex.tok() == tok_colon) {   // fun(...): <ret_type>
    lex.next();
    ret_type = parse_type_from_tokens(lex);
  }

  auto v_body = parse_block_statement(lex);
  range.end(v_body->range);
  return createV<ast_lambda_fun>(range, v_param_list, v_body, ret_type); 
}

static V<ast_lazy_operator> parse_lazy_operator(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_lazy, "`lazy`");

  AnyExprV expr = parse_expr(lex);
  range.end(expr->range);
  return createV<ast_lazy_operator>(range, expr);
}

// parse (expr) / [expr] / identifier / number
static AnyExprV parse_expr100(Lexer& lex) {
  switch (lex.tok()) {
    case tok_oppar: {
      SrcRange range = lex.range_start();
      lex.next();
      if (lex.tok() == tok_clpar) {
        range.end(lex.cur_range());
        lex.next();
        return createV<ast_tensor>(range, {});
      }
      AnyExprV first = parse_expr(lex);
      if (lex.tok() == tok_clpar) {
        range.end(lex.cur_range());
        lex.next();
        return create_parenthesized_expression(range, first);
      }
      std::vector<AnyExprV> items(1, first);
      while (lex.tok() == tok_comma) {
        lex.next();
        if (lex.tok() == tok_clpar) {   // trailing comma
          break;
        }
        items.emplace_back(parse_expr(lex));
      }
      lex.check(tok_clpar, "`)`");
      range.end(lex.cur_range());
      lex.next();
      if (items.size() == 1) {
        return create_parenthesized_expression(range, items[0]);  // treat `(item,)` like `(item)`
      }
      return createV<ast_tensor>(range, std::move(items));
    }
    case tok_opbracket: {           // `[1, 2]` (not `array<int> [1, 2]`)
      return parse_square_brackets(lex, nullptr);
    }
    case tok_int_const: {
      SrcRange range = lex.cur_range();
      std::string_view orig_str = lex.cur_str();
      td::RefInt256 intval = parse_tok_int_const(orig_str, lex.cur_range());
      lex.next();
      return createV<ast_int_const>(range, std::move(intval), orig_str);
    }
    case tok_string_const: {
      SrcRange range = lex.cur_range();
      std::string_view orig_str = lex.cur_str();  // with surrounding quotes and non-escaped symbols
      lex.next();
      return createV<ast_string_const>(range, parse_tok_string_const(orig_str, range));
    }
    case tok_underscore: {
      SrcRange range = lex.cur_range();
      lex.next();
      return createV<ast_underscore>(range);
    }
    case tok_true: {
      SrcRange range = lex.cur_range();
      lex.next();
      return createV<ast_bool_const>(range, true);
    }
    case tok_false: {
      SrcRange range = lex.cur_range();
      lex.next();
      return createV<ast_bool_const>(range, false);
    }
    case tok_null: {
      SrcRange range = lex.cur_range();
      lex.next();
      return createV<ast_null_keyword>(range);
    }
    case tok_self: {
      SrcRange range = lex.cur_range();
      lex.next();
      auto v_ident = createV<ast_identifier>(range, "self");
      return createV<ast_reference>(range, v_ident, nullptr);
    }
    case tok_identifier:
    case tok_contract:
    case tok_receive:
    case tok_receive_external:
    case tok_storage: {
      auto v_ident = parse_identifier(lex, "identifier");
      SrcRange range = v_ident->range;
      V<ast_instantiationT_list> v_instantiationTs = nullptr;
      if (lex.tok() == tok_lt) {
        v_instantiationTs = parse_maybe_instantiationTs_after_identifier(lex);
        if (v_instantiationTs) {
          range.end(v_instantiationTs->range);
        }
      }
      if (lex.tok() == tok_opbrace || lex.tok() == tok_opbracket) {     // `Pair { ... }` or `array [ ... ]`
        AnyTypeV type_node = createV<ast_type_leaf_text>(v_ident->range, v_ident->name);  // `Pair { ... }`
        if (v_instantiationTs) {                                                          // `Pair<int> { ... }`
          std::vector<AnyTypeV> ident_and_args;
          ident_and_args.reserve(1 + v_instantiationTs->size());
          ident_and_args.push_back(type_node);
          for (int i = 0; i < v_instantiationTs->size(); ++i) {
            ident_and_args.push_back(v_instantiationTs->get_item(i)->type_node);
          }
          SrcRange tri_range = SrcRange::overlap(v_ident->range, v_instantiationTs->range);
          type_node = createV<ast_type_triangle_args>(tri_range, std::move(ident_and_args));
        }
        if (lex.tok() == tok_opbracket) {       // `array<int> []` / `lisp_list<int> [ 1,2,3 ]`
          return parse_square_brackets(lex, type_node);
        }
        auto body = parse_object_body(lex);
        range.end(body->range);
        return createV<ast_object_literal>(range, type_node, body);
      }
      return createV<ast_reference>(range, v_ident, v_instantiationTs);
    }
    case tok_opbrace: {
      auto body = parse_object_body(lex);
      return createV<ast_object_literal>(body->range, nullptr, body);
    }
    case tok_match:
      return parse_match_expression(lex);
    case tok_fun:
      return parse_lambda_fun_expression(lex);
    case tok_lazy:
      return parse_lazy_operator(lex);
    default:
      lex.unexpected("<expression>");
  }
}

// parse E(...) / E! / E++ / E-- having parsed E already (left-to-right)
static AnyExprV parse_fun_call_postfix(Lexer& lex, AnyExprV lhs) {
  while (true) {
    if (lex.tok() == tok_oppar) {
      auto argument_list = parse_argument_list(lex);
      SrcRange range = SrcRange::overlap(lhs->range, argument_list->range);
      lhs = createV<ast_function_call>(range, lhs, argument_list);
    } else if (lex.tok() == tok_logical_not) {
      SrcRange range = SrcRange::overlap(lhs->range, lex.cur_range());
      lex.next();
      lhs = createV<ast_not_null_operator>(range, lhs);
    } else if (lex.tok() == tok_double_plus || lex.tok() == tok_double_minus) {
      lex.tok() == tok_double_plus ? err_no_increment_operator().fire(lex.cur_range()) : err_no_decrement_operator().fire(lex.cur_range());
    } else {
      break;
    }
  }
  return lhs;
}

// parse E(...) and E! (left-to-right)
static AnyExprV parse_expr90(Lexer& lex) {
  AnyExprV res = parse_expr100(lex);
  if (lex.tok() == tok_oppar || lex.tok() == tok_logical_not || lex.tok() == tok_double_plus || lex.tok() == tok_double_minus) {
    res = parse_fun_call_postfix(lex, res);
  }
  return res;
}

// parse E.field and E.method(...) and E.field! (left-to-right)
static AnyExprV parse_expr80(Lexer& lex) {
  AnyExprV lhs = parse_expr90(lex);
  while (lex.tok() == tok_dot) {
    SrcRange range(lhs->range);
    lex.next();
    V<ast_identifier> v_ident = nullptr;
    V<ast_instantiationT_list> v_instantiationTs = nullptr;
    if (is_identifier_like(lex.tok())) {    // obj.field / obj.method
      v_ident = parse_identifier(lex, "field name");
      range.end(v_ident->range);
      if (lex.tok() == tok_lt) {          // obj.method<int>
        v_instantiationTs = parse_maybe_instantiationTs_after_identifier(lex);
        if (v_instantiationTs) {
          range.end(v_instantiationTs->range);
        }
      }
    } else if (lex.tok() == tok_int_const) {  // obj.0 (indexed access)
      SrcRange idx_range = lex.cur_range();
      std::string_view idx_name = lex.cur_str();
      v_ident = createV<ast_identifier>(idx_range, idx_name);
      range.end(v_ident->range);
      lex.next();
    } else {
      lex.unexpected("method name");
    }
    lhs = createV<ast_dot_access>(range, lhs, v_ident, v_instantiationTs);
    if (lex.tok() == tok_oppar || lex.tok() == tok_logical_not || lex.tok() == tok_double_plus || lex.tok() == tok_double_minus) {
      lhs = parse_fun_call_postfix(lex, lhs);
    }
  }
  return lhs;
}

// parse ! ~ - + E (unary)
static AnyExprV parse_expr75(Lexer& lex) {
  TokenType t = lex.tok();
  if (t == tok_logical_not || t == tok_bitwise_not || t == tok_minus || t == tok_plus) {
    SrcRange range = lex.range_start();
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr75(lex);
    range.end(rhs->range);

    // convert `-1` to `int(-1)`, not to a tree `unary(-) > int(1)` right here 
    if (auto rhs_int = rhs->try_as<ast_int_const>(); rhs_int && (t == tok_minus || t == tok_plus)) {
      td::RefInt256 intval = rhs_int->intval;
      tol_assert(!intval.is_null());
      if (t == tok_minus) {
        intval = -intval; // negation (and multiple consecutive negations) always fits 257 bits if originally fits
      }
      return createV<ast_int_const>(range, std::move(intval), rhs_int->orig_str);
    }
    return createV<ast_unary_operator>(range, operator_range, operator_name, t, rhs);
  }
  if (t == tok_double_minus || t == tok_double_plus) {
    SrcRange range = lex.cur_range();
    lex.next();
    parse_expr75(lex);
    t == tok_double_plus ? err_no_increment_operator().fire(range) : err_no_decrement_operator().fire(range);
  }
  return parse_expr80(lex);
}

// parse E as / is / !is <type> (left-to-right)
static AnyExprV parse_expr40(Lexer& lex) {
  AnyExprV lhs = parse_expr75(lex);
  TokenType t = lex.tok();
  while (t == tok_as || t == tok_is) {
    lex.next();
    AnyTypeV rhs_type = parse_type_from_tokens(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs_type->range);
    if (t == tok_as) {
      lhs = createV<ast_cast_as_operator>(range, lhs, rhs_type);
    } else {
      // detect `a !is T`, which is parsed as `a! is T` (lhs = `a!`), don't confuse with `(a!) is T`
      bool is_negated = lhs->kind == ast_not_null_operator && !lhs->was_parenthesized;
      if (is_negated) {
        lhs = lhs->as<ast_not_null_operator>()->get_expr();
      }
      lhs = createV<ast_is_type_operator>(range, lhs, rhs_type, is_negated);
    }
    t = lex.tok();
  }
  return lhs;
}

// parse E * / % ^/ ~/ E (left-to-right)
static AnyExprV parse_expr30(Lexer& lex) {
  AnyExprV lhs = parse_expr40(lex);
  TokenType t = lex.tok();
  while (t == tok_mul || t == tok_div || t == tok_mod || t == tok_divC || t == tok_divR) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr40(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    t = lex.tok();
  }
  return lhs;
}

// parse E + - E (left-to-right)
static AnyExprV parse_expr20(Lexer& lex) {
  AnyExprV lhs = parse_expr30(lex);
  TokenType t = lex.tok();
  while (t == tok_minus || t == tok_plus) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr30(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    t = lex.tok();
  }
  return lhs;
}

// parse E << >> ~>> ^>> E (left-to-right)
static AnyExprV parse_expr17(Lexer& lex) {
  AnyExprV lhs = parse_expr20(lex);
  TokenType t = lex.tok();
  while (t == tok_lshift || t == tok_rshift || t == tok_rshiftC || t == tok_rshiftR) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr20(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    diagnose_addition_in_bitshift(range, operator_name, rhs);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    t = lex.tok();
  }
  return lhs;
}

// parse E == < > <= >= != <=> E (left-to-right)
static AnyExprV parse_expr15(Lexer& lex) {
  AnyExprV lhs = parse_expr17(lex);
  TokenType t = lex.tok();
  if (t == tok_eq || t == tok_lt || t == tok_gt || t == tok_leq || t == tok_geq || t == tok_neq || t == tok_spaceship) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr17(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    if (t == tok_eq || t == tok_neq) {
      lhs = maybe_replace_eq_null_with_isNull_check(lhs->as<ast_binary_operator>());
    }
  }
  return lhs;
}

// parse E & | ^ E (left-to-right)
static AnyExprV parse_expr14(Lexer& lex) {
  AnyExprV lhs = parse_expr15(lex);
  TokenType t = lex.tok();
  while (t == tok_bitwise_and || t == tok_bitwise_or || t == tok_bitwise_xor) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr15(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    diagnose_bitwise_precedence(range, operator_name, lhs, rhs);
    diagnose_and_or_precedence(range, lhs, t, operator_name);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    t = lex.tok();
  }
  return lhs;
}

// parse E && || E (left-to-right)
static AnyExprV parse_expr13(Lexer& lex) {
  AnyExprV lhs = parse_expr14(lex);
  TokenType t = lex.tok();
  while (t == tok_logical_and || t == tok_logical_or) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str();
    lex.next();
    AnyExprV rhs = parse_expr14(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    diagnose_and_or_precedence(range, lhs, t, operator_name);
    lhs = createV<ast_binary_operator>(range, operator_range, operator_name, t, lhs, rhs);
    t = lex.tok();
  }
  return lhs;
}

// parse E = += -= E and E ? E : E and E ?? E (right-to-left)
static AnyExprV parse_expr10(Lexer& lex) {
  AnyExprV lhs = parse_expr13(lex);
  TokenType t = lex.tok();
  if (t == tok_assign) {
    lex.next();
    AnyExprV rhs = parse_expr10(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    return createV<ast_assign>(range, lhs, rhs);
  }
  if (t == tok_set_plus || t == tok_set_minus || t == tok_set_mul || t == tok_set_div ||
      t == tok_set_mod || t == tok_set_lshift || t == tok_set_rshift ||
      t == tok_set_bitwise_and || t == tok_set_bitwise_or || t == tok_set_bitwise_xor) {
    SrcRange operator_range = lex.cur_range();
    std::string_view operator_name = lex.cur_str().substr(0, lex.cur_str().size() - 1);   // "+" for +=
    lex.next();
    AnyExprV rhs = parse_expr10(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    return createV<ast_set_assign>(range, operator_range, operator_name, t, lhs, rhs);
  }
  if (t == tok_question) {
    lex.next();
    AnyExprV when_true = parse_expr10(lex);
    lex.expect(tok_colon, "`:`");
    AnyExprV when_false = parse_expr10(lex);
    SrcRange range = SrcRange::overlap(lhs->range, when_false->range);
    return createV<ast_ternary_operator>(range, lhs, when_true, when_false);
  }
  if (t == tok_double_question) {
    lex.next();
    AnyExprV rhs = parse_expr10(lex);
    SrcRange range = SrcRange::overlap(lhs->range, rhs->range);
    return createV<ast_null_coalesce_operator>(range, lhs, rhs);
  }
  return lhs;
}

AnyExprV parse_expr(Lexer& lex) {
  return parse_expr10(lex);
}

static AnyV parse_return_statement(Lexer& lex) {
  lex.check(tok_return, "`return`");
  SrcRange range = lex.cur_range();
  lex.next();

  AnyExprV child = nullptr;
  if (lex.tok() == tok_semicolon || lex.tok() == tok_clbrace) {
    child = createV<ast_empty_expression>(SrcRange::empty_at_end(range));
  } else {
    child = parse_expr(lex);
    range.end(child->range);
  }
  return createV<ast_return_statement>(range, child);
}

static AnyV parse_if_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_if, "`if`");

  lex.expect(tok_oppar, "`(`");
  AnyExprV cond = parse_expr(lex);
  lex.expect(tok_clpar, "`)`");

  V<ast_block_statement> if_body = parse_block_statement(lex, in_contract_receive);
  V<ast_block_statement> else_body = nullptr;
  if (lex.tok() == tok_else) {  // else if(e) { } or else { }
    lex.next();
    if (lex.tok() == tok_if) {
      AnyV v_inner_if = parse_if_statement(lex, in_contract_receive);
      else_body = createV<ast_block_statement>(v_inner_if->range, {v_inner_if});
    } else {
      else_body = parse_block_statement(lex, in_contract_receive);
    }
  } else {  // no 'else', create empty block
    else_body = createV<ast_block_statement>(SrcRange::empty_at_end(if_body->range), {});
  }
  range.end(else_body->range);
  return createV<ast_if_statement>(range, false, cond, if_body, else_body);
}

static AnyV parse_repeat_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_repeat, "`repeat`");
  lex.expect(tok_oppar, "`(`");
  AnyExprV cond = parse_expr(lex);
  lex.expect(tok_clpar, "`)`");
  V<ast_block_statement> body = parse_block_statement(lex, in_contract_receive);
  range.end(body->range);
  return createV<ast_repeat_statement>(range, cond, body);
}

static AnyV parse_while_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_while, "`while`");
  lex.expect(tok_oppar, "`(`");
  AnyExprV cond = parse_expr(lex);
  lex.expect(tok_clpar, "`)`");
  V<ast_block_statement> body = parse_block_statement(lex, in_contract_receive);
  range.end(body->range);
  return createV<ast_while_statement>(range, cond, body);
}

static AnyV parse_do_while_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_do, "`do`");
  V<ast_block_statement> body = parse_block_statement(lex, in_contract_receive);
  lex.expect(tok_while, "`while`");
  lex.expect(tok_oppar, "`(`");
  AnyExprV cond = parse_expr(lex);

  lex.check(tok_clpar, "`)`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_do_while_statement>(range, body, cond);
}

static AnyExprV parse_catch_variable(Lexer& lex) {
  if (is_identifier_like(lex.tok())) {
    auto v_ident = parse_identifier(lex, "catch variable");
    return createV<ast_reference>(v_ident->range, v_ident, nullptr);
  }
  if (lex.tok() == tok_underscore) {
    auto v_ident = createV<ast_identifier>(lex.cur_range(), "");
    lex.next();
    return createV<ast_reference>(v_ident->range, v_ident, nullptr);
  }
  lex.unexpected("identifier");
}

static AnyExprV create_catch_underscore_variable(const Lexer& lex) {
  auto v_ident = createV<ast_identifier>(SrcRange::empty_at_start(lex.cur_range()), "");
  return createV<ast_reference>(v_ident->range, v_ident, nullptr);
}

static AnyV parse_assert_statement(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_assert, "`assert`");

  lex.expect(tok_oppar, "`(`");
  AnyExprV cond = parse_expr(lex);
  AnyExprV thrown_code;
  if (lex.tok() == tok_comma) {   // assert(cond, code)
    lex.next();
    thrown_code = parse_expr(lex);
    lex.check(tok_clpar, "`)`");
    range.end(lex.cur_range());
    lex.next();
  } else {  // assert(cond) throw code
    lex.expect(tok_clpar, "`)`");
    lex.expect(tok_throw, "`throw excNo` after assert");
    thrown_code = parse_expr(lex);
    range.end(thrown_code->range);
  }

  return createV<ast_assert_statement>(range, cond, thrown_code);
}

static AnyV parse_try_catch_statement(Lexer& lex, bool in_contract_receive = false) {
  SrcRange range = lex.range_start();
  lex.expect(tok_try, "`try`");
  V<ast_block_statement> try_body = parse_block_statement(lex, in_contract_receive);

  std::vector<AnyExprV> catch_args;
  lex.expect(tok_catch, "`catch`");
  SrcRange catch_range = lex.range_start();
  if (lex.tok() == tok_oppar) {
    lex.next();
    catch_args.push_back(parse_catch_variable(lex));
    if (lex.tok() == tok_comma) { // catch (excNo, arg)
      lex.next();
      catch_args.push_back(parse_catch_variable(lex));
    } else {  // catch (excNo) -> catch (excNo, _)
      catch_args.push_back(create_catch_underscore_variable(lex));
    }
    lex.check(tok_clpar, "`)`");
    catch_range.end(lex.cur_range());
    lex.next();
  } else {  // catch -> catch (_, _)
    catch_args.push_back(create_catch_underscore_variable(lex));
    catch_args.push_back(create_catch_underscore_variable(lex));
    catch_range = SrcRange::empty_at_start(lex.cur_range());
  }
  V<ast_tensor> catch_expr = createV<ast_tensor>(catch_range, std::move(catch_args));

  V<ast_block_statement> catch_body = parse_block_statement(lex, in_contract_receive);
  range.end(catch_body->range);
  return createV<ast_try_catch_statement>(range, try_body, catch_expr, catch_body);
}

static const char* slice2_deferred_msg() {
  return "deferred to future Slice 2 commit; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §10.1";
}

static bool is_slice2_deferred_statement(std::string_view name) {
  // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.7) ships `require(...)`;
  // it's no longer deferred. Keep the helper around for future deferred names.
  (void)name;
  return false;
}

static AnyV parse_become_statement(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.check(tok_identifier, "`become`");
  lex.next();
  auto state_identifier = parse_identifier(lex, "state name after `become`");
  range.end(state_identifier->range);
  return createV<ast_become_statement>(range, state_identifier);
}

static AnyV parse_keep_state_statement(Lexer& lex) {
  SrcRange range = lex.cur_range();
  lex.check(tok_identifier, "`keep_state`");
  lex.next();
  return createV<ast_keep_state_statement>(range);
}

AnyV parse_statement(Lexer& lex, bool in_contract_receive) {
  if (in_contract_receive && lex.tok() == tok_identifier && is_slice2_deferred_statement(lex.cur_str())) {
    err("`{}` is {}", lex.cur_str(), slice2_deferred_msg()).fire(lex.cur_range());
  }
  if (in_contract_receive && lex.tok() == tok_identifier && lex.cur_str() == "become") {
    return parse_become_statement(lex);
  }
  if (in_contract_receive && lex.tok() == tok_identifier && lex.cur_str() == "keep_state") {
    return parse_keep_state_statement(lex);
  }

  switch (lex.tok()) {
    case tok_var:   // `var x = 0` is technically an expression, but can not appear in "any place",
    case tok_val:   // only as a separate declaration
      return parse_local_vars_declaration(lex, true);
    case tok_opbrace:
      return parse_block_statement(lex, in_contract_receive);
    case tok_return:
      return parse_return_statement(lex);
    case tok_if:
      return parse_if_statement(lex, in_contract_receive);
    case tok_repeat:
      return parse_repeat_statement(lex, in_contract_receive);
    case tok_do:
      return parse_do_while_statement(lex, in_contract_receive);
    case tok_while:
      return parse_while_statement(lex, in_contract_receive);
    case tok_throw:
      return parse_throw_expression(lex);
    case tok_assert:
      return parse_assert_statement(lex);
    case tok_try:
      return parse_try_catch_statement(lex, in_contract_receive);
    case tok_semicolon:
      return createV<ast_empty_statement>(lex.cur_range());
    case tok_break:
    case tok_continue:
      lex.error("break/continue from loops are not supported yet");
    default:
      return parse_expr(lex);
  }
}


// --------------------------------------------
//    parsing top-level declarations
//


static AnyV parse_asm_func_body(Lexer& lex, V<ast_identifier> name_ident, V<ast_parameter_list> param_list) {
  SrcRange range = lex.range_start();
  lex.expect(tok_asm, "`asm`");
  size_t n_params = param_list->size();
  if (n_params > 16) {
    err("assembler built-in function can have at most 16 arguments").fire(name_ident);
  }
  std::vector<int> arg_order, ret_order;
  if (lex.tok() == tok_oppar) {
    lex.next();
    while (is_identifier_like(lex.tok()) || lex.tok() == tok_self) {
      int arg_idx = param_list->lookup_idx(lex.cur_str());
      if (arg_idx == -1) {
        lex.unexpected("parameter name");
      }
      arg_order.push_back(arg_idx);
      lex.next();
    }
    if (lex.tok() == tok_arrow) {
      lex.next();
      while (lex.tok() == tok_int_const) {
        int ret_idx = static_cast<int>(parse_tok_int_const(lex.cur_str(), lex.cur_range())->to_long());
        ret_order.push_back(ret_idx);
        lex.next();
      }
    }
    lex.expect(tok_clpar, "`)`");
  }
  std::vector<AnyV> asm_commands;
  lex.check(tok_string_const, "\"ASM COMMAND\"");
  while (lex.tok() == tok_string_const) {
    asm_commands.push_back(parse_expr100(lex));
  }
  range.end(asm_commands.back()->range);
  return createV<ast_asm_body>(range, std::move(arg_order), std::move(ret_order), std::move(asm_commands));
}

static V<ast_annotation> parse_annotation(Lexer& lex) {
  SrcRange range = lex.cur_range();
  lex.check(tok_annotation_at, "`@`");
  std::string_view name = lex.cur_str();
  AnnotationKind kind = Vertex<ast_annotation>::parse_kind(name);
  lex.next();

  V<ast_tensor> v_arg = nullptr;
  if (lex.tok() == tok_oppar) {
    SrcRange range_args = lex.range_start();
    lex.next();
    std::vector<AnyExprV> args;
    args.push_back(parse_expr(lex));
    while (lex.tok() == tok_comma) {
      lex.next();
      if (lex.tok() == tok_clpar) {   // trailing comma
        break;
      }
      args.push_back(parse_expr(lex));
    }
    lex.check(tok_clpar, "`)`");
    range_args.end(lex.cur_range());
    v_arg = createV<ast_tensor>(range_args, std::move(args));
    lex.next();
  }

  switch (kind) {
    case AnnotationKind::unknown:
      err("unknown annotation {}", name).fire(range);
    case AnnotationKind::inline_simple:
    case AnnotationKind::inline_ref:
    case AnnotationKind::noinline:
    case AnnotationKind::pure:
      if (v_arg) {
        err("arguments aren't allowed for {}", name).fire(range);
      }
      v_arg = createV<ast_tensor>(range, {});
      break;
    case AnnotationKind::custom:
      break;
    case AnnotationKind::method_id:
      if (!v_arg || v_arg->size() != 1) {
        err("expecting one argument after {}", name).fire(range);
      }
      break;
    case AnnotationKind::overflow1023_policy:
    case AnnotationKind::on_bounced_policy: {
      if (!v_arg || v_arg->size() != 1 || v_arg->get_item(0)->kind != ast_string_const) {
        err("expecting `(\"policy_name\")` after {}", name).fire(range);
      }
      break;
    }
    case AnnotationKind::on_states: {
      if (!v_arg || v_arg->size() == 0) {
        err("expecting `(State1, State2, ...)` after {}; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.4", name).fire(range);
      }
      for (int i = 0; i < v_arg->size(); ++i) {
        AnyExprV item = v_arg->get_item(i);
        if (item->kind != ast_reference) {
          err("`@on(...)` arguments must be state identifiers; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.4").fire(item);
        }
      }
      break;
    }
  }

  if (v_arg == nullptr) {
    v_arg = createV<ast_tensor>(SrcRange::empty_at_end(range), {});
  }
  range.end(v_arg->range);
  return createV<ast_annotation>(range, name, kind, v_arg);
}

static AnyV parse_function_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations, bool is_contract_getter) {
  SrcRange range = lex.range_start();
  lex.expect(tok_fun, "`fun`");

  AnyTypeV receiver_type = nullptr;
  auto backup = lex.save_parsing_position();
  try {
    receiver_type = parse_type_expression(lex);
    lex.expect(tok_dot, "");
  } catch (const ThrownParseError&) {
    receiver_type = nullptr;
    lex.restore_position(backup);
  }

  if (!is_identifier_like(lex.tok())) {
    lex.unexpected("function name identifier");
  }

  std::string_view f_name = lex.cur_str();
  bool is_entrypoint = !receiver_type && (
        f_name == "main" || f_name == "onInternalMessage" || f_name == "onExternalMessage" ||
        f_name == "onRunTickTock" || f_name == "onSplitPrepare" || f_name == "onSplitInstall" ||
        f_name == "onBouncedMessage");
  bool is_FunC_entrypoint = !receiver_type && (
        f_name == "recv_internal" || f_name == "recv_external" ||
        f_name == "run_ticktock" || f_name == "split_prepare" || f_name == "split_install");
  if (is_FunC_entrypoint) {
    lex.error("this is a reserved FunC/Fift identifier; you need `onInternalMessage`");
  }

  auto v_ident = createV<ast_identifier>(lex.cur_range(), f_name);
  lex.next();

  V<ast_genericsT_list> genericsT_list = nullptr;
  if (lex.tok() == tok_lt) {    // 'fun f<T1,T2>'
    genericsT_list = parse_genericsT_list(lex);
  }

  V<ast_parameter_list> v_param_list = parse_parameter_list(lex, receiver_type, false);
  bool accepts_self = !v_param_list->empty() && v_param_list->get_param(0)->get_name() == "self";
  int n_mutate_params = v_param_list->get_mutate_params_count();

  AnyTypeV ret_type = nullptr;
  bool returns_self = false;
  if (lex.tok() == tok_colon) {   // : <ret_type> (if absent, it means "auto infer", not void)
    lex.next();
    if (lex.tok() == tok_self) {
      if (!accepts_self) {
        lex.error("only a member function can return `self` (which accepts `self` first parameter)");
      }
      returns_self = true;
      ret_type = createV<ast_type_leaf_text>(lex.cur_range(), "void");
      lex.next();
    } else {
      ret_type = parse_type_from_tokens(lex);
    }
  }
  bool is_code_function = lex.tok() == tok_opbrace;

  if (is_entrypoint && (is_contract_getter || genericsT_list || n_mutate_params || !is_code_function)) {
    err("invalid declaration of a reserved function").fire(v_ident);
  }
  if (is_contract_getter && (genericsT_list || n_mutate_params || receiver_type || !is_code_function)) {
    err("invalid declaration of a get method").fire(v_ident);
  }

  AnyV v_body = nullptr;

  if (lex.tok() == tok_builtin) {
    v_body = createV<ast_empty_statement>(lex.cur_range());
    lex.next();
  } else if (lex.tok() == tok_opbrace) {
    v_body = parse_block_statement(lex);
  } else if (lex.tok() == tok_asm) {
    if (!ret_type) {
      lex.error("asm function must specify return type");
    }
    v_body = parse_asm_func_body(lex, v_ident, v_param_list);
  } else {
    lex.unexpected("{ function body }");
  }

  int flags = 0;
  if (is_entrypoint) {
    flags |= FunctionData::flagIsEntrypoint;
  }
  if (is_contract_getter) {
    flags |= FunctionData::flagContractGetter;
  }
  if (accepts_self) {
    flags |= FunctionData::flagAcceptsSelf;
  }
  if (returns_self) {
    flags |= FunctionData::flagReturnsSelf;
  }

  int tvm_method_id = FunctionData::EMPTY_TVM_METHOD_ID;
  AnyExprV tvm_method_id_expr = nullptr;
  FunctionInlineMode inline_mode = FunctionInlineMode::notCalculated;
  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::inline_simple:
        inline_mode = FunctionInlineMode::inlineViaFif;   // maybe will be replaced by inlineInPlace later
        break;
      case AnnotationKind::inline_ref:
        inline_mode = FunctionInlineMode::inlineRef;
        break;
      case AnnotationKind::noinline:
        inline_mode = FunctionInlineMode::noInline;
        break;
      case AnnotationKind::pure:
        flags |= FunctionData::flagMarkedAsPure;
        break;
      case AnnotationKind::method_id: {
        if (is_contract_getter || genericsT_list || receiver_type || is_entrypoint || n_mutate_params || accepts_self) {
          err("@method_id can be specified only for regular functions").fire(v_annotation);
        }
        tvm_method_id_expr = v_annotation->get_arg()->get_item(0);
        break;
      }
      case AnnotationKind::on_bounced_policy: {
        std::string_view str = v_annotation->get_arg()->get_item(0)->as<ast_string_const>()->str_val;
        if (str == "manual") {
          flags |= FunctionData::flagManualOnBounce;
        } else if (str == "ignore") {
          flags |= FunctionData::flagIgnoreOnBounce;
        } else {
          err("incorrect value for {}", v_annotation->name).fire(v_annotation);
        }
        if (f_name != "onInternalMessage") {
          err("this annotation is applicable only to onInternalMessage()").fire(v_annotation);
        }
        break;
      }
      case AnnotationKind::custom:
        break;

      default:
        err("this annotation is not applicable to functions").fire(v_annotation);
    }
  }

  range.end(v_body->range);
  return createV<ast_function_declaration>(range, v_ident, v_param_list, v_body, receiver_type, ret_type, genericsT_list, tvm_method_id_expr, tvm_method_id, flags, inline_mode);
}

static AnyV parse_struct_field(Lexer& lex) {
  SrcRange range = lex.range_start();

  // Slice 2 Stage 3: a struct field MAY be prefixed with one annotation; today only `@on(...)` is meaningful.
  // `@on(...)` is permitted in front of (`private`? `readonly`? name `:` type ...);
  // it is also permitted as a TRAILING annotation after the type (per the §3.4 example
  // `payoutsRemaining: uint8 @on(Settling)`). Both forms are accepted; only one annotation per field.
  std::vector<V<ast_annotation>> field_annotations;
  while (lex.tok() == tok_annotation_at) {
    field_annotations.push_back(parse_annotation(lex));
  }

  bool is_private = false;
  if (lex.tok() == tok_private) {
    lex.next();
    is_private = true;
  }

  bool is_readonly = false;
  if (lex.tok() == tok_readonly) {    // `private readonly` ok, `readonly private` not
    lex.next();
    is_readonly = true;
  }

  auto v_ident = parse_identifier(lex, "field name");
  lex.expect(tok_colon, "`: <type>`");
  AnyTypeV declared_type = parse_type_from_tokens(lex);
  range.end(declared_type->range);

  // accept the §3.4-spelled `payoutsRemaining: uint8 @on(Settling)` trailing position
  while (lex.tok() == tok_annotation_at) {
    field_annotations.push_back(parse_annotation(lex));
    range.end(field_annotations.back()->range);
  }

  AnyExprV default_value = nullptr;
  if (lex.tok() == tok_assign) {    // `id: int = 3`
    lex.next();
    default_value = parse_expr(lex);
    range.end(default_value->range);
  }

  std::vector<std::string_view> on_states;
  SrcRange on_states_range = SrcRange::undefined();
  for (auto v_annotation : field_annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::on_states: {
        if (!on_states.empty()) {
          err("`@on(...)` may be specified at most once per field; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.4")
            .fire(v_annotation);
        }
        on_states_range = v_annotation->range;
        for (int i = 0; i < v_annotation->get_arg()->size(); ++i) {
          auto ref = v_annotation->get_arg()->get_item(i)->as<ast_reference>();
          on_states.push_back(ref->get_name());
        }
        break;
      }
      case AnnotationKind::custom:
        // allow @custom.* / @deprecated above a field, ignore
        break;
      default:
        err("annotation `{}` is not applicable to a struct field; only `@on(...)` is permitted in Slice 2",
            v_annotation->name)
          .fire(v_annotation);
    }
  }

  return createV<ast_struct_field>(range, v_ident, is_private, is_readonly, default_value, declared_type, std::move(on_states), on_states_range);
}

static V<ast_struct_body> parse_struct_body(Lexer& lex, V<ast_identifier> name_ident) {
  SrcRange range = lex.range_start();
  std::vector<AnyV> fields;

  if (lex.tok() == tok_opbrace) {   // `struct A` equal to `struct A {}`
    lex.next();
    while (lex.tok() != tok_clbrace) {
      fields.push_back(parse_struct_field(lex));
      if (lex.tok() == tok_comma || lex.tok() == tok_semicolon) {
        lex.next();
      }
    }
    lex.check(tok_clbrace, "`}`");
    range.end(lex.cur_range());
    lex.next();
  } else {
    range = name_ident->range;
  }

  return createV<ast_struct_body>(range, std::move(fields));
}

static AnyV parse_struct_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.range_start();
  lex.expect(tok_struct, "`struct`");

  AnyExprV opcode = nullptr;
  if (lex.tok() == tok_oppar) {     // struct(0x0012) CounterIncrement
    lex.next();
    opcode = parse_expr(lex);
    lex.expect(tok_clpar, "`)`");
  } else {
    opcode = createV<ast_empty_expression>(SrcRange::empty_at_start(range));
  }

  auto v_ident = parse_identifier(lex, "identifier");

  V<ast_genericsT_list> genericsT_list = nullptr;
  if (lex.tok() == tok_lt) {    // 'struct Wrapper<T>'
    genericsT_list = parse_genericsT_list(lex);
  }

  StructData::Overflow1023Policy overflow1023_policy = StructData::Overflow1023Policy::not_specified;
  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::custom:
        break;
      case AnnotationKind::overflow1023_policy: {
        std::string_view str = v_annotation->get_arg()->get_item(0)->as<ast_string_const>()->str_val;
        if (str == "suppress") {
          overflow1023_policy = StructData::Overflow1023Policy::suppress;
        } else {
          err("incorrect value for {}", v_annotation->name).fire(v_annotation);
        }
        break;
      }
      default:
        err("this annotation is not applicable to struct").fire(v_annotation);
    }
  }

  auto body = parse_struct_body(lex, v_ident);
  range.end(body->range);
  return createV<ast_struct_declaration>(range, v_ident, genericsT_list, overflow1023_policy, opcode, body);
}

static AnyV parse_enum_member(Lexer& lex) {
  SrcRange range = lex.range_start();
  auto v_ident = parse_identifier(lex, "member name");
  range.end(v_ident->range);

  AnyExprV init_value = nullptr;
  if (lex.tok() == tok_assign) {    // `Red = 1`
    lex.next();
    init_value = parse_expr(lex);
    range.end(init_value->range);
  }

  return createV<ast_enum_member>(range, v_ident, init_value);  
}

static V<ast_enum_body> parse_enum_body(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_opbrace, "`{`");

  std::vector<AnyV> members;
  while (lex.tok() != tok_clbrace) {
    members.push_back(parse_enum_member(lex));
    if (lex.tok() == tok_comma || lex.tok() == tok_semicolon) {
      lex.next();
    }
  }

  lex.check(tok_clbrace, "`}`");
  range.end(lex.cur_range());
  lex.next();
  return createV<ast_enum_body>(range, std::move(members));
}

static AnyV parse_enum_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.range_start();
  lex.expect(tok_enum, "`enum`");

  auto v_ident = parse_identifier(lex, "identifier");

  AnyTypeV colon_type = nullptr;
  if (lex.tok() == tok_colon) {   // enum Role: int8
    lex.next();
    colon_type = parse_type_expression(lex);
  }

  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::custom:
        break;
      default:
        err("this annotation is not applicable to enum").fire(v_annotation);
    }
  }

  auto body = parse_enum_body(lex);
  range.end(body->range);
  return createV<ast_enum_declaration>(range, v_ident, colon_type, body);
}

static AnyV parse_tol_required_version(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.next_special(tok_semver, "semver");   // syntax: "tol 0.6"
  std::string semver = static_cast<std::string>(lex.cur_str());
  range.end(lex.cur_range());
  lex.next();

  // for simplicity, there is no syntax ">= version" and so on, just strict compare
  if (TOL_VERSION != semver && TOL_VERSION != semver + ".0") {    // 0.6 = 0.6.0
    err("the contract is written in Tol v{}, but you use Tol compiler v{}; probably, it will lead to compilation errors or hash changes", semver, TOL_VERSION).warning(range, nullptr);
  }

  return createV<ast_tol_required_version>(range, semver);  // semicolon is not necessary
}

static AnyV parse_import_directive(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_import, "`import`");
  lex.check(tok_string_const, "source file name");
  auto v_str = parse_expr100(lex)->as<ast_string_const>();
  std::string_view rel_filename = v_str->str_val;
  if (rel_filename.empty()) {
    err("imported file name is an empty string").fire(v_str);
  }
  range.end(v_str->range);
  return createV<ast_import_directive>(range, v_str);
}

static AnyTypeV parse_contract_type_identifier(Lexer& lex, const char* what) {
  AnyTypeV type_node = parse_type_from_tokens(lex);
  if (!type_node->try_as<ast_type_leaf_text>()) {
    err("{} must be a simple type identifier", what).fire(type_node);
  }
  return type_node;
}

static bool is_deferred_contract_member_name(std::string_view name) {
  // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8) ships `receive_external`;
  // the parser handles it as a real keyword above. Reserved for future deferred names.
  (void)name;
  return false;
}

// Parse a `get fun` block inside a contract declaration.
// Caller has already consumed `get` (and any annotations are passed in).
// see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.5
static AnyV parse_contract_get_fun_block(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  SrcRange range = lex.cur_range();
  lex.expect(tok_fun, "`fun` after `get`");

  if (!is_identifier_like(lex.tok())) {
    lex.unexpected("get-method name");
  }
  auto v_ident = createV<ast_identifier>(lex.cur_range(), lex.cur_str());
  lex.next();

  V<ast_parameter_list> v_param_list = parse_parameter_list(lex, nullptr, false);

  AnyTypeV ret_type = nullptr;
  if (lex.tok() == tok_colon) {
    lex.next();
    ret_type = parse_type_from_tokens(lex);
  } else {
    err("`get fun` must declare an explicit return type; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.5").fire(v_ident);
  }

  // process annotations: only @method_id, @inline, @inline_ref, @noinline, @pure, @deprecated, custom are allowed
  AnyExprV tvm_method_id_expr = nullptr;
  int extra_flags = 0;
  FunctionInlineMode inline_mode = FunctionInlineMode::notCalculated;
  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::method_id:
        if (tvm_method_id_expr) {
          err("duplicate `@method_id` annotation").fire(v_annotation);
        }
        tvm_method_id_expr = v_annotation->get_arg()->get_item(0);
        break;
      case AnnotationKind::inline_simple:
        inline_mode = FunctionInlineMode::inlineViaFif;
        break;
      case AnnotationKind::inline_ref:
        inline_mode = FunctionInlineMode::inlineRef;
        break;
      case AnnotationKind::noinline:
        inline_mode = FunctionInlineMode::noInline;
        break;
      case AnnotationKind::pure:
        extra_flags |= FunctionData::flagMarkedAsPure;
        break;
      case AnnotationKind::custom:
        // allowed; opaque to the compiler (e.g. @deprecated)
        break;
      default:
        err("annotation `@{}` is not applicable to `get fun`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.5", v_annotation->name).fire(v_annotation);
    }
  }

  if (lex.tok() != tok_opbrace) {
    lex.unexpected("`{ get fun body }`");
  }
  auto v_body = parse_block_statement(lex);
  range.end(v_body->range);
  return createV<ast_get_fun_block>(range, v_ident, v_param_list, v_body, ret_type, tvm_method_id_expr, extra_flags, inline_mode);
}

static AnyV parse_receive_block(Lexer& lex,
                                bool has_disclaim_query_id_annotation = false,
                                SrcRange disclaim_annotation_range = SrcRange::undefined(),
                                bool is_deploy = false,
                                SrcRange deploy_annotation_range = SrcRange::undefined()) {
  // When an annotation (`@disclaim_query_id` or `@deploy`) precedes the `receive(...)` block,
  // anchor the AST node's SrcRange at the earliest annotation; otherwise use the `receive` keyword.
  SrcRange range = lex.range_start();
  if (is_deploy && deploy_annotation_range.is_defined()) {
    range = deploy_annotation_range;
  } else if (has_disclaim_query_id_annotation && disclaim_annotation_range.is_defined()) {
    range = disclaim_annotation_range;
  }
  lex.expect(tok_receive, "`receive`");
  lex.expect(tok_oppar, "`(`");
  auto v_param = parse_identifier(lex, "receive parameter name");
  lex.expect(tok_colon, "`:`");
  AnyTypeV msg_type = parse_contract_type_identifier(lex, "receive message type");
  lex.expect(tok_clpar, "`)`");
  V<ast_identifier> state_identifier = nullptr;
  if (lex.tok() == tok_identifier && lex.cur_str() == "on") {
    lex.next();
    state_identifier = parse_identifier(lex, "state name after `on`");
  }
  auto v_body = parse_block_statement(lex, true);
  range.end(v_body->range);

  // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2 v3): the reserved literal type name
  // `UnknownOpcode` flips this receive into the catch-all kind. The parameter is bound to the
  // raw `in.body` slice at lowering time. Other annotations are mutually exclusive with
  // `UnknownOpcode` per §3.2 / §3.6.
  bool is_unknown_opcode_catch_all = false;
  if (auto leaf = msg_type->try_as<ast_type_leaf_text>(); leaf && leaf->text == "UnknownOpcode") {
    is_unknown_opcode_catch_all = true;
    if (state_identifier != nullptr) {
      err("`receive(msg: UnknownOpcode)` cannot carry an `on <State>` clause; the catch-all body runs irrespective of contract state; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2")
        .fire(state_identifier);
    }
    if (has_disclaim_query_id_annotation) {
      err("`@disclaim_query_id` cannot decorate `receive(msg: UnknownOpcode)`; the unknown-opcode catch-all has no parsed query_id surface; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2")
        .fire(disclaim_annotation_range);
    }
    if (is_deploy) {
      err("`@deploy` cannot decorate `receive(msg: UnknownOpcode)`; deploy and unknown-opcode catch-all are distinct entry points; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6")
        .fire(deploy_annotation_range);
    }
  }

  // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6): `@deploy` cannot combine with
  // `on <State>` (deployment has exactly one initial state) nor with `@disclaim_query_id`.
  if (is_deploy) {
    if (state_identifier != nullptr) {
      err("`@deploy` cannot combine with `on <State>`; deployment has exactly one authoritative initial state; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6")
        .fire(state_identifier);
    }
    if (has_disclaim_query_id_annotation) {
      err("`@deploy` cannot combine with `@disclaim_query_id`; the deploy receiver runs before storage exists and has its own scope rules; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6")
        .fire(disclaim_annotation_range);
    }
  }

  return createV<ast_receive_block>(range, v_param, msg_type, state_identifier, v_body,
                                    has_disclaim_query_id_annotation, disclaim_annotation_range,
                                    is_deploy, deploy_annotation_range,
                                    is_unknown_opcode_catch_all);
}

// Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8): parse a
// `receive_external(msg: T) { ... }` block. Externals do NOT carry an
// `on State` clause (state-machine guards apply only to internals) and
// do NOT accept `@disclaim_query_id` (externals have no query_id).
static AnyV parse_receive_external_block(Lexer& lex) {
  SrcRange range = lex.range_start();
  lex.expect(tok_receive_external, "`receive_external`");
  lex.expect(tok_oppar, "`(`");
  auto v_param = parse_identifier(lex, "receive_external parameter name");
  lex.expect(tok_colon, "`:`");
  AnyTypeV msg_type = parse_contract_type_identifier(lex, "receive_external message type");
  lex.expect(tok_clpar, "`)`");
  if (lex.tok() == tok_identifier && lex.cur_str() == "on") {
    err("`receive_external(...)` cannot carry an `on State` clause; state-machine guards apply to internal receivers only; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8").fire(lex.cur_range());
  }
  auto v_body = parse_block_statement(lex, true);
  range.end(v_body->range);
  return createV<ast_receive_external_block>(range, v_param, msg_type, v_body);
}

static void parse_contract_state_list(Lexer& lex, std::vector<V<ast_identifier>>& state_identifiers) {
  lex.next();
  lex.expect(tok_colon, "`:`");
  state_identifiers.push_back(parse_identifier(lex, "state name"));
  while (lex.tok() == tok_comma) {
    lex.next();
    state_identifiers.push_back(parse_identifier(lex, "state name"));
  }
  if (lex.tok() == tok_semicolon) {
    lex.next();
  }
}

static V<ast_identifier> parse_initial_state(Lexer& lex) {
  lex.check(tok_annotation_at, "`@initial`");
  lex.next();
  auto state_keyword = parse_identifier(lex, "`state` after `@initial`");
  if (state_keyword->name != "state") {
    err("expected `state` after `@initial`").fire(state_keyword);
  }
  auto initial_state = parse_identifier(lex, "initial state name");
  if (lex.tok() == tok_semicolon) {
    lex.next();
  }
  return initial_state;
}

static AnyV parse_contract_declaration(Lexer& lex, const std::vector<V<ast_annotation>>& annotations) {
  int on_bounced_policy_flags = 0;
  for (auto v_annotation : annotations) {
    switch (v_annotation->kind) {
      case AnnotationKind::on_bounced_policy: {
        if (on_bounced_policy_flags != 0) {
          err("contract may specify only one @on_bounced_policy annotation").fire(v_annotation);
        }
        std::string_view str = v_annotation->get_arg()->get_item(0)->as<ast_string_const>()->str_val;
        if (str == "manual") {
          on_bounced_policy_flags |= FunctionData::flagManualOnBounce;
        } else if (str == "ignore") {
          on_bounced_policy_flags |= FunctionData::flagIgnoreOnBounce;
        } else {
          err("incorrect value for {}", v_annotation->name).fire(v_annotation);
        }
        break;
      }
      default:
        err("contract annotations are {}", slice2_deferred_msg()).fire(v_annotation);
    }
  }

  SrcRange range = lex.range_start();
  lex.expect(tok_contract, "`contract`");
  auto v_ident = parse_identifier(lex, "contract name");
  lex.expect(tok_opbrace, "`{`");

  AnyTypeV storage_type = nullptr;
  std::vector<V<ast_identifier>> state_identifiers;
  V<ast_identifier> initial_state_identifier = nullptr;
  std::vector<AnyV> receive_blocks;
  std::vector<AnyV> receive_external_blocks;       // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8)
  std::vector<AnyV> get_fun_blocks;
  // annotations queued for the next `get fun` (see §3.5 / §10.1: parser fix at line 1712 — @method_id is now accepted on contract get fun)
  std::vector<V<ast_annotation>> pending_member_annotations;

  // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2 v3): contract-level unknown-opcode mode.
  // Tracks whether `@unknown_silent_drop;` or `@unknown_throw(N);` was declared at contract scope,
  // so we can diagnose duplicates and conflicts with a `receive(msg: UnknownOpcode)` body.
  ContractUnknownMode unknown_mode = ContractUnknownMode::default_protocol_throw;
  int64_t unknown_throw_code = 0;
  SrcRange unknown_annotation_range = SrcRange::undefined();
  bool unknown_set_explicitly = false;
  std::string_view unknown_set_label;     // for diagnostics ("@unknown_silent_drop", etc.)
  bool implicit_protocol_default = false;
  SrcRange implicit_protocol_default_range = SrcRange::undefined();
  std::vector<ContractImplicitProtocolFor> implicit_protocol_for;

  while (lex.tok() != tok_clbrace) {
    if (lex.tok() == tok_semicolon) {
      lex.next();
      continue;
    }
    if (lex.tok() == tok_annotation_at) {
      if (lex.cur_str() == "@initial") {
        if (!pending_member_annotations.empty()) {
          err("`@initial state` cannot follow other annotations").fire(lex.cur_range());
        }
        if (initial_state_identifier) {
          err("contract block may contain only one `@initial state` declaration; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.4").fire(lex.cur_range());
        }
        initial_state_identifier = parse_initial_state(lex);
        continue;
      }
      // Slice 2 Stage 7 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2.1):
      // `@disclaim_query_id` is a per-receiver annotation; consume it directly
      // and pass the flag into the upcoming receive block.
      if (lex.cur_str() == "@disclaim_query_id") {
        if (!pending_member_annotations.empty()) {
          err("`@disclaim_query_id` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        // Allow `@disclaim_query_id @deploy receive(...)` ordering — but it is rejected later
        // inside parse_receive_block as a §3.6 conflict.
        bool deploy_follows = false;
        SrcRange deploy_range = SrcRange::undefined();
        if (lex.tok() == tok_annotation_at && lex.cur_str() == "@deploy") {
          deploy_follows = true;
          deploy_range = lex.cur_range();
          lex.next();
        }
        if (lex.tok() != tok_receive) {
          err("`@disclaim_query_id` is only valid immediately before a `receive(...)` block; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2.1").fire(annotation_range);
        }
        if (!storage_type) {
          err("contract `storage:` declaration must appear before `receive(...)` blocks").fire(lex.cur_range());
        }
        receive_blocks.push_back(parse_receive_block(lex,
            /*has_disclaim_query_id_annotation=*/true, annotation_range,
            /*is_deploy=*/deploy_follows, deploy_range));
        continue;
      }
      // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6):
      // `@deploy` is a per-receiver annotation marking the bootstrap path that runs before
      // loadData(). Multiple `@deploy` receivers are a compile error.
      if (lex.cur_str() == "@deploy") {
        if (!pending_member_annotations.empty()) {
          err("`@deploy` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        // Allow `@deploy @disclaim_query_id receive(...)` ordering — rejected later as a §3.6 conflict.
        bool disclaim_follows = false;
        SrcRange disclaim_range = SrcRange::undefined();
        if (lex.tok() == tok_annotation_at && lex.cur_str() == "@disclaim_query_id") {
          disclaim_follows = true;
          disclaim_range = lex.cur_range();
          lex.next();
        }
        if (lex.tok() != tok_receive) {
          err("`@deploy` is only valid immediately before a `receive(...)` block; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6").fire(annotation_range);
        }
        if (!storage_type) {
          err("contract `storage:` declaration must appear before `receive(...)` blocks").fire(lex.cur_range());
        }
        receive_blocks.push_back(parse_receive_block(lex,
            /*has_disclaim_query_id_annotation=*/disclaim_follows, disclaim_range,
            /*is_deploy=*/true, annotation_range));
        continue;
      }
      // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2 v3):
      // `@unknown_silent_drop;` / `@unknown_throw(N);` are contract-level statements declaring
      // the unknown-opcode dispatch tail. Mutually exclusive with each other and with a
      // `receive(msg: UnknownOpcode)` catch-all receiver (the latter is checked at lowering).
      if (lex.cur_str() == "@unknown_silent_drop") {
        if (!pending_member_annotations.empty()) {
          err("`@unknown_silent_drop` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        if (unknown_set_explicitly) {
          err("contract block already declares `{}`; `@unknown_silent_drop` and `@unknown_throw(...)` are mutually exclusive; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2",
              std::string(unknown_set_label)).fire(annotation_range);
        }
        unknown_mode = ContractUnknownMode::silent_drop;
        unknown_annotation_range = annotation_range;
        unknown_set_explicitly = true;
        unknown_set_label = "@unknown_silent_drop";
        if (lex.tok() == tok_semicolon) {
          lex.next();
        }
        continue;
      }
      if (lex.cur_str() == "@unknown_throw") {
        if (!pending_member_annotations.empty()) {
          err("`@unknown_throw` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        if (unknown_set_explicitly) {
          err("contract block already declares `{}`; `@unknown_silent_drop` and `@unknown_throw(...)` are mutually exclusive; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2",
              std::string(unknown_set_label)).fire(annotation_range);
        }
        if (lex.tok() != tok_oppar) {
          err("`@unknown_throw` requires a literal int argument: `@unknown_throw(N);`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2").fire(annotation_range);
        }
        lex.next();
        if (lex.tok() != tok_int_const) {
          err("`@unknown_throw(N)` requires a literal int; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2").fire(lex.cur_range());
        }
        td::RefInt256 parsed_int = parse_tok_int_const(lex.cur_str(), lex.cur_range());
        if (!parsed_int->signed_fits_bits(64)) {
          err("`@unknown_throw(N)` literal does not fit a signed 64-bit int").fire(lex.cur_range());
        }
        unknown_throw_code = parsed_int->to_long();
        lex.next();
        lex.expect(tok_clpar, "`)` after `@unknown_throw(N)` argument");
        unknown_mode = ContractUnknownMode::throw_code;
        unknown_annotation_range = annotation_range;
        unknown_set_explicitly = true;
        unknown_set_label = "@unknown_throw";
        if (lex.tok() == tok_semicolon) {
          lex.next();
        }
        continue;
      }
      // Slice 6 hardening: large state machines need a scalable way to document
      // intentionally implicit Protocol paths for known-opcode/wrong-state pairs.
      if (lex.cur_str() == "@implicit_protocol_default") {
        if (!pending_member_annotations.empty()) {
          err("`@implicit_protocol_default` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        if (implicit_protocol_default) {
          err("contract block already declares `@implicit_protocol_default`; duplicate state-cross-product suppressions are not allowed; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5")
            .fire(annotation_range);
        }
        if (lex.tok() == tok_oppar) {
          err("`@implicit_protocol_default` takes no arguments; write `@implicit_protocol_default;`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5")
            .fire(annotation_range);
        }
        implicit_protocol_default = true;
        implicit_protocol_default_range = annotation_range;
        if (lex.tok() == tok_semicolon) {
          lex.next();
        }
        continue;
      }
      if (lex.cur_str() == "@implicit_protocol_for") {
        if (!pending_member_annotations.empty()) {
          err("`@implicit_protocol_for` cannot follow other annotations").fire(lex.cur_range());
        }
        SrcRange annotation_range = lex.cur_range();
        lex.next();
        if (lex.tok() != tok_oppar) {
          err("`@implicit_protocol_for` requires `(MessageType, StateName)`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §5")
            .fire(annotation_range);
        }
        lex.next();
        auto message_identifier = parse_identifier(lex, "message type in `@implicit_protocol_for(MessageType, StateName)`");
        lex.expect(tok_comma, "`,` between message type and state name");
        auto state_identifier = parse_identifier(lex, "state name in `@implicit_protocol_for(MessageType, StateName)`");
        lex.expect(tok_clpar, "`)` after `@implicit_protocol_for(MessageType, StateName)`");
        implicit_protocol_for.push_back(ContractImplicitProtocolFor{
            std::string(message_identifier->name),
            std::string(state_identifier->name),
            annotation_range});
        if (lex.tok() == tok_semicolon) {
          lex.next();
        }
        continue;
      }
      // Otherwise queue this annotation; it must be followed by a member it applies to
      // (e.g. `@method_id(N) get fun adminAddress(): address {...}` per §3.5)
      pending_member_annotations.push_back(parse_annotation(lex));
      continue;
    }
    if (lex.tok() == tok_storage) {
      if (!pending_member_annotations.empty()) {
        err("annotations are not applicable to `storage:`").fire(pending_member_annotations.front());
      }
      if (storage_type) {
        err("contract block must contain exactly one `storage:` declaration").fire(lex.cur_range());
      }
      lex.next();
      lex.expect(tok_colon, "`:`");
      storage_type = parse_contract_type_identifier(lex, "contract storage type");
      if (lex.tok() == tok_semicolon) {
        lex.next();
      }
      continue;
    }
    if (lex.tok() == tok_identifier && lex.cur_str() == "states") {
      if (!pending_member_annotations.empty()) {
        err("annotations are not applicable to `states:`").fire(pending_member_annotations.front());
      }
      if (!state_identifiers.empty()) {
        err("contract block may contain only one `states:` declaration; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.4").fire(lex.cur_range());
      }
      parse_contract_state_list(lex, state_identifiers);
      continue;
    }
    if (lex.tok() == tok_receive) {
      if (!pending_member_annotations.empty()) {
        err("contract receiver annotations are {}", slice2_deferred_msg()).fire(pending_member_annotations.front());
      }
      if (!storage_type) {
        err("contract `storage:` declaration must appear before `receive(...)` blocks").fire(lex.cur_range());
      }
      receive_blocks.push_back(parse_receive_block(lex));
      continue;
    }
    if (lex.tok() == tok_receive_external) {
      // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8): external receivers
      // do not accept any annotations (no `@deploy`, no `@disclaim_query_id`, etc).
      if (!pending_member_annotations.empty()) {
        err("`receive_external(...)` blocks do not accept annotations; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8").fire(pending_member_annotations.front());
      }
      if (!storage_type) {
        err("contract `storage:` declaration must appear before `receive_external(...)` blocks").fire(lex.cur_range());
      }
      receive_external_blocks.push_back(parse_receive_external_block(lex));
      continue;
    }
    if (lex.tok() == tok_identifier && lex.cur_str() == "get") {
      if (!storage_type) {
        err("contract `storage:` declaration must appear before `get fun` blocks").fire(lex.cur_range());
      }
      lex.next();
      get_fun_blocks.push_back(parse_contract_get_fun_block(lex, pending_member_annotations));
      pending_member_annotations.clear();
      continue;
    }
    if (lex.tok() == tok_fun) {
      err("free-standing `fun` declarations are not permitted inside a contract block; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.1").fire(lex.cur_range());
    }
    if (lex.tok() == tok_identifier && is_deferred_contract_member_name(lex.cur_str())) {
      err("`{}` is {}", lex.cur_str(), slice2_deferred_msg()).fire(lex.cur_range());
    }
    err("contract blocks may contain only `storage:`, `states:`, `@initial state`, `@implicit_protocol_default`, `@implicit_protocol_for(...)`, `receive(...)`, `receive_external(...)`, and `get fun` declarations; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.1 / §3.5 / §3.8").fire(lex.cur_range());
  }

  if (!pending_member_annotations.empty()) {
    err("trailing annotation has no following declaration").fire(pending_member_annotations.front());
  }
  if (!storage_type) {
    err("contract block must contain exactly one `storage:` declaration").fire(v_ident);
  }
  if (receive_blocks.empty()) {
    // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8): every contract is
    // addressable internally, so at least one `receive(...)` is required even when
    // the contract is wallet-style external-driven. External-only contracts can
    // still ship a single trivial `receive(msg: NoOpInternal) {}` to satisfy this.
    err("contract block must contain at least one `receive(...)` declaration").fire(v_ident);
  }

  // Slice 2 Stage 4 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2 / §3.6):
  // - At most one `@deploy` receiver per contract.
  // - At most one `receive(msg: UnknownOpcode)` receiver per contract.
  // - `UnknownOpcode` receiver is mutually exclusive with `@unknown_silent_drop` and
  //   `@unknown_throw(N)` annotations.
  V<ast_receive_block> first_deploy = nullptr;
  V<ast_receive_block> first_unknown_catch_all = nullptr;
  for (AnyV r : receive_blocks) {
    auto rv = r->as<ast_receive_block>();
    if (rv->is_deploy) {
      if (first_deploy != nullptr) {
        err("contract `{}` declares more than one `@deploy receive(...)`; first declared at {}; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.6",
            v_ident->name, first_deploy->range.stringify_start_location(false))
          .fire(rv->deploy_annotation_range);
      }
      first_deploy = rv;
    }
    if (rv->is_unknown_opcode_catch_all) {
      if (first_unknown_catch_all != nullptr) {
        err("contract `{}` declares more than one `receive(msg: UnknownOpcode)`; first declared at {}; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2",
            v_ident->name, first_unknown_catch_all->range.stringify_start_location(false))
          .fire(rv->range);
      }
      first_unknown_catch_all = rv;
    }
  }

  if (first_unknown_catch_all != nullptr) {
    if (unknown_set_explicitly) {
      err("contract `{}` declares both `{}` and `receive(msg: UnknownOpcode)`; pick one of the two unknown-opcode handlers; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.2",
          v_ident->name, std::string(unknown_set_label))
        .fire(unknown_annotation_range);
    }
    unknown_mode = ContractUnknownMode::catch_all_receiver;
    unknown_annotation_range = first_unknown_catch_all->range;
  }

  range.end(lex.cur_range());
  lex.next();
  return createV<ast_contract_declaration>(range, v_ident, storage_type, std::move(state_identifiers), initial_state_identifier, std::move(receive_blocks), std::move(receive_external_blocks), std::move(get_fun_blocks),
                                           on_bounced_policy_flags, unknown_mode, unknown_throw_code, unknown_annotation_range,
                                           implicit_protocol_default, implicit_protocol_default_range, std::move(implicit_protocol_for));
}

static void reject_contract_mixed_with_onInternalMessage(const std::vector<AnyV>& declarations) {
  V<ast_contract_declaration> contract_decl = nullptr;
  V<ast_function_declaration> on_internal = nullptr;
  V<ast_function_declaration> on_external = nullptr;
  V<ast_function_declaration> file_scope_get_fun = nullptr;

  for (AnyV v : declarations) {
    if (auto v_contract = v->try_as<ast_contract_declaration>()) {
      if (contract_decl) {
        err("Slice 2 Stage 1 supports one `contract` declaration per .tol file; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §10.1").fire(v_contract);
      }
      contract_decl = v_contract;
    } else if (auto v_func = v->try_as<ast_function_declaration>(); v_func && v_func->get_identifier()->name == "onInternalMessage") {
      on_internal = v_func;
    } else if (auto v_func = v->try_as<ast_function_declaration>(); v_func && v_func->get_identifier()->name == "onExternalMessage") {
      on_external = v_func;
    } else if (auto v_func = v->try_as<ast_function_declaration>(); v_func && (v_func->flags & FunctionData::flagContractGetter) && !file_scope_get_fun) {
      file_scope_get_fun = v_func;
    }
  }

  if (contract_decl && on_internal) {
    err("a .tol file cannot contain both `contract X { ... }` and top-level `fun onInternalMessage(...)`; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §6.3").fire(on_internal);
  }
  // Slice 2 Stage 6 (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8): the contract block synthesizes
  // `onExternalMessage` from declared `receive_external` blocks; a hand-written
  // `fun onExternalMessage(...)` would collide with the synthesized one.
  if (contract_decl && contract_decl->get_num_externals() > 0 && on_external) {
    err("a .tol file with `receive_external(...)` blocks cannot also declare top-level `fun onExternalMessage(...)`; the contract synthesizes it; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.8").fire(on_external);
  }
  if (contract_decl && file_scope_get_fun) {
    err("a .tol file with a `contract X { ... }` block cannot also declare top-level `get fun {}(...)`; move the get-method inside the contract; see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-language-syntax-policy.md §3.5",
        file_scope_get_fun->get_identifier()->name).fire(file_scope_get_fun);
  }
}


// --------------------------------------------
//    parse .tol source file to AST
//    (the main, exported, function)
//

AnyV parse_src_file_to_ast(const SrcFile* file) {
  std::vector<AnyV> toplevel_declarations;
  std::vector<V<ast_annotation>> annotations;
  Lexer lex(file);
  SrcRange range = lex.range_start();

  while (!lex.is_eof()) {
    switch (lex.tok()) {
      case tok_tol:
        if (!annotations.empty()) {
          lex.unexpected("declaration after @annotations");
        }
        toplevel_declarations.push_back(parse_tol_required_version(lex));
        break;
      case tok_import:
        if (!annotations.empty()) {
          lex.unexpected("declaration after @annotations");
        }
        toplevel_declarations.push_back(parse_import_directive(lex));
        break;
      case tok_semicolon:
        if (!annotations.empty()) {
          lex.unexpected("declaration after @annotations");
        }
        lex.next();  // don't add ast_empty, no need
        break;

      case tok_annotation_at:
        annotations.push_back(parse_annotation(lex));
        break;
      case tok_global:
        toplevel_declarations.push_back(parse_global_var_declaration(lex, annotations));
        annotations.clear();
        break;
      case tok_const:
        toplevel_declarations.push_back(parse_constant_declaration(lex, annotations));
        annotations.clear();
        break;
      case tok_type:
        toplevel_declarations.push_back(parse_type_alias_declaration(lex, annotations));
        annotations.clear();
        break;
      case tok_fun:
        toplevel_declarations.push_back(parse_function_declaration(lex, annotations, false));
        annotations.clear();
        break;
      case tok_struct:
        toplevel_declarations.push_back(parse_struct_declaration(lex, annotations));
        annotations.clear();
        break;
      case tok_enum:
        toplevel_declarations.push_back(parse_enum_declaration(lex, annotations));
        annotations.clear();
        break;
      case tok_contract:
        toplevel_declarations.push_back(parse_contract_declaration(lex, annotations));
        annotations.clear();
        break;

      case tok_export:
      case tok_operator:
      case tok_infix:
        err("`{}` is not supported yet", lex.cur_str()).fire(lex.cur_range());

      case tok_identifier:
        if (lex.cur_str() == "get") {     // top-level "get", contract getter
          lex.next();
          toplevel_declarations.push_back(parse_function_declaration(lex, annotations, true));
          annotations.clear();
          break;
        }
        // fallthrough
      default:
        lex.unexpected("top-level declaration");
    }
  }

  reject_contract_mixed_with_onInternalMessage(toplevel_declarations);
  range.end(toplevel_declarations.empty() ? lex.cur_range() : toplevel_declarations.back()->range);
  return createV<ast_tol_file>(file, range, std::move(toplevel_declarations));
}

}  // namespace tol
