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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cstddef>
#include <set>
#include <string>

#include "td/tl/tl_config.h"
#include "td/tl/tl_core.h"

namespace td {

// The Java class name of a TL type or constructor: its letters and digits, each
// run after a separator starting with a capital (blocks.blockSignatures ->
// BlocksBlockSignatures).
inline std::string java_class_name_letters(const std::string &name) {
  std::string result;
  bool next_to_upper = true;
  for (char c : name) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (!alnum) {
      next_to_upper = true;
      continue;
    }
    if (next_to_upper && c >= 'a' && c <= 'z') {
      result += static_cast<char>(c - 'a' + 'A');
    } else {
      result += c;
    }
    next_to_upper = false;
  }
  return result;
}

// Suffix of the Java class of a polymorphic type whose name would otherwise be
// the name of one of its own constructors.
inline const std::string &java_type_collision_suffix() {
  static const std::string suffix = "Type";
  return suffix;
}

// TL tells a type from its constructor by the case of the first letter
// (blocks.BlockSignatures and blocks.blockSignatures), which a Java class name
// does not keep. A type with one constructor is generated as that constructor's
// class alone, so only a type with several gets an abstract class that can
// collide. Returns the TL names of the types whose abstract class takes
// java_type_collision_suffix(); their constructors keep their names.
// It counts the constructors the schema declares: simple_constructors is
// filled in only while the schema is written.
inline std::set<std::string> java_colliding_type_names(const tl::tl_config &config) {
  std::set<std::string> result;
  for (std::size_t i = 0; i < config.get_type_count(); i++) {
    const tl::tl_type *t = config.get_type_by_num(i);
    if (t == nullptr || t->constructors.size() <= 1) {
      continue;
    }
    const std::string type_name = java_class_name_letters(t->name);
    for (const tl::tl_combinator *constructor : t->constructors) {
      if (constructor != nullptr && java_class_name_letters(constructor->name) == type_name) {
        result.insert(t->name);
        break;
      }
    }
  }
  return result;
}

}  // namespace td
