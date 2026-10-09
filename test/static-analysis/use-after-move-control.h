// Positive control for scripts/check-use-after-move.py, pass A (header coverage).
//
// The shape of a real defect: a value is passed by const reference to a helper while
// the same call's lambda argument move-captures it, so the helper reads a moved-from
// object. It sits in a function template in a header so the control proves that the
// pass's header filter reaches diagnostics located in headers. Not built by CMake.
#pragma once

#include <string>
#include <utility>

namespace use_after_move_control {

template <class Fn>
void with_value(const std::string& value, Fn&& continuation) {
  continuation(value.size());
}

template <class T>
void header_shape(T value) {
  with_value(value, [value = std::move(value)](std::size_t) { (void)value; });
}

}  // namespace use_after_move_control
