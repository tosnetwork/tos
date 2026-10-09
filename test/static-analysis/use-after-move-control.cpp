// Positive control for scripts/check-use-after-move.py, pass A (main file).
//
// Exactly two bugprone-use-after-move diagnostics are expected: one here, one in
// use-after-move-control.h through the header filter. Not built by CMake.
#include <string>
#include <utility>

#include "use-after-move-control.h"

namespace {

void sink(const std::string& first, std::string second) {
  (void)first;
  (void)second;
}

}  // namespace

int main() {
  std::string s = "value";
  sink(s, std::move(s));
  use_after_move_control::header_shape(std::string("value"));
  return 0;
}
