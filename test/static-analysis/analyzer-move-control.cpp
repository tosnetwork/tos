// Positive control for scripts/check-use-after-move.py, pass B.
//
// clang-analyzer-cplusplus.Move must report exactly one diagnostic here: a method
// called on a moved-from std::string. Not built by CMake.
#include <cstddef>
#include <string>
#include <utility>

namespace {

std::size_t consume(std::string value) {
  return value.size();
}

}  // namespace

int main() {
  std::string s = "value";
  std::size_t total = consume(std::move(s));
  total += s.size();
  return static_cast<int>(total);
}
