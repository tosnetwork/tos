// Positive control: a moved-from string is read again. Both the clang-tidy check
// and the Clang Static Analyzer checker must report the same line.
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
  total += s.size();  // expect: bugprone-use-after-move, cplusplus.Move
  return static_cast<int>(total);
}
