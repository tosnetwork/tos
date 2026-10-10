// Positive control: a string_view bound to a temporary string.
#include <string>
#include <string_view>

int main() {
  std::string_view view = std::string("temporary");  // expect: bugprone-dangling-handle
  return static_cast<int>(view.size());
}
