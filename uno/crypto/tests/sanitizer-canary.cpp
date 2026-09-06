#include "uno_crypto.h"
#include <limits>

// Deliberately invalid, opt-in instrument check. Never register as a passing
// test: both modes must fail under their respective sanitizer.
int main(int argc, char**) {
  if (argc > 1) {
    volatile int top = std::numeric_limits<int>::max();
    return top + 1;  // Non-monetary, intentional undefined arithmetic.
  }
  auto* short_allocation = new uint64_t[1]{};
  UnoTreeRequest request{};
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.frontier = reinterpret_cast<UnoTreeFrontier*>(short_allocation);
  UnoTreeResult result{};
  // Deliberately violate the allocation contract; the Rust read must trip ASan.
  return uno_crypto_tree_append_v0(&request, &result);
}
