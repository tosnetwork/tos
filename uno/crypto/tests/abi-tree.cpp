#include "uno_crypto.h"
#include "abi-concurrency.h"
#include <cstring>
#include <cstddef>
#include <limits>

static_assert(sizeof(UnoTreeFrontier) == 1072);
static_assert(sizeof(UnoTreeResult) == 1104);
static_assert(offsetof(UnoTreeFrontier, ommers) == 48);

bool concurrent_tree() {
  UnoTreeFrontier empty{};
  std::array<UnoTreeResult, 8> expected{};
  for (std::size_t index = 0; index < expected.size(); ++index) {
    uint8_t leaves[2][32]{};
    leaves[0][0] = static_cast<uint8_t>(index + 1);
    leaves[1][0] = 42;
    UnoTreeRequest request{};
    request.profile = UNO_CRYPTO_FIXED_PROFILE;
    request.frontier = &empty;
    request.commitments = leaves;
    request.commitment_count = request.max_commitments = 2;
    if (uno_crypto_tree_append_v0(&request, &expected[index]) != UNO_CRYPTO_OK ||
        expected[index].frontier.next_position != 2) return false;
  }
  return concurrent_abi_calls([&](std::size_t index) {
    uint8_t leaves[2][32]{};
    leaves[0][0] = static_cast<uint8_t>(index + 1);
    leaves[1][0] = 42;
    UnoTreeRequest request{};
    request.profile = UNO_CRYPTO_FIXED_PROFILE;
    request.frontier = &empty;
    request.commitments = leaves;
    request.commitment_count = request.max_commitments = 2;
    request.reserved_leaves = 7;
    for (unsigned iteration = 0; iteration < 4; ++iteration) {
      UnoTreeResult output;
      std::memset(&output, 0xa5, sizeof(output));
      if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK ||
          std::memcmp(&output, &expected[index], sizeof(output))) return false;
      const auto before = output;
      std::memset(leaves[1], 0xff, 32);
      if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_DECODE ||
          std::memcmp(&output, &before, sizeof(output))) return false;
      std::memset(leaves[1], 0, 32);
      leaves[1][0] = 42;
    }
    return true;
  });
}

int main() {
  if (!concurrent_tree()) return 18;
  UnoTreeFrontier empty{};
  UnoTreeResult output{};
  UnoTreeRequest request{};
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.frontier = &empty;
  if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK) return 1;
  if (output.frontier.next_position != 0) return 2;
  auto empty_result = output;
  uint8_t leaves[3][32]{};
  leaves[0][0] = 1;
  leaves[1][0] = 2;
  leaves[2][0] = 3;
  request.commitments = leaves;
  request.commitment_count = request.max_commitments = 3;
  if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK) return 3;
  if (output.frontier.next_position != 3 || !std::memcmp(output.root, empty_result.root, 32)) return 4;
  const auto batch = output;
  auto frontier = empty;
  request.commitment_count = 1;
  for (size_t i = 0; i < 3; ++i) {
    request.frontier = &frontier;
    request.commitments = leaves + i;
    if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK) return 5;
    frontier = output.frontier;
  }
  if (std::memcmp(&output, &batch, sizeof(output))) return 6;
  // Restore with no appends, including canonical zeroed unused node slots.
  request.frontier = &frontier;
  request.commitments = nullptr;
  request.commitment_count = 0;
  if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK ||
      std::memcmp(&output, &batch, sizeof(output))) return 7;
  auto rejects_without_write = [&]() {
    std::memset(&output, 0xa5, sizeof(output));
    auto sentinel = output;
    return uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK &&
           !std::memcmp(&output, &sentinel, sizeof(output));
  };
  request.commitments = leaves;
  request.commitment_count = 3;
  std::memset(leaves[2], 0xff, 32);
  if (!rejects_without_write()) return 8;
  std::memset(leaves[2], 0, 32);
  leaves[2][0] = 3;
  request.max_commitments = 2;
  if (!rejects_without_write()) return 9;
  request.max_commitments = 3;
  request.reserved_leaves = std::numeric_limits<uint64_t>::max();
  if (!rejects_without_write()) return 10;
  request.reserved_leaves = 0;
  frontier.ommers[31][0] = 1;
  if (!rejects_without_write()) return 11;
  frontier.ommers[31][0] = 0;
  request.profile = 0;
  if (!rejects_without_write()) return 12;
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.commitments = nullptr;
  if (!rejects_without_write()) return 13;
  request.commitments = leaves;
  // The output overlaps a live input, so reject before borrowing or writing it.
  output = batch;
  request.frontier = &output.frontier;
  if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_ARGUMENTS ||
      std::memcmp(&output, &batch, sizeof(output))) return 14;
  request.frontier = &frontier;
  if (uno_crypto_tree_append_v0(nullptr, &output) != UNO_CRYPTO_ARGUMENTS) return 15;
  if (uno_crypto_tree_append_v0(&request, nullptr) != UNO_CRYPTO_ARGUMENTS) return 16;
  if (uno_crypto_tree_append_v0(&request, &output) != UNO_CRYPTO_OK || output.frontier.next_position != 6) return 17;
  return 0;
}
