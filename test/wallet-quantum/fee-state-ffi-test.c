#ifdef NDEBUG
#undef NDEBUG
#endif
#include "tos_fee_state.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  assert(argc == 2); /* Caller supplies an existing private fixture directory. */
  uint8_t network[32], vault[32], tree[32], digest[32];
  memset(network, 1, 32); memset(vault, 2, 32); memset(tree, 3, 32); memset(digest, 9, 32);
  uint64_t handle = 0, other = 99, receipt = 99;
  uint32_t leaf = 99;
  const uint8_t *path = (const uint8_t *)argv[1];
  assert(tos_fee_state_open(path, strlen(argv[1]), 42, network, vault, tree, 100, 100, &handle) == 0);
  assert(handle != 0);
  assert(tos_fee_state_open(path, strlen(argv[1]), 42, network, vault, tree, 100, 100, &other) == -2 && other == 0);
  assert(tos_fee_state_preview(handle, 100, 0, &leaf) == -2 && leaf == UINT32_MAX);
  assert(tos_fee_state_preview(handle, 3700, 0, &leaf) == 0 && leaf == 4);
  assert(tos_fee_state_reserve(handle, 3700, 0, 5, digest, &receipt) == -2 && receipt == 0);
  assert(tos_fee_state_reserve(handle, 3700, 0, 4, digest, &receipt) == 0 && receipt != 0);
  assert(tos_fee_state_close(handle) == 0);
  assert(tos_fee_state_preview(handle, 7300, 0, &leaf) == -1 && leaf == UINT32_MAX);
  assert(tos_fee_state_open(path, strlen(argv[1]), 42, network, vault, tree, 100, 3700, &other) == 0 && other != handle);
  assert(tos_fee_state_preview(other, 3700, 0, &leaf) == -2);
  assert(tos_fee_state_preview(other, 7300, 0, &leaf) == 0 && leaf == 8);
  assert(tos_fee_state_close(other) == 0);
  puts("fee state C ABI: locked ownership, durable reservation and restore barrier pass");
  return 0;
}
