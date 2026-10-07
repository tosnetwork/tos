#include "tos_v5r2_kdf.h"
#include "sha2_api.h"
#include <string.h>

static void wipe(void *p, size_t size) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  if (v) while (size--) *v++ = 0;
}
/* Internal inputs are bounded: key <= 32, message <= 136 bytes. */
static void hmac(const uint8_t *key, size_t key_size, const uint8_t *msg,
                 size_t msg_size, uint8_t out[32]) {
  uint8_t pad[64], inner[32];
  sha2_256_t hash;
  memset(pad, 0x36, sizeof pad);
  for (size_t i = 0; i < key_size; ++i) pad[i] ^= key[i];
  sha2_256_init(&hash); sha2_256_update(&hash, pad, sizeof pad);
  sha2_256_update(&hash, msg, msg_size); sha2_256_final(&hash, inner);
  memset(pad, 0x5c, sizeof pad);
  for (size_t i = 0; i < key_size; ++i) pad[i] ^= key[i];
  sha2_256_init(&hash); sha2_256_update(&hash, pad, sizeof pad);
  sha2_256_update(&hash, inner, sizeof inner); sha2_256_final(&hash, out);
  wipe(pad, sizeof pad); wipe(inner, sizeof inner); wipe(&hash, sizeof hash);
}
static void be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
int tos_v5r2_derive_and_wipe(int material, uint8_t *master, size_t master_size,
    const uint8_t *network, int32_t global_id, uint32_t account_index,
    uint32_t key_generation, const uint8_t *tree_id, uint8_t *output, size_t output_size) {
  static const uint8_t salt[] = "TOS-WALLET-DUALROOT-KDF-v1";
  const char *label = material == 1 ? "ML-DSA-44" : material == 2 ? "SLH-DSA-SHA2-128s" :
                      material == 3 ? "TOS-FEE-LMS-SHA256-M32-v1" : NULL;
  int result = -1;
  uint8_t info[103] = {0}, input[136] = {0}, prk[32] = {0}, block[32] = {0};
  wipe(output, output_size);
  if (!master || master_size != 32 || !network || !output || !label ||
      output_size != (material == 1 ? 32u : 48u) ||
      (material == 3 ? !tree_id : tree_id != NULL)) goto done;
  const size_t label_size = strlen(label);
  size_t size = 2 + label_size;
  info[0] = 1; info[1] = (uint8_t)label_size;
  memcpy(info + 2, label, label_size); memcpy(info + size, network, 32); size += 32;
  be32(info + size, (uint32_t)global_id); size += 4;
  be32(info + size, account_index); size += 4;
  be32(info + size, key_generation); size += 4;
  if (material == 3) { memcpy(info + size, tree_id, 32); size += 32; }
  hmac(salt, sizeof salt - 1, master, master_size, prk);
  memcpy(input, info, size); input[size] = 1;
  hmac(prk, sizeof prk, input, size + 1, block); memcpy(output, block, 32);
  if (output_size == 48) {
    memcpy(input, block, 32); memcpy(input + 32, info, size); input[32 + size] = 2;
    hmac(prk, sizeof prk, input, 33 + size, block); memcpy(output + 32, block, 16);
  }
  result = 0;
done:
  wipe(master, master_size); wipe(info, sizeof info); wipe(input, sizeof input);
  wipe(prk, sizeof prk); wipe(block, sizeof block);
  return result;
}
