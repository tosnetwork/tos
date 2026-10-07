#ifndef TOS_LMS_SHA256_H
#define TOS_LMS_SHA256_H
#include "sha2_api.h"
#include <stddef.h>
#include <stdint.h>
/* SHA API adapter for the existing reference LMS primitive. No external crypto library. */
typedef sha2_256_t SHA256_CTX;
static inline int SHA256_Init(SHA256_CTX *ctx) { sha2_256_init(ctx); return 1; }
static inline int SHA256_Update(SHA256_CTX *ctx, const void *data, size_t size) {
  sha2_256_update(ctx, (const uint8_t *)data, size); return 1;
}
static inline int SHA256_Final(unsigned char *output, SHA256_CTX *ctx) {
  sha2_256_final(ctx, output); return 1;
}
static inline unsigned char *SHA256(const unsigned char *data, size_t size, unsigned char *output) {
  sha2_256(output, data, size); return output;
}
static inline void tos_lms_wipe(void *data, size_t size) {
  volatile uint8_t *p = (volatile uint8_t *)data;
  while (size--) *p++ = 0;
}
static inline int tos_lms_compare(const void *left, const void *right, size_t size) {
  const uint8_t *a = (const uint8_t *)left, *b = (const uint8_t *)right;
  volatile unsigned difference = 0;
  for (size_t i = 0; i < size; ++i) difference |= a[i] ^ b[i];
  return (int)difference;
}
#endif
