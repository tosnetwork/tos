/* Test-only LMS (RFC 8554) key generation from SEED and I (Appendix A) and signing, for the
 * fee profile LMOTS_SHA256_N32_W4 with any height. PUBLIC TEST DATA only: no secret hygiene,
 * no durable signer state. Leaves are computed in parallel.
 *
 *   lms_tool keygen <seed64hex> <I32hex> <h> <treefile>     prints the HSS (L = 1) public key
 *   lms_tool sign <seed64hex> <I32hex> <h> <treefile> <q> <msgfile> <C64hex> <sigfile>
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 32
#define P 67
#define W 4
#define LS 4
#define LMS_TYPE(h) ((h) == 5 ? 5 : (h) == 10 ? 6 : (h) == 15 ? 7 : (h) == 20 ? 8 : 0)

static uint8_t SEED[32], I[16];
static unsigned H;
static uint8_t *tree; /* 2^(H+1) nodes of N bytes, index 1 is the root */

static int unhex(const char *s, uint8_t *out, size_t len) {
  if (strlen(s) != 2 * len) return -1;
  for (size_t i = 0; i < len; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
    out[i] = (uint8_t)v;
  }
  return 0;
}

/* The low-level interface: the one-shot SHA256() fetches a provider context per call, which
 * serializes the parallel key generation on a lock. */
static void sha256(const uint8_t *in, size_t len, uint8_t *out) {
  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, in, len);
  SHA256_Final(out, &c);
}

static void u32(uint8_t *p, uint32_t v) {
  p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static void x_key(uint32_t q, uint16_t i, uint8_t out[N]) {
  uint8_t buf[16 + 4 + 2 + 1 + 32];
  memcpy(buf, I, 16); u32(buf + 16, q); buf[20] = i >> 8; buf[21] = i; buf[22] = 0xff;
  memcpy(buf + 23, SEED, 32);
  sha256(buf, sizeof buf, out);
}

static void chain(uint32_t q, uint16_t i, uint8_t tmp[N], unsigned from, unsigned to) {
  uint8_t buf[16 + 4 + 2 + 1 + N];
  memcpy(buf, I, 16); u32(buf + 16, q); buf[20] = i >> 8; buf[21] = i;
  for (unsigned j = from; j < to; j++) {
    buf[22] = (uint8_t)j;
    memcpy(buf + 23, tmp, N);
    sha256(buf, sizeof buf, tmp);
  }
}

static void leaf(uint32_t q, uint8_t out[N]) {
  uint8_t kin[16 + 4 + 2 + P * N], k[N];
  memcpy(kin, I, 16); u32(kin + 16, q); kin[20] = 0x80; kin[21] = 0x80;
  for (uint16_t i = 0; i < P; i++) {
    uint8_t tmp[N];
    x_key(q, i, tmp);
    chain(q, i, tmp, 0, (1u << W) - 1);
    memcpy(kin + 22 + i * N, tmp, N);
  }
  sha256(kin, sizeof kin, k);
  uint8_t lin[16 + 4 + 2 + N];
  memcpy(lin, I, 16); u32(lin + 16, (1u << H) + q); lin[20] = 0x82; lin[21] = 0x82;
  memcpy(lin + 22, k, N);
  sha256(lin, sizeof lin, out);
}

struct job { uint32_t from, to; };

static void *leaves(void *arg) {
  struct job *j = arg;
  for (uint32_t q = j->from; q < j->to; q++) leaf(q, tree + ((size_t)(1u << H) + q) * N);
  return NULL;
}

static int build(const char *path) {
  size_t nodes = (size_t)2 << H;
  tree = calloc(nodes, N);
  if (!tree) return -1;
  FILE *f = fopen(path, "rb");
  if (f) {
    size_t got = fread(tree, N, nodes, f);
    fclose(f);
    if (got == nodes) return 0;
  }
  enum { T = 64 };
  pthread_t th[T];
  struct job jobs[T];
  uint32_t count = 1u << H, per = (count + T - 1) / T;
  for (int t = 0; t < T; t++) {
    jobs[t].from = t * per < count ? t * per : count;
    jobs[t].to = (t + 1) * per < count ? (t + 1) * per : count;
    if (pthread_create(&th[t], NULL, leaves, &jobs[t])) return -1;
  }
  for (int t = 0; t < T; t++) pthread_join(th[t], NULL);
  for (uint32_t r = count - 1; r >= 1; r--) {
    uint8_t in[16 + 4 + 2 + 2 * N];
    memcpy(in, I, 16); u32(in + 16, r); in[20] = 0x83; in[21] = 0x83;
    memcpy(in + 22, tree + (size_t)2 * r * N, 2 * N);
    sha256(in, sizeof in, tree + (size_t)r * N);
  }
  f = fopen(path, "wb");
  if (!f || fwrite(tree, N, nodes, f) != nodes) return -1;
  return fclose(f);
}

static unsigned coef(const uint8_t *s, unsigned i) {
  return (s[(i * W) / 8] >> (8 - (W * (i % (8 / W)) + W))) & ((1u << W) - 1);
}

int main(int argc, char **argv) {
  if (argc < 6 || unhex(argv[2], SEED, 32) || unhex(argv[3], I, 16)) return 1;
  H = (unsigned)atoi(argv[4]);
  if (!LMS_TYPE(H)) return 1;
  if (build(argv[5])) return 2;
  if (!strcmp(argv[1], "keygen") && argc == 6) {
    printf("00000001%08x%08x", LMS_TYPE(H), 3);
    for (int i = 0; i < 16; i++) printf("%02x", I[i]);
    for (int i = 0; i < N; i++) printf("%02x", tree[N + i]);
    printf("\n");
    return 0;
  }
  if (!strcmp(argv[1], "sign") && argc == 10) {
    uint32_t q = (uint32_t)strtoul(argv[6], NULL, 10);
    uint8_t C[N], msg[8192], sig[4 + 4 + 4 + N + P * N + 4 + 20 * N];
    if (q >= (1u << H) || unhex(argv[8], C, N)) return 1;
    FILE *f = fopen(argv[7], "rb");
    if (!f) return 2;
    size_t m = fread(msg, 1, sizeof msg, f);
    fclose(f);
    uint8_t *qin = malloc(16 + 4 + 2 + N + m), qd[N + 2];
    if (!qin) return 2;
    memcpy(qin, I, 16); u32(qin + 16, q); qin[20] = 0x81; qin[21] = 0x81;
    memcpy(qin + 22, C, N); memcpy(qin + 22 + N, msg, m);
    sha256(qin, 22 + N + m, qd);
    free(qin);
    unsigned sum = 0;
    for (unsigned i = 0; i < N * 8 / W; i++) sum += (1u << W) - 1 - coef(qd, i);
    sum <<= LS;
    qd[N] = sum >> 8; qd[N + 1] = sum;
    uint8_t *s = sig;
    u32(s, 0); u32(s + 4, q); u32(s + 8, 3); memcpy(s + 12, C, N);
    for (uint16_t i = 0; i < P; i++) {
      uint8_t tmp[N];
      x_key(q, i, tmp);
      chain(q, i, tmp, 0, coef(qd, i));
      memcpy(s + 12 + N + i * N, tmp, N);
    }
    uint8_t *t = s + 12 + N + P * N;
    u32(t, LMS_TYPE(H));
    uint32_t node = (1u << H) + q;
    for (unsigned i = 0; i < H; i++, node /= 2) memcpy(t + 4 + i * N, tree + (size_t)(node ^ 1) * N, N);
    size_t len = 12 + N + P * N + 4 + H * N;
    f = fopen(argv[9], "wb");
    if (!f || fwrite(sig, 1, len, f) != len) return 2;
    return fclose(f) ? 2 : 0;
  }
  return 1;
}
