#ifndef HEADER_at_src_disco_sign_at_sign_tile_h
#define HEADER_at_src_disco_sign_at_sign_tile_h

/* The sign tile provides cryptographic signing services for other tiles.
   It receives signing requests and returns signatures.

   TOS uses Schnorr-variant signatures on Ristretto255 with SHA3-512.

   Security:
   - Private key is loaded in privileged_init before dropping capabilities
   - Stack is marked MADV_DONTDUMP to prevent key leakage in core dumps
   - Key authorization is checked before signing (keyguard)
*/

#include "../at_topo.h"
#include "at/crypto/at_schnorr.h"
#include "at/crypto/at_sha3.h"
#include "at/crypto/at_base58.h"

/* Maximum number of input/output link pairs */
#define AT_SIGN_MAX_IN (32UL)

/* Maximum signing request size */
#define AT_SIGN_REQ_MTU (2048UL)

/* Signing roles - determines what payloads are authorized */
#define AT_SIGN_ROLE_GOSSIP    (0)  /* Gossip protocol messages */
#define AT_SIGN_ROLE_REPAIR    (1)  /* Repair protocol messages */
#define AT_SIGN_ROLE_LEADER    (2)  /* Block production (shred signing) */
#define AT_SIGN_ROLE_VALIDATOR (3)  /* Validator consensus messages */
#define AT_SIGN_ROLE_TXN       (4)  /* Transaction signing */

/* Sign types - what kind of data is being signed */
#define AT_SIGN_TYPE_SCHNORR         (0)  /* Standard TOS Schnorr signature */
#define AT_SIGN_TYPE_SHA3_SCHNORR    (1)  /* Hash with SHA3-256 first, then sign */
#define AT_SIGN_TYPE_PUBKEY_CONCAT   (2)  /* Prepend pubkey to message before signing */

/* Input link context */
typedef struct {
  int         role;
  at_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} at_sign_in_ctx_t;

/* Output link context */
typedef struct {
  at_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} at_sign_out_ctx_t;

/* Sign tile context */
typedef struct {
  /* Buffer for incoming signing request */
  uchar _data[ AT_SIGN_REQ_MTU ];

  /* Identity key (loaded in privileged_init) */
  uchar * public_key;   /* Points into private_key + 32 for Ed25519 format,
                           or separate allocation for TOS format */
  uchar * private_key;

  /* Pre-encoded public key for PUBKEY_CONCAT sign type */
  ulong public_key_base58_sz;
  uchar concat[ AT_BASE58_ENCODED_32_SZ + 1UL + 64UL ];

  /* Input/output link contexts */
  at_sign_in_ctx_t  in[ AT_SIGN_MAX_IN ];
  at_sign_out_ctx_t out[ AT_SIGN_MAX_IN ];

  /* SHA3 context for hashing operations */
  at_sha3_512_t sha3[ 1 ];

  /* Metrics */
  struct {
    ulong sign_cnt;
    ulong sign_fail_cnt;
    ulong unauthorized_cnt;
  } metrics;
} at_sign_ctx_t;

/* at_sign_tile_footprint returns memory required for sign tile */
AT_FN_PURE static inline ulong
at_sign_tile_footprint( void ) {
  ulong l = AT_LAYOUT_INIT;
  l = AT_LAYOUT_APPEND( l, alignof(at_sign_ctx_t), sizeof(at_sign_ctx_t) );
  return AT_LAYOUT_FINI( l, 128UL );
}

#endif /* HEADER_at_src_disco_sign_at_sign_tile_h */