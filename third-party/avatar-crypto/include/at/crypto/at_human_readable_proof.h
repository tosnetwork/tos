#ifndef HEADER_at_crypto_at_human_readable_proof_h
#define HEADER_at_crypto_at_human_readable_proof_h

/* at_human_readable_proof.h - Shareable UNO proof envelope encoding.

   Format (binary payload before Bech32):
   [kind:1][proof_sz:2][proof_bytes:*][asset:32][topoheight:8]

   Bech32 HRP prefix matches TOS Rust: "proof".
*/

#include "at_crypto_base.h"
#include "at_bech32.h"

AT_PROTOTYPES_BEGIN

#define AT_HUMAN_PROOF_PREFIX "proof"
#define AT_HUMAN_PROOF_MAX_BYTES (2048UL)

typedef enum {
  AT_HUMAN_PROOF_KIND_BALANCE   = 0,
  AT_HUMAN_PROOF_KIND_OWNERSHIP = 1,
} at_human_proof_kind_t;

typedef struct {
  uchar kind;                  /* at_human_proof_kind_t */
  ushort proof_sz;
  uchar proof[AT_HUMAN_PROOF_MAX_BYTES];
  uchar asset[32];
  ulong topoheight;
} at_human_readable_proof_t;

/* Pack/unpack binary representation. */
int
at_human_proof_pack( uchar *                              out,
                     ulong *                              out_sz,
                     at_human_readable_proof_t const *    proof );

int
at_human_proof_unpack( at_human_readable_proof_t * out,
                       uchar const *               in,
                       ulong                       in_sz );

/* Convert to/from shareable Bech32 string with "proof" prefix. */
int
at_human_proof_as_string( char *                               out,
                          ulong                                out_sz,
                          at_human_readable_proof_t const *    proof );

int
at_human_proof_from_string( at_human_readable_proof_t * out,
                            char const *                s );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_human_readable_proof_h */

