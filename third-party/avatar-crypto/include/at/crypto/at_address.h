#ifndef HEADER_at_crypto_at_address_h
#define HEADER_at_crypto_at_address_h

/* at_address.h - TOS-compatible Bech32 address helpers.

   Rust reference: common/src/crypto/address.rs
   Binary payload (before bech32 8->5 conversion):
   [pubkey:32][addr_type:1][integrated_data:0..N]

   addr_type:
   - 0: normal address
   - 1: integrated address with embedded data
*/

#include "at_crypto_base.h"
#include "at_bech32.h"

AT_PROTOTYPES_BEGIN

#define AT_ADDRESS_MAX_INTEGRATED_DATA (128UL) /* TOS EXTRA_DATA_LIMIT_SIZE */

typedef enum {
  AT_ADDRESS_TYPE_NORMAL = 0,
  AT_ADDRESS_TYPE_DATA   = 1
} at_address_type_t;

typedef struct {
  int              mainnet;
  at_address_type_t addr_type;
  uchar            public_key[32];
  uchar            integrated_data[AT_ADDRESS_MAX_INTEGRATED_DATA];
  ulong            integrated_data_sz;
} at_address_t;

int
at_address_new_normal( at_address_t *      out,
                       int                 mainnet,
                       uchar const         public_key[32] );

int
at_address_new_data( at_address_t *      out,
                     int                 mainnet,
                     uchar const         public_key[32],
                     void const *        integrated_data,
                     ulong               integrated_data_sz );

int
at_address_from_string( char const * s,
                        at_address_t * out );

int
at_address_as_string( at_address_t const * address,
                      char *               out,
                      ulong                out_sz );

int
at_address_is_normal( at_address_t const * address );

int
at_address_is_mainnet( at_address_t const * address );

int
at_address_get_public_key( at_address_t const * address,
                           uchar                out[32] );

int
at_address_to_public_key( at_address_t * address,
                          uchar          out[32] );

int
at_address_get_type( at_address_t const * address,
                     at_address_type_t *  out_type );

int
at_address_split( at_address_t *        address,
                  uchar                 out_public_key[32],
                  at_address_type_t *   out_type,
                  void *                out_data,
                  ulong *               out_data_sz );

int
at_address_get_extra_data( at_address_t const * address,
                           void *               out,
                           ulong *              out_sz,
                           int *                has_data_out );

int
at_address_extract_data_only( at_address_t * address,
                              void *         out,
                              ulong *        out_sz,
                              int *          had_data_out );

int
at_address_extract_data( at_address_t const * address,
                         void *               out_data,
                         ulong *              out_data_sz,
                         int *                has_data_out,
                         at_address_t *       out_without_data );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_address_h */
