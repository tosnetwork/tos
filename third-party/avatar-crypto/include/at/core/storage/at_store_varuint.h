#ifndef HEADER_at_store_varuint_h
#define HEADER_at_store_varuint_h

/* at_store_varuint.h - TOS VarUint helpers for RocksDB storage */

#include "at/infra/at_util_base.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

#define AT_STORE_VARUINT_MAX_LEN  (32U)
#define AT_STORE_VARUINT_MAX_SIZE (33U) /* 1 byte len + 32 bytes */

/* Encode a u64 as TOS VarUint (U256 big-endian with trailing zeros stripped).
   Returns AT_STORE_OK on success. */
int
at_store_varuint_encode_u64( ulong value,
                             uchar * buf,
                             ulong   buf_sz,
                             ulong * out_sz );

/* Decode a TOS VarUint into u64.
   Returns AT_STORE_OK on success; AT_STORE_ERR_CORRUPTION on invalid/overflow. */
int
at_store_varuint_decode_u64( uchar const * buf,
                             ulong         buf_sz,
                             ulong       * value_out,
                             ulong       * bytes_read_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_varuint_h */
