#ifndef HEADER_at_tos_at_txn_encoding_h
#define HEADER_at_tos_at_txn_encoding_h

/* at_txn_encoding.h - Contract entry/hook deterministic encoding.

   TOS-compatible encoding:
   - Entry point: [0x00, entry_low, entry_high] (u16 little-endian)
   - Hook:        [0x01, hook_id]
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

#define AT_ENTRY_POINT_DISCRIMINATOR (0x00u)
#define AT_HOOK_DISCRIMINATOR        (0x01u)

static inline void
at_encode_entry_point( ushort entry_id,
                       uchar  out[3] ) {
  out[0] = (uchar)AT_ENTRY_POINT_DISCRIMINATOR;
  out[1] = (uchar)(entry_id & 0xffu);
  out[2] = (uchar)((entry_id >> 8) & 0xffu);
}

static inline void
at_encode_hook( uchar hook_id,
                uchar out[2] ) {
  out[0] = (uchar)AT_HOOK_DISCRIMINATOR;
  out[1] = hook_id;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_encoding_h */
