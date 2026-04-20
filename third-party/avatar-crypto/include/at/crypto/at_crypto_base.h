#ifndef HEADER_at_src_ballet_at_ballet_base_h
#define HEADER_at_src_ballet_at_ballet_base_h

#include "at/infra/at_util_base.h"

/* AT_TPU_MTU: The maximum size of a transaction in serialized
   wire-protocol form.  This does not count any network-level (e.g. UDP
   or QUIC) headers. */
#define AT_TPU_MTU (1232UL)

/* AT_ALIGN: Default alignment according to platform:
    - avx512     => 64
    - avx        => 32
    - noarch128  => 16
    - noarch(64) =>  8 */

 #if AT_HAS_AVX512
 #define AT_ALIGN (64UL)
 #elif AT_HAS_AVX
 #define AT_ALIGN (32UL)
 #elif AT_HAS_INT128
 #define AT_ALIGN (16UL)
 #else
 #define AT_ALIGN (8UL)
 #endif

 /* AT_ALIGNED: shortcut to compiler aligned attribute with default alignment */
 #define AT_ALIGNED __attribute__((aligned(AT_ALIGN)))

//AT_PROTOTYPES_BEGIN

/* This is currently just a stub in anticipation of future common
   interoperability functionality */

//AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_at_ballet_base_h */