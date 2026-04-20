#ifndef HEADER_at_src_util_sanitize_at_sanitize_h
#define HEADER_at_src_util_sanitize_at_sanitize_h

/* APIs provided by compiler sanitizers.

   Sanitizers are error detection tools built from a combination of
   hardware facilities, hooks injected into compiled code, special
   memory mappings, and library functions.

   For example, the AddressSanitizer can be used to detect out-of-bounds
   memory accesses that otherwise don't crash a process and various
   other undefined behavior. */

#include "at_asan.h"
#include "at_msan.h"

#endif /* HEADER_at_src_util_sanitize_at_sanitize_h */