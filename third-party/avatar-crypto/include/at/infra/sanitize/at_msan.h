#ifndef HEADER_at_src_util_sanitize_at_msan_h
#define HEADER_at_src_util_sanitize_at_msan_h

#include "../at_util_base.h"

/* MemorySanitizer (MSan) detects uninitialized access via a global
   bitmap.

   More info on MSan:
     - https://clang.llvm.org/docs/MemorySanitizer.html
     - https://github.com/google/sanitizers/wiki/MemorySanitizer */

/* Based on https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/msan_interface.h

   Part of the LLVM Project, under the Apache License v2.0 with LLVM
   Exceptions.  See https://llvm.org/LICENSE.txt for license
   information.  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

   This file was originally part of MemorySanitizer (MSan). */

#ifndef AT_HAS_MSAN
#if defined(__has_feature)
#define AT_HAS_MSAN __has_feature(memory_sanitizer)
#else
#define AT_HAS_MSAN 0
#endif
#endif

#if AT_HAS_MSAN
#define AT_FN_NO_MSAN __attribute__((no_sanitize("memory")))
#else
#define AT_FN_NO_MSAN
#endif

#define AT_MSAN_ALIGN (4UL)

AT_PROTOTYPES_BEGIN

#if AT_HAS_MSAN

/* These are for internal use only */

void __msan_poison                  ( void const volatile * addr, ulong sz );
void __msan_unpoison                ( void const volatile * addr, ulong sz );
void __msan_check_mem_is_initialized( void const volatile * addr, ulong sz );


/* at_msan_poison marks a region of memory as uninitialized.  MSAN
   detects uninitialized memory when it is used in a conditional branch,
   for memory accesses, as a direct argument to a function call, or
   as a direct return value. */
static inline void * at_msan_poison  ( void *       addr, ulong sz ) { __msan_poison  ( addr, sz ); return addr; }

/* at_msan_unpoison marks a region of memory as initialized.
   Use cases:
   - Marking memory initialized that MSAN can not track, most notably
     memory initialized by handwritten assembly.
   - Avoiding false positives where an uninitialized value is used
     in a scenario described by the  at_msan_poison doc comment, but the
     use is actually correct in the application logic. */
static inline void * at_msan_unpoison( void *       addr, ulong sz ) { __msan_unpoison( addr, sz ); return addr; }

/* at_msan_check checks if a region of memory is initialized.  If it is
   not, MSAN will report an error.  For making sure memory is
   initialized in cases beyond those describe in the at_msan poison
   comment.  Furthermore, it is useful for debugging MSAN crashes. */
static inline void   at_msan_check   ( void const * addr, ulong sz ) { __msan_check_mem_is_initialized( addr, sz ); }

#else

static inline void * at_msan_poison  ( void *       addr, ulong sz ) { (void)sz; return addr; }
static inline void * at_msan_unpoison( void *       addr, ulong sz ) { (void)sz; return addr; }
static inline void   at_msan_check   ( void const * addr, ulong sz ) { (void)addr; (void)sz; }

#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_sanitize_at_msan_h */