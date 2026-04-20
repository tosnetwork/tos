#ifndef HEADER_at_src_util_simd_at_avx_h
#define HEADER_at_src_util_simd_at_avx_h

#if AT_HAS_AVX

/* An API for writing vectorized C/C++ code using 8-wide 32-bit ints,
   8-wide 32-bit uints, 8-wide 32-bit floats, 4-wide 64-bit doubles,
   4-wide 64-bit longs, 4-wide 64-bit ulongs and 8- or 4-wide logicals
   assuming a platform with AVX support.

   Essentially, all the usual C/C++ operations you can do on an int,
   uint, float, double, long, ulong or logical has a fast O(1)
   vectorized equivalent here.  Most operations boil down to a single
   assembly instruction in most cases and the macros are robust.

   Further operations commonly used to transition from scalar/vector to
   vector/scalar code, to do cross lane data motion, etc are also
   provided to make it much easier to convert scalar implementations
   into highly optimized vectorized implementations.

   That is, this is a thin wrapper around Intel's AVX intrinsics to give
   it a sane type system and robust semantics for writing mixed type and
   mixed width vectorized code (including branching).  This includes a
   lot of non-obvious tricks, fixes for ultra high density of
   irregularities in their intrinsics, implementations of missing
   intrinsics and lots of workarounds to get Intel AVX to behave sanely.

   A side effect is that this API also makes it easy to port code
   vectorized for AVX to non-Intel architectures.  Just make
   implementations of these wrappers for the target platform and then,
   magically, code written in terms of this API has been ported.  (This
   is similar to how CUDA works under the hood.  Developers don't write
   GPU code ... they write CUDA code that is then adapted for the target
   architecture by the CUDA tooling at compile- or run-time.)

   Much like the at_util_base.h primitive types, APIs in here generally
   aren't prefixed with at_ given how aggressively they get used in
   writing compute intensive code.  This is unlikely to matter
   practically given this API is both optional and limited to particular
   build targets (i.e. namespace collisions highly unlikely to occur
   accidentally). */

#include "../bits/at_bits.h"
#include <x86intrin.h> /* Include the intrinsics we are going to patch up */

/* Some useful constants */

#define W_WIDTH         (8) /* Vector width / element count / lanes (32-bit elements) */
#define W_FOOTPRINT    (32) /* Vector byte size */
#define W_ALIGN        (32) /* Vector byte alignment required for aligned operations */
#define W_LG_WIDTH      (3) /* log_2 W_WIDTH */
#define W_LG_FOOTPRINT  (5) /* log_2 W_FOOTPRINT */
#define W_LG_ALIGN      (5) /* log_2 W_ALIGN */
#define W_ATTR         __attribute__((aligned(W_ALIGN)))

/* Include all the APIs */

#include "at_avx_wc.h" /* Vector conditional support */
#include "at_avx_wf.h" /* Vector float support */
#include "at_avx_wi.h" /* Vector int support */
#include "at_avx_wu.h" /* Vector uint support */
#include "at_avx_wd.h" /* Vector double support */
#include "at_avx_wl.h" /* Vector long support */
#include "at_avx_wv.h" /* Vector ulong support */
#include "at_avx_wb.h" /* Vector uchar (byte) support */
#include "at_avx_ws.h" /* Vector short support */
#include "at_avx_wh.h" /* Vector ushort support */

#else
#error "Build target does not support AVX wrappers"
#endif

#endif /* HEADER_at_src_util_simd_at_avx_h */
