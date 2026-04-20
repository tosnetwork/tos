#ifndef HEADER_at_src_util_at_util_base_h
#define HEADER_at_src_util_at_util_base_h

/* Base development environment */

/* Compiler checks ****************************************************/

#ifdef __cplusplus

#if __cplusplus<201703L
#error "Reference requires C++17 or later"
#endif

#else

#if __STDC_VERSION__<201710L
#error "Reference requires C Standard version C17 or later"
#endif

#endif //__cplusplus

/* Build target capabilities ******************************************/

/* Different build targets often have different levels of support for
   various language and hardware features.  The presence of various
   features can be tested at preprocessor, compile, or run time via the
   below capability macros.

   Code that does not exploit any of these capabilities written within
   the base development environment should be broadly portable across a
   range of build targets ranging from on-chain virtual machines to
   commodity hosts to custom hardware.

   As such, highly portable yet high performance code is possible by
   writing generic implementations that do not exploit any of the below
   capabilities as a portable fallback along with build target specific
   optimized implementations that are invoked when the build target
   supports the appropriate capabilities.

   The base development itself provide lots of functionality to help
   with implementing portable fallbacks while making very minimal
   assumptions about the build targets and zero use of 3rd party
   libraries (these might make unknown additional assumptions about the
   build target, including availability of a quality implementation of
   the library on the build target). */

/* AT_HAS_HOSTED:  If the build target is hosted (e.g. resides on a host
   with a POSIX-ish environment ... practically speaking, stdio.h,
   stdlib.h, unistd.h, et al more or less behave normally ...
   pedantically XOPEN_SOURCE=700), AT_HAS_HOSTED will be 1.  It will be
   zero otherwise. */

#ifndef AT_HAS_HOSTED
#define AT_HAS_HOSTED 0
#endif

/* AT_HAS_ATOMIC:  If the build target supports atomic operations
   between threads accessing a common memory region (include threads
   that reside in different processes on a host communicating via a
   shared memory region with potentially different local virtual
   mappings).  Practically speaking, does atomic compare-and-swap et al
   work? */

#ifndef AT_HAS_ATOMIC
#define AT_HAS_ATOMIC 0
#endif

/* AT_HAS_THREADS:  If the build target supports a POSIX-ish notion of
   threads (e.g. practically speaking, global variables declared within
   a compile unit are visible to more than one thread of execution,
   pthreads.h / threading parts of C standard, the atomics parts of the
   C standard, ... more or less work normally), AT_HAS_THREADS will be
   1.  It will be zero otherwise.  AT_HAS_THREADS implies AT_HAS_HOSTED
   and AT_HAS_ATOMIC. */

#ifndef AT_HAS_THREADS
#define AT_HAS_THREADS 0
#endif

/* AT_HAS_INT128:  If the build target supports reasonably efficient
   128-bit wide integer operations, define AT_HAS_INT128 to 1 to enable
   use of them in implementations. */

#ifndef AT_HAS_INT128
#define AT_HAS_INT128 0
#endif

/* AT_HAS_DOUBLE:  If the build target supports reasonably efficient
   IEEE 754 64-bit wide double precision floating point options, define
   AT_HAS_DOUBLE to 1 to enable use of them in implementations.  Note
   that even if the build target does not, va_args handling in the C /
   C++ language requires promotion of a float in an va_arg list to a
   double.  Thus, C / C++ language that support IEEE 754 float also
   implies a minimum level of support for double (though not necessarily
   efficient or IEEE 754).  That is, even if a target does not have
   AT_HAS_DOUBLE, there might still be limited use of double in va_arg
   list handling. */

#ifndef AT_HAS_DOUBLE
#define AT_HAS_DOUBLE 0
#endif

/* AT_HAS_ALLOCA:  If the build target supports fast alloca-style
   dynamic stack memory allocation (e.g. alloca.h / __builtin_alloca
   more or less work normally), define AT_HAS_ALLOCA to 1 to enable use
   of it in implementations. */

#ifndef AT_HAS_ALLOCA
#if defined(__GNUC__) || defined(__clang__)
#define AT_HAS_ALLOCA 1
#else
#define AT_HAS_ALLOCA 0
#endif
#endif

/* AT_HAS_X86:  If the build target supports x86 specific features and
   can benefit from x86 specific optimizations, define AT_HAS_X86.  Code
   needing more specific target features (Intel / AMD / SSE / AVX2 /
   AVX512 / etc) can specialize further as necessary with even more
   precise capabilities (that in turn imply AT_HAS_X86). */

#ifndef AT_HAS_X86
#define AT_HAS_X86 0
#endif

/* These allow even more precise targeting for X86. */

/* AT_HAS_SSE indicates the target supports Intel SSE4 style SIMD
   (basically do the 128-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/at_sse.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies AT_HAS_X86. */

#ifndef AT_HAS_SSE
#define AT_HAS_SSE 0
#endif

/* AT_HAS_AVX indicates the target supports Intel AVX2 style SIMD
   (basically do the 256-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/at_avx.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies AT_HAS_SSE. */

#ifndef AT_HAS_AVX
#define AT_HAS_AVX 0
#endif

/* AT_HAS_AVX512 indicates the target supports Intel AVX-512 style SIMD
   (basically do the 512-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/at_avx512.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies AT_HAS_AVX. */

#ifndef AT_HAS_AVX512
#define AT_HAS_AVX512 0
#endif

/* AT_HAS_SHANI indicates that the target supports Intel SHA extensions
   which accelerate SHA-1 and SHA-256 computation.  This extension is
   also called SHA-NI or SHA_NI (Secure Hash Algorithm New
   Instructions).  Although proposed in 2013, they're only supported on
   Intel Ice Lake and AMD Zen CPUs and newer.  Implies AT_HAS_AVX. */

#ifndef AT_HAS_SHANI
#define AT_HAS_SHANI 0
#endif

/* AT_HAS_GFNI indicates that the target supports Intel Galois Field
   extensions, which accelerate operations over binary extension fields,
   especially GF(2^8).  These instructions are supported on Intel Ice
   Lake and newer and AMD Zen4 and newer CPUs.  Implies AT_HAS_AVX. */

#ifndef AT_HAS_GFNI
#define AT_HAS_GFNI 0
#endif

/* AT_HAS_AESNI indicates that the target supports AES-NI extensions,
   which accelerate AES encryption and decryption.  While AVX predates
   the original AES-NI extension, the combination of AES-NI+AVX adds
   additional opcodes (such as vaesenc, a more flexible variant of
   aesenc).  Thus, implies AT_HAS_AVX.  A conservative estimate for
   minimum platform support is Intel Haswell or AMD Zen. */

#ifndef AT_HAS_AESNI
#define AT_HAS_AESNI 0
#endif

/* AT_HAS_ARM:  If the build target supports armv8-a specific features
   and can benefit from aarch64 specific optimizations, define
   AT_HAS_ARM. */

#ifndef AT_HAS_ARM
#define AT_HAS_ARM 0
#endif

/* AT_HAS_ARM_SHA indicates that the target supports ARMv8 SHA256
   Crypto Extensions (vsha256hq_u32 etc.), which accelerate SHA-256
   computation.  All Apple Silicon (M1/M2/M3/M4) and many ARM
   Cortex-A cores support these instructions. */

#ifndef AT_HAS_ARM_SHA
#define AT_HAS_ARM_SHA 0
#endif

/* AT_HAS_LZ4 indicates that the target supports LZ4 compression.
   Roughly, does "#include <lz4.h>" and the APIs therein work? */

#ifndef AT_HAS_LZ4
#define AT_HAS_LZ4 0
#endif

/* AT_HAS_ZSTD indicates that the target supports ZSTD compression.
   Roughly, does "#include <zstd.h>" and the APIs therein work? */

#ifndef AT_HAS_ZSTD
#define AT_HAS_ZSTD 1
#endif

/* AT_HAS_COVERAGE indicates that the build target is built with coverage instrumentation. */

#ifndef AT_HAS_COVERAGE
#define AT_HAS_COVERAGE 0
#endif

/* AT_HAS_ASAN indicates that the build target is using ASAN. */

#ifndef AT_HAS_ASAN
#define AT_HAS_ASAN 0
#endif

/* AT_HAS_UBSAN indicates that the build target is using UBSAN. */

#ifndef AT_HAS_UBSAN
#define AT_HAS_UBSAN 0
#endif

/* AT_HAS_DEEPASAN indicates that the build target is using ASAN with manual
   memory poisoning for at_alloc, at_wksp, and at_scratch. */

#ifndef AT_HAS_DEEPASAN
#define AT_HAS_DEEPASAN 0
#endif

/* Base development environment ***************************************/

/* The functionality provided by these vanilla headers are always
   available within the base development environment.  Notably, stdio.h
   / stdlib.h / et al at are not included here as these make lots of
   assumptions about the build target that may not be true (especially
   for on-chain and custom hardware use).  Code should prefer the fd
   util equivalents for such functionality when possible. */

#include <stdalign.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <float.h>

/* Work around some library naming irregularities */
/* FIXME: Consider this for FLOAT/FLT, DOUBLE/DBL too? */

#define  SHORT_MIN  SHRT_MIN
#define  SHORT_MAX  SHRT_MAX
#define USHORT_MAX USHRT_MAX

/* Primitive types ****************************************************/

/* These typedefs provide single token regularized names for all the
   primitive types in the base development environment:

     char !
     schar !   short   int   long   int128 !!
     uchar    ushort  uint  ulong  uint128 !!
     float
     double !!!

   ! Does not assume the sign of char.  A naked char should be treated
     as cstr character and mathematical operations should be avoided on
     them.  This is less than ideal as the patterns for integer types in
     the C/C++ language spec itself are far more consistent with a naked
     char naturally being treated as signed (see above).  But there are
     lots of conflicts between architectures, languages and standard
     libraries about this so any use of a naked char shouldn't assume
     the sign ... sigh.

   !! Only available if AT_HAS_INT128 is defined

   !!! Should only used if AT_HAS_DOUBLE is defined but see note in
       AT_HAS_DOUBLE about C/C++ silent promotions of float to double in
       va_arg lists.

   Note also that these token names more naturally interoperate with
   integer constant declarations, type generic code generation
   techniques, with printf-style format strings than the stdint.h /
   inttypes.h handling.

   To minimize portability issues, unexpected silent type conversion
   issues, align with typical developer implicit usage, align with
   typical build target usage, ..., assumes char / short / int / long
   are 8 / 16 / 32 / 64 twos complement integers and float is IEEE-754
   single precision.  Further assumes little endian, truncating signed
   integer division, sign extending (arithmetic) signed right shift and
   signed left shift behaves the same as an unsigned left shift from bit
   operations point of view (technically the standard says signed left
   shift is undefined if the result would overflow).  Also, except for
   int128/uint128, assumes that aligned access to these will be
   naturally atomic.  Lastly assumes that unaligned access to these is
   functionally valid but does not assume that unaligned access to these
   is efficient or atomic.

   For values meant to be held in registers, code should prefer long /
   ulong types (improves asm generation given the prevalence of 64-bit
   targets and also to avoid lots of tricky bugs with silent promotions
   in the language ... e.g. ushort should ideally only be used for
   in-memory representations).

   These are currently not prefixed given how often they are used.  If
   this becomes problematic prefixes can be added as necessary.
   Specifically, C++ allows typedefs to be defined multiple times so
   long as they are equivalent.  Inequivalent collisions are not
   supported but should be rare (e.g. if a 3rd party header thinks
   "ulong" should be something other an "unsigned long", the 3rd party
   header probably should be nuked from orbit).  C11 and forward also
   allow multiple equivalent typedefs.  C99 and earlier don't but this
   is typically only a warning and then only if pedantic warnings are
   enabled.  Thus, if we want to support users using C99 and earlier who
   want to do a strict compile and have a superfluous collision with
   these types in other libraries, uncomment the below (or do something
   equivalent for the compiler). */

//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wpedantic"

typedef signed char schar; /* See above note of sadness */

typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

#if AT_HAS_INT128

__extension__ typedef          __int128  int128;
__extension__ typedef unsigned __int128 uint128;

#define UINT128_MAX (~(uint128)0)
#define  INT128_MAX ((int128)(UINT128_MAX>>1))
#define  INT128_MIN (-INT128_MAX-(int128)1)

#endif

//#pragma GCC diagnostic pop

/* Compiler tricks ****************************************************/

/* AT_STRINGIFY,AT_CONCAT{2,3,4}:  Various macros for token
   stringification and pasting.  AT_STRINGIFY returns the argument as a
   cstr (e.g. AT_STRINGIFY(foo) -> "foo").  AT_CONCAT* pastes the tokens
   together into a single token (e.g.  AT_CONCAT3(a,b,c) -> abc).  The
   EXPAND variants first expand their arguments and then do the token
   operation (e.g.  AT_EXPAND_THEN_STRINGIFY(__LINE__) -> "104" if done
   on line 104 of the source code file). */

#define AT_STRINGIFY(x)#x
#define AT_CONCAT2(a,b)a##b
#define AT_CONCAT3(a,b,c)a##b##c
#define AT_CONCAT4(a,b,c,d)a##b##c##d

#define AT_EXPAND_THEN_STRINGIFY(x)AT_STRINGIFY(x)
#define AT_EXPAND_THEN_CONCAT2(a,b)AT_CONCAT2(a,b)
#define AT_EXPAND_THEN_CONCAT3(a,b,c)AT_CONCAT3(a,b,c)
#define AT_EXPAND_THEN_CONCAT4(a,b,c,d)AT_CONCAT4(a,b,c,d)

/* AT_VA_ARGS_SELECT(__VA_ARGS__,e32,e31,...e1):  Macro that expands to
   en at compile time where n is number of items in the __VA_ARGS__
   list.  If __VA_ARGS__ is empty, returns e1.  Assumes __VA_ARGS__ has
   at most 32 arguments.  Useful for making a variadic macro whose
   behavior depends on the number of arguments in __VA_ARGS__. */

#define AT_VA_ARGS_SELECT(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,a,b,c,d,e,f,_,...)_

/* AT_SRC_LOCATION returns a const cstr holding the line of code where
   AT_SRC_LOCATION was used. */

#define AT_SRC_LOCATION __FILE__ "(" AT_EXPAND_THEN_STRINGIFY(__LINE__) ")"

/* AT_STATIC_ASSERT tests at compile time if c is non-zero.  If not,
   it aborts the compile with an error.  err itself should be a token
   (e.g. not a string, no whitespace, etc). */

#ifdef __cplusplus
#define AT_STATIC_ASSERT(c,err) static_assert(c, #err)
#else
#define AT_STATIC_ASSERT(c,err) _Static_assert(c, #err)
#endif

/* AT_ADDRESS_OF_PACKED_MEMBER(x):  Linguistically does &(x) but without
   recent compiler complaints that &x might be unaligned if x is a
   member of a packed datastructure.  (Often needed for interfacing with
   hardware / packets / etc.) */

#define AT_ADDRESS_OF_PACKED_MEMBER( x ) (__extension__({                                      \
    char * _at_aopm = (char *)&(x);                                                            \
    __asm__( "# AT_ADDRESS_OF_PACKED_MEMBER(" #x ") @" AT_SRC_LOCATION : "+r" (_at_aopm) :: ); \
    (__typeof__(&(x)))_at_aopm;                                                                \
  }))

/* AT_PROTOTYPES_{BEGIN,END}:  Headers that might be included in C++
   source should encapsulate the prototypes of code and globals
   contained in compilation units compiled as C with a
   AT_PROTOTYPE_{BEGIN,END} pair. */

#ifdef __cplusplus
#define AT_PROTOTYPES_BEGIN extern "C" {
#else
#define AT_PROTOTYPES_BEGIN
#endif

#ifdef __cplusplus
#define AT_PROTOTYPES_END }
#else
#define AT_PROTOTYPES_END
#endif

/* AT_ASM_LG_ALIGN(lg_n) expands to an alignment assembler directive
   appropriate for the current architecture/ABI.  The resulting align
   is 2^(lg_n) bytes, i.e. AT_ASM_LG_ALIGN(3) aligns by 8 bytes. */

#if defined(__aarch64__)
#define AT_ASM_LG_ALIGN(lg_n) ".align " #lg_n "\n"
#elif defined(__x86_64__) || defined(__powerpc64__) || defined(__riscv)
#define AT_ASM_LG_ALIGN(lg_n) ".p2align " #lg_n "\n"
#endif

/* AT_IMPORT declares a variable name and initializes with the contents
   of the file at path (with potentially some assembly directives for
   additional footer info).  It is equivalent to:

     type const name[] __attribute__((aligned(align))) = {

       ... code that would initialize the contents of name to the
       ... raw binary data found in the file at path at compile time
       ... (with any appended information as specified by footer)

     };

     ulong const name_sz = ... number of bytes pointed to by name;

   More precisely, this creates a symbol "name" in the object file that
   points to a read-only copy of the raw data in the file at "path" as
   it was at compile time.  2^lg_align specifies the minimum alignment
   required for the copy's first byte as an unsuffixed decimal integer.
   footer are assembly commands to permit additional data to be appended
   to the copy (use "" for footer if no footer is necessary).

   Then it exposes a pointer to this copy in the current compilation
   unit as name and the byte size as name_sz.  name_sz covers the first
   byte of the included data to the last byte of the footer inclusive.

   The dummy linker symbol _at_import_name_sz will also be created in
   the object file as some under the hood magic to make this work.  This
   should not be used in any compile unit as some compilers (I'm looking
   at you clang-15, but apparently not clang-10) will sometimes mangle
   its value from what it was set to in the object file even marked as
   absolute in the object file.

   This should only be used at global scope and should be done at most
   once over all object files / libraries used to make a program.  If
   other compilation units want to make use of an import in a different
   compilation unit, they should declare:

     extern type const name[] __attribute__((aligned(align)));

   and/or:

     extern ulong const name_sz;

   as necessary (that is, do the usual to use name and name_sz as shown
   for the pseudo code above).

   Important safety tip!  gcc -M will generally not detect the
   dependency this creates between the importing file and the imported
   file.  This can cause incremental builds to miss changes to the
   imported file.  Ideally, we would have AT_IMPORT automatically do
   something like:

     _Pragma( "GCC dependency \"" path "\" )

   This doesn't work as is because _Pragma needs some macro expansion
   hacks to accept this (this is doable).  After that workaround, this
   still doesn't work because, due to tooling limitations, the pragma
   path is relative to the source file directory and the AT_IMPORT path
   is relative to the make directory (working around this would
   require a __FILE__-like directive for the source code directory base
   path).  Even if that did exist, it might still not work because
   out-of-tree builds often require some substitutions to the gcc -M
   generated dependencies that this might not pick up (at least not
   without some build system surgery).  And then it still wouldn't work
   because gcc -M seems to ignore all of this anyways (which is the
   actual show stopper as this pragma does something subtly different
   than what the name suggests and there isn't any obvious support for a
   "pseudo-include".)  Another reminder that make clean and fast builds
   are our friend. */

#if defined(__ELF__)

#define AT_IMPORT( name, path, type, lg_align, footer )      \
  __asm__( ".section .rodata,\"a\",@progbits\n"              \
           ".type " #name ",@object\n"                       \
           ".globl " #name "\n"                              \
           AT_ASM_LG_ALIGN(lg_align)                         \
           #name ":\n"                                       \
           ".incbin \"" path "\"\n"                          \
           footer "\n"                                       \
           ".size " #name ",. - " #name "\n"                 \
           "_at_import_" #name "_sz = . - " #name "\n"       \
           ".type " #name "_sz,@object\n"                    \
           ".globl " #name "_sz\n"                           \
           AT_ASM_LG_ALIGN(3)                                \
           #name "_sz:\n"                                    \
           ".quad _at_import_" #name "_sz\n"                 \
           ".size " #name "_sz,8\n"                          \
           ".previous\n" );                                  \
  extern type  const name[] __attribute__((aligned(1<<(lg_align)))); \
  extern ulong const name##_sz

#elif defined(__MACH__)

#define AT_IMPORT( name, path, type, lg_align, footer )      \
  __asm__( ".section __DATA,__const\n"                       \
           ".globl _" #name "\n"                             \
           AT_ASM_LG_ALIGN(lg_align)                         \
           "_" #name ":\n"                                   \
           ".incbin \"" path "\"\n"                          \
           footer "\n"                                       \
           "_at_import_" #name "_sz = . - _" #name "\n"      \
           ".globl _" #name "_sz\n"                          \
           AT_ASM_LG_ALIGN(3)                                \
           "_" #name "_sz:\n"                                \
           ".quad _at_import_" #name "_sz\n"                 \
           ".previous\n" );                                  \
  extern type  const name[] __attribute__((aligned(1<<(lg_align)))); \
  extern ulong const name##_sz

#endif

/* AT_IMPORT_{BINARY,CSTR} are common cases for AT_IMPORT.

   In BINARY, the file is imported into the object file and exposed to
   the caller as a uchar binary data.  name_sz will be the number of
   bytes in the file at time of import.  name will have 128 byte
   alignment.

   In CSTR, the file is imported into the object caller with a '\0'
   termination appended and exposed to the caller as a cstr.  Assuming
   the file is text (i.e. has no internal '\0's), strlen(name) will the
   number of bytes in the file and name_sz will be strlen(name)+1.  name
   can have arbitrary alignment. */

#ifdef AT_IMPORT
#define AT_IMPORT_BINARY(name, path) AT_IMPORT( name, path, uchar, 7, ""        )
#define AT_IMPORT_CSTR(  name, path) AT_IMPORT( name, path,  char, 1, ".byte 0" )
#endif

/* Optimizer tricks ***************************************************/

/* AT_RESTRICT is a pointer modifier for to designate a pointer as
   restricted.  Hoops jumped because C++-17 still doesn't understand
   restrict ... sigh */

#ifndef AT_RESTRICT
#ifdef __cplusplus
#define AT_RESTRICT __restrict
#else
#define AT_RESTRICT restrict
#endif
#endif

/* at_type_pun(p), at_type_pun_const(p):  These allow use of type
   punning while keeping strict aliasing optimizations enabled (e.g.
   some UNIX APIs, like sockaddr related APIs are dependent on type
   punning).  These allow these API's to be used cleanly while keeping
   strict aliasing optimizations enabled and strict alias checking done. */

static inline void *
at_type_pun( void * p ) {
  __asm__( "# at_type_pun @" AT_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

static inline void const *
at_type_pun_const( void const * p ) {
  __asm__( "# at_type_pun_const @" AT_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

/* AT_{LIKELY,UNLIKELY}(c):  Evaluates c and returns whether it is
   logical true/false as long (1L/0L).  It also hints to the optimizer
   whether it should optimize for the case of c evaluating as
   true/false. */

#define AT_LIKELY(c)   __builtin_expect( !!(c), 1L )
#define AT_UNLIKELY(c) __builtin_expect( !!(c), 0L )

/* AT_FN_PURE hints to the optimizer that the function, roughly
   speaking, does not have side effects.  As such, the compiler can
   replace a call to the function with the result of an earlier call to
   that function provide the inputs and memory used hasn't changed.

   IMPORTANT SAFETY TIP!  Recent compilers seem to take an undocumented
   and debatable stance that pure functions do no writes to memory.
   This is a sufficient condition for the above but not a necessary one.

   Consider, for example, the real world case of an otherwise pure
   function that uses pass-by-reference to return more than one value
   (an unpleasant practice that is sadly often necessary because C/C++,
   compilers and underlying platform ABIs are very bad at helping
   developers simply and clearly express their intent to return multiple
   values and then generate good assembly for such).

   If called multiple times sequentially, all but the first call to such
   a "pure" function could be optimized away because the non-volatile
   memory writes done in the all but the 1st call for the
   pass-by-reference-returns write the same value to normal memory that
   was written on the 1st call.  That is, these calls return the same
   value for their direct return and do writes that do not have any
   visible effect.

   Thus, while it is safe for the compiler to eliminate all but the
   first call via techniques like common subexpression elimination, it
   is not safe for the compiler to infer that the first call did no
   writes.

   But recent compilers seem to do exactly that.

   Sigh ... we can't use AT_FN_PURE on such functions because of all the
   above linguistic, compiler, documentation and ABI infinite sadness.

   TL;DR To be safe against the above vagaries, recommend using
   AT_FN_PURE to annotate functions that do no memory writes (including
   trivial memory writes) and try to design HPC APIs to avoid returning
   multiple values as much as possible.

   Followup: AT_FN_PURE expands to nothing by default given additional
   confusion between how current languages, compilers, CI, fuzzing, and
   developers interpret this function attribute.  We keep it around
   given it documents the intent of various APIs and so it can be
   manually enabled to find implementation surprises during bullet
   proofing (e.g. under compiler options like "extra-brutality").
   Hopefully someday, pure function attributes will someday be handled
   more consistently across the board. */

#ifndef AT_FN_PURE
#define AT_FN_PURE
#endif

/* AT_FN_CONST is like pure but also, even stronger, indicates that the
   function does not depend on the state of memory.  See note above
   about why this expands to nothing by default. */

#ifndef AT_FN_CONST
#define AT_FN_CONST
#endif

/* AT_FN_UNUSED indicates that it is okay if the function with static
   linkage is not used.  Allows working around -Winline in header only
   APIs where the compiler decides not to actually inline the function.
   (This belief, frequently promulgated by anti-macro cults, that "An
   Inline Function is As Fast As a Macro" ... an entire section in gcc's
   documentation devoted to it in fact ... remains among the biggest
   lies in computer science.  Yes, an inline function is as fast as a
   macro ... when the compiler actually decides to treat the inline
   keyword more than just for entertainment purposes only.  Which, as
   -Winline proves, it frequently doesn't.  Sigh ... force_inline like
   compiler extensions might be an alternative here but they have their
   own portability issues.) */

#define AT_FN_UNUSED __attribute__((unused))

/* AT_FN_UNSANITIZED tells the compiler to disable AddressSanitizer and
   UndefinedBehaviorSanitizer instrumentation.  For some functions, this
   can improve instrumented compile time by ~30x. */

#define AT_FN_UNSANITIZED __attribute__((no_sanitize("address", "undefined")))

/* AT_FN_SENSITIVE instruments the compiler to sanitize sensitive functions.
   https://eprint.iacr.org/2023/1713 (Sec 3.2)
   - Clear all registers with __attribute__((zero_call_used_regs("all")))
   - Clear stack with __attribute__((strub)), available in gcc 14+ */

#if __has_attribute(strub)
#define AT_FN_SENSITIVE __attribute__((strub)) __attribute__((zero_call_used_regs("all")))
#elif __has_attribute(zero_call_used_regs)
#define AT_FN_SENSITIVE __attribute__((zero_call_used_regs("all")))
#else
#define AT_FN_SENSITIVE
#endif

/* AT_PARAM_UNUSED indicates that it is okay if the function parameter is not
   used. */

#define AT_PARAM_UNUSED __attribute__((unused))

/* AT_TYPE_PACKED indicates that a type is to be packed, reseting its alignment
   to 1. */

#define AT_TYPE_PACKED __attribute__((packed))

/* AT_WARN_UNUSED tells the compiler the result (from a function) should
   be checked. This is useful to force callers to either check the result
   or deliberately and explicitly ignore it. Good for result codes and
   errors */

#define AT_WARN_UNUSED __attribute__ ((warn_unused_result))

/* AT_FALLTHRU tells the compiler that a case in a switch falls through
   to the next case. This avoids the compiler complaining, in cases where
   it is an intentional fall through.
   The "while(0)" avoids a compiler complaint in the event the case
   has no statement, example:
     switch( return_code ) {
       case RETURN_CASE_1: AT_FALLTHRU;
       case RETURN_CASE_2: AT_FALLTHRU;
       case RETURN_CASE_3:
         case_123();
       default:
         case_other();
     }

   See C++17 [[fallthrough]] and gcc __attribute__((fallthrough)) */

#define AT_FALLTHRU while(0) __attribute__((fallthrough))

/* AT_COMPILER_FORGET(var):  Tells the compiler that it shouldn't use
   any knowledge it has about the provided register-compatible variable
   var for optimizations going forward (i.e. the variable has changed in
   a deterministic but unknown-to-the-compiler way where the actual
   change is the identity operation).  Useful for inhibiting various
   branch nest misoptimizations (compilers unfortunately tend to
   radically underestimate the impact in raw average performance and
   jitter and the probability of branch mispredicts or the cost to the
   CPU of having lots of branches).  This is not asm volatile (use
   UNPREDICTABLE below for that) and has no clobbers.  So if var is not
   used after the forget, the compiler can optimize the FORGET away
   (along with operations preceding it used to produce var). */

#define AT_COMPILER_FORGET(var) __asm__( "# AT_COMPILER_FORGET(" #var ")@" AT_SRC_LOCATION : "+r" (var) )

/* AT_COMPILER_UNPREDICTABLE(var):  Same as AT_COMPILER_FORGET(var) but
   the provided variable has changed in a non-deterministic way from the
   compiler's POV (e.g. the value in the variable on output should not
   be treated as a compile time constant even if it is one
   linguistically).  Useful for suppressing unwanted
   compile-time-const-based optimizations like hoisting operations with
   useful CPU side effects out of a critical loop. */

#define AT_COMPILER_UNPREDICTABLE(var) __asm__ __volatile__( "# AT_COMPILER_UNPREDICTABLE(" #var ")@" AT_SRC_LOCATION : "+m,r" (var) )

/* Atomic tricks ******************************************************/

/* AT_COMPILER_MFENCE():  Tells the compiler that it can't move any
   memory operations (load or store) from before the MFENCE to after the
   MFENCE (and vice versa).  The processor itself might still reorder
   around the fence though (that requires platform specific fences). */

#define AT_COMPILER_MFENCE() __asm__ __volatile__( "# AT_COMPILER_MFENCE()@" AT_SRC_LOCATION ::: "memory" )

/* AT_SPIN_PAUSE():  Yields the logical core of the calling thread to
   the other logical cores sharing the same underlying physical core for
   a few clocks without yielding it to the operating system scheduler.
   Typically useful for shared memory spin polling loops, especially if
   hyperthreading is in use.  IMPORTANT SAFETY TIP!  This might act as a
   AT_COMPILER_MFENCE on some combinations of toolchains and targets
   (e.g. gcc documents that __builtin_ia32_pause also does a compiler
   memory) but this should not be relied upon for portable code
   (consider making this a compiler memory fence on all platforms?) */

#if AT_HAS_X86
#define AT_SPIN_PAUSE() __builtin_ia32_pause()
#else
#define AT_SPIN_PAUSE() ((void)0)
#endif

/* AT_YIELD():  Yields the logical core of the calling thread to the
   operating system scheduler if a hosted target and does a spin pause
   otherwise. */

#if AT_HAS_HOSTED
#define AT_YIELD() at_yield()
#else
#define AT_YIELD() AT_SPIN_PAUSE()
#endif

/* AT_VOLATILE_CONST(x):  Tells the compiler is not able to predict the
   value obtained by dereferencing x and that dereferencing x might have
   other side effects (e.g. maybe another thread could change the value
   and the compiler has no way of knowing this).  Generally speaking,
   the volatile keyword is broken linguistically.  Volatility is not a
   property of the variable but of the dereferencing of a variable (e.g.
   what is volatile from the POV of a reader of a shared variable is not
   necessarily volatile from the POV a writer of that shared variable in
   a different thread). */

#define AT_VOLATILE_CONST(x) (*((volatile const __typeof__((x)) *)&(x)))

/* AT_VOLATILE(x): tells the compiler is not able to predict the effect
   of modifying x and that dereferencing x might have other side effects
   (e.g. maybe another thread is spinning on x waiting for its value to
   change and the compiler has no way of knowing this). */

#define AT_VOLATILE(x) (*((volatile __typeof__((x)) *)&(x)))

#if AT_HAS_ATOMIC

/* AT_ATOMIC_FETCH_AND_{ADD,SUB,OR,AND,XOR}(p,v):

   AT_ATOMIC_FETCH_AND_ADD(p,v) does
     f = *p;
     *p = f + v
     return f;
   as a single atomic operation.  Similarly for the other variants. */

#define AT_ATOMIC_FETCH_AND_ADD(p,v) __sync_fetch_and_add( (p), (v) )
#define AT_ATOMIC_FETCH_AND_SUB(p,v) __sync_fetch_and_sub( (p), (v) )
#define AT_ATOMIC_FETCH_AND_OR( p,v) __sync_fetch_and_or(  (p), (v) )
#define AT_ATOMIC_FETCH_AND_AND(p,v) __sync_fetch_and_and( (p), (v) )
#define AT_ATOMIC_FETCH_AND_XOR(p,v) __sync_fetch_and_xor( (p), (v) )

/* AT_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v):

   AT_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v) does
     r = *p + v;
     *p = r;
     return r;
   as a single atomic operation.  Similarly for the other variants. */

#define AT_ATOMIC_ADD_AND_FETCH(p,v) __sync_add_and_fetch( (p), (v) )
#define AT_ATOMIC_SUB_AND_FETCH(p,v) __sync_sub_and_fetch( (p), (v) )
#define AT_ATOMIC_OR_AND_FETCH( p,v) __sync_or_and_fetch(  (p), (v) )
#define AT_ATOMIC_AND_AND_FETCH(p,v) __sync_and_and_fetch( (p), (v) )
#define AT_ATOMIC_XOR_AND_FETCH(p,v) __sync_xor_and_fetch( (p), (v) )

/* AT_ATOMIC_CAS(p,c,s):

   o = AT_ATOMIC_CAS(p,c,s) conceptually does:
     o = *p;
     if( o==c ) *p = s;
     return o
   as a single atomic operation. */

#define AT_ATOMIC_CAS(p,c,s) __sync_val_compare_and_swap( (p), (c), (s) )

/* AT_ATOMIC_XCHG(p,v):

   o = AT_ATOMIC_XCHG( p, v ) conceptually does:
     o = *p
     *p = v
     return o
   as a single atomic operation.

   Intel's __sync compiler extensions from the days of yore mysteriously
   implemented atomic exchange via the very misleadingly named
   __sync_lock_test_and_set.  And some implementations (and C++)
   debatably then implemented this API according to what the misleading
   name implied as opposed to what it actually did.  But those
   implementations didn't bother to provide a replacement for atomic
   exchange functionality (forcing us to emulate atomic exchange more
   slowly via CAS there).  Sigh ... we do what we can to fix this up. */

#ifndef AT_ATOMIC_XCHG_STYLE
#if AT_HAS_X86 && !__cplusplus
#define AT_ATOMIC_XCHG_STYLE 1
#else
#define AT_ATOMIC_XCHG_STYLE 0
#endif
#endif

#if AT_ATOMIC_XCHG_STYLE==0
#define AT_ATOMIC_XCHG(p,v) (__extension__({                                                                            \
    __typeof__(*(p)) * _at_atomic_xchg_p = (p);                                                                         \
    __typeof__(*(p))   _at_atomic_xchg_v = (v);                                                                         \
    __typeof__(*(p))   _at_atomic_xchg_t;                                                                               \
    for(;;) {                                                                                                           \
      _at_atomic_xchg_t = AT_VOLATILE_CONST( *_at_atomic_xchg_p );                                                      \
      if( AT_LIKELY( __sync_bool_compare_and_swap( _at_atomic_xchg_p, _at_atomic_xchg_t, _at_atomic_xchg_v ) ) ) break; \
      AT_SPIN_PAUSE();                                                                                                  \
    }                                                                                                                   \
    _at_atomic_xchg_t;                                                                                                  \
  }))
#elif AT_ATOMIC_XCHG_STYLE==1
#define AT_ATOMIC_XCHG(p,v) __sync_lock_test_and_set( (p), (v) )
#else
#error "Unknown AT_ATOMIC_XCHG_STYLE"
#endif

#endif /* AT_HAS_ATOMIC */

/* AT_TL:  This indicates that the variable should be thread local.

   AT_ONCE_{BEGIN,END}:  The block:

     AT_ONCE_BEGIN {
       ... code ...
     } AT_ONCE_END

   linguistically behaves like:

     do {
       ... code ...
     } while(0)

   But provides a low overhead guarantee that:
     - The block will be executed by at most once over all threads
       in a process (i.e. the set of threads which share global
       variables).
     - No thread in a process that encounters the block will continue
       past it until it has executed once.

   This implies that caller promises a ONCE block will execute in a
   finite time.  (Meant for doing simple lightweight initializations.)

   It is okay to nest ONCE blocks.  The thread that executes the
   outermost will execute all the nested once as part of executing the
   outermost.

   A ONCE implicitly provides a compiler memory fence to reduce the risk
   that the compiler will assume that operations done in the once block
   on another thread have not been done (e.g. propagating pre-once block
   variable values into post-once block code).  It is up to the user to
   provide any necessary hardware fencing (usually not necessary).

   AT_THREAD_ONCE_{BEGIN,END}:  The block:

     AT_THREAD_ONCE_BEGIN {
       ... code ...
     } AT_THREAD_ONCE_END;

   is similar except the guarantee is that the block only covers the
   invoking thread and it does not provide any fencing.  If a thread
   once begin is nested inside a once begin, that thread once begin will
   only be executed on the thread that executes the thread once begin.
   It is similarly okay to nest ONCE block inside a THREAD_ONCE block.

   AT_TURNSTILE_{BEGIN,BLOCKED,END} implement a turnstile for all
   threads in a process.  Only one thread can be in the turnstile at a
   time.  Usage:

     AT_TURNSTILE_BEGIN(blocking) {

       ... At this point, we are the only thread executing this block of
       ... code.
       ...
       ... Do operations that must be done by threads one-at-a-time
       ... here.
       ...
       ... Because compiler memory fences are done just before entering
       ... and after exiting this block, there is typically no need to
       ... use any atomics / volatile / fencing here.  That is, we can
       ... just write "normal" code on platforms where writes to memory
       ... become visible to other threads in the order in which they
       ... were issued in the machine code (e.g. x86) as others will not
       ... proceed with this block until they exit it.  YMMV for non-x86
       ... platforms (probably need additional hardware store fences in
       ... these macros).
       ...
       ... It is safe to use "break" and/or "continue" within this
       ... block.  The block will exit with the appropriate compiler
       ... fencing and unlocking.  Execution will resume immediately
       ... after AT_TURNSTILE_END.

       ... IMPORTANT SAFETY TIP!  DO NOT RETURN FROM THIS BLOCK.

     } AT_TURNSTILE_BLOCKED {

       ... At this point, there was another thread in the turnstile when
       ... we tried to enter the turnstile.
       ...
       ... Handle blocked here.
       ...
       ... On exiting this block, if blocking was zero, we will resume
       ... execution immediately after AT_TURNSTILE_END.  If blocking
       ... was non-zero, we will resume execution immediately before
       ... AT_TURNSTILE_BEGIN (e.g. we will retry again after a short
       ... spin pause).
       ...
       ... It is safe to use "break" and/or "continue" within this
       ... block.  Both will exit this block and resume execution
       ... at the location indicated as per what blocking specified
       ... then the turnstile was entered.
       ...
       ... It is technically safe to return from this block but
       ... also extremely gross.

     } AT_TURNSTILE_END; */

#if AT_HAS_THREADS /* Potentially more than one thread in the process */

#ifndef AT_TL
#define AT_TL __thread
#endif

#define AT_ONCE_BEGIN do {                                                \
    AT_COMPILER_MFENCE();                                                 \
    static volatile int _at_once_block_state = 0;                         \
    for(;;) {                                                             \
      int _at_once_block_tmp = _at_once_block_state;                      \
      if( AT_LIKELY( _at_once_block_tmp>0 ) ) break;                      \
      if( AT_LIKELY( !_at_once_block_tmp ) &&                             \
          AT_LIKELY( !AT_ATOMIC_CAS( &_at_once_block_state, 0, -1 ) ) ) { \
        do

#define AT_ONCE_END               \
        while(0);                 \
        AT_COMPILER_MFENCE();     \
        _at_once_block_state = 1; \
        break;                    \
      }                           \
      AT_YIELD();                 \
    }                             \
  } while(0)

#define AT_THREAD_ONCE_BEGIN do {                       \
    static AT_TL int _at_thread_once_block_state = 0;   \
    if( AT_UNLIKELY( !_at_thread_once_block_state ) ) { \
      do

#define AT_THREAD_ONCE_END             \
      while(0);                        \
      _at_thread_once_block_state = 1; \
    }                                  \
  } while(0)

#define AT_TURNSTILE_BEGIN(blocking) do {                               \
    static volatile int _at_turnstile_state    = 0;                     \
    int                 _at_turnstile_blocking = (blocking);            \
    for(;;) {                                                           \
      int _at_turnstile_tmp = _at_turnstile_state;                      \
      if( AT_LIKELY( !_at_turnstile_tmp ) &&                            \
          AT_LIKELY( !AT_ATOMIC_CAS( &_at_turnstile_state, 0, 1 ) ) ) { \
        AT_COMPILER_MFENCE();                                           \
        do

#define AT_TURNSTILE_BLOCKED     \
        while(0);                \
        AT_COMPILER_MFENCE();    \
        _at_turnstile_state = 0; \
        AT_COMPILER_MFENCE();    \
        break;                   \
      }                          \
      AT_COMPILER_MFENCE();      \
      do

#define AT_TURNSTILE_END                                             \
      while(0);                                                      \
      AT_COMPILER_MFENCE();                                          \
      if( !_at_turnstile_blocking ) break; /* likely compile time */ \
      AT_SPIN_PAUSE();                                               \
    }                                                                \
  } while(0)

#else /* Only one thread in the process */

#ifndef AT_TL
#define AT_TL /**/
#endif

#define AT_ONCE_BEGIN do {                       \
    static int _at_once_block_state = 0;         \
    if( AT_UNLIKELY( !_at_once_block_state ) ) { \
      do

#define AT_ONCE_END             \
      while(0);                 \
      _at_once_block_state = 1; \
    }                           \
  } while(0)

#define AT_THREAD_ONCE_BEGIN AT_ONCE_BEGIN
#define AT_THREAD_ONCE_END   AT_ONCE_END

#define AT_TURNSTILE_BEGIN(blocking) do { \
    (void)(blocking);                     \
    AT_COMPILER_MFENCE();                 \
    if( 1 ) {                             \
      do

#define AT_TURNSTILE_BLOCKED \
      while(0);              \
    } else {                 \
      do

#define AT_TURNSTILE_END  \
      while(0);           \
    }                     \
    AT_COMPILER_MFENCE(); \
  } while(0)

#endif

/* An ideal at_clock_func_t is a function such that:

     long dx = clock( args );
     ... stuff ...
     dx = clock( args ) - dx;

   yields a strictly positive dx where dx approximates the amount of
   wallclock time elapsed on the caller in some clock specific unit
   (e.g. nanoseconds, CPU ticks, etc) for a reasonable amount of "stuff"
   (including no "stuff").  args allows arbitrary clock specific context
   to be passed to the clock implication.  (clocks that need a non-const
   args can cast away the const in the implementation or cast the
   function pointer as necessary.) */

typedef long (*at_clock_func_t)( void const * args );

AT_PROTOTYPES_BEGIN

/* at_memcpy(d,s,sz):  On modern x86 in some circumstances, rep mov will
   be faster than memcpy under the hood (basically due to RFO /
   read-for-ownership optimizations in the cache protocol under the hood
   that aren't easily done from the ISA ... see Intel docs on enhanced
   rep mov).  Compile time configurable though as this is not always
   true.  So application can tune to taste.  Hard to beat rep mov for
   code density though (2 bytes) and pretty hard to beat in situations
   needing a completely generic memcpy.  But it can be beaten in
   specialized situations for the usual reasons. */

/* FIXME: CONSIDER MEMCMP TOO! */
/* FIXME: CONSIDER MEMCPY RELATED FUNC ATTRS */

#ifndef AT_USE_ARCH_MEMCPY
#define AT_USE_ARCH_MEMCPY 0
#endif

#if AT_HAS_X86 && AT_USE_ARCH_MEMCPY && !defined(CBMC) && !AT_HAS_DEEPASAN && !AT_HAS_MSAN

static inline void *
at_memcpy( void       * AT_RESTRICT d,
           void const * AT_RESTRICT s,
           ulong                    sz ) {
  void * p = d;
  __asm__ __volatile__( "rep movsb" : "+D" (p), "+S" (s), "+c" (sz) :: "memory" );
  return d;
}

#elif AT_HAS_MSAN

void * __msan_memcpy( void * dest, void const * src, ulong n );

static inline void *
at_memcpy( void       * AT_RESTRICT d,
           void const * AT_RESTRICT s,
           ulong                    sz ) {
  return __msan_memcpy( d, s, sz );
}

#else

static inline void *
at_memcpy( void       * AT_RESTRICT d,
           void const * AT_RESTRICT s,
           ulong                    sz ) {
#if defined(CBMC) || AT_HAS_ASAN
  if( AT_UNLIKELY( !sz ) ) return d; /* Standard says sz 0 is UB, uncomment if target is insane and doesn't treat sz 0 as a nop */
#endif
  return memcpy( d, s, sz );
}

#endif

/* at_memset(d,c,sz): architecturally optimized memset.  See at_memcpy
   for considerations. */

/* FIXME: CONSIDER MEMSET RELATED FUNC ATTRS */

#ifndef AT_USE_ARCH_MEMSET
#define AT_USE_ARCH_MEMSET 0
#endif

#if AT_HAS_X86 && AT_USE_ARCH_MEMSET && !defined(CBMC) && !AT_HAS_DEEPASAN && !AT_HAS_MSAN

static inline void *
at_memset( void  * d,
           int     c,
           ulong   sz ) {
  void * p = d;
  __asm__ __volatile__( "rep stosb" : "+D" (p), "+c" (sz) : "a" (c) : "memory" );
  return d;
}

#else

static inline void *
at_memset( void  * d,
           int     c,
           ulong   sz ) {
# ifdef CBMC
  if( AT_UNLIKELY( !sz ) ) return d; /* See at_memcpy note */
# endif
  return memset( d, c, sz );
}

#endif

/* C23 has memset_explicit, i.e. a memset that can't be removed by the
   optimizer. This is our own equivalent. */

static void * (* volatile at_memset_explicit)(void *, int, size_t) = memset;

/* at_memeq(s0,s1,sz):  Compares two blocks of memory.  Returns 1 if
   equal or sz is zero and 0 otherwise.  No memory accesses made if sz
   is zero (pointers may be invalid).  On x86, uses repe cmpsb which is
   preferable to __builtin_memcmp in some cases. */

#ifndef AT_USE_ARCH_MEMEQ
#define AT_USE_ARCH_MEMEQ 0
#endif

#if AT_HAS_X86 && AT_USE_ARCH_MEMEQ && defined(__GCC_ASM_FLAG_OUTPUTS__) && __STDC_VERSION__>=199901L

AT_FN_PURE static inline int
at_memeq( void const * s0,
          void const * s1,
          ulong        sz ) {
  /* ZF flag is set and exported in two cases:
      a) size is zero (via test)
      b) buffer is equal (via repe cmpsb) */
  int r;
  __asm__( "test %3, %3;"
           "repe cmpsb"
         : "=@cce" (r), "+S" (s0), "+D" (s1), "+c" (sz)
         : "m" (*(char const (*)[sz]) s0), "m" (*(char const (*)[sz]) s1)
         : "cc" );
  return r;
}

#else

AT_FN_PURE static inline int
at_memeq( void const * s1,
          void const * s2,
          ulong        sz ) {
  return 0==memcmp( s1, s2, sz );
}

#endif

/* at_memcmp(s1,s2,sz): Wrapper around memcmp for consistency. */
AT_FN_PURE static inline int
at_memcmp( void const * s1,
           void const * s2,
           ulong        sz ) {
  return memcmp( s1, s2, sz );
}

/* at_memmove(d,s,sz): Wrapper around memmove for overlapping memory regions.
   Unlike at_memcpy, this safely handles cases where source and destination
   regions overlap. Use at_memcpy when regions are known not to overlap
   (it may be faster). */

static inline void *
at_memmove( void       * d,
            void const * s,
            ulong        sz ) {
#if defined(CBMC) || AT_HAS_ASAN
  if( AT_UNLIKELY( !sz ) ) return d;
#endif
  return memmove( d, s, sz );
}

/* Returns 1 if all sz bytes starting at s are zero, 0 otherwise. */
AT_FN_PURE static inline int
at_mem_iszero( uchar const * s,
               ulong         sz ) {
  for( ulong i=0UL; i<sz; i++ ) {
   if( s[i]!=0 ) return 0;
  }
  return 1;
}

/* ========================================================================
   String function wrappers
   ======================================================================== */

/* at_strlen(s): Wrapper around strlen. Returns the length of the
   null-terminated string s, not including the terminating null byte. */

AT_FN_PURE static inline ulong
at_strlen( char const * s ) {
  return (ulong)strlen( s );
}

/* at_strcmp(s1,s2): Wrapper around strcmp. Compares two null-terminated
   strings. Returns <0 if s1<s2, 0 if s1==s2, >0 if s1>s2. */

AT_FN_PURE static inline int
at_strcmp( char const * s1,
           char const * s2 ) {
  return strcmp( s1, s2 );
}

/* at_strncmp(s1,s2,n): Wrapper around strncmp. Compares up to n characters
   of two null-terminated strings. Returns <0 if s1<s2, 0 if s1==s2, >0 if s1>s2. */

AT_FN_PURE static inline int
at_strncmp( char const * s1,
            char const * s2,
            ulong        n ) {
  return strncmp( s1, s2, n );
}

/* at_strtol(s,endp,base): Wrapper around strtol. Converts string to long.
   If endp is not NULL, stores address of first invalid character.
   base is the number base (0 for auto-detect, 2-36 for explicit). */

AT_FN_PURE static inline long
at_strtol( char const *  s,
           char **       endp,
           int           base ) {
  return strtol( s, endp, base );
}

/* at_strtoul(s,endp,base): Wrapper around strtoul. Converts string to
   unsigned long. Same semantics as at_strtol but for unsigned values. */

AT_FN_PURE static inline ulong
at_strtoul( char const *  s,
            char **       endp,
            int           base ) {
  return (ulong)strtoul( s, endp, base );
}

/* at_strtoull(s,endp,base): Wrapper around strtoull. Converts string to
   unsigned long long. Same semantics as at_strtoul but for unsigned
   long long values. */

AT_FN_PURE static inline ulong
at_strtoull( char const *  s,
             char **       endp,
             int           base ) {
  return (ulong)strtoull( s, endp, base );
}

/* at_strerror(errnum): Wrapper around strerror. Returns a string
   describing the error code errnum. Not AT_FN_PURE because the
   returned pointer may reference a shared static buffer. */

static inline char const *
at_strerror( int errnum ) {
  return strerror( errnum );
}

/* at_snprintf(buf,sz,fmt,...): Wrapper around snprintf. Writes formatted
   output to buf (at most sz bytes including null terminator).
   Returns the number of characters that would have been written if sz
   was large enough, not including the null terminator. */

#define at_snprintf( buf, sz, ... ) snprintf( (buf), (sz), __VA_ARGS__ )

/* at_vsnprintf(buf,sz,fmt,ap): Wrapper around vsnprintf. Same as at_snprintf
   but takes a va_list instead of variadic arguments. */

static inline int
at_vsnprintf( char *       buf,
              ulong        sz,
              char const * fmt,
              va_list      ap ) {
  return vsnprintf( buf, (size_t)sz, fmt, ap );
}

/* at_hash(seed,buf,sz), at_hash_memcpy(seed,d,s,sz):  High quality
   (full avalanche) high speed variable length buffer -> 64-bit hash
   function (memcpy_hash is often as fast as plain memcpy).  Based on
   the xxhash-r39 (open source BSD licensed) implementation.  In-place
   and out-of-place variants provided (out-of-place variant assumes dst
   and src do not overlap).  Caller promises valid input arguments,
   cannot fail given valid inputs arguments.  sz==0 is fine. */

AT_FN_PURE ulong
at_hash( ulong        seed,
         void const * buf,
         ulong        sz );

ulong
at_hash_memcpy( ulong                    seed,
                void       * AT_RESTRICT d,
                void const * AT_RESTRICT s,
                ulong                    sz );

#ifndef AT_TICKCOUNT_STYLE
#if AT_HAS_X86 /* Use RDTSC */
#define AT_TICKCOUNT_STYLE 1
#elif AT_HAS_ARM /* Use CNTVCT_EL0 */
#define AT_TICKCOUNT_STYLE 2
#else /* Use portable fallback */
#define AT_TICKCOUNT_STYLE 0
#endif
#endif

#if AT_TICKCOUNT_STYLE==0 /* Portable fallback (slow).  Ticks at 1 ns / tick */

#define at_tickcount() at_log_wallclock() /* TODO: fix ugly pre-log usage */

#elif AT_TICKCOUNT_STYLE==1 /* RTDSC (fast) */

/* at_tickcount:  Reads the hardware invariant tickcounter ("RDTSC").
   This monotonically increases at an approximately constant rate
   relative to the system wallclock and is synchronous across all CPUs
   on a host.

   The rate this ticks at is not precisely defined (see Intel docs for
   more details) but it is typically in the ballpark of the CPU base
   clock frequency.  The relationship to the wallclock is very well
   approximated as linear over short periods of time (i.e. less than a
   fraction of a second) and this should not exhibit any sudden changes
   in its rate relative to the wallclock.  Notably, its rate is not
   directly impacted by CPU clock frequency adaptation / Turbo mode (see
   other Intel performance monitoring counters for various CPU cycle
   counters).  It can drift over longer period time for the usual clock
   synchronization reasons.

   This is a reasonably fast O(1) cost (~6-8 ns on recent Intel).
   Because of all compiler options and parallel execution going on in
   modern CPUs cores, other instructions might be reordered around this
   by the compiler and/or CPU.  It is up to the user to do lower level
   tricks as necessary when the precise location of this in the
   execution stream and/or when executed by the CPU is needed.  (This is
   often unnecessary as such levels of precision are not frequently
   required and often have self-defeating overheads.)

   It is worth noting that RDTSC and/or (even more frequently) lower
   level performance counters are often restricted from use in user
   space applications.  It is recommended that applications use this
   primarily for debugging / performance tuning on unrestricted hosts
   and/or when the developer is confident that applications using this
   will have appropriate permissions when deployed. */

#define at_tickcount() ((long)__builtin_ia32_rdtsc())

#elif AT_TICKCOUNT_STYLE==2 /* armv8 (fast) */

/* at_tickcount (ARM): https://developer.arm.com/documentation/ddi0601/2021-12/AArch64-Registers/CNTVCT-EL0--Counter-timer-Virtual-Count-register
   Approx 24 MHz on Apple M1. */

static inline long
at_tickcount( void ) {
  /* consider using 'isb' */
  ulong value;
  __asm__ __volatile__ (
    "isb\n"
    "mrs %0, cntvct_el0\n"
    "nop"
    : "=r" (value) );
  return (long)value;
}

#else
#error "Unknown AT_TICKCOUNT_STYLE"
#endif

long _at_tickcount( void const * _ ); /* at_clock_func_t compat */

#if AT_HAS_HOSTED

/* at_yield yields the calling thread to the operating system scheduler. */

void
at_yield( void );

#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_at_util_base_h */