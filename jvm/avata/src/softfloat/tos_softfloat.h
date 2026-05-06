/* TOS deterministic floating-point shim for Java float/double opcodes.
 *
 * TODO(consensus-fp): This implementation uses the host C99 FP unit with
 * explicit NaN canonicalization and JVMS-correct conversion clamping.  It
 * correctly handles NaN, signed-zero, Infinity, and all conversion edge
 * cases.  For full cross-platform bit-identity across x87/SSE/ARM/RISC-V
 * validators, replace the arithmetic operations with Berkeley SoftFloat 3e
 * (http://www.jhauser.us/arithmetic/SoftFloat.html) compiled with
 * SOFTFLOAT_ROUND_NEAR_EVEN before consensus activation.
 *
 * What IS already deterministic here:
 *   - NaN detection (bit pattern, no FPU)
 *   - NaN canonicalization on all outputs
 *   - fneg/dneg (single-bit flip, no FPU)
 *   - fcmpg/fcmpl/dcmpg/dcmpl NaN return path (early exit, no comparison)
 *   - f2i/f2l/d2i/d2l clamping (NaN→0, ±Inf and overflow→MAX/MIN_VALUE)
 *
 * What depends on the host FPU (round-to-nearest-even assumed):
 *   - fadd/fsub/fmul/fdiv/frem and their double counterparts
 *   - f2d/d2f/i2f/l2f/i2d/l2d
 *
 * All functions operate on raw bit representations (uint32_t for float,
 * uint64_t for double) so the interpreter can stay in integer space.
 */

#pragma once

#include <stdint.h>
#include <math.h>
#include <string.h>

/* Canonical NaN bit patterns (quietNaN, sign=0, payload=0x400000/0x8000000000000) */
#define TOS_FLOAT_CANONICAL_NAN  UINT32_C(0x7FC00000)
#define TOS_DOUBLE_CANONICAL_NAN UINT64_C(0x7FF8000000000000)

/* Bit-level type punning -- standard C++ via memcpy, no UB */
static inline float tos_u32_to_f(uint32_t b)
{
  float f;
  memcpy(&f, &b, 4);
  return f;
}
static inline uint32_t tos_f_to_u32(float f)
{
  uint32_t b;
  memcpy(&b, &f, 4);
  return b;
}
static inline double tos_u64_to_d(uint64_t b)
{
  double d;
  memcpy(&d, &b, 8);
  return d;
}
static inline uint64_t tos_d_to_u64(double d)
{
  uint64_t b;
  memcpy(&b, &d, 8);
  return b;
}

/* NaN detection via bit pattern -- host-FPU-independent */
static inline int tos_fnan(uint32_t bits)
{
  return (bits & UINT32_C(0x7F800000)) == UINT32_C(0x7F800000)
      && (bits & UINT32_C(0x007FFFFF)) != 0;
}
static inline int tos_dnan(uint64_t bits)
{
  return (bits & UINT64_C(0x7FF0000000000000)) == UINT64_C(0x7FF0000000000000)
      && (bits & UINT64_C(0x000FFFFFFFFFFFFF)) != 0;
}

/* NaN canonicalization */
static inline uint32_t tos_fcanon(uint32_t bits)
{
  return tos_fnan(bits) ? TOS_FLOAT_CANONICAL_NAN : bits;
}
static inline uint64_t tos_dcanon(uint64_t bits)
{
  return tos_dnan(bits) ? TOS_DOUBLE_CANONICAL_NAN : bits;
}

/* ------------------------------------------------------------------ */
/* Float arithmetic (fadd fsub fmul fdiv frem)                         */
/* ------------------------------------------------------------------ */

static inline uint32_t tos_fadd(uint32_t a, uint32_t b)
{
  return tos_fcanon(tos_f_to_u32(tos_u32_to_f(a) + tos_u32_to_f(b)));
}
static inline uint32_t tos_fsub(uint32_t a, uint32_t b)
{
  return tos_fcanon(tos_f_to_u32(tos_u32_to_f(a) - tos_u32_to_f(b)));
}
static inline uint32_t tos_fmul(uint32_t a, uint32_t b)
{
  return tos_fcanon(tos_f_to_u32(tos_u32_to_f(a) * tos_u32_to_f(b)));
}
static inline uint32_t tos_fdiv(uint32_t a, uint32_t b)
{
  return tos_fcanon(tos_f_to_u32(tos_u32_to_f(a) / tos_u32_to_f(b)));
}
static inline uint32_t tos_frem(uint32_t a, uint32_t b)
{
  return tos_fcanon(tos_f_to_u32(fmodf(tos_u32_to_f(a), tos_u32_to_f(b))));
}

/* fneg: flip sign bit only, then canonicalize if NaN */
static inline uint32_t tos_fneg(uint32_t a)
{
  uint32_t r = a ^ UINT32_C(0x80000000);
  return tos_fnan(r) ? TOS_FLOAT_CANONICAL_NAN : r;
}

/* ------------------------------------------------------------------ */
/* Float comparisons (JVMS NaN semantics)                              */
/* fcmpg: NaN → +1;  fcmpl: NaN → -1                                  */
/* ------------------------------------------------------------------ */

static inline int32_t tos_fcmpg(uint32_t ab, uint32_t bb)
{
  if (tos_fnan(ab) || tos_fnan(bb))
    return 1;
  float a = tos_u32_to_f(ab), b = tos_u32_to_f(bb);
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}
static inline int32_t tos_fcmpl(uint32_t ab, uint32_t bb)
{
  if (tos_fnan(ab) || tos_fnan(bb))
    return -1;
  float a = tos_u32_to_f(ab), b = tos_u32_to_f(bb);
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Double arithmetic (dadd dsub dmul ddiv drem)                        */
/* ------------------------------------------------------------------ */

static inline uint64_t tos_dadd(uint64_t a, uint64_t b)
{
  return tos_dcanon(tos_d_to_u64(tos_u64_to_d(a) + tos_u64_to_d(b)));
}
static inline uint64_t tos_dsub(uint64_t a, uint64_t b)
{
  return tos_dcanon(tos_d_to_u64(tos_u64_to_d(a) - tos_u64_to_d(b)));
}
static inline uint64_t tos_dmul(uint64_t a, uint64_t b)
{
  return tos_dcanon(tos_d_to_u64(tos_u64_to_d(a) * tos_u64_to_d(b)));
}
static inline uint64_t tos_ddiv(uint64_t a, uint64_t b)
{
  return tos_dcanon(tos_d_to_u64(tos_u64_to_d(a) / tos_u64_to_d(b)));
}
static inline uint64_t tos_drem(uint64_t a, uint64_t b)
{
  return tos_dcanon(tos_d_to_u64(fmod(tos_u64_to_d(a), tos_u64_to_d(b))));
}

/* dneg: flip sign bit only, then canonicalize if NaN */
static inline uint64_t tos_dneg(uint64_t a)
{
  uint64_t r = a ^ UINT64_C(0x8000000000000000);
  return tos_dnan(r) ? TOS_DOUBLE_CANONICAL_NAN : r;
}

/* ------------------------------------------------------------------ */
/* Double comparisons                                                   */
/* ------------------------------------------------------------------ */

static inline int32_t tos_dcmpg(uint64_t ab, uint64_t bb)
{
  if (tos_dnan(ab) || tos_dnan(bb))
    return 1;
  double a = tos_u64_to_d(ab), b = tos_u64_to_d(bb);
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}
static inline int32_t tos_dcmpl(uint64_t ab, uint64_t bb)
{
  if (tos_dnan(ab) || tos_dnan(bb))
    return -1;
  double a = tos_u64_to_d(ab), b = tos_u64_to_d(bb);
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Conversions                                                          */
/* ------------------------------------------------------------------ */

/* f2d: widen float to double; NaN → canonical double NaN */
static inline uint64_t tos_f2d(uint32_t fb)
{
  if (tos_fnan(fb))
    return TOS_DOUBLE_CANONICAL_NAN;
  return tos_d_to_u64((double)tos_u32_to_f(fb));
}

/* d2f: narrow double to float; NaN → canonical float NaN */
static inline uint32_t tos_d2f(uint64_t db)
{
  if (tos_dnan(db))
    return TOS_FLOAT_CANONICAL_NAN;
  return tos_fcanon(tos_f_to_u32((float)tos_u64_to_d(db)));
}

/* f2i: NaN→0; ±Inf and overflow clamp to INT32_MAX/MIN */
static inline int32_t tos_f2i(uint32_t fb)
{
  if (tos_fnan(fb))
    return 0;
  float f = tos_u32_to_f(fb);
  /* 2147483648.0f is the smallest float > INT32_MAX */
  if (f >= 2147483648.0f)
    return INT32_MAX;
  if (f <= -2147483648.0f)
    return INT32_MIN;
  return (int32_t)f;
}

/* f2l: NaN→0; ±Inf and overflow clamp to INT64_MAX/MIN */
static inline int64_t tos_f2l(uint32_t fb)
{
  if (tos_fnan(fb))
    return 0;
  float f = tos_u32_to_f(fb);
  /* 9.223372036854776e18f == 2^63 (smallest float > INT64_MAX) */
  if (f >= 9.223372036854776e18f)
    return INT64_MAX;
  /* -2^63 == INT64_MIN, exactly representable as float */
  if (f <= -9.223372036854776e18f)
    return INT64_MIN;
  return (int64_t)f;
}

/* d2i: NaN→0; ±Inf and overflow clamp */
static inline int32_t tos_d2i(uint64_t db)
{
  if (tos_dnan(db))
    return 0;
  double d = tos_u64_to_d(db);
  if (d >= 2147483648.0)
    return INT32_MAX;
  if (d <= -2147483649.0)
    return INT32_MIN;
  return (int32_t)d;
}

/* d2l: NaN→0; ±Inf and overflow clamp */
static inline int64_t tos_d2l(uint64_t db)
{
  if (tos_dnan(db))
    return 0;
  double d = tos_u64_to_d(db);
  /* 9.223372036854776e18 == 2^63 */
  if (d >= 9.223372036854776e18)
    return INT64_MAX;
  if (d <= -9.223372036854776e18)
    return INT64_MIN;
  return (int64_t)d;
}

/* i2f / l2f: int/long → float bits */
static inline uint32_t tos_i2f(int32_t i)
{
  return tos_f_to_u32((float)i);
}
static inline uint32_t tos_l2f(int64_t l)
{
  return tos_f_to_u32((float)l);
}

/* i2d / l2d: int/long → double bits */
static inline uint64_t tos_i2d(int32_t i)
{
  return tos_d_to_u64((double)i);
}
static inline uint64_t tos_l2d(int64_t l)
{
  return tos_d_to_u64((double)l);
}
