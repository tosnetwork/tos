/* TOS deterministic floating-point shim for Java float/double opcodes.
 *
 * All arithmetic, comparisons, and conversions are routed through Berkeley
 * SoftFloat 3e.  The interpreter passes raw IEEE-754 bit patterns
 * (uint32_t/uint64_t), so this layer never asks the host FPU to compute a
 * consensus value.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "platform.h"
#include "softfloat.h"

float32_t tos_softfloat_f32_fmod(float32_t a, float32_t b);
float64_t tos_softfloat_f64_fmod(float64_t a, float64_t b);
#ifdef __cplusplus
}
#endif

/* Canonical NaN bit patterns (quietNaN, sign=0). */
#define TOS_FLOAT_CANONICAL_NAN  UINT32_C(0x7FC00000)
#define TOS_DOUBLE_CANONICAL_NAN UINT64_C(0x7FF8000000000000)

static inline void tos_softfloat_begin()
{
  softfloat_roundingMode = softfloat_round_near_even;
  softfloat_detectTininess = softfloat_tininess_afterRounding;
  softfloat_exceptionFlags = 0;
}

static inline float32_t tos_f32(uint32_t bits)
{
  float32_t value;
  value.v = bits;
  return value;
}

static inline float64_t tos_f64(uint64_t bits)
{
  float64_t value;
  value.v = bits;
  return value;
}

/* NaN detection via bit pattern. */
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

static inline uint32_t tos_fcanon(uint32_t bits)
{
  return tos_fnan(bits) ? TOS_FLOAT_CANONICAL_NAN : bits;
}

static inline uint64_t tos_dcanon(uint64_t bits)
{
  return tos_dnan(bits) ? TOS_DOUBLE_CANONICAL_NAN : bits;
}

static inline int tos_fpositive_ge(uint32_t bits, uint32_t threshold)
{
  return (bits & UINT32_C(0x80000000)) == 0 && bits >= threshold;
}

static inline int tos_fnegative_le(uint32_t bits, uint32_t threshold)
{
  return (bits & UINT32_C(0x80000000)) != 0 && bits >= threshold;
}

static inline int tos_dpositive_ge(uint64_t bits, uint64_t threshold)
{
  return (bits & UINT64_C(0x8000000000000000)) == 0 && bits >= threshold;
}

static inline int tos_dnegative_le(uint64_t bits, uint64_t threshold)
{
  return (bits & UINT64_C(0x8000000000000000)) != 0 && bits >= threshold;
}

/* ------------------------------------------------------------------ */
/* Float arithmetic (fadd fsub fmul fdiv frem)                         */
/* ------------------------------------------------------------------ */

static inline uint32_t tos_fadd(uint32_t a, uint32_t b)
{
  tos_softfloat_begin();
  return tos_fcanon(f32_add(tos_f32(a), tos_f32(b)).v);
}

static inline uint32_t tos_fsub(uint32_t a, uint32_t b)
{
  tos_softfloat_begin();
  return tos_fcanon(f32_sub(tos_f32(a), tos_f32(b)).v);
}

static inline uint32_t tos_fmul(uint32_t a, uint32_t b)
{
  tos_softfloat_begin();
  return tos_fcanon(f32_mul(tos_f32(a), tos_f32(b)).v);
}

static inline uint32_t tos_fdiv(uint32_t a, uint32_t b)
{
  tos_softfloat_begin();
  return tos_fcanon(f32_div(tos_f32(a), tos_f32(b)).v);
}

static inline uint32_t tos_frem(uint32_t a, uint32_t b)
{
  tos_softfloat_begin();
  return tos_fcanon(tos_softfloat_f32_fmod(tos_f32(a), tos_f32(b)).v);
}

/* fneg: flip sign bit only, then canonicalize if NaN. */
static inline uint32_t tos_fneg(uint32_t a)
{
  uint32_t r = a ^ UINT32_C(0x80000000);
  return tos_fnan(r) ? TOS_FLOAT_CANONICAL_NAN : r;
}

/* ------------------------------------------------------------------ */
/* Float comparisons (JVMS NaN semantics)                              */
/* fcmpg: NaN -> +1; fcmpl: NaN -> -1                                  */
/* ------------------------------------------------------------------ */

static inline int32_t tos_fcmpg(uint32_t ab, uint32_t bb)
{
  if (tos_fnan(ab) || tos_fnan(bb))
    return 1;

  tos_softfloat_begin();
  if (f32_lt(tos_f32(ab), tos_f32(bb)))
    return -1;
  if (f32_lt(tos_f32(bb), tos_f32(ab)))
    return 1;
  return 0;
}

static inline int32_t tos_fcmpl(uint32_t ab, uint32_t bb)
{
  if (tos_fnan(ab) || tos_fnan(bb))
    return -1;

  tos_softfloat_begin();
  if (f32_lt(tos_f32(ab), tos_f32(bb)))
    return -1;
  if (f32_lt(tos_f32(bb), tos_f32(ab)))
    return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Double arithmetic (dadd dsub dmul ddiv drem)                        */
/* ------------------------------------------------------------------ */

static inline uint64_t tos_dadd(uint64_t a, uint64_t b)
{
  tos_softfloat_begin();
  return tos_dcanon(f64_add(tos_f64(a), tos_f64(b)).v);
}

static inline uint64_t tos_dsub(uint64_t a, uint64_t b)
{
  tos_softfloat_begin();
  return tos_dcanon(f64_sub(tos_f64(a), tos_f64(b)).v);
}

static inline uint64_t tos_dmul(uint64_t a, uint64_t b)
{
  tos_softfloat_begin();
  return tos_dcanon(f64_mul(tos_f64(a), tos_f64(b)).v);
}

static inline uint64_t tos_ddiv(uint64_t a, uint64_t b)
{
  tos_softfloat_begin();
  return tos_dcanon(f64_div(tos_f64(a), tos_f64(b)).v);
}

static inline uint64_t tos_drem(uint64_t a, uint64_t b)
{
  tos_softfloat_begin();
  return tos_dcanon(tos_softfloat_f64_fmod(tos_f64(a), tos_f64(b)).v);
}

/* dneg: flip sign bit only, then canonicalize if NaN. */
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

  tos_softfloat_begin();
  if (f64_lt(tos_f64(ab), tos_f64(bb)))
    return -1;
  if (f64_lt(tos_f64(bb), tos_f64(ab)))
    return 1;
  return 0;
}

static inline int32_t tos_dcmpl(uint64_t ab, uint64_t bb)
{
  if (tos_dnan(ab) || tos_dnan(bb))
    return -1;

  tos_softfloat_begin();
  if (f64_lt(tos_f64(ab), tos_f64(bb)))
    return -1;
  if (f64_lt(tos_f64(bb), tos_f64(ab)))
    return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Conversions                                                          */
/* ------------------------------------------------------------------ */

static inline uint64_t tos_f2d(uint32_t fb)
{
  if (tos_fnan(fb))
    return TOS_DOUBLE_CANONICAL_NAN;

  tos_softfloat_begin();
  return tos_dcanon(f32_to_f64(tos_f32(fb)).v);
}

static inline uint32_t tos_d2f(uint64_t db)
{
  if (tos_dnan(db))
    return TOS_FLOAT_CANONICAL_NAN;

  tos_softfloat_begin();
  return tos_fcanon(f64_to_f32(tos_f64(db)).v);
}

static inline int32_t tos_f2i(uint32_t fb)
{
  if (tos_fnan(fb))
    return 0;
  if (tos_fpositive_ge(fb, UINT32_C(0x4F000000)))
    return INT32_MAX;
  if (tos_fnegative_le(fb, UINT32_C(0xCF000000)))
    return INT32_MIN;

  tos_softfloat_begin();
  return static_cast<int32_t>(
      f32_to_i32(tos_f32(fb), softfloat_round_minMag, false));
}

static inline int64_t tos_f2l(uint32_t fb)
{
  if (tos_fnan(fb))
    return 0;
  if (tos_fpositive_ge(fb, UINT32_C(0x5F000000)))
    return INT64_MAX;
  if (tos_fnegative_le(fb, UINT32_C(0xDF000000)))
    return INT64_MIN;

  tos_softfloat_begin();
  return static_cast<int64_t>(
      f32_to_i64(tos_f32(fb), softfloat_round_minMag, false));
}

static inline int32_t tos_d2i(uint64_t db)
{
  if (tos_dnan(db))
    return 0;
  if (tos_dpositive_ge(db, UINT64_C(0x41E0000000000000)))
    return INT32_MAX;
  if (tos_dnegative_le(db, UINT64_C(0xC1E0000000200000)))
    return INT32_MIN;

  tos_softfloat_begin();
  return static_cast<int32_t>(
      f64_to_i32(tos_f64(db), softfloat_round_minMag, false));
}

static inline int64_t tos_d2l(uint64_t db)
{
  if (tos_dnan(db))
    return 0;
  if (tos_dpositive_ge(db, UINT64_C(0x43E0000000000000)))
    return INT64_MAX;
  if (tos_dnegative_le(db, UINT64_C(0xC3E0000000000000)))
    return INT64_MIN;

  tos_softfloat_begin();
  return static_cast<int64_t>(
      f64_to_i64(tos_f64(db), softfloat_round_minMag, false));
}

static inline uint32_t tos_i2f(int32_t i)
{
  tos_softfloat_begin();
  return i32_to_f32(i).v;
}

static inline uint32_t tos_l2f(int64_t l)
{
  tos_softfloat_begin();
  return i64_to_f32(l).v;
}

static inline uint64_t tos_i2d(int32_t i)
{
  tos_softfloat_begin();
  return i32_to_f64(i).v;
}

static inline uint64_t tos_l2d(int64_t l)
{
  tos_softfloat_begin();
  return i64_to_f64(l).v;
}
