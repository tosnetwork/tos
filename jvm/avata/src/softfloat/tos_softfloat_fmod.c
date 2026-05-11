/* Java-compatible floating remainder helpers for the Avata SoftFloat path.
 *
 * Derived from Berkeley SoftFloat 3e f32_rem.c and f64_rem.c by John R.
 * Hauser.  SoftFloat's public f*_rem routines implement the IEEE remainder
 * operation, whose quotient is rounded to nearest.  Java's frem/drem opcodes
 * require the fmod-style remainder, whose quotient is rounded toward zero.
 *
 * The original SoftFloat license is retained in
 * src/softfloat/berkeley/COPYING.txt.
 */

#include <stdbool.h>
#include <stdint.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

float32_t tos_softfloat_f32_fmod(float32_t a, float32_t b)
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast32_t sigA;
    union ui32_f32 uB;
    uint_fast32_t uiB;
    int_fast16_t expB;
    uint_fast32_t sigB;
    struct exp16_sig32 normExpSig;
    uint32_t rem;
    int_fast16_t expDiff;
    uint32_t q, recip32, altRem;
    uint_fast32_t uiZ;
    union ui32_f32 uZ;

    uA.f = a;
    uiA = uA.ui;
    signA = signF32UI(uiA);
    expA = expF32UI(uiA);
    sigA = fracF32UI(uiA);
    uB.f = b;
    uiB = uB.ui;
    expB = expF32UI(uiB);
    sigB = fracF32UI(uiB);

    if (expA == 0xFF) {
        if (sigA || ((expB == 0xFF) && sigB)) goto propagateNaN;
        goto invalid;
    }
    if (expB == 0xFF) {
        if (sigB) goto propagateNaN;
        return a;
    }

    if (!expB) {
        if (!sigB) goto invalid;
        normExpSig = softfloat_normSubnormalF32Sig(sigB);
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if (!expA) {
        if (!sigA) return a;
        normExpSig = softfloat_normSubnormalF32Sig(sigA);
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }

    rem = sigA | 0x00800000;
    sigB |= 0x00800000;
    expDiff = expA - expB;
    if (expDiff < 1) {
        if (expDiff < -1) return a;
        sigB <<= 6;
        if (expDiff) {
            rem <<= 5;
        } else {
            rem <<= 6;
            if (sigB <= rem) rem -= sigB;
        }
    } else {
        recip32 = softfloat_approxRecip32_1(sigB << 8);
        rem <<= 7;
        expDiff -= 31;
        sigB <<= 6;
        for (;;) {
            q = (rem * (uint_fast64_t) recip32) >> 32;
            if (expDiff < 0) break;
            rem = -(q * (uint32_t) sigB);
            expDiff -= 29;
        }
        q >>= ~expDiff & 31;
        rem = (rem << (expDiff + 30)) - q * (uint32_t) sigB;
    }

    do {
        altRem = rem;
        rem -= sigB;
    } while (!(rem & 0x80000000));

    return softfloat_normRoundPackToF32(signA, expB, altRem);

 propagateNaN:
    uiZ = softfloat_propagateNaNF32UI(uiA, uiB);
    goto uiZ;
 invalid:
    softfloat_raiseFlags(softfloat_flag_invalid);
    uiZ = defaultNaNF32UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

float64_t tos_softfloat_f64_fmod(float64_t a, float64_t b)
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    struct exp16_sig64 normExpSig;
    uint64_t rem;
    int_fast16_t expDiff;
    uint32_t q, recip32;
    uint_fast64_t q64;
    uint64_t altRem;
    uint_fast64_t uiZ;
    union ui64_f64 uZ;

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI(uiA);
    expA = expF64UI(uiA);
    sigA = fracF64UI(uiA);
    uB.f = b;
    uiB = uB.ui;
    expB = expF64UI(uiB);
    sigB = fracF64UI(uiB);

    if (expA == 0x7FF) {
        if (sigA || ((expB == 0x7FF) && sigB)) goto propagateNaN;
        goto invalid;
    }
    if (expB == 0x7FF) {
        if (sigB) goto propagateNaN;
        return a;
    }
    if (expA < expB - 1) return a;

    if (!expB) {
        if (!sigB) goto invalid;
        normExpSig = softfloat_normSubnormalF64Sig(sigB);
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if (!expA) {
        if (!sigA) return a;
        normExpSig = softfloat_normSubnormalF64Sig(sigA);
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }

    rem = sigA | UINT64_C(0x0010000000000000);
    sigB |= UINT64_C(0x0010000000000000);
    expDiff = expA - expB;
    if (expDiff < 1) {
        if (expDiff < -1) return a;
        sigB <<= 9;
        if (expDiff) {
            rem <<= 8;
        } else {
            rem <<= 9;
            if (sigB <= rem) rem -= sigB;
        }
    } else {
        recip32 = softfloat_approxRecip32_1(sigB >> 21);
        rem <<= 9;
        expDiff -= 30;
        sigB <<= 9;
        for (;;) {
            q64 = (uint32_t) (rem >> 32) * (uint_fast64_t) recip32;
            if (expDiff < 0) break;
            q = (q64 + 0x80000000) >> 32;
#ifdef SOFTFLOAT_FAST_INT64
            rem <<= 29;
#else
            rem = (uint_fast64_t) (uint32_t) (rem >> 3) << 32;
#endif
            rem -= q * (uint64_t) sigB;
            if (rem & UINT64_C(0x8000000000000000)) rem += sigB;
            expDiff -= 29;
        }
        q = (uint32_t) (q64 >> 32) >> (~expDiff & 31);
        rem = (rem << (expDiff + 30)) - q * (uint64_t) sigB;
        if (rem & UINT64_C(0x8000000000000000)) {
            altRem = rem + sigB;
            goto packRem;
        }
    }

    do {
        altRem = rem;
        rem -= sigB;
    } while (!(rem & UINT64_C(0x8000000000000000)));

 packRem:
    return softfloat_normRoundPackToF64(signA, expB, altRem);

 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI(uiA, uiB);
    goto uiZ;
 invalid:
    softfloat_raiseFlags(softfloat_flag_invalid);
    uiZ = defaultNaNF64UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}
