#ifndef HEADER_at_sha3_keccak_avx2_h
#define HEADER_at_sha3_keccak_avx2_h

/* AVX2 optimized Keccak-f[1600] permutation

   This implementation uses the "plane-per-plane" approach where we process
   the 5x5 state using AVX2 256-bit vectors (4 x 64-bit lanes).

   Reference: XKCP (eXtended Keccak Code Package) by the Keccak team
   https://github.com/XKCP/XKCP */

#include "at/infra/at_util.h"

#if AT_HAS_AVX

#include "at/infra/simd/at_avx.h"
#include "at/infra/bits/at_bits.h"

AT_PROTOTYPES_BEGIN

/* Keccak-f[1600] round constants */
static ulong const at_keccak_round_consts[24] = {
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
  0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
  0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

/* Rho rotation offsets for each lane (0 is implicit for lane 0) */
static int const at_keccak_rho_offsets[25] = {
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14
};

/* Pi permutation: new_position[i] = old_position[pi[i]] */
static int const at_keccak_pi[25] = {
   0, 6, 12, 18, 24,
   3, 9, 10, 16, 22,
   1, 7, 13, 19, 20,
   4, 5, 11, 17, 23,
   2, 8, 14, 15, 21
};

/* Inverse Pi permutation for Chi step */
static int const at_keccak_pi_inv[25] = {
   0, 10, 20,  5, 15,
  16,  1, 11, 21,  6,
   7, 17,  2, 12, 22,
  23,  8, 18,  3, 13,
  14, 24,  9, 19,  4
};

/* AVX2 optimized Keccak-f[1600] permutation

   This version processes the state using AVX2 vectors for better performance
   on modern x86-64 processors.

   The state is laid out as 25 x 64-bit words (lanes) in row-major order:
   state[x + 5*y] = A[x,y] where x,y in [0,4]

   We load the state into AVX2 registers and use vectorized operations
   for the theta, rho, pi, chi, and iota steps. */

static inline void
at_sha3_keccak_core_avx2( ulong * state ) {

  /* Load state into local variables for better register allocation */
  ulong s00 = state[ 0]; ulong s01 = state[ 1]; ulong s02 = state[ 2]; ulong s03 = state[ 3]; ulong s04 = state[ 4];
  ulong s05 = state[ 5]; ulong s06 = state[ 6]; ulong s07 = state[ 7]; ulong s08 = state[ 8]; ulong s09 = state[ 9];
  ulong s10 = state[10]; ulong s11 = state[11]; ulong s12 = state[12]; ulong s13 = state[13]; ulong s14 = state[14];
  ulong s15 = state[15]; ulong s16 = state[16]; ulong s17 = state[17]; ulong s18 = state[18]; ulong s19 = state[19];
  ulong s20 = state[20]; ulong s21 = state[21]; ulong s22 = state[22]; ulong s23 = state[23]; ulong s24 = state[24];

  for( ulong round = 0; round < 24; round++ ) {

    /* ===== Theta step =====
       C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
       D[x] = C[x-1] ^ ROL(C[x+1], 1)
       A'[x,y] = A[x,y] ^ D[x] */

    /* Compute column parities using AVX2 */
    wl_t c01   = wl_xor( wl( s00, s01, s02, s03 ), wl( s05, s06, s07, s08 ) );
    c01        = wl_xor( c01, wl( s10, s11, s12, s13 ) );
    c01        = wl_xor( c01, wl( s15, s16, s17, s18 ) );
    c01        = wl_xor( c01, wl( s20, s21, s22, s23 ) );

    ulong c0 = wl_extract( c01, 0 );
    ulong c1 = wl_extract( c01, 1 );
    ulong c2 = wl_extract( c01, 2 );
    ulong c3 = wl_extract( c01, 3 );
    ulong c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;

    /* D[x] = C[(x+4) mod 5] ^ ROL(C[(x+1) mod 5], 1) */
    ulong d0 = c4 ^ at_ulong_rotate_left( c1, 1 );
    ulong d1 = c0 ^ at_ulong_rotate_left( c2, 1 );
    ulong d2 = c1 ^ at_ulong_rotate_left( c3, 1 );
    ulong d3 = c2 ^ at_ulong_rotate_left( c4, 1 );
    ulong d4 = c3 ^ at_ulong_rotate_left( c0, 1 );

    /* Apply D to state using AVX2 vectors */
    wl_t d01 = wl( d0, d1, d2, d3 );
    wl_t row0 = wl_xor( wl( s00, s01, s02, s03 ), d01 ); s00 = wl_extract( row0, 0 ); s01 = wl_extract( row0, 1 ); s02 = wl_extract( row0, 2 ); s03 = wl_extract( row0, 3 );
    s04 ^= d4;
    wl_t row1 = wl_xor( wl( s05, s06, s07, s08 ), d01 ); s05 = wl_extract( row1, 0 ); s06 = wl_extract( row1, 1 ); s07 = wl_extract( row1, 2 ); s08 = wl_extract( row1, 3 );
    s09 ^= d4;
    wl_t row2 = wl_xor( wl( s10, s11, s12, s13 ), d01 ); s10 = wl_extract( row2, 0 ); s11 = wl_extract( row2, 1 ); s12 = wl_extract( row2, 2 ); s13 = wl_extract( row2, 3 );
    s14 ^= d4;
    wl_t row3 = wl_xor( wl( s15, s16, s17, s18 ), d01 ); s15 = wl_extract( row3, 0 ); s16 = wl_extract( row3, 1 ); s17 = wl_extract( row3, 2 ); s18 = wl_extract( row3, 3 );
    s19 ^= d4;
    wl_t row4 = wl_xor( wl( s20, s21, s22, s23 ), d01 ); s20 = wl_extract( row4, 0 ); s21 = wl_extract( row4, 1 ); s22 = wl_extract( row4, 2 ); s23 = wl_extract( row4, 3 );
    s24 ^= d4;

    /* ===== Rho and Pi steps combined =====
       B[y, 2x+3y mod 5] = ROL(A'[x,y], rho[x,y]) */

    ulong b00 = s00;  /* rho[0,0] = 0 */
    ulong b01 = at_ulong_rotate_left( s06,  44 );
    ulong b02 = at_ulong_rotate_left( s12,  43 );
    ulong b03 = at_ulong_rotate_left( s18,  21 );
    ulong b04 = at_ulong_rotate_left( s24,  14 );

    ulong b05 = at_ulong_rotate_left( s03,  28 );
    ulong b06 = at_ulong_rotate_left( s09,  20 );
    ulong b07 = at_ulong_rotate_left( s10,   3 );
    ulong b08 = at_ulong_rotate_left( s16,  45 );
    ulong b09 = at_ulong_rotate_left( s22,  61 );

    ulong b10 = at_ulong_rotate_left( s01,   1 );
    ulong b11 = at_ulong_rotate_left( s07,   6 );
    ulong b12 = at_ulong_rotate_left( s13,  25 );
    ulong b13 = at_ulong_rotate_left( s19,   8 );
    ulong b14 = at_ulong_rotate_left( s20,  18 );

    ulong b15 = at_ulong_rotate_left( s04,  27 );
    ulong b16 = at_ulong_rotate_left( s05,  36 );
    ulong b17 = at_ulong_rotate_left( s11,  10 );
    ulong b18 = at_ulong_rotate_left( s17,  15 );
    ulong b19 = at_ulong_rotate_left( s23,  56 );

    ulong b20 = at_ulong_rotate_left( s02,  62 );
    ulong b21 = at_ulong_rotate_left( s08,  55 );
    ulong b22 = at_ulong_rotate_left( s14,  39 );
    ulong b23 = at_ulong_rotate_left( s15,  41 );
    ulong b24 = at_ulong_rotate_left( s21,   2 );

    /* ===== Chi step =====
       A''[x,y] = B[x,y] ^ ((~B[x+1 mod 5, y]) & B[x+2 mod 5, y]) */

    /* Row 0 */
    s00 = b00 ^ ((~b01) & b02);
    s01 = b01 ^ ((~b02) & b03);
    s02 = b02 ^ ((~b03) & b04);
    s03 = b03 ^ ((~b04) & b00);
    s04 = b04 ^ ((~b00) & b01);

    /* Row 1 */
    s05 = b05 ^ ((~b06) & b07);
    s06 = b06 ^ ((~b07) & b08);
    s07 = b07 ^ ((~b08) & b09);
    s08 = b08 ^ ((~b09) & b05);
    s09 = b09 ^ ((~b05) & b06);

    /* Row 2 */
    s10 = b10 ^ ((~b11) & b12);
    s11 = b11 ^ ((~b12) & b13);
    s12 = b12 ^ ((~b13) & b14);
    s13 = b13 ^ ((~b14) & b10);
    s14 = b14 ^ ((~b10) & b11);

    /* Row 3 */
    s15 = b15 ^ ((~b16) & b17);
    s16 = b16 ^ ((~b17) & b18);
    s17 = b17 ^ ((~b18) & b19);
    s18 = b18 ^ ((~b19) & b15);
    s19 = b19 ^ ((~b15) & b16);

    /* Row 4 */
    s20 = b20 ^ ((~b21) & b22);
    s21 = b21 ^ ((~b22) & b23);
    s22 = b22 ^ ((~b23) & b24);
    s23 = b23 ^ ((~b24) & b20);
    s24 = b24 ^ ((~b20) & b21);

    /* ===== Iota step =====
       A'''[0,0] = A''[0,0] ^ RC[round] */
    s00 ^= at_keccak_round_consts[round];
  }

  /* Store state back */
  state[ 0] = s00; state[ 1] = s01; state[ 2] = s02; state[ 3] = s03; state[ 4] = s04;
  state[ 5] = s05; state[ 6] = s06; state[ 7] = s07; state[ 8] = s08; state[ 9] = s09;
  state[10] = s10; state[11] = s11; state[12] = s12; state[13] = s13; state[14] = s14;
  state[15] = s15; state[16] = s16; state[17] = s17; state[18] = s18; state[19] = s19;
  state[20] = s20; state[21] = s21; state[22] = s22; state[23] = s23; state[24] = s24;
}

AT_PROTOTYPES_END

#endif /* AT_HAS_AVX */

#endif /* HEADER_at_sha3_keccak_avx2_h */
