#ifndef HEADER_at_ballet_at_merlin_h
#define HEADER_at_ballet_at_merlin_h

/* at_merlin.h - Merlin transcript for Fiat-Shamir heuristic

   Merlin is a STROBE-based transcript construction for zero-knowledge
   proof systems. It provides a way to transform interactive protocols
   into non-interactive ones using the Fiat-Shamir heuristic.

   Reference: https://github.com/hdevalence/libmerlin */

#include "at_crypto_base.h"

#define AT_MERLIN_LITERAL(STR) ("" STR), (sizeof(STR)-1)

struct at_merlin_strobe128 {
  union {
    ulong state[25];
    uchar state_bytes[200];
  };
  uchar pos;
  uchar pos_begin;
  uchar cur_flags;
};
typedef struct at_merlin_strobe128 at_merlin_strobe128_t;

struct at_merlin_transcript {
  at_merlin_strobe128_t sctx;
};
typedef struct at_merlin_transcript at_merlin_transcript_t;

AT_PROTOTYPES_BEGIN

void
at_merlin_transcript_init( at_merlin_transcript_t * mctx,
                           char const * const       label,
                           uint const               label_len );

void
at_merlin_transcript_append_message( at_merlin_transcript_t * mctx,
                                     char const * const       label,
                                     uint const               label_len,
                                     uchar const *            message,
                                     uint const               message_len );

void
at_merlin_transcript_append_u64( at_merlin_transcript_t * mctx,
                                 char const * const       label,
                                 uint const               label_len,
                                 ulong const              message_u64 );

void
at_merlin_transcript_challenge_bytes( at_merlin_transcript_t * mctx,
                                      char const * const       label,
                                      uint const               label_len,
                                      uchar *                  buffer,
                                      uint const               buffer_len );

AT_PROTOTYPES_END
#endif /* HEADER_at_ballet_at_merlin_h */