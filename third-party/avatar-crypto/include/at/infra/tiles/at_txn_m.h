#ifndef HEADER_at_src_disco_at_txn_m_h
#define HEADER_at_src_disco_at_txn_m_h

/* at_txn_m_t is a parsed meta transaction, containing not just the
   payload but also metadata about the transaction source and processing.

   TODO: Implement based on TOS requirements
   This structure needs to be redesigned for TOS. The current definition
   is a placeholder. */

#include "at_disco_base.h"

/* TODO: Implement based on TOS requirements - transaction source types */
#define AT_TXN_M_SOURCE_QUIC   (1UL)  /* TODO: Implement based on TOS requirements */
#define AT_TXN_M_SOURCE_UDP    (2UL)
#define AT_TXN_M_SOURCE_GOSSIP (3UL)  /* TODO: Implement based on TOS requirements */
#define AT_TXN_M_SOURCE_BUNDLE (4UL)  /* TODO: Implement based on TOS requirements */
#define AT_TXN_M_SOURCE_SEND   (5UL)

/* TODO: Implement based on TOS requirements - Transaction metadata structure */

struct at_txn_m {
  /* TODO: Implement based on TOS requirements - reference concept */
  ulong    reference_block;  /* Placeholder - adjust for TOS */

  ushort   payload_sz;
  ushort   txn_t_sz;

  /* Network source information */
  uint     source_ipv4;      /* Big endian */
  uchar    source_type;      /* AT_TXN_M_SOURCE_* */

  /* 7 bytes padding */

  /* TODO: Implement based on TOS requirements - Bundle support */
  struct {
    ulong bundle_id;         /* TODO: Implement based on TOS requirements */
    ulong bundle_txn_cnt;    /* TODO: Implement based on TOS requirements */
    uchar commission;        /* TODO: Implement based on TOS requirements */
    uchar commission_pubkey[ 32 ];  /* TODO: Implement based on TOS requirements */
  } block_engine;

  /* Variable length fields follow (not in struct size):
     uchar    payload[ ]
     at_txn_t txn_t[ ]       - TODO: Define at_txn_t for TOS
     ... */
};

typedef struct at_txn_m at_txn_m_t;

static AT_FN_CONST inline ulong
at_txn_m_align( void ) {
  return alignof(at_txn_m_t);
}

/* TODO: Implement based on TOS requirements - footprint calculation
   Needs at_txn_t structure first.

static inline ulong
at_txn_m_footprint( ulong payload_sz,
                    ulong instr_cnt,
                    ulong addr_table_lookup_cnt,
                    ulong addr_table_adtl_cnt ) {
  ulong l = AT_LAYOUT_INIT;
  l = AT_LAYOUT_APPEND( l, alignof(at_txn_m_t), sizeof(at_txn_m_t) );
  l = AT_LAYOUT_APPEND( l, 1UL,                 payload_sz );
  l = AT_LAYOUT_APPEND( l, at_txn_align(),      at_txn_footprint( instr_cnt, addr_table_lookup_cnt ) );
  return AT_LAYOUT_FINI( l, at_txn_m_align() );
}
*/

static inline uchar *
at_txn_m_payload( at_txn_m_t * txnm ) {
  return (uchar *)(txnm+1UL);
}

static inline uchar const *
at_txn_m_payload_const( at_txn_m_t const * txnm ) {
  return (uchar const *)(txnm+1UL);
}

/* TODO: Implement based on TOS requirements
   Additional accessor functions for at_txn_t once it's defined:
   - at_txn_m_txn()
   - at_txn_m_txn_const()
   etc. */

#endif /* HEADER_at_src_disco_at_txn_m_h */