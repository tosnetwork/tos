#ifndef HEADER_at_tos_at_txn_transfer_h
#define HEADER_at_tos_at_txn_transfer_h

/* at_txn_transfer.h - TOS Transfer and Burn Payload Structures

   Transaction Type Discriminators:
   - 0: BurnPayload
   - 1: TransfersPayload

   Wire Format (Big-Endian):

   BurnPayload (Type 0):
     [asset:32][amount:8]

   TransfersPayload (Type 1):
     [count:2][transfers:*]
     where each transfer is:
       [asset:32][destination:32][amount:8][extra_data_len:2][extra_data:*]
*/

#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                           */
/**********************************************************************/

#define AT_TRANSFER_ASSET_SZ       (32UL)  /* Asset identifier size */
#define AT_TRANSFER_DEST_SZ        (32UL)  /* Destination address size */
#define AT_TRANSFER_MAX_EXTRA_DATA     (128UL)  /* Max extra data per transfer (TOS: EXTRA_DATA_LIMIT_SIZE) */
#define AT_TRANSFER_MAX_EXTRA_DATA_SUM (4096UL) /* Max total extra data in one TX (TOS: EXTRA_DATA_LIMIT_SUM_SIZE) */

/* Native TOS asset (all zeros) */
static uchar const AT_ASSET_TOS[AT_TRANSFER_ASSET_SZ] = {0};

/**********************************************************************/
/* Burn Payload (Type 0)                                               */
/**********************************************************************/

/* Burn payload structure (40 bytes fixed)
   Wire format: [asset:32][amount:8] */
typedef struct __attribute__((packed)) {
  uchar asset[AT_TRANSFER_ASSET_SZ];  /* Asset to burn (32 bytes) */
  uchar amount_be[8];                  /* Amount in big-endian */
} at_burn_payload_wire_t;

#define AT_BURN_PAYLOAD_SZ (40UL)

/* Parsed burn payload */
typedef struct {
  uchar asset[AT_TRANSFER_ASSET_SZ];
  ulong amount;
} at_burn_payload_t;

/* Parse burn payload from wire format */
static inline int
at_burn_payload_parse( uchar const *      data,
                       ulong              data_sz,
                       at_burn_payload_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_BURN_PAYLOAD_SZ ) ) {
    return -1;
  }

  at_burn_payload_wire_t const * wire = (at_burn_payload_wire_t const *)data;
  at_memcpy( out->asset, wire->asset, AT_TRANSFER_ASSET_SZ );
  out->amount = at_be64_to_native( wire->amount_be );

  /* Validate amount > 0 */
  if( AT_UNLIKELY( out->amount == 0 ) ) {
    return -1;
  }

  return 0;
}

/* Check if burning native TOS */
static inline int
at_burn_is_native( at_burn_payload_t const * burn ) {
  return at_memcmp( burn->asset, AT_ASSET_TOS, AT_TRANSFER_ASSET_SZ ) == 0;
}

/**********************************************************************/
/* Single Transfer Structure                                           */
/**********************************************************************/

/* Single transfer entry
   Wire format: [asset:32][destination:32][amount:8][extra_data_len:2][extra_data:*] */
typedef struct {
  uchar   asset[AT_TRANSFER_ASSET_SZ];      /* Asset identifier */
  uchar   destination[AT_TRANSFER_DEST_SZ]; /* Recipient address */
  ulong   amount;                            /* Transfer amount */
  ushort  extra_data_len;                    /* Extra data length */
  uint    extra_data_off;                    /* Offset to extra data in raw */
} at_transfer_t;

/* Minimum size for one transfer entry: asset(32) + dest(32) + amount(8) + len(2) */
#define AT_TRANSFER_MIN_SZ (74UL)

/* Parse a single transfer from wire format.
   Returns bytes consumed, or 0 on error. */
static inline ulong
at_transfer_parse( uchar const *   data,
                   ulong           data_sz,
                   ulong           base_off,
                   at_transfer_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_TRANSFER_MIN_SZ ) ) {
    return 0;
  }

  ulong off = 0;

  /* Asset (32 bytes) */
  at_memcpy( out->asset, data + off, AT_TRANSFER_ASSET_SZ );
  off += AT_TRANSFER_ASSET_SZ;

  /* Destination (32 bytes) */
  at_memcpy( out->destination, data + off, AT_TRANSFER_DEST_SZ );
  off += AT_TRANSFER_DEST_SZ;

  /* Amount (8 bytes, big-endian) */
  out->amount = at_be64_to_native( data + off );
  off += 8;

  /* Validate amount > 0 */
  if( AT_UNLIKELY( out->amount == 0 ) ) {
    return 0;
  }

  /* Extra data length (2 bytes, big-endian) */
  out->extra_data_len = at_be16_to_native( data + off );
  off += 2;

  /* Validate extra data length */
  if( AT_UNLIKELY( out->extra_data_len > AT_TRANSFER_MAX_EXTRA_DATA ) ) {
    return 0;
  }

  /* Check remaining buffer for extra data */
  if( AT_UNLIKELY( data_sz < off + out->extra_data_len ) ) {
    return 0;
  }

  out->extra_data_off = (uint)(base_off + off);
  off += out->extra_data_len;

  return off;
}

/**********************************************************************/
/* Transfers Payload (Type 1)                                          */
/**********************************************************************/

/* Transfers payload header
   Wire format: [count:2][transfers:*] */

#define AT_TRANSFERS_MAX_COUNT (500UL)

/* Parsed transfers payload (iterator-style for zero-copy) */
typedef struct {
  ushort count;           /* Number of transfers */
  uint   data_off;        /* Offset to first transfer in raw */
  uint   data_sz;         /* Size of transfer data */
} at_transfers_payload_t;

/* Parse transfers payload header.
   Returns 0 on success, -1 on error.
   Use at_transfers_iter_* to iterate through transfers. */
static inline int
at_transfers_payload_parse( uchar const *           data,
                            ulong                   data_sz,
                            uint                    base_off,
                            at_transfers_payload_t * out ) {
  /* Minimum: count(2) */
  if( AT_UNLIKELY( data_sz < 2 ) ) {
    return -1;
  }

  out->count = at_be16_to_native( data );

  /* Validate count */
  if( AT_UNLIKELY( out->count == 0 ) ) {
    return -1;
  }
  if( AT_UNLIKELY( out->count > AT_TRANSFERS_MAX_COUNT ) ) {
    return -1;
  }

  out->data_off = base_off + 2;
  out->data_sz = (uint)(data_sz - 2);

  return 0;
}

/**********************************************************************/
/* Transfers Iterator                                                  */
/**********************************************************************/

/* Iterator for walking through transfers in payload */
typedef struct {
  uchar const * data;      /* Pointer to transfer data */
  ulong         remaining; /* Remaining bytes */
  uint          base_off;  /* Base offset for extra_data_off calculation */
  ushort        count;     /* Total transfer count */
  ushort        idx;       /* Current index */
} at_transfers_iter_t;

/* Initialize transfers iterator */
static inline void
at_transfers_iter_init( at_transfers_iter_t *          iter,
                        at_transfers_payload_t const * payload,
                        uchar const *                  raw ) {
  iter->data = raw + payload->data_off;
  iter->remaining = payload->data_sz;
  iter->base_off = payload->data_off;
  iter->count = payload->count;
  iter->idx = 0;
}

/* Get next transfer from iterator.
   Returns 1 if transfer was read, 0 if done, -1 on error. */
static inline int
at_transfers_iter_next( at_transfers_iter_t * iter,
                        at_transfer_t *       out ) {
  if( iter->idx >= iter->count ) {
    return 0;
  }

  ulong consumed = at_transfer_parse( iter->data, iter->remaining,
                                      iter->base_off, out );
  if( AT_UNLIKELY( consumed == 0 ) ) {
    return -1;
  }

  iter->data += consumed;
  iter->remaining -= consumed;
  iter->base_off += (uint)consumed;
  iter->idx++;

  return 1;
}

/* Validate all transfers in payload (full walk) */
static inline int
at_transfers_validate( at_transfers_payload_t const * payload,
                       uchar const *                  raw ) {
  at_transfers_iter_t iter;
  at_transfers_iter_init( &iter, payload, raw );

  at_transfer_t transfer;
  ulong extra_data_sum = 0;
  int rc;
  while( (rc = at_transfers_iter_next( &iter, &transfer )) == 1 ) {
    /* Accumulate total extra data size across all transfers */
    extra_data_sum += transfer.extra_data_len;
    if( AT_UNLIKELY( extra_data_sum > AT_TRANSFER_MAX_EXTRA_DATA_SUM ) ) {
      return -1;
    }
  }

  return (rc == 0) ? 0 : -1;
}

/* Validate no self-transfers (TOS Rust alignment: VerificationError::SenderIsReceiver)
   Returns 0 on success, -1 if any transfer has destination == sender. */
static inline int
at_transfers_validate_no_self_transfer( at_transfers_payload_t const * payload,
                                        uchar const * raw,
                                        uchar const sender[32] ) {
  at_transfers_iter_t iter;
  at_transfers_iter_init( &iter, payload, raw );

  at_transfer_t transfer;
  int rc;
  while( (rc = at_transfers_iter_next( &iter, &transfer )) == 1 ) {
    /* TOS Rust: "sender cannot be the receiver in the same TX"
       Reference: ~/tos/common/src/transaction/verify/mod.rs:2178-2182 */
    if( at_memcmp( transfer.destination, sender, 32 ) == 0 ) {
      return -1;  /* Self-transfer detected */
    }
  }
  return (rc == 0) ? 0 : -1;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_transfer_h */