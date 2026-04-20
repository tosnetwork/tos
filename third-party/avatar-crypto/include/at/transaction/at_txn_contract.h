#ifndef HEADER_at_tos_at_txn_contract_h
#define HEADER_at_tos_at_txn_contract_h

/* at_txn_contract.h - TOS Contract Operations and ValueCell Parser

   Transaction Type Discriminators:
   - 3: InvokeContract
   - 4: DeployContract

   ValueCell Two-Level Type System:
   - Outer tags: Default(0), Bytes(1), Object(2), Map(3)
   - Inner Primitive tags (inside Default): Null(0), U8(1), U16(2), U32(3),
     U64(4), U128(5), U256(6), Bool(7), String(8), Range(9), Opaque(10)

   Wire Format (Big-Endian):

   InvokeContract (Type 3) (Rust):
     [contract:32][deposits_len:1][deposits:*][entry_id:2][max_gas:8][params_len:1][params:*]
     where each deposit = asset[32] + type_tag[1] + amount[8]
     and each param is a ValueCell

   DeployContract (Type 4) (Rust):
     [code_len:4][code:*][has_invoke:1][if has: max_gas:8][deposits_len:2][deposits:*]
*/

#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* ValueCell Type Tags                                                 */
/**********************************************************************/

/* Outer type tags */
typedef enum {
  AT_VALUE_DEFAULT = 0,  /* Contains a Primitive */
  AT_VALUE_BYTES   = 1,  /* Raw byte array */
  AT_VALUE_OBJECT  = 2,  /* Nested object/struct */
  AT_VALUE_MAP     = 3,  /* Key-value map */
} at_value_type_t;

/* Inner Primitive tags (when outer type is Default) */
typedef enum {
  AT_PRIM_NULL   = 0,
  AT_PRIM_U8     = 1,
  AT_PRIM_U16    = 2,
  AT_PRIM_U32    = 3,
  AT_PRIM_U64    = 4,
  AT_PRIM_U128   = 5,
  AT_PRIM_U256   = 6,
  AT_PRIM_BOOL   = 7,   /* Note: Bool is 7, NOT 0! */
  AT_PRIM_STRING = 8,
  AT_PRIM_RANGE  = 9,
  AT_PRIM_OPAQUE = 10,
} at_primitive_type_t;

#define AT_PRIM_MAX (10)

/* Check if primitive type is valid */
static inline int
at_primitive_type_is_valid( uchar prim ) {
  return prim <= AT_PRIM_MAX;
}

/**********************************************************************/
/* ValueCell Structure                                                 */
/**********************************************************************/

/* Parsed ValueCell (zero-copy with offsets) */
typedef struct at_value_cell at_value_cell_t;
struct at_value_cell {
  uchar outer_type;     /* at_value_type_t */
  uchar inner_type;     /* at_primitive_type_t (if outer_type == DEFAULT) */
  uint  data_off;       /* Offset to value data in raw */
  uint  data_sz;        /* Size of value data */

  /* For nested types (Object/Map) */
  ushort child_count;   /* Number of children (if Object/Map) */
  uint   children_off;  /* Offset to first child in raw */
};

/* ValueCell parsing hard limits (TOS Rust aligned) */
#define AT_VALUE_CELL_MAX_DEPTH      (64UL)
#define AT_VALUE_CELL_MAX_ARRAY_SIZE (10000UL)
#define AT_VALUE_CELL_MAX_MAP_SIZE   (10000UL)
#define AT_VALUE_CELL_MAX_BYTES_SIZE (1000000UL)

/**********************************************************************/
/* ValueCell Parsing                                                   */
/**********************************************************************/

/* Forward declaration for recursive parsing */
static inline int
at_value_cell_parse_with_depth( uchar const *     data,
                                ulong             data_sz,
                                uint              base_off,
                                ulong             depth,
                                at_value_cell_t * out,
                                ulong *           consumed );

/* Parse a Default (Primitive) value */
static inline int
at_value_cell_parse_primitive( uchar const *     data,
                               ulong             data_sz,
                               uint              base_off,
                               at_value_cell_t * out,
                               ulong *           consumed ) {
  if( AT_UNLIKELY( data_sz < 2 ) ) {
    return -1;
  }

  out->outer_type = AT_VALUE_DEFAULT;
  out->inner_type = data[1];
  out->child_count = 0;
  out->children_off = 0;

  if( AT_UNLIKELY( !at_primitive_type_is_valid( out->inner_type ) ) ) {
    return -1;
  }

  ulong off = 2;

  switch( out->inner_type ) {
    case AT_PRIM_NULL:
      out->data_off = base_off + (uint)off;
      out->data_sz = 0;
      break;

    case AT_PRIM_BOOL:
    case AT_PRIM_U8:
      if( AT_UNLIKELY( data_sz < off + 1 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 1;
      off += 1;
      break;

    case AT_PRIM_U16:
      if( AT_UNLIKELY( data_sz < off + 2 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 2;
      off += 2;
      break;

    case AT_PRIM_U32:
      if( AT_UNLIKELY( data_sz < off + 4 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 4;
      off += 4;
      break;

    case AT_PRIM_U64:
      if( AT_UNLIKELY( data_sz < off + 8 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 8;
      off += 8;
      break;

    case AT_PRIM_U128:
      if( AT_UNLIKELY( data_sz < off + 16 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 16;
      off += 16;
      break;

    case AT_PRIM_U256:
      if( AT_UNLIKELY( data_sz < off + 32 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 32;
      off += 32;
      break;

    case AT_PRIM_STRING:
    case AT_PRIM_OPAQUE: {
      /* Variable length: [len:4][data:*] */
      if( AT_UNLIKELY( data_sz < off + 4 ) ) return -1;
      uint len = at_be32_to_native( data + off );
      if( AT_UNLIKELY( (ulong)len > AT_VALUE_CELL_MAX_BYTES_SIZE ) ) return -1;
      off += 4;
      if( AT_UNLIKELY( data_sz < off + len ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = len;
      off += len;
      break;
    }

    case AT_PRIM_RANGE: {
      /* Range: [start:8][end:8] = 16 bytes */
      if( AT_UNLIKELY( data_sz < off + 16 ) ) return -1;
      out->data_off = base_off + (uint)off;
      out->data_sz = 16;
      off += 16;
      break;
    }

    default:
      return -1;
  }

  *consumed = off;
  return 0;
}

/* Parse Bytes value */
static inline int
at_value_cell_parse_bytes( uchar const *     data,
                           ulong             data_sz,
                           uint              base_off,
                           at_value_cell_t * out,
                           ulong *           consumed ) {
  /* Format: [type:1][len:4][data:*] */
  if( AT_UNLIKELY( data_sz < 5 ) ) {
    return -1;
  }

  out->outer_type = AT_VALUE_BYTES;
  out->inner_type = 0;
  out->child_count = 0;
  out->children_off = 0;

  uint len = at_be32_to_native( data + 1 );
  if( AT_UNLIKELY( (ulong)len > AT_VALUE_CELL_MAX_BYTES_SIZE ) ) {
    return -1;
  }
  if( AT_UNLIKELY( data_sz < 5 + len ) ) {
    return -1;
  }

  out->data_off = base_off + 5;
  out->data_sz = len;
  *consumed = 5 + len;
  return 0;
}

/* Parse Object value (recursive) */
static inline int
at_value_cell_parse_object( uchar const *     data,
                            ulong             data_sz,
                            uint              base_off,
                            ulong             depth,
                            at_value_cell_t * out,
                            ulong *           consumed ) {
  /* Format: [type:1][field_count:2][fields:*]
     Each field: [name_len:2][name:*][value:ValueCell] */
  if( AT_UNLIKELY( data_sz < 3 ) ) {
    return -1;
  }

  out->outer_type = AT_VALUE_OBJECT;
  out->inner_type = 0;
  out->child_count = at_be16_to_native( data + 1 );
  if( AT_UNLIKELY( (ulong)out->child_count > AT_VALUE_CELL_MAX_ARRAY_SIZE ) ) {
    return -1;
  }
  out->children_off = base_off + 3;
  out->data_off = base_off + 3;

  ulong off = 3;

  /* Walk through fields to calculate total size */
  for( ushort i = 0; i < out->child_count; i++ ) {
    /* Field name */
    if( AT_UNLIKELY( data_sz < off + 2 ) ) return -1;
    ushort name_len = at_be16_to_native( data + off );
    off += 2;
    if( AT_UNLIKELY( data_sz < off + name_len ) ) return -1;
    off += name_len;

    /* Field value (recursive) */
    at_value_cell_t child;
    ulong child_consumed = 0;
    int rc = at_value_cell_parse_with_depth( data + off, data_sz - off,
                                             base_off + (uint)off, depth + 1UL,
                                             &child, &child_consumed );
    if( AT_UNLIKELY( rc != 0 ) ) return rc;
    off += child_consumed;
  }

  out->data_sz = (uint)(off - 3);
  *consumed = off;
  return 0;
}

/* Parse Map value (recursive) */
static inline int
at_value_cell_parse_map( uchar const *     data,
                         ulong             data_sz,
                         uint              base_off,
                         ulong             depth,
                         at_value_cell_t * out,
                         ulong *           consumed ) {
  /* Format: [type:1][entry_count:2][entries:*]
     Each entry: [key:ValueCell][value:ValueCell] */
  if( AT_UNLIKELY( data_sz < 3 ) ) {
    return -1;
  }

  out->outer_type = AT_VALUE_MAP;
  out->inner_type = 0;
  out->child_count = at_be16_to_native( data + 1 );
  if( AT_UNLIKELY( (ulong)out->child_count > AT_VALUE_CELL_MAX_MAP_SIZE ) ) {
    return -1;
  }
  out->children_off = base_off + 3;
  out->data_off = base_off + 3;

  ulong off = 3;

  /* Walk through entries to calculate total size */
  for( ushort i = 0; i < out->child_count; i++ ) {
    /* Key */
    at_value_cell_t key;
    ulong key_consumed = 0;
    int rc = at_value_cell_parse_with_depth( data + off, data_sz - off,
                                             base_off + (uint)off, depth + 1UL,
                                             &key, &key_consumed );
    if( AT_UNLIKELY( rc != 0 ) ) return rc;
    off += key_consumed;

    /* Value */
    at_value_cell_t value;
    ulong value_consumed = 0;
    rc = at_value_cell_parse_with_depth( data + off, data_sz - off,
                                         base_off + (uint)off, depth + 1UL,
                                         &value, &value_consumed );
    if( AT_UNLIKELY( rc != 0 ) ) return rc;
    off += value_consumed;
  }

  out->data_sz = (uint)(off - 3);
  *consumed = off;
  return 0;
}

/* Main ValueCell parser (dispatches based on outer type) */
static inline int
at_value_cell_parse_with_depth( uchar const *     data,
                                ulong             data_sz,
                                uint              base_off,
                                ulong             depth,
                                at_value_cell_t * out,
                                ulong *           consumed ) {
  if( AT_UNLIKELY( depth > AT_VALUE_CELL_MAX_DEPTH ) ) {
    return -1;
  }
  if( AT_UNLIKELY( data_sz < 1 ) ) {
    return -1;
  }

  uchar outer_type = data[0];

  switch( outer_type ) {
    case AT_VALUE_DEFAULT:
      return at_value_cell_parse_primitive( data, data_sz, base_off, out, consumed );
    case AT_VALUE_BYTES:
      return at_value_cell_parse_bytes( data, data_sz, base_off, out, consumed );
    case AT_VALUE_OBJECT:
      return at_value_cell_parse_object( data, data_sz, base_off, depth, out, consumed );
    case AT_VALUE_MAP:
      return at_value_cell_parse_map( data, data_sz, base_off, depth, out, consumed );
    default:
      return -1;
  }
}

static inline int
at_value_cell_parse( uchar const *     data,
                     ulong             data_sz,
                     uint              base_off,
                     at_value_cell_t * out,
                     ulong *           consumed ) {
  return at_value_cell_parse_with_depth( data, data_sz, base_off, 0UL, out, consumed );
}

/**********************************************************************/
/* ValueCell Accessors                                                 */
/**********************************************************************/

/* Get value as u8 */
static inline int
at_value_cell_get_u8( at_value_cell_t const * cell, uchar const * raw, uchar * out ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_U8 ) {
    return -1;
  }
  *out = raw[cell->data_off];
  return 0;
}

/* Get value as u16 (big-endian) */
static inline int
at_value_cell_get_u16( at_value_cell_t const * cell, uchar const * raw, ushort * out ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_U16 ) {
    return -1;
  }
  *out = at_be16_to_native( raw + cell->data_off );
  return 0;
}

/* Get value as u32 (big-endian) */
static inline int
at_value_cell_get_u32( at_value_cell_t const * cell, uchar const * raw, uint * out ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_U32 ) {
    return -1;
  }
  *out = at_be32_to_native( raw + cell->data_off );
  return 0;
}

/* Get value as u64 (big-endian) */
static inline int
at_value_cell_get_u64( at_value_cell_t const * cell, uchar const * raw, ulong * out ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_U64 ) {
    return -1;
  }
  *out = at_be64_to_native( raw + cell->data_off );
  return 0;
}

/* Get value as bool */
static inline int
at_value_cell_get_bool( at_value_cell_t const * cell, uchar const * raw, int * out ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_BOOL ) {
    return -1;
  }
  *out = (raw[cell->data_off] != 0) ? 1 : 0;
  return 0;
}

/* Get value as bytes (returns pointer and length) */
static inline int
at_value_cell_get_bytes( at_value_cell_t const * cell,
                         uchar const *           raw,
                         uchar const **          out_ptr,
                         uint *                  out_len ) {
  if( cell->outer_type != AT_VALUE_BYTES ) {
    return -1;
  }
  *out_ptr = raw + cell->data_off;
  *out_len = cell->data_sz;
  return 0;
}

/* Get value as string (returns pointer and length) */
static inline int
at_value_cell_get_string( at_value_cell_t const * cell,
                          uchar const *           raw,
                          char const **           out_ptr,
                          uint *                  out_len ) {
  if( cell->outer_type != AT_VALUE_DEFAULT || cell->inner_type != AT_PRIM_STRING ) {
    return -1;
  }
  *out_ptr = (char const *)(raw + cell->data_off);
  *out_len = cell->data_sz;
  return 0;
}

/**********************************************************************/
/* Contract Constants (TOS-aligned)                                    */
/**********************************************************************/

#define AT_COIN_VALUE                (100000000UL) /* 10^8 */
#define AT_MIN_ARBITER_STAKE         (1000UL * AT_COIN_VALUE) /* 1000 TOS */
#define AT_BURN_PER_CONTRACT         (AT_COIN_VALUE)
#define AT_MAX_GAS_USAGE_PER_TX      (AT_COIN_VALUE * 10UL)
#define AT_MAX_DEPOSIT_PER_INVOKE_CALL (255U)
/* Percent of used gas that is burned (rest is miner fee) */
#define AT_TX_GAS_BURN_PERCENT       (30UL)
#define AT_COST_PER_TOKEN            (AT_COIN_VALUE)  /* 1 TOS per token creation (gas charge) */

/**********************************************************************/
/* Contract Deposits (Rust-compatible)                                 */
/**********************************************************************/

typedef struct {
  uchar asset[32];
  ulong amount;
} at_contract_deposit_t;

/* Deposit format: asset[32] + type_tag[1] + amount[8]
   type_tag 0 = public deposit (only supported) */
static inline int
at_contract_deposit_read( uchar const * raw,
                           ulong raw_sz,
                           uint off,
                           at_contract_deposit_t * out,
                           uint * next_off ) {
  if( AT_UNLIKELY( !raw || !out ) ) return -1;
  if( AT_UNLIKELY( raw_sz < (ulong)off + 41UL ) ) return -1;
  at_memcpy( out->asset, raw + off, 32 );
  off += 32;
  uchar type_tag = raw[off++];
  if( AT_UNLIKELY( type_tag != 0 ) ) return -1;
  out->amount = at_be64_to_native( raw + off );
  off += 8;
  if( next_off ) *next_off = off;
  return 0;
}

/**********************************************************************/
/* InvokeContract Payload (Type 3)                                     */
/**********************************************************************/

/* Wire format (Rust):
   [contract:32][deposits_len:1][deposits:*][entry_id:2][max_gas:8][params_len:1][params:*] */
#define AT_INVOKE_CONTRACT_MIN_SZ (44UL) /* contract(32)+deposits_len(1)+entry_id(2)+max_gas(8)+params_len(1) */

typedef struct {
  uchar  contract[32];    /* Contract address */
  uchar  deposits_cnt;    /* Number of deposits */
  uint   deposits_off;    /* Offset to first deposit */
  ushort entry_id;        /* Entry point ID */
  ulong  max_gas;         /* Max gas */
  uchar  params_cnt;      /* Number of parameters */
  uint   params_off;      /* Offset to first parameter */
} at_invoke_contract_t;

/* Parse InvokeContract payload header (use value cell parser to advance params) */
static inline int
at_invoke_contract_parse( uchar const *          data,
                          ulong                  data_sz,
                          uint                   base_off,
                          at_invoke_contract_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_INVOKE_CONTRACT_MIN_SZ ) ) {
    return -1;
  }

  ulong off = 0;
  at_memcpy( out->contract, data + off, 32 ); off += 32;

  out->deposits_cnt = data[off++];
  out->deposits_off = base_off + (uint)off;
  if( AT_UNLIKELY( out->deposits_cnt > AT_MAX_DEPOSIT_PER_INVOKE_CALL ) ) return -1;
  for( uchar i = 0; i < out->deposits_cnt; i++ ) {
    if( AT_UNLIKELY( data_sz < off + 41UL ) ) return -1;
    if( AT_UNLIKELY( data[off + 32] != 0 ) ) return -1;
    off += 41UL;
  }

  if( AT_UNLIKELY( data_sz < off + 2UL + 8UL + 1UL ) ) return -1;
  out->entry_id = at_be16_to_native( data + off ); off += 2;
  out->max_gas = at_be64_to_native( data + off ); off += 8;
  out->params_cnt = data[off++];
  out->params_off = base_off + (uint)off;

  /* Validate parameters (ValueCell) */
  for( uchar i = 0; i < out->params_cnt; i++ ) {
    at_value_cell_t cell;
    ulong consumed = 0;
    if( at_value_cell_parse( data + off, data_sz - off, base_off + (uint)off, &cell, &consumed ) ) return -1;
    off += consumed;
    if( AT_UNLIKELY( off > data_sz ) ) return -1;
  }

  return 0;
}

/**********************************************************************/
/* DeployContract Payload (Type 4)                                     */
/**********************************************************************/

/* Wire format (Rust):
   [code_len:4][code:*][has_invoke:1][if has: max_gas:8][deposits_len:2][deposits:*] */
#define AT_DEPLOY_CONTRACT_MIN_SZ (5UL)  /* code_len(4) + has_invoke(1) */

typedef struct {
  uint   code_off;         /* Offset to bytecode in raw */
  uint   code_len;         /* Bytecode length */
  uchar  invoke_present;   /* 1 if constructor invoke present */
  ulong  invoke_max_gas;   /* Constructor max gas */
  ushort invoke_deposits_cnt; /* Deposits count */
  uint   invoke_deposits_off; /* Offset to first deposit */
} at_deploy_contract_t;

/* Parse DeployContract payload header */
static inline int
at_deploy_contract_parse( uchar const *          data,
                          ulong                  data_sz,
                          uint                   base_off,
                          at_deploy_contract_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_DEPLOY_CONTRACT_MIN_SZ ) ) {
    return -1;
  }

  ulong off = 0;
  out->code_len = at_be32_to_native( data + off ); off += 4;
  if( AT_UNLIKELY( data_sz < off + out->code_len + 1UL ) ) return -1;
  out->code_off = base_off + (uint)off;
  off += out->code_len;

  out->invoke_present = data[off++];
  out->invoke_max_gas = 0;
  out->invoke_deposits_cnt = 0;
  out->invoke_deposits_off = 0;
  if( !out->invoke_present ) return 0;

  if( AT_UNLIKELY( data_sz < off + 8UL + 2UL ) ) return -1;
  out->invoke_max_gas = at_be64_to_native( data + off ); off += 8;
  out->invoke_deposits_cnt = at_be16_to_native( data + off ); off += 2;
  if( AT_UNLIKELY( out->invoke_deposits_cnt > AT_MAX_DEPOSIT_PER_INVOKE_CALL ) ) return -1;
  out->invoke_deposits_off = base_off + (uint)off;
  for( ushort i = 0; i < out->invoke_deposits_cnt; i++ ) {
    if( AT_UNLIKELY( data_sz < off + 41UL ) ) return -1;
    if( AT_UNLIKELY( data[off + 32] != 0 ) ) return -1;
    off += 41UL;
  }

  return 0;
}

/* Get bytecode pointer */
static inline uchar const *
at_deploy_contract_code( at_deploy_contract_t const * dc,
                         uchar const *                raw ) {
  return raw + dc->code_off;
}

/**********************************************************************/
/* Contract Args Iterator                                              */
/**********************************************************************/

/* Iterator for contract arguments */
typedef struct {
  uchar const * data;
  ulong         remaining;
  uint          base_off;
  ushort        count;
  ushort        idx;
} at_contract_args_iter_t;

/* Initialize args iterator for InvokeContract */
static inline void
at_invoke_args_iter_init( at_contract_args_iter_t *     iter,
                          at_invoke_contract_t const * ic,
                          uchar const *                raw,
                          ulong                        raw_sz ) {
  iter->data = raw + ic->params_off;
  iter->remaining = raw_sz - ic->params_off;
  iter->base_off = ic->params_off;
  iter->count = ic->params_cnt;
  iter->idx = 0;
}

/* Initialize args iterator for DeployContract */
static inline void
at_deploy_args_iter_init( at_contract_args_iter_t *     iter,
                          at_deploy_contract_t const * dc,
                          uchar const *                raw,
                          ulong                        raw_sz ) {
  (void)dc;
  iter->data = raw + raw_sz;
  iter->remaining = 0;
  iter->base_off = 0;
  iter->count = 0;
  iter->idx = 0;
}

/* Get next argument from iterator.
   Returns 1 if arg was read, 0 if done, -1 on error. */
static inline int
at_contract_args_iter_next( at_contract_args_iter_t * iter,
                            at_value_cell_t *         out ) {
  if( iter->idx >= iter->count ) {
    return 0;
  }

  ulong consumed = 0;
  int rc = at_value_cell_parse( iter->data, iter->remaining,
                                iter->base_off, out, &consumed );
  if( AT_UNLIKELY( rc != 0 ) ) {
    return -1;
  }

  iter->data += consumed;
  iter->remaining -= consumed;
  iter->base_off += (uint)consumed;
  iter->idx++;

  return 1;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_contract_h */
