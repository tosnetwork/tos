#ifndef HEADER_at_rocks_at_rocks_h
#define HEADER_at_rocks_at_rocks_h

/* at_rocks.h - RocksDB Storage for Avatar (100% TOS Compatible)

   This module provides persistent key-value storage using RocksDB with
   column families and serialization format IDENTICAL to TOS daemon.

   CRITICAL: All data structures, column names, key formats, and
   serialization must match TOS exactly for database interoperability.

   TOS Serialization Rules:
   - All integers: BIG-ENDIAN
   - Option<T>: 1 byte bool (1=Some, 0=None) + optional value
   - Vec<T>: u16 count (2 bytes, BE) + elements
   - Strings: 1 byte length + UTF-8 bytes (max 255)

   Thread Safety:
   - at_rocks_t is thread-safe for concurrent reads
   - Single writer model: only one thread may call write operations
*/

#include "at_rocks_error.h"
#include "at/infra/at_util_base.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Column Families - MUST match TOS exactly (snake_case names)
   See: tos/daemon/src/core/storage/rocksdb/column.rs
   ============================================================================ */

/* If at_store.h was included first, use its macro definitions instead */
#ifndef AT_CF_TRANSACTIONS
typedef enum {
  /* Transaction columns */
  AT_CF_TRANSACTIONS               = 0,
  AT_CF_TRANSACTIONS_EXECUTED      = 1,
  AT_CF_TRANSACTION_IN_BLOCKS      = 2,
  AT_CF_TRANSACTIONS_OUTPUTS       = 3,

  /* Block columns */
  AT_CF_BLOCKS_EXECUTION_ORDER     = 4,
  AT_CF_BLOCKS                     = 5,
  AT_CF_BLOCKS_AT_HEIGHT           = 6,
  AT_CF_TOPO_BY_HASH               = 7,
  AT_CF_HASH_AT_TOPO               = 8,
  AT_CF_BLOCK_DIFFICULTY           = 9,

  /* Common metadata */
  AT_CF_COMMON                     = 10,
  AT_CF_TOPO_HEIGHT_METADATA       = 11,

  /* Asset columns */
  AT_CF_ASSETS                     = 12,
  AT_CF_ASSET_BY_ID                = 13,
  AT_CF_VERSIONED_ASSETS           = 14,

  /* Account columns */
  AT_CF_ACCOUNT                    = 15,
  AT_CF_PREFIXED_REGISTRATIONS     = 16,
  AT_CF_ACCOUNT_BY_ID              = 17,

  /* Versioned account data */
  AT_CF_VERSIONED_MULTISIG         = 18,
  AT_CF_VERSIONED_NONCES           = 19,

  /* Balance columns */
  AT_CF_BALANCES                   = 20,
  AT_CF_VERSIONED_BALANCES         = 21,

  /* UNO (privacy) balance columns */
  AT_CF_UNO_BALANCES               = 22,
  AT_CF_VERSIONED_UNO_BALANCES     = 23,

  /* Contract columns */
  AT_CF_CONTRACTS                  = 24,
  AT_CF_CONTRACT_BY_ID             = 25,
  AT_CF_VERSIONED_CONTRACTS        = 26,
  AT_CF_VERSIONED_CONTRACTS_DATA   = 27,
  AT_CF_CONTRACTS_DATA             = 28,
  AT_CF_CONTRACT_DATA_BY_ID        = 29,
  AT_CF_CONTRACTS_BALANCES         = 30,
  AT_CF_VERSIONED_CONTRACTS_BALANCES = 31,
  AT_CF_CONTRACTS_ASSET_EXT        = 32,
  AT_CF_VERSIONED_CONTRACTS_ASSET_EXT = 33,
  AT_CF_VERSIONED_ASSETS_SUPPLY    = 34,

  /* Energy columns */
  AT_CF_VERSIONED_ENERGY_RESOURCES = 35,

  /* Contract events */
  AT_CF_CONTRACT_EVENTS            = 36,
  AT_CF_CONTRACT_EVENTS_BY_TX      = 37,
  AT_CF_CONTRACT_EVENTS_BY_TOPIC   = 38,

  /* Delayed execution */
  AT_CF_DELAYED_EXECUTION          = 39,
  AT_CF_DELAYED_EXECUTION_REGISTRATIONS = 40,
  AT_CF_DELAYED_EXECUTION_PRIORITY = 41,

  /* Energy Delegation */
  AT_CF_DELEGATION_RECORDS         = 42,
  AT_CF_DELEGATOR_STATE            = 43,

  AT_CF_COUNT                      = 44
} at_cf_t;

/* Guard for at_store.h to know at_cf_t is already defined */
#define AT_ROCKS_AT_CF_T_DEFINED 1
#endif /* AT_CF_TRANSACTIONS */

/* Column family names - MUST match TOS strum snake_case serialization */
extern char const * const AT_CF_NAMES[AT_CF_COUNT];

/* Column family prefix lengths (for RocksDB prefix extractor) */
int at_cf_prefix_len( at_cf_t cf );

/* ============================================================================
   Storage Constants - MUST match TOS exactly
   See: tos/daemon/src/core/storage/constants.rs
   ============================================================================ */

/* Keys in AT_CF_COMMON (4 bytes each) */
#define AT_KEY_TIPS               "TIPS"  /* Current chain tips */
#define AT_KEY_TOP_TOPO_HEIGHT    "TOPO"  /* Highest topoheight */
#define AT_KEY_TOP_HEIGHT         "TOPH"  /* Highest height */
#define AT_KEY_PRUNED_TOPOHEIGHT  "PRUN"  /* Pruned topoheight */
#define AT_KEY_TXS_COUNT          "CTXS"  /* Transaction count */
#define AT_KEY_BLOCKS_COUNT       "CBLK"  /* Block count */
#define AT_KEY_BLOCKS_EXEC_ORDER  "EBLK"  /* Blocks execution order count */
#define AT_KEY_NEXT_ACCOUNT_ID    "NAID"  /* Next account ID counter */
#define AT_KEY_ASSETS_ID          "ASID"  /* Assets counter */
#define AT_KEY_NEXT_CONTRACT_ID   "NCID"  /* Next contract ID */

/* ============================================================================
   TOS Serialization Helpers (Big Endian)
   ============================================================================ */

/* Write u64 in big-endian format */
static inline void
at_write_u64_be( uchar * dst, ulong val ) {
  dst[0] = (uchar)(val >> 56);
  dst[1] = (uchar)(val >> 48);
  dst[2] = (uchar)(val >> 40);
  dst[3] = (uchar)(val >> 32);
  dst[4] = (uchar)(val >> 24);
  dst[5] = (uchar)(val >> 16);
  dst[6] = (uchar)(val >> 8);
  dst[7] = (uchar)(val);
}

/* Read u64 from big-endian format */
static inline ulong
at_read_u64_be( uchar const * src ) {
  return ((ulong)src[0] << 56) |
         ((ulong)src[1] << 48) |
         ((ulong)src[2] << 40) |
         ((ulong)src[3] << 32) |
         ((ulong)src[4] << 24) |
         ((ulong)src[5] << 16) |
         ((ulong)src[6] << 8) |
         ((ulong)src[7]);
}

/* Write u32 in big-endian format */
static inline void
at_write_u32_be( uchar * dst, uint val ) {
  dst[0] = (uchar)(val >> 24);
  dst[1] = (uchar)(val >> 16);
  dst[2] = (uchar)(val >> 8);
  dst[3] = (uchar)(val);
}

/* Read u32 from big-endian format */
static inline uint
at_read_u32_be( uchar const * src ) {
  return ((uint)src[0] << 24) |
         ((uint)src[1] << 16) |
         ((uint)src[2] << 8) |
         ((uint)src[3]);
}

/* Write u16 in big-endian format */
static inline void
at_write_u16_be( uchar * dst, ushort val ) {
  dst[0] = (uchar)(val >> 8);
  dst[1] = (uchar)(val);
}

/* Read u16 from big-endian format */
static inline ushort
at_read_u16_be( uchar const * src ) {
  return (ushort)(((ushort)src[0] << 8) | (ushort)src[1]);
}

#if AT_HAS_INT128
/* Write u128 in big-endian format */
static inline void
at_write_u128_be( uchar * dst, __uint128_t val ) {
  for( int i = 15; i >= 0; i-- ) {
    dst[i] = (uchar)(val & 0xffU);
    val >>= 8;
  }
}

/* Read u128 from big-endian format */
static inline __uint128_t
at_read_u128_be( uchar const * src ) {
  __uint128_t val = 0;
  for( int i = 0; i < 16; i++ ) {
    val = (val << 8) | (__uint128_t)src[i];
  }
  return val;
}
#endif

/* Write Option<u64>: 1 byte flag + optional 8 bytes value
   Returns number of bytes written (1 or 9) */
static inline int
at_write_option_u64_be( uchar * dst, int has_value, ulong value ) {
  if( has_value ) {
    dst[0] = 0x01;
    at_write_u64_be( dst + 1, value );
    return 9;
  } else {
    dst[0] = 0x00;
    return 1;
  }
}

/* Read Option<u64>: returns 1 if Some, 0 if None, -1 on error
   Sets *value_out if Some */
static inline int
at_read_option_u64_be( uchar const * src, ulong src_len, ulong * value_out, ulong * bytes_read ) {
  if( src_len < 1 ) return -1;
  if( src[0] == 0x00 ) {
    *bytes_read = 1;
    return 0;  /* None */
  } else if( src[0] == 0x01 ) {
    if( src_len < 9 ) return -1;
    *value_out = at_read_u64_be( src + 1 );
    *bytes_read = 9;
    return 1;  /* Some */
  }
  return -1;  /* Invalid */
}

/* ============================================================================
   Opaque Types
   ============================================================================ */

typedef struct at_rocks         at_rocks_t;
typedef struct at_rocks_batch   at_rocks_batch_t;
typedef struct at_rocks_iter    at_rocks_iter_t;
typedef struct at_rocks_snapshot at_rocks_snapshot_t;

/* ============================================================================
   Configuration
   ============================================================================ */

typedef struct at_rocks_cfg {
  char const * db_path;           /* Database directory path */
  ulong        cache_size;        /* Block cache (default: 128MB) */
  ulong        write_buffer_size; /* Memtable (default: 64MB) */
  int          compression;       /* 0=none, 1=snappy (default), 2=zstd */
  int          parallelism;       /* Background threads (default: 4) */
  int          create_if_missing; /* Create database if it doesn't exist (default: 1) */
  int          error_if_exists;   /* Error if database already exists (default: 0) */
  at_alloc_t * alloc;             /* Optional allocator for internal objects */
} at_rocks_cfg_t;

#define AT_ROCKS_CFG_DEFAULT { \
  .db_path           = "./avatar_state", \
  .cache_size        = 128UL << 20,      \
  .write_buffer_size = 64UL << 20,       \
  .compression       = 1,                \
  .parallelism       = 4,                \
  .create_if_missing = 1,                \
  .error_if_exists   = 0,                \
  .alloc             = NULL,             \
}

static inline at_rocks_cfg_t
at_rocks_cfg_for_tests( void ) {
  at_rocks_cfg_t cfg = (at_rocks_cfg_t)AT_ROCKS_CFG_DEFAULT;
  cfg.parallelism = 1;
  return cfg;
}

/* ============================================================================
   Database Lifecycle
   ============================================================================ */

at_rocks_t * at_rocks_open( at_rocks_cfg_t const * cfg );
void         at_rocks_close( at_rocks_t * db );
char const * at_rocks_strerror( at_rocks_t * db );
char const * at_rocks_last_error( at_rocks_t * db );
at_alloc_t * at_rocks_alloc( at_rocks_t * db );
at_alloc_t * at_rocks_batch_alloc( at_rocks_batch_t * batch );

/* ============================================================================
   Basic Operations
   ============================================================================ */

int at_rocks_get( at_rocks_t * db, at_cf_t cf,
                  void const * key, ulong key_sz,
                  void * val_out, ulong * val_sz_inout );

int at_rocks_get_alloc( at_rocks_t * db, at_cf_t cf,
                        void const * key, ulong key_sz,
                        void ** val_out, ulong * val_sz_out );

void at_rocks_free( void * ptr );

int at_rocks_put( at_rocks_t * db, at_cf_t cf,
                  void const * key, ulong key_sz,
                  void const * val, ulong val_sz );

int at_rocks_delete( at_rocks_t * db, at_cf_t cf,
                     void const * key, ulong key_sz );

int at_rocks_exists( at_rocks_t * db, at_cf_t cf,
                     void const * key, ulong key_sz );

/* ============================================================================
   Atomic Batch Operations
   ============================================================================ */

at_rocks_batch_t * at_rocks_batch_new( at_rocks_t * db );

int at_rocks_batch_put( at_rocks_batch_t * batch, at_cf_t cf,
                        void const * key, ulong key_sz,
                        void const * val, ulong val_sz );

int at_rocks_batch_delete( at_rocks_batch_t * batch, at_cf_t cf,
                           void const * key, ulong key_sz );

int at_rocks_batch_delete_range( at_rocks_batch_t * batch, at_cf_t cf,
                                 void const * start_key, ulong start_key_sz,
                                 void const * end_key,   ulong end_key_sz );

int  at_rocks_batch_commit( at_rocks_batch_t * batch );
void at_rocks_batch_abort( at_rocks_batch_t * batch );
void at_rocks_batch_clear( at_rocks_batch_t * batch );
void at_rocks_batch_destroy( at_rocks_batch_t * batch );
ulong at_rocks_batch_count( at_rocks_batch_t const * batch );

/* ============================================================================
   Iterator
   ============================================================================ */

at_rocks_iter_t * at_rocks_iter_new( at_rocks_t * db, at_cf_t cf );
void at_rocks_iter_seek_first( at_rocks_iter_t * iter );
void at_rocks_iter_seek_last( at_rocks_iter_t * iter );
void at_rocks_iter_seek( at_rocks_iter_t * iter, void const * key, ulong key_sz );
void at_rocks_iter_seek_prefix( at_rocks_iter_t * iter, void const * prefix, ulong prefix_sz );
int  at_rocks_iter_valid( at_rocks_iter_t * iter );
int  at_rocks_iter_valid_prefix( at_rocks_iter_t * iter );
void at_rocks_iter_next( at_rocks_iter_t * iter );
void at_rocks_iter_prev( at_rocks_iter_t * iter );
void const * at_rocks_iter_key( at_rocks_iter_t * iter, ulong * key_sz );
void const * at_rocks_iter_val( at_rocks_iter_t * iter, ulong * val_sz );
void at_rocks_iter_destroy( at_rocks_iter_t * iter );

/* ============================================================================
   Snapshot
   ============================================================================ */

at_rocks_snapshot_t * at_rocks_snapshot_new( at_rocks_t * db );
void at_rocks_snapshot_destroy( at_rocks_snapshot_t * snap );
int  at_rocks_snapshot_get( at_rocks_snapshot_t * snap, at_cf_t cf,
                            void const * key, ulong key_sz,
                            void * val_out, ulong * val_sz_inout );

/* ============================================================================
   Maintenance
   ============================================================================ */

int at_rocks_compact( at_rocks_t * db );
int at_rocks_flush( at_rocks_t * db );

/* ============================================================================
   Utilities
   ============================================================================ */

char * at_rocks_get_property( at_rocks_t * db, char const * property );
ulong  at_rocks_get_size_on_disk( at_rocks_t * db );
ulong  at_rocks_get_top_topoheight( at_rocks_t * db );
int    at_rocks_set_top_topoheight( at_rocks_t * db, ulong topoheight );
ulong  at_rocks_get_next_account_id( at_rocks_t * db );
ulong  at_rocks_get_next_contract_id( at_rocks_t * db );

AT_PROTOTYPES_END

#endif /* HEADER_at_rocks_at_rocks_h */
