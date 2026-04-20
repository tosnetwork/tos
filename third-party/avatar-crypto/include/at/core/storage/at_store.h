/* at_store.h - Abstract Storage Interface for Avatar
 *
 * This module provides a backend-agnostic storage interface supporting
 * RocksDB and in-memory backends with identical column family semantics.
 *
 * Usage:
 *   - Use at_store_* APIs for backend-independent operations
 *   - Column families remain identical to at_rocks (TOS-compatible)
 *   - Backend selection via at_store_cfg_t.backend field
 *
 * Thread Safety:
 *   - at_store_t is thread-safe for concurrent reads
 *   - RocksDB supports concurrent writes
 */

#ifndef HEADER_at_store_at_store_h
#define HEADER_at_store_at_store_h

#include "at/infra/at_util_base.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Error Codes - Compatible with at_rocks
   ============================================================================ */

typedef enum {
  AT_STORE_OK             =  0,  /* Success */
  AT_STORE_ERR_NOT_FOUND  = -1,  /* Key not found */
  AT_STORE_ERR_IO         = -2,  /* Backend IO error */
  AT_STORE_ERR_CORRUPTION = -3,  /* Data corruption detected */
  AT_STORE_ERR_INVALID    = -4,  /* Invalid argument */
  AT_STORE_ERR_FULL       = -5,  /* Buffer too small */
  AT_STORE_ERR_EXISTS     = -6,  /* Key already exists */
  AT_STORE_ERR_BUSY       = -7,  /* Resource busy */
  AT_STORE_ERR_UNSUPPORTED= -8,  /* Operation intentionally unsupported */
} at_store_err_t;

/* ============================================================================
   Backend Selection
   ============================================================================ */

typedef enum {
  AT_STORE_BACKEND_ROCKS = 0,  /* RocksDB backend */
  AT_STORE_BACKEND_MEM   = 1,  /* In-memory backend */
} at_store_backend_t;

/* ============================================================================
   Column Families - Identical to at_rocks.h for TOS compatibility
   See: at_rocks.h for full documentation

   Note: When at_rocks.h is included first, at_cf_t will already be defined
   as an enum type. The AT_ROCKS_AT_CF_T_DEFINED guard is set by at_rocks.h.
   ============================================================================ */

/* Only define at_cf_t if not already defined by at_rocks.h */
#ifndef AT_ROCKS_AT_CF_T_DEFINED
typedef uint at_cf_t;
#endif

/* Only define CF constants if not already defined by at_rocks.h */
#ifndef AT_CF_COUNT

/* Transaction columns */
#define AT_CF_TRANSACTIONS               (0)
#define AT_CF_TRANSACTIONS_EXECUTED      (1)
#define AT_CF_TRANSACTION_IN_BLOCKS      (2)
#define AT_CF_TRANSACTIONS_OUTPUTS       (3)

/* Block columns */
#define AT_CF_BLOCKS_EXECUTION_ORDER     (4)
#define AT_CF_BLOCKS                     (5)
#define AT_CF_BLOCKS_AT_HEIGHT           (6)
#define AT_CF_TOPO_BY_HASH               (7)
#define AT_CF_HASH_AT_TOPO               (8)
#define AT_CF_BLOCK_DIFFICULTY           (9)

/* Common metadata */
#define AT_CF_COMMON                     (10)
#define AT_CF_TOPO_HEIGHT_METADATA       (11)

/* Asset columns */
#define AT_CF_ASSETS                     (12)
#define AT_CF_ASSET_BY_ID                (13)
#define AT_CF_VERSIONED_ASSETS           (14)

/* Account columns */
#define AT_CF_ACCOUNT                    (15)
#define AT_CF_PREFIXED_REGISTRATIONS     (16)
#define AT_CF_ACCOUNT_BY_ID              (17)

/* Versioned account data */
#define AT_CF_VERSIONED_MULTISIG         (18)
#define AT_CF_VERSIONED_NONCES           (19)

/* Balance columns */
#define AT_CF_BALANCES                   (20)
#define AT_CF_VERSIONED_BALANCES         (21)

/* UNO (privacy) balance columns */
#define AT_CF_UNO_BALANCES               (22)
#define AT_CF_VERSIONED_UNO_BALANCES     (23)

/* Contract columns */
#define AT_CF_CONTRACTS                  (24)
#define AT_CF_CONTRACT_BY_ID             (25)
#define AT_CF_VERSIONED_CONTRACTS        (26)
#define AT_CF_VERSIONED_CONTRACTS_DATA   (27)
#define AT_CF_CONTRACTS_DATA             (28)
#define AT_CF_CONTRACT_DATA_BY_ID        (29)
#define AT_CF_CONTRACTS_BALANCES         (30)
#define AT_CF_VERSIONED_CONTRACTS_BALANCES (31)
#define AT_CF_CONTRACTS_ASSET_EXT        (32)
#define AT_CF_VERSIONED_CONTRACTS_ASSET_EXT (33)
#define AT_CF_VERSIONED_ASSETS_SUPPLY    (34)

/* Energy columns */
#define AT_CF_VERSIONED_ENERGY_RESOURCES (35)

/* Contract events */
#define AT_CF_CONTRACT_EVENTS            (36)
#define AT_CF_CONTRACT_EVENTS_BY_TX      (37)
#define AT_CF_CONTRACT_EVENTS_BY_TOPIC   (38)

/* Delayed execution */
#define AT_CF_DELAYED_EXECUTION          (39)
#define AT_CF_DELAYED_EXECUTION_REGISTRATIONS (40)
#define AT_CF_DELAYED_EXECUTION_PRIORITY (41)

/* Energy Delegation */
#define AT_CF_DELEGATION_RECORDS         (42)
#define AT_CF_DELEGATOR_STATE            (43)

#define AT_CF_COUNT                      (44)

#endif /* AT_CF_COUNT */

/* Column family names for TOS compatibility */
extern char const * const AT_STORE_CF_NAMES[AT_CF_COUNT];

/* ============================================================================
   Storage Constants - Compatible with at_rocks
   ============================================================================ */

/* Keys in AT_CF_COMMON (4 bytes each) */
#define AT_STORE_KEY_TIPS               "TIPS"
#define AT_STORE_KEY_TOP_TOPO_HEIGHT    "TOPO"
#define AT_STORE_KEY_TOP_HEIGHT         "TOPH"
#define AT_STORE_KEY_PRUNED_TOPOHEIGHT  "PRUN"
#define AT_STORE_KEY_TXS_COUNT          "CTXS"
#define AT_STORE_KEY_BLOCKS_COUNT       "CBLK"
#define AT_STORE_KEY_BLOCKS_EXEC_ORDER  "EBLK"
#define AT_STORE_KEY_NEXT_ACCOUNT_ID    "NAID"
#define AT_STORE_KEY_ASSETS_ID          "ASID"
#define AT_STORE_KEY_NEXT_CONTRACT_ID   "NCID"

/* ============================================================================
   TOS Serialization Helpers (Big Endian) - Identical to at_rocks
   ============================================================================ */

static inline void
at_store_write_u64_be( uchar * dst, ulong val ) {
  dst[0] = (uchar)(val >> 56);
  dst[1] = (uchar)(val >> 48);
  dst[2] = (uchar)(val >> 40);
  dst[3] = (uchar)(val >> 32);
  dst[4] = (uchar)(val >> 24);
  dst[5] = (uchar)(val >> 16);
  dst[6] = (uchar)(val >> 8);
  dst[7] = (uchar)(val);
}

static inline ulong
at_store_read_u64_be( uchar const * src ) {
  return ((ulong)src[0] << 56) |
         ((ulong)src[1] << 48) |
         ((ulong)src[2] << 40) |
         ((ulong)src[3] << 32) |
         ((ulong)src[4] << 24) |
         ((ulong)src[5] << 16) |
         ((ulong)src[6] << 8) |
         ((ulong)src[7]);
}

static inline void
at_store_write_u32_be( uchar * dst, uint val ) {
  dst[0] = (uchar)(val >> 24);
  dst[1] = (uchar)(val >> 16);
  dst[2] = (uchar)(val >> 8);
  dst[3] = (uchar)(val);
}

static inline uint
at_store_read_u32_be( uchar const * src ) {
  return ((uint)src[0] << 24) |
         ((uint)src[1] << 16) |
         ((uint)src[2] << 8) |
         ((uint)src[3]);
}

static inline void
at_store_write_u16_be( uchar * dst, ushort val ) {
  dst[0] = (uchar)(val >> 8);
  dst[1] = (uchar)(val);
}

static inline ushort
at_store_read_u16_be( uchar const * src ) {
  return (ushort)(((ushort)src[0] << 8) | (ushort)src[1]);
}

#if AT_HAS_INT128
static inline void
at_store_write_u128_be( uchar * dst, __uint128_t val ) {
  for( int i = 15; i >= 0; i-- ) {
    dst[i] = (uchar)(val & 0xffU);
    val >>= 8;
  }
}

static inline __uint128_t
at_store_read_u128_be( uchar const * src ) {
  __uint128_t val = 0;
  for( int i = 0; i < 16; i++ ) {
    val = (val << 8) | (__uint128_t)src[i];
  }
  return val;
}
#endif

static inline int
at_store_write_option_u64_be( uchar * dst, int has_value, ulong value ) {
  if( has_value ) {
    dst[0] = 0x01;
    at_store_write_u64_be( dst + 1, value );
    return 9;
  } else {
    dst[0] = 0x00;
    return 1;
  }
}

static inline int
at_store_read_option_u64_be( uchar const * src, ulong src_len, ulong * value_out, ulong * bytes_read ) {
  if( src_len < 1 ) return -1;
  if( src[0] == 0x00 ) {
    *bytes_read = 1;
    return 0;  /* None */
  } else if( src[0] == 0x01 ) {
    if( src_len < 9 ) return -1;
    *value_out = at_store_read_u64_be( src + 1 );
    *bytes_read = 9;
    return 1;  /* Some */
  }
  return -1;  /* Invalid */
}

/* ============================================================================
   Opaque Types
   ============================================================================ */

typedef struct at_store       at_store_t;
typedef struct at_store_batch at_store_batch_t;
typedef struct at_store_iter  at_store_iter_t;
typedef struct at_store_snap  at_store_snap_t;

/* Internal allocation header for at_store_get_alloc results */
#define AT_STORE_ALLOC_MAGIC (0x617473746f72655fUL) /* "atstore_" */
typedef struct {
  ulong       magic;
  at_alloc_t * alloc;
} at_store_alloc_hdr_t;

/* ============================================================================
   Configuration
   ============================================================================ */

typedef struct at_store_cfg {
  char const *       db_path;           /* Database directory path */
  at_store_backend_t backend;           /* Backend type (rocks/mem) */
  ulong              cache_size;        /* Block cache (default: 128MB) */
  ulong              map_size;          /* Reserved for compatibility */
  ulong              write_buffer_size; /* RocksDB: memtable (default: 64MB) */
  int                compression;       /* RocksDB: 0=none, 1=snappy, 2=zstd */
  int                parallelism;       /* RocksDB: background threads (default: 4) */
  int                sync_mode;         /* 0=async, 1=sync (default: 0) */
  int                create_if_missing; /* Create if not exists (default: 1) */
  int                read_only;         /* Open read-only (default: 0) */
  at_alloc_t *       alloc;             /* Optional allocator for internal objects */
} at_store_cfg_t;

#define AT_STORE_CFG_DEFAULT { \
  .db_path           = "./avatar_state", \
  .backend           = AT_STORE_BACKEND_ROCKS, \
  .cache_size        = 128UL << 20, \
  .map_size          = 1UL << 30, \
  .write_buffer_size = 64UL << 20, \
  .compression       = 1, \
  .parallelism       = 4, \
  .sync_mode         = 0, \
  .create_if_missing = 1, \
  .read_only         = 0, \
  .alloc             = NULL, \
}

static inline at_store_cfg_t
at_store_cfg_for_tests( void ) {
  at_store_cfg_t cfg = (at_store_cfg_t)AT_STORE_CFG_DEFAULT;
  cfg.parallelism = 1;
  return cfg;
}

/* ============================================================================
   Database Lifecycle
   ============================================================================ */

/* Open a database with the specified configuration.
   Returns NULL on failure, use at_store_strerror() for error details. */
at_store_t * at_store_open( at_store_cfg_t const * cfg );

/* Close database and release resources. */
void at_store_close( at_store_t * store );

/* Get last error message. */
char const * at_store_strerror( at_store_t * store );

/* Get the backend type of an open store. */
at_store_backend_t at_store_backend( at_store_t * store );

/* Get allocator used by store (if any). */
at_alloc_t * at_store_alloc( at_store_t * store );

/* ============================================================================
   Basic Operations
   ============================================================================ */

/* Get value by key. Copies to val_out buffer (max *val_sz_inout bytes).
   Returns: AT_STORE_OK, AT_STORE_ERR_NOT_FOUND, AT_STORE_ERR_FULL, etc. */
int at_store_get( at_store_t * store, at_cf_t cf,
                  void const * key, ulong key_sz,
                  void * val_out, ulong * val_sz_inout );

/* Get value by key with allocation. Caller frees with at_store_free().
   Returns: AT_STORE_OK, AT_STORE_ERR_NOT_FOUND, etc. */
int at_store_get_alloc( at_store_t * store, at_cf_t cf,
                        void const * key, ulong key_sz,
                        void ** val_out, ulong * val_sz_out );

/* Free memory allocated by at_store_get_alloc(). */
void at_store_free( void * ptr );

/* Put key-value pair. */
int at_store_put( at_store_t * store, at_cf_t cf,
                  void const * key, ulong key_sz,
                  void const * val, ulong val_sz );

/* Delete key. */
int at_store_delete( at_store_t * store, at_cf_t cf,
                     void const * key, ulong key_sz );

/* Check if key exists. Returns 1 if exists, 0 if not, <0 on error. */
int at_store_exists( at_store_t * store, at_cf_t cf,
                     void const * key, ulong key_sz );

/* ============================================================================
   Atomic Batch Operations
   ============================================================================ */

/* Create a new write batch. */
at_store_batch_t * at_store_batch_new( at_store_t * store );

/* Add put operation to batch. */
int at_store_batch_put( at_store_batch_t * batch, at_cf_t cf,
                        void const * key, ulong key_sz,
                        void const * val, ulong val_sz );

/* Add delete operation to batch. */
int at_store_batch_delete( at_store_batch_t * batch, at_cf_t cf,
                           void const * key, ulong key_sz );

/* Add delete-range operation to batch (deletes all keys in [start_key, end_key)). */
int at_store_batch_delete_range( at_store_batch_t * batch, at_cf_t cf,
                                 void const * start_key, ulong start_key_sz,
                                 void const * end_key,   ulong end_key_sz );

/* Commit batch atomically. Destroys batch on success. */
int at_store_batch_commit( at_store_batch_t * batch );

/* Abort batch without committing. */
void at_store_batch_abort( at_store_batch_t * batch );

/* Clear all operations from batch without destroying it. */
void at_store_batch_clear( at_store_batch_t * batch );

/* Destroy batch (use after abort, not after successful commit). */
void at_store_batch_destroy( at_store_batch_t * batch );

/* Get number of operations in batch. */
ulong at_store_batch_count( at_store_batch_t const * batch );

/* ============================================================================
   Iterator
   ============================================================================ */

/* Create iterator for column family. */
at_store_iter_t * at_store_iter_new( at_store_t * store, at_cf_t cf );

/* Seek to first key. */
void at_store_iter_seek_first( at_store_iter_t * iter );

/* Seek to last key. */
void at_store_iter_seek_last( at_store_iter_t * iter );

/* Seek to specific key (or next greater). */
void at_store_iter_seek( at_store_iter_t * iter, void const * key, ulong key_sz );

/* Seek to prefix (for prefix iteration). */
void at_store_iter_seek_prefix( at_store_iter_t * iter, void const * prefix, ulong prefix_sz );

/* Check if iterator is valid. */
int at_store_iter_valid( at_store_iter_t * iter );

/* Check if iterator is valid and key matches prefix. */
int at_store_iter_valid_prefix( at_store_iter_t * iter );

/* Move to next entry. */
void at_store_iter_next( at_store_iter_t * iter );

/* Move to previous entry. */
void at_store_iter_prev( at_store_iter_t * iter );

/* Get current key (valid until next operation). */
void const * at_store_iter_key( at_store_iter_t * iter, ulong * key_sz );

/* Get current value (valid until next operation). */
void const * at_store_iter_val( at_store_iter_t * iter, ulong * val_sz );

/* Destroy iterator. */
void at_store_iter_destroy( at_store_iter_t * iter );

/* ============================================================================
   Snapshot
   ============================================================================ */

/* Create a point-in-time snapshot. */
at_store_snap_t * at_store_snap_new( at_store_t * store );

/* Destroy snapshot. */
void at_store_snap_destroy( at_store_snap_t * snap );

/* Get value from snapshot. */
int at_store_snap_get( at_store_snap_t * snap, at_cf_t cf,
                       void const * key, ulong key_sz,
                       void * val_out, ulong * val_sz_inout );

/* Create iterator on snapshot. */
at_store_iter_t * at_store_snap_iter_new( at_store_snap_t * snap, at_cf_t cf );

/* ============================================================================
   Maintenance
   ============================================================================ */

/* Trigger compaction (RocksDB). */
int at_store_compact( at_store_t * store );

/* Flush memtable to disk. */
int at_store_flush( at_store_t * store );

/* Sync to disk. */
int at_store_sync( at_store_t * store );

/* ============================================================================
   Transactions (for atomic multi-operation commits)
   ============================================================================ */

/* Begin a transaction. All writes after this will be buffered until commit. */
int at_store_tx_begin( at_store_t * store );

/* Commit all buffered writes atomically. */
int at_store_tx_commit( at_store_t * store );

/* Rollback and discard all buffered writes. */
int at_store_tx_rollback( at_store_t * store );

/* Check if a transaction is currently active. */
int at_store_tx_is_active( at_store_t * store );

/* Delete all keys with given prefix in column family (for version rollback). */
int at_store_delete_prefix( at_store_t * store, at_cf_t cf,
                            void const * prefix, ulong prefix_sz );

/* Clear internal caches (after rollback or major state change). */
void at_store_clear_caches( at_store_t * store );

/* ============================================================================
   Utilities
   ============================================================================ */

/* Get database property (backend-specific). */
char * at_store_get_property( at_store_t * store, char const * property );

/* Get highest topoheight. */
ulong at_store_get_top_topoheight( at_store_t * store );

/* Get highest height. */
ulong at_store_get_top_height( at_store_t * store );

/* Set highest topoheight. */
int at_store_set_top_topoheight( at_store_t * store, ulong topoheight );

/* Set highest height. */
int at_store_set_top_height( at_store_t * store, ulong height );

/* Get next account ID. */
ulong at_store_get_next_account_id( at_store_t * store );

/* Get next contract ID. */
ulong at_store_get_next_contract_id( at_store_t * store );

/* ============================================================================
   Compatibility Helpers
   ============================================================================ */

/* Forward declaration for at_rocks_t */
struct at_rocks;
typedef struct at_rocks at_rocks_t;

/* Get underlying at_rocks_t pointer for backwards compatibility.
   Returns NULL if store is not a RocksDB backend. */
at_rocks_t * at_store_get_rocks( at_store_t * store );

/* Create an at_store_t wrapper around an existing at_rocks_t.
   The caller is responsible for calling at_store_unwrap_rocks() to free
   the wrapper (NOT at_store_close which would close the underlying rocks). */
at_store_t * at_store_wrap_rocks( at_rocks_t * rocks );

/* Free a wrapper created by at_store_wrap_rocks().
   Does NOT close the underlying at_rocks_t. */
void at_store_unwrap_rocks( at_store_t * store );

/* ============================================================================
   Backend-Specific Functions (Internal Use)

   When both backends are compiled, the generic at_store_* functions
   dispatch to the appropriate backend based on store->backend field.
   ============================================================================ */

at_store_t * at_store_rocks_open( at_store_cfg_t const * cfg );
void         at_store_rocks_close( at_store_t * store );
char const * at_store_rocks_strerror( at_store_t * store );
int  at_store_rocks_get( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void * val_out, ulong * val_sz_inout );
int  at_store_rocks_get_alloc( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void ** val_out, ulong * val_sz_out );
void at_store_rocks_free( void * ptr );
int  at_store_rocks_put( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void const * val, ulong val_sz );
int  at_store_rocks_delete( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz );
int  at_store_rocks_exists( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz );
at_store_batch_t * at_store_rocks_batch_new( at_store_t * store );
int  at_store_rocks_batch_put( at_store_batch_t * batch, at_cf_t cf, void const * key, ulong key_sz, void const * val, ulong val_sz );
int  at_store_rocks_batch_delete( at_store_batch_t * batch, at_cf_t cf, void const * key, ulong key_sz );
int  at_store_rocks_batch_delete_range( at_store_batch_t * batch, at_cf_t cf, void const * start_key, ulong start_key_sz, void const * end_key, ulong end_key_sz );
int  at_store_rocks_batch_commit( at_store_batch_t * batch );
void at_store_rocks_batch_abort( at_store_batch_t * batch );
void at_store_rocks_batch_clear( at_store_batch_t * batch );
void at_store_rocks_batch_destroy( at_store_batch_t * batch );
ulong at_store_rocks_batch_count( at_store_batch_t const * batch );
at_store_iter_t * at_store_rocks_iter_new( at_store_t * store, at_cf_t cf );
void at_store_rocks_iter_seek_first( at_store_iter_t * iter );
void at_store_rocks_iter_seek_last( at_store_iter_t * iter );
void at_store_rocks_iter_seek( at_store_iter_t * iter, void const * key, ulong key_sz );
void at_store_rocks_iter_seek_prefix( at_store_iter_t * iter, void const * prefix, ulong prefix_sz );
int  at_store_rocks_iter_valid( at_store_iter_t * iter );
int  at_store_rocks_iter_valid_prefix( at_store_iter_t * iter );
void at_store_rocks_iter_next( at_store_iter_t * iter );
void at_store_rocks_iter_prev( at_store_iter_t * iter );
void const * at_store_rocks_iter_key( at_store_iter_t * iter, ulong * key_sz );
void const * at_store_rocks_iter_val( at_store_iter_t * iter, ulong * val_sz );
void at_store_rocks_iter_destroy( at_store_iter_t * iter );
at_store_snap_t * at_store_rocks_snap_new( at_store_t * store );
void at_store_rocks_snap_destroy( at_store_snap_t * snap );
int  at_store_rocks_snap_get( at_store_snap_t * snap, at_cf_t cf, void const * key, ulong key_sz, void * val_out, ulong * val_sz_inout );
at_store_iter_t * at_store_rocks_snap_iter_new( at_store_snap_t * snap, at_cf_t cf );
int  at_store_rocks_compact( at_store_t * store );
int  at_store_rocks_flush( at_store_t * store );
int  at_store_rocks_sync( at_store_t * store );
at_alloc_t * at_store_rocks_alloc( at_store_t * store );

/* In-memory backend (always available on hosted builds). */
at_store_t * at_store_mem_open( at_store_cfg_t const * cfg );
void         at_store_mem_close( at_store_t * store );
char const * at_store_mem_strerror( at_store_t * store );
int  at_store_mem_get( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void * val_out, ulong * val_sz_inout );
int  at_store_mem_get_alloc( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void ** val_out, ulong * val_sz_out );
void at_store_mem_free( void * ptr );
int  at_store_mem_put( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz, void const * val, ulong val_sz );
int  at_store_mem_delete( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz );
int  at_store_mem_exists( at_store_t * store, at_cf_t cf, void const * key, ulong key_sz );
at_store_batch_t * at_store_mem_batch_new( at_store_t * store );
int  at_store_mem_batch_put( at_store_batch_t * batch, at_cf_t cf, void const * key, ulong key_sz, void const * val, ulong val_sz );
int  at_store_mem_batch_delete( at_store_batch_t * batch, at_cf_t cf, void const * key, ulong key_sz );
int  at_store_mem_batch_delete_range( at_store_batch_t * batch, at_cf_t cf, void const * start_key, ulong start_key_sz, void const * end_key, ulong end_key_sz );
int  at_store_mem_batch_commit( at_store_batch_t * batch );
void at_store_mem_batch_abort( at_store_batch_t * batch );
void at_store_mem_batch_clear( at_store_batch_t * batch );
void at_store_mem_batch_destroy( at_store_batch_t * batch );
ulong at_store_mem_batch_count( at_store_batch_t const * batch );
at_store_iter_t * at_store_mem_iter_new( at_store_t * store, at_cf_t cf );
void at_store_mem_iter_seek_first( at_store_iter_t * iter );
void at_store_mem_iter_seek_last( at_store_iter_t * iter );
void at_store_mem_iter_seek( at_store_iter_t * iter, void const * key, ulong key_sz );
void at_store_mem_iter_seek_prefix( at_store_iter_t * iter, void const * prefix, ulong prefix_sz );
int  at_store_mem_iter_valid( at_store_iter_t * iter );
int  at_store_mem_iter_valid_prefix( at_store_iter_t * iter );
void at_store_mem_iter_next( at_store_iter_t * iter );
void at_store_mem_iter_prev( at_store_iter_t * iter );
void const * at_store_mem_iter_key( at_store_iter_t * iter, ulong * key_sz );
void const * at_store_mem_iter_val( at_store_iter_t * iter, ulong * val_sz );
void at_store_mem_iter_destroy( at_store_iter_t * iter );
at_store_snap_t * at_store_mem_snap_new( at_store_t * store );
void at_store_mem_snap_destroy( at_store_snap_t * snap );
int  at_store_mem_snap_get( at_store_snap_t * snap, at_cf_t cf, void const * key, ulong key_sz, void * val_out, ulong * val_sz_inout );
at_store_iter_t * at_store_mem_snap_iter_new( at_store_snap_t * snap, at_cf_t cf );
int  at_store_mem_compact( at_store_t * store );
int  at_store_mem_flush( at_store_t * store );
int  at_store_mem_sync( at_store_t * store );
at_alloc_t * at_store_mem_alloc( at_store_t * store );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_at_store_h */
