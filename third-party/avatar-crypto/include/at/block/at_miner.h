#ifndef HEADER_at_block_at_miner_h
#define HEADER_at_block_at_miner_h

/* at_miner.h - TOS-aligned MinerWork/Worker surface

   Mirrors common/src/block/miner.rs structure and data layout. */

#include "at/infra/at_util_base.h"
#include "at/block/at_block.h"
#include "at/crypto/at_tos_hash_v1.h"
#include "at/crypto/at_tos_hash_v2.h"
#include "at/crypto/at_tos_hash_v3.h"

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_MINING_ALGORITHM_V1 = 0,
  AT_MINING_ALGORITHM_V2 = 1,
  AT_MINING_ALGORITHM_V3 = 2
} at_mining_algorithm_t;

typedef enum {
  AT_MINING_WORK_VARIANT_UNINITIALIZED = 0,
  AT_MINING_WORK_VARIANT_V1            = 1,
  AT_MINING_WORK_VARIANT_V2            = 2,
  AT_MINING_WORK_VARIANT_V3            = 3
} at_mining_work_variant_t;

typedef struct {
  uchar header_work_hash[32];
  ulong timestamp_ms;
  ulong nonce;
  uchar extra_nonce[32];
  uchar miner[32];
  int   has_miner;
} at_miner_work_t;

typedef struct {
  int                       has_work;
  at_mining_work_variant_t  variant;
  at_miner_work_t           work;
  uchar                     work_bytes[AT_BLOCK_MINER_WORK_SIZE];
  at_tos_hash_v1_scratch_t  scratch_v1;
  at_tos_hash_v2_scratch_t  scratch_v2;
  at_tos_hash_v3_scratch_t  scratch_v3;
} at_miner_worker_t;

typedef enum {
  AT_MINER_WORKER_OK                         = 0,
  AT_MINER_WORKER_ERR_UNINITIALIZED          = -1,
  AT_MINER_WORKER_ERR_MISSING_WORK           = -2,
  AT_MINER_WORKER_ERR_INVALID_ARGUMENT       = -3,
  AT_MINER_WORKER_ERR_INVALID_ALGORITHM      = -4,
  AT_MINER_WORKER_ERR_UNSUPPORTED_POW_BACKEND= -5
} at_miner_worker_err_t;

char const *
at_mining_algorithm_to_cstr( at_mining_algorithm_t algorithm );

int
at_mining_algorithm_from_cstr( char const *            s,
                               at_mining_algorithm_t * out_algorithm );

at_mining_work_variant_t
at_mining_work_variant_for_algorithm( at_mining_algorithm_t algorithm );

at_mining_algorithm_t
at_mining_work_variant_get_algorithm( at_mining_work_variant_t variant );

at_miner_work_t *
at_miner_work_new( at_miner_work_t * out,
                   uchar const       header_work_hash[32],
                   ulong             timestamp_ms );

at_miner_work_t *
at_miner_work_from_block_header( at_miner_work_t *          out,
                                 at_block_header_t const *  header );

void
at_miner_work_set_timestamp( at_miner_work_t * work,
                             ulong             timestamp_ms );

void
at_miner_work_increase_nonce( at_miner_work_t * work );

void
at_miner_work_set_miner( at_miner_work_t * work,
                         uchar const       miner[32] );

void
at_miner_work_clear_miner( at_miner_work_t * work );

void
at_miner_work_set_thread_id( at_miner_work_t * work,
                             uchar             thread_id );

void
at_miner_work_set_thread_id_u16( at_miner_work_t * work,
                                 ushort            thread_id );

int
at_miner_work_serialize( at_miner_work_t const * work,
                         uchar                   out[AT_BLOCK_MINER_WORK_SIZE] );

int
at_miner_work_deserialize( at_miner_work_t * out_work,
                           uchar const *     data,
                           ulong             data_sz );

int
at_miner_work_hash( at_miner_work_t const * work,
                    uchar                   out_hash[32] );

/* Hex encoding/decoding for JSON-RPC (WebSocket mining) */
ulong
at_miner_work_to_hex( at_miner_work_t const * work,
                      char *                  out_hex,
                      ulong                   out_hex_max );

int
at_miner_work_from_hex( at_miner_work_t * out_work,
                        char const *      hex,
                        ulong             hex_len );

void
at_miner_worker_new( at_miner_worker_t * worker );

int
at_miner_worker_take_work( at_miner_worker_t * worker,
                           at_miner_work_t *   out_work );

int
at_miner_worker_set_work( at_miner_worker_t *      worker,
                          at_miner_work_t const *  work,
                          at_mining_algorithm_t    algorithm );

int
at_miner_worker_increase_nonce( at_miner_worker_t * worker );

int
at_miner_worker_set_timestamp( at_miner_worker_t * worker,
                               ulong               timestamp_ms );

int
at_miner_worker_get_block_hash( at_miner_worker_t const * worker,
                                uchar                     out_hash[32] );

int
at_miner_worker_get_pow_hash( at_miner_worker_t * worker,
                              uchar                     out_hash[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_block_at_miner_h */
