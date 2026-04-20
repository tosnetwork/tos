#ifndef HEADER_at_core_mempool_at_mempool_state_h
#define HEADER_at_core_mempool_at_mempool_state_h

#include "at/infra/at_util_base.h"
#include "at/core/storage/at_store.h"
#include "at/core/mempool/at_mempool_types.h"
#include "at/transaction/at_txn.h"

typedef struct at_mempool at_mempool_t;

AT_PROTOTYPES_BEGIN

typedef struct at_mempool_state at_mempool_state_t;

struct at_mempool_state {
  int                    mainnet;
  at_mempool_t const *   mempool;
  at_store_t const *     store;
  void const *           environment;

  ulong                  stable_topoheight;
  ulong                  topoheight;
  uint                   block_version;

  void * accounts_map;
  void * accounts_map_shmem;

  void * receiver_bal_map;
  void * receiver_uno_map;
  void * receiver_bal_map_shmem;
  void * receiver_uno_map_shmem;

  void * escrow_map;
  void * arbiter_map;
  void * dispute_map;
  void * escrow_map_shmem;
  void * arbiter_map_shmem;
  void * dispute_map_shmem;

  void * commit_round_map;
  void * commit_request_map;
  void * commit_vote_map;
  void * commit_sel_map;
  void * commit_juror_map;
  void * commit_round_map_shmem;
  void * commit_request_map_shmem;
  void * commit_vote_map_shmem;
  void * commit_sel_map_shmem;
  void * commit_juror_map_shmem;

  void * contract_map;
  void * contract_map_shmem;

  /* Referral system */
  void * referral_code_map;       /* code_hash -> account */
  void * referral_account_map;    /* account -> referrer */
  void * referral_code_map_shmem;
  void * referral_account_map_shmem;

  /* KYC system */
  void * kyc_committee_map;       /* committee_id -> committee_data */
  void * kyc_account_map;         /* account -> kyc_data */
  void * kyc_committee_map_shmem;
  void * kyc_account_map_shmem;
};

int
at_mempool_state_init( at_mempool_state_t * state,
                       int                 mainnet,
                       at_mempool_t const * mempool,
                       at_store_t const *   store,
                       void const *         environment,
                       ulong                stable_topoheight,
                       ulong                topoheight,
                       uint                 block_version );

void
at_mempool_state_fini( at_mempool_state_t * state );

int
at_mempool_state_apply_tx( at_mempool_state_t * state,
                           at_txn_t const *     txn,
                           uchar const *        raw,
                           int                  allow_same_nonce );

int
at_mempool_state_fill_cache( at_mempool_state_t * state,
                             uchar const          sender[32],
                             at_mempool_cache_t * cache );

AT_PROTOTYPES_END

#endif /* HEADER_at_core_mempool_at_mempool_state_h */
