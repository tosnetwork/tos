#ifndef HEADER_at_core_mempool_at_mempool_types_h
#define HEADER_at_core_mempool_at_mempool_types_h

#include "at/infra/at_util_base.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/transaction/at_txn.h"
#include "at/account/at_account.h"

AT_PROTOTYPES_BEGIN

/* Limits (defaults from Mempool.md) */
#define AT_MEMPOOL_MAX_TXS            (200000UL)
#define AT_MEMPOOL_MAX_TXS_PER_SENDER (1024UL)
#define AT_MEMPOOL_MAX_ASSETS_PER_ACC (64UL)
#define AT_MEMPOOL_MAX_SENDERS        (65536UL)
#define AT_MEMPOOL_BYTES_PER_KB       (1024UL)
#define AT_MEMPOOL_MAX_MULTISIG_PARTICIPANTS (255UL)

#define AT_MEMPOOL_ENTRY_NONE (ULONG_MAX)

/* Mempool entry (pending transaction) */
typedef struct {
  uchar  hash[32];
  uchar  source[32];
  ulong  nonce;
  ulong  fee;
  ulong  fee_rate_per_kb;
  ulong  size_bytes;
  ulong  first_seen_sec;
  uchar * raw;
  ulong  raw_sz;
  ulong  prev_idx;
  ulong  next_idx;
  int    in_use;
} at_mempool_entry_t;

/* MultiSig account configuration (TOS-style) */
typedef struct {
  uchar threshold;
  uchar participants_cnt;
  uchar participants[AT_MEMPOOL_MAX_MULTISIG_PARTICIPANTS][32];
} at_mempool_multisig_t;

/* Per-sender cache (minimal TOS-aligned fields) */
typedef struct {
  uchar  owner[32];
  ulong  min_nonce;
  ulong  max_nonce;
  ulong  tx_cnt;
  /* Ring of hashes, slot = (nonce - min_nonce) */
  uchar hashes[AT_MEMPOOL_MAX_TXS_PER_SENDER][32];
  uchar present[AT_MEMPOOL_MAX_TXS_PER_SENDER];

  /* Optional predicted state (placeholders for full state) */
  struct {
    uchar asset[32];
    ulong balance;
  } balances[AT_MEMPOOL_MAX_ASSETS_PER_ACC];
  ulong balance_cnt;

  int   has_multisig;
  int   has_energy;
  at_mempool_multisig_t  multisig;
  at_energy_resource_t   energy;
} at_mempool_cache_t;

/* Mempool iterator */
typedef struct {
  void const * mp;
  ulong        cur_idx;
} at_mempool_iter_t;

/* Tx selector group (same-sender ordered queue) */
typedef struct {
  at_mempool_entry_t * entries;
  ulong                cnt;
  ulong                cap;
} at_mempool_tx_group_t;

/* Tx selector state */
typedef struct {
  at_alloc_t *            alloc;
  at_mempool_tx_group_t * groups;
  ulong                   group_cnt;
  ulong                   group_cap;
} at_mempool_tx_selector_t;

/* Mempool cache iterator */
typedef struct {
  void const * mp;
  ulong        slot;
} at_mempool_cache_iter_t;

AT_PROTOTYPES_END

#endif /* HEADER_at_core_mempool_at_mempool_types_h */
