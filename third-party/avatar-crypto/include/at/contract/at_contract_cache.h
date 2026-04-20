#ifndef HEADER_at_contract_at_contract_cache_h
#define HEADER_at_contract_at_contract_cache_h

#include "at/contract/at_contract_base.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

/* Parsed asset data subset used by contract provider/cache. */
typedef struct {
  uchar decimals;
  char  name[256];
  char  ticker[32];
  int   has_max_supply;
  ulong max_supply;
  int   has_owner;
  uchar owner_contract[32];
  ulong owner_id;
} at_contract_asset_data_t;

typedef struct {
  at_contract_versioned_state_t data;
  at_contract_asset_data_t      data_value;
  int                           has_supply;
  at_contract_versioned_state_t supply_state;
  ulong                         supply;
} at_contract_asset_changes_t;

typedef struct {
  uchar *                       key;
  ulong                         key_sz;
  at_contract_versioned_state_t state;
  int                           has_value;
  uchar *                       value;
  ulong                         value_sz;
} at_contract_cache_storage_entry_t;

typedef struct {
  uchar                         asset[32];
  int                           has_balance;
  at_contract_versioned_state_t state;
  ulong                         balance;
} at_contract_cache_balance_entry_t;

typedef struct {
  uchar * key;
  ulong   key_sz;
  uchar * value;
  ulong   value_sz;
} at_contract_cache_memory_entry_t;

typedef struct {
  ulong   event_id;
  uchar * payload;
  ulong   payload_sz;
} at_contract_cache_event_entry_t;

typedef struct {
  at_alloc_t * alloc;

  at_contract_cache_storage_entry_t * storage;
  ulong                               storage_cnt;
  ulong                               storage_cap;

  at_contract_cache_balance_entry_t * balances;
  ulong                               balances_cnt;
  ulong                               balances_cap;

  at_contract_cache_memory_entry_t * memory;
  ulong                              memory_cnt;
  ulong                              memory_cap;

  at_contract_cache_event_entry_t * events;
  ulong                             events_cnt;
  ulong                             events_cap;
} at_contract_cache_t;

int
at_contract_cache_init( at_contract_cache_t * cache,
                        at_alloc_t *          alloc );

void
at_contract_cache_fini( at_contract_cache_t * cache );

void
at_contract_cache_clear( at_contract_cache_t * cache );

int
at_contract_cache_set_storage( at_contract_cache_t *               cache,
                               uchar const *                       key,
                               ulong                               key_sz,
                               at_contract_versioned_state_t const * state,
                               int                                 has_value,
                               uchar const *                       value,
                               ulong                               value_sz );

int
at_contract_cache_set_balance( at_contract_cache_t *               cache,
                               uchar const                         asset[32],
                               at_contract_versioned_state_t const * state,
                               int                                 has_balance,
                               ulong                               balance );

int
at_contract_cache_set_memory( at_contract_cache_t * cache,
                              uchar const *         key,
                              ulong                 key_sz,
                              uchar const *         value,
                              ulong                 value_sz );

int
at_contract_cache_add_event( at_contract_cache_t * cache,
                             ulong                 event_id,
                             uchar const *         payload,
                             ulong                 payload_sz );

/* Rust merge_overlay_storage alignment: merge storage entries only. */
int
at_contract_cache_merge_overlay_storage( at_contract_cache_t *       cache,
                                         at_contract_cache_t const * other );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_cache_h */
