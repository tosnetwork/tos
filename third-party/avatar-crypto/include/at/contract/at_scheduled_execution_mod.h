#ifndef HEADER_at_contract_at_scheduled_execution_mod_h
#define HEADER_at_contract_at_scheduled_execution_mod_h

#include "at/contract/at_contract_base.h"
#include "at/contract/at_contract_source.h"
#include "at/contract/at_scheduled_execution_constants.h"
#include "at/contract/at_scheduled_execution_kind.h"
#include "at/contract/at_scheduled_execution_status.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  at_contract_source_t source;
  ulong                amount;
} at_contract_scheduled_gas_source_t;

typedef struct {
  uchar                                  hash[32];
  uchar                                  contract[32];
  ushort                                 chunk_id;
  uchar *                                params;
  ulong                                  params_sz;
  ulong                                  max_gas;
  at_contract_scheduled_execution_kind_t kind;
  at_contract_scheduled_gas_source_t *   gas_sources;
  ulong                                  gas_sources_cnt;
  ulong                                  gas_sources_cap;
  ulong                                  offer_amount;
  uchar                                  scheduler_contract[32];
  uchar *                                input_data;
  ulong                                  input_data_sz;
  ulong                                  registration_topoheight;
  at_contract_scheduled_execution_status_t status;
  uchar                                  defer_count;
} at_contract_scheduled_execution_t;

typedef struct {
  at_contract_scheduled_execution_kind_t kind;
  uchar                                  hash[32];
} at_contract_opaque_scheduled_execution_t;

int
at_contract_scheduled_execution_compute_hash( uchar                         out_hash[32],
                                              uchar const                   contract[32],
                                              at_contract_scheduled_execution_kind_t const * kind,
                                              ulong                         registration_topoheight,
                                              ushort                        chunk_id,
                                              uchar const                   scheduler_contract[32] );

int
at_contract_scheduled_execution_init_offercall(
    at_contract_scheduled_execution_t *          out,
    at_alloc_t *                                 alloc,
    uchar const                                  contract[32],
    ushort                                       chunk_id,
    uchar const *                                input_data,
    ulong                                        input_data_sz,
    ulong                                        max_gas,
    ulong                                        offer_amount,
    uchar const                                  scheduler_contract[32],
    at_contract_scheduled_execution_kind_t const * kind,
    ulong                                        registration_topoheight );

void
at_contract_scheduled_execution_fini( at_alloc_t *                        alloc,
                                      at_contract_scheduled_execution_t *  exec );

int
at_contract_scheduled_execution_can_cancel( at_contract_scheduled_execution_t const * exec,
                                            ulong                                     current_topoheight );

static inline int
at_contract_scheduled_execution_is_pending( at_contract_scheduled_execution_t const * exec ) {
  return exec && exec->status == AT_CONTRACT_SCHED_STATUS_PENDING;
}

int
at_contract_scheduled_execution_defer( at_contract_scheduled_execution_t * exec );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_scheduled_execution_mod_h */
