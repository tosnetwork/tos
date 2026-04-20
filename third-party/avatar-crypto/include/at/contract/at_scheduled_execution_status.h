#ifndef HEADER_at_contract_at_scheduled_execution_status_h
#define HEADER_at_contract_at_scheduled_execution_status_h

#include "at/contract/at_contract_base.h"

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_CONTRACT_SCHED_STATUS_PENDING   = 0,
  AT_CONTRACT_SCHED_STATUS_EXECUTED  = 1,
  AT_CONTRACT_SCHED_STATUS_CANCELLED = 2,
  AT_CONTRACT_SCHED_STATUS_FAILED    = 3,
  AT_CONTRACT_SCHED_STATUS_EXPIRED   = 4
} at_contract_scheduled_execution_status_t;

static inline uchar
at_contract_scheduled_execution_status_id( at_contract_scheduled_execution_status_t status ) {
  return (uchar)status;
}

int
at_contract_scheduled_execution_status_is_terminal( at_contract_scheduled_execution_status_t status );

int
at_contract_scheduled_execution_status_is_success( at_contract_scheduled_execution_status_t status );

int
at_contract_scheduled_execution_status_write( at_contract_scheduled_execution_status_t status,
                                              uchar *                                  out,
                                              ulong                                    out_sz,
                                              ulong *                                  written_out );

int
at_contract_scheduled_execution_status_read( uchar const *                               in,
                                             ulong                                       in_sz,
                                             at_contract_scheduled_execution_status_t *  status_out,
                                             ulong *                                     consumed_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_scheduled_execution_status_h */
