#ifndef HEADER_at_contract_at_scheduled_execution_priority_h
#define HEADER_at_contract_at_scheduled_execution_priority_h

#include "at/contract/at_contract_base.h"
#include "at/contract/at_scheduled_execution_mod.h"

AT_PROTOTYPES_BEGIN

/* tos/common/src/contract/scheduled_execution/priority.rs constants */
#define AT_CONTRACT_SCHED_OFFER_WEIGHT         (1000UL)
#define AT_CONTRACT_SCHED_MAX_TOPO_FOR_PRIORITY (ULONG_MAX)

/* Compare priority:
   >0 : left higher priority
   =0 : equal
   <0 : right higher priority */
int
at_contract_scheduled_execution_priority_cmp( at_contract_scheduled_execution_t const * left,
                                              at_contract_scheduled_execution_t const * right );

/* Numeric score (higher = higher priority). */
unsigned __int128
at_contract_scheduled_execution_priority_score( at_contract_scheduled_execution_t const * exec );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_scheduled_execution_priority_h */
