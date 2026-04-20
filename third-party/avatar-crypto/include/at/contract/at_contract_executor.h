#ifndef HEADER_at_contract_at_contract_executor_h
#define HEADER_at_contract_at_contract_executor_h

#include "at/contract/at_contract_base.h"
#include "at/contract/at_contract_cache.h"
#include "at/contract/at_contract_provider.h"
#include "at/contract/opaque/at_contract_opaque_mod.h"
#include "at/contract/at_contract_output.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  uchar contract[32];
  uchar topics[4UL * 32UL];
  ulong topics_cnt;
  uchar * data;
  ulong   data_sz;
} at_contract_event_t;

typedef struct {
  ulong                      gas_used;
  int                        has_exit_code;
  ulong                      exit_code;
  uchar *                    return_data;
  ulong                      return_data_sz;
  at_contract_transfer_output_t * transfers;
  ulong                      transfers_cnt;
  ulong                      transfers_cap;
  at_contract_event_t *      events;
  ulong                      events_cnt;
  ulong                      events_cap;
  at_contract_cache_t *      cache;
  at_alloc_t *               alloc;
} at_contract_execution_result_t;

int
at_contract_execution_result_init( at_contract_execution_result_t * result,
                                   at_alloc_t *                    alloc );

void
at_contract_execution_result_fini( at_contract_execution_result_t * result );

typedef int (*at_contract_executor_execute_fn)(
    void *                          exec_ctx,
    uchar const *                   bytecode,
    ulong                           bytecode_sz,
    at_contract_provider_t const *  provider,
    ulong                           topoheight,
    uchar const                     contract_hash[32],
    uchar const                     block_hash[32],
    ulong                           block_height,
    ulong                           block_timestamp,
    uchar const                     tx_hash[32],
    uchar const                     tx_sender[32],
    ulong                           max_gas,
    uchar const *                   parameters,
    ulong                           parameters_sz,
    at_contract_execution_result_t *result_out );

typedef int (*at_contract_executor_supports_format_fn)(
    void *        exec_ctx,
    uchar const * bytecode,
    ulong         bytecode_sz );

typedef char const * (*at_contract_executor_name_fn)( void * exec_ctx );

typedef struct {
  at_contract_executor_execute_fn         execute;
  at_contract_executor_supports_format_fn supports_format;
  at_contract_executor_name_fn            name;
} at_contract_executor_vtbl_t;

typedef struct {
  void *                         ctx;
  at_contract_executor_vtbl_t const * vtbl;
  at_contract_environment_t const *   environment;
} at_contract_executor_t;

int
at_contract_executor_execute( at_contract_executor_t const *   executor,
                              uchar const *                    bytecode,
                              ulong                            bytecode_sz,
                              at_contract_provider_t const *   provider,
                              ulong                            topoheight,
                              uchar const                      contract_hash[32],
                              uchar const                      block_hash[32],
                              ulong                            block_height,
                              ulong                            block_timestamp,
                              uchar const                      tx_hash[32],
                              uchar const                      tx_sender[32],
                              ulong                            max_gas,
                              uchar const *                    parameters,
                              ulong                            parameters_sz,
                              at_contract_execution_result_t * result_out );

int
at_contract_executor_supports_format( at_contract_executor_t const * executor,
                                      uchar const *                  bytecode,
                                      ulong                          bytecode_sz );

char const *
at_contract_executor_name( at_contract_executor_t const * executor );

at_contract_environment_t const *
at_contract_executor_environment( at_contract_executor_t const * executor );

int
at_contract_executor_init_noop_checked( at_contract_executor_t * executor );

/* No-op executor equivalent to Rust NoOpExecutor. */
void
at_contract_executor_init_noop( at_contract_executor_t * executor );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_executor_h */
