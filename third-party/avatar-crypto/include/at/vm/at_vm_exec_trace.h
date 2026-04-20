#ifndef HEADER_at_vm_at_vm_exec_trace_h
#define HEADER_at_vm_at_vm_exec_trace_h

#include "at/infra/at_flamenco_base.h"

AT_PROTOTYPES_BEGIN

#define AT_VM_EXEC_TRACE_MAX_TRANSFERS  (16UL)
#define AT_VM_EXEC_TRACE_MAX_EVENTS     (8UL)
#define AT_VM_EXEC_TRACE_MAX_EVENT_DATA (256UL)
#define AT_VM_EXEC_TRACE_MAX_LOGS       (16UL)
#define AT_VM_EXEC_TRACE_MAX_LOG_LEN    (160UL)

typedef struct {
  uchar destination[32];
  uchar asset[32];
  ulong amount;
} at_vm_exec_transfer_t;

typedef struct {
  uchar contract[32];
  uchar topics[4][32];
  uint  topics_cnt;
  uchar data[AT_VM_EXEC_TRACE_MAX_EVENT_DATA];
  ulong data_sz;
} at_vm_exec_event_t;

typedef struct {
  char  msg[AT_VM_EXEC_TRACE_MAX_LOG_LEN];
  ulong msg_len;
} at_vm_exec_log_t;

struct at_vm_exec_trace {
  uchar return_data[AT_CPI_MAX_RETURN_DATA];
  ulong return_data_len;

  at_vm_exec_transfer_t transfers[AT_VM_EXEC_TRACE_MAX_TRANSFERS];
  ulong                 transfers_cnt;
  ulong                 transfers_dropped;

  at_vm_exec_event_t events[AT_VM_EXEC_TRACE_MAX_EVENTS];
  ulong              events_cnt;
  ulong              events_dropped;

  at_vm_exec_log_t logs[AT_VM_EXEC_TRACE_MAX_LOGS];
  ulong            logs_cnt;
  ulong            logs_dropped;
};

typedef struct at_vm_exec_trace at_vm_exec_trace_t;

static inline void
at_vm_exec_trace_reset( at_vm_exec_trace_t * trace ) {
  if( !trace ) return;
  at_memset( trace, 0, sizeof(*trace) );
}

static inline void
at_vm_exec_trace_capture_return_data( at_vm_exec_trace_t * trace,
                                      uchar const *        data,
                                      ulong                data_len ) {
  if( !trace ) return;
  ulong copy_len = data_len;
  if( copy_len > AT_CPI_MAX_RETURN_DATA ) copy_len = AT_CPI_MAX_RETURN_DATA;
  trace->return_data_len = copy_len;
  if( copy_len > 0UL && data ) at_memcpy( trace->return_data, data, copy_len );
}

static inline void
at_vm_exec_trace_add_transfer( at_exec_instr_ctx_t * ctx,
                               uchar const          destination[32],
                               uchar const          asset[32],
                               ulong                amount ) {
  if( !ctx || !destination || !asset || !amount ) return;
  at_vm_exec_trace_t * trace = ctx->exec_trace;
  if( !trace ) return;

  if( trace->transfers_cnt >= AT_VM_EXEC_TRACE_MAX_TRANSFERS ) {
    trace->transfers_dropped++;
    return;
  }

  at_vm_exec_transfer_t * out = &trace->transfers[trace->transfers_cnt++];
  at_memcpy( out->destination, destination, 32UL );
  at_memcpy( out->asset, asset, 32UL );
  out->amount = amount;
}

static inline void
at_vm_exec_trace_add_event( at_exec_instr_ctx_t * ctx,
                            uchar const          contract[32],
                            uchar const *        topics,
                            ulong                topics_cnt,
                            uchar const *        data,
                            ulong                data_len ) {
  if( !ctx || !contract ) return;
  at_vm_exec_trace_t * trace = ctx->exec_trace;
  if( !trace ) return;

  if( trace->events_cnt >= AT_VM_EXEC_TRACE_MAX_EVENTS ) {
    trace->events_dropped++;
    return;
  }

  at_vm_exec_event_t * out = &trace->events[trace->events_cnt++];
  at_memset( out, 0, sizeof(*out) );
  at_memcpy( out->contract, contract, 32UL );

  ulong safe_topics = topics_cnt;
  if( safe_topics > 4UL ) safe_topics = 4UL;
  out->topics_cnt = (uint)safe_topics;
  if( topics && safe_topics ) {
    at_memcpy( out->topics, topics, safe_topics * 32UL );
  }

  ulong safe_data_len = data_len;
  if( safe_data_len > AT_VM_EXEC_TRACE_MAX_EVENT_DATA ) safe_data_len = AT_VM_EXEC_TRACE_MAX_EVENT_DATA;
  out->data_sz = safe_data_len;
  if( data && safe_data_len ) {
    at_memcpy( out->data, data, safe_data_len );
  }
}

static inline void
at_vm_exec_trace_add_log( at_exec_instr_ctx_t * ctx,
                          uchar const *         msg,
                          ulong                 msg_len ) {
  if( !ctx || !msg || !msg_len ) return;
  at_vm_exec_trace_t * trace = ctx->exec_trace;
  if( !trace ) return;

  if( trace->logs_cnt >= AT_VM_EXEC_TRACE_MAX_LOGS ) {
    trace->logs_dropped++;
    return;
  }

  at_vm_exec_log_t * out = &trace->logs[trace->logs_cnt++];
  at_memset( out, 0, sizeof(*out) );
  ulong copy_len = msg_len;
  if( copy_len >= AT_VM_EXEC_TRACE_MAX_LOG_LEN ) copy_len = AT_VM_EXEC_TRACE_MAX_LOG_LEN - 1UL;
  at_memcpy( out->msg, msg, copy_len );
  out->msg[copy_len] = '\0';
  out->msg_len = copy_len;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_vm_at_vm_exec_trace_h */
