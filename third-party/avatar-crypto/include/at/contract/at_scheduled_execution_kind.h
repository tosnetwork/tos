#ifndef HEADER_at_contract_at_scheduled_execution_kind_h
#define HEADER_at_contract_at_scheduled_execution_kind_h

#include "at/contract/at_contract_base.h"

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_CONTRACT_SCHED_KIND_TOPOHEIGHT = 0,
  AT_CONTRACT_SCHED_KIND_BLOCK_END  = 1
} at_contract_scheduled_execution_kind_tag_t;

typedef struct {
  at_contract_scheduled_execution_kind_tag_t tag;
  ulong                                      topoheight;
} at_contract_scheduled_execution_kind_t;

typedef struct {
  at_contract_scheduled_execution_kind_tag_t tag;
  union {
    struct {
      ulong topoheight;
    } topoheight;
    struct {
      ushort chunk_id;
      ulong  max_gas;
      uchar *params;
      ulong  params_sz;
    } block_end;
  };
} at_contract_scheduled_execution_kind_log_t;

static inline uchar
at_contract_scheduled_execution_kind_id( at_contract_scheduled_execution_kind_t const * kind ) {
  return kind ? (uchar)kind->tag : 0xffU;
}

int
at_contract_scheduled_execution_kind_write( at_contract_scheduled_execution_kind_t const * kind,
                                            uchar *                                        out,
                                            ulong                                          out_sz,
                                            ulong *                                        written_out );

int
at_contract_scheduled_execution_kind_read( uchar const *                           in,
                                           ulong                                   in_sz,
                                           at_contract_scheduled_execution_kind_t *kind_out,
                                           ulong *                                 consumed_out );

int
at_contract_scheduled_execution_kind_log_write( at_contract_scheduled_execution_kind_log_t const * kind_log,
                                                uchar *                                            out,
                                                ulong                                              out_sz,
                                                ulong *                                            written_out );

int
at_contract_scheduled_execution_kind_log_read( uchar const *                               in,
                                               ulong                                       in_sz,
                                               at_contract_scheduled_execution_kind_log_t * kind_log_out,
                                               ulong *                                     consumed_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_scheduled_execution_kind_h */
