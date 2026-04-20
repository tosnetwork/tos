#ifndef HEADER_at_contract_at_contract_source_h
#define HEADER_at_contract_at_contract_source_h

#include "at/contract/at_contract_base.h"

AT_PROTOTYPES_BEGIN

/* Source of gas funding for scheduled execution. */
typedef enum {
  AT_CONTRACT_SOURCE_CONTRACT = 0,
  AT_CONTRACT_SOURCE_ACCOUNT  = 1
} at_contract_source_kind_t;

typedef struct {
  at_contract_source_kind_t kind;
  uchar                     value[32];
} at_contract_source_t;

/* Serializer-compatible helpers:
   wire format = [tag:1][value:32] */
ulong
at_contract_source_size( at_contract_source_t const * source );

int
at_contract_source_write( at_contract_source_t const * source,
                          uchar *                      out,
                          ulong                        out_sz,
                          ulong *                      written_out );

int
at_contract_source_read( uchar const *         in,
                         ulong                 in_sz,
                         at_contract_source_t *source_out,
                         ulong *               consumed_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_source_h */
