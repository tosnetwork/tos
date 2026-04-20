#ifndef HEADER_at_contract_at_contract_output_h
#define HEADER_at_contract_at_contract_output_h

#include "at/contract/at_contract_base.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

/* TOS common/src/contract/output.rs alignment. */
typedef enum {
  AT_CONTRACT_VM_OUTPUT_REFUND_GAS      = 0,
  AT_CONTRACT_VM_OUTPUT_TRANSFER        = 1,
  AT_CONTRACT_VM_OUTPUT_MINT            = 2,
  AT_CONTRACT_VM_OUTPUT_BURN            = 3,
  AT_CONTRACT_VM_OUTPUT_NEW_ASSET       = 4,
  AT_CONTRACT_VM_OUTPUT_EXIT_CODE       = 5,
  AT_CONTRACT_VM_OUTPUT_REFUND_DEPOSITS = 6,
  AT_CONTRACT_VM_OUTPUT_RETURN_DATA     = 7
} at_contract_vm_output_type_t;

typedef struct {
  uchar destination[32];
  ulong amount;
  uchar asset[32];
} at_contract_transfer_output_t;

typedef struct {
  at_contract_vm_output_type_t type;
  union {
    struct {
      ulong amount;
    } refund_gas;
    at_contract_transfer_output_t transfer;
    struct {
      uchar asset[32];
      ulong amount;
    } mint;
    struct {
      uchar asset[32];
      ulong amount;
    } burn;
    struct {
      uchar asset[32];
    } new_asset;
    struct {
      int   has_code;
      ulong code;
    } exit_code;
    struct {
      uchar * data;
      ulong   data_sz;
    } return_data;
  };
} at_contract_vm_output_t;

ulong
at_contract_vm_output_size( at_contract_vm_output_t const * output );

int
at_contract_vm_output_write( at_contract_vm_output_t const * output,
                             uchar *                         out,
                             ulong                           out_sz,
                             ulong *                         written_out );

int
at_contract_vm_output_read( at_alloc_t *             alloc,
                            uchar const *            in,
                            ulong                    in_sz,
                            at_contract_vm_output_t *output_out,
                            ulong *                  consumed_out );

void
at_contract_vm_output_fini( at_alloc_t * alloc,
                            at_contract_vm_output_t * output );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_output_h */
