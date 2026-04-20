#ifndef HEADER_at_vm_at_vm_error_h
#define HEADER_at_vm_at_vm_error_h

#include "at/infra/at_util_base.h"

typedef enum at_vm_tako_exec_error_code {
  AT_VM_TAKO_ERR_COMPUTE_BUDGET_EXCEEDED = 1,
  AT_VM_TAKO_ERR_INVALID_BYTECODE = 2,
  AT_VM_TAKO_ERR_SYSCALL_REGISTRATION_FAILED = 3,
  AT_VM_TAKO_ERR_EXECUTABLE_LOAD_FAILED = 4,
  AT_VM_TAKO_ERR_MEMORY_MAPPING_FAILED = 5,
  AT_VM_TAKO_ERR_EXECUTION_FAILED = 6,
  AT_VM_TAKO_ERR_OUT_OF_COMPUTE_UNITS = 7,
  AT_VM_TAKO_ERR_MEMORY_ACCESS_VIOLATION = 8,
  AT_VM_TAKO_ERR_STACK_OVERFLOW = 9,
  AT_VM_TAKO_ERR_INVALID_INSTRUCTION = 10,
  AT_VM_TAKO_ERR_CPI_INVOCATION_FAILED = 11,
  AT_VM_TAKO_ERR_LOADED_DATA_LIMIT_EXCEEDED = 12,
  AT_VM_TAKO_ERR_PRECOMPILE_VERIFICATION_FAILED = 13,
  AT_VM_TAKO_ERR_VRF_VALIDATION_FAILED = 14
} at_vm_tako_exec_error_code_t;

typedef struct at_vm_tako_exec_error {
  at_vm_tako_exec_error_code_t code;
  ulong                        instruction_count;
  ulong                        compute_units_used;
  ulong                        requested;
  ulong                        maximum;
  ulong                        current_size;
  ulong                        limit;
  char const *                 details;
} at_vm_tako_exec_error_t;

AT_PROTOTYPES_BEGIN

char const *
at_vm_tako_error_category( at_vm_tako_exec_error_code_t code );

int
at_vm_tako_error_is_recoverable( at_vm_tako_exec_error_code_t code );

ulong
at_vm_tako_error_user_message( at_vm_tako_exec_error_t const * err,
                               char *                         out,
                               ulong                          out_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_vm_at_vm_error_h */
