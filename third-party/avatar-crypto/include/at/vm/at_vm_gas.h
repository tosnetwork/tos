#ifndef HEADER_at_vm_at_vm_gas_h
#define HEADER_at_vm_at_vm_gas_h

#include "at/infra/at_util_base.h"

/* TOS daemon/src/tako_integration/precompile_cost.rs */
#define AT_VM_GAS_ED25519_COST                         (2280UL)
#define AT_VM_GAS_SECP256K1_COST                       (6690UL)
#define AT_VM_GAS_SECP256R1_COST                       (4800UL)
#define AT_VM_GAS_SCHNORR_RISTRETTO_COST              (69000UL)
#define AT_VM_GAS_THRESHOLD_MULTISIG_BASE_COST         (20000UL)
#define AT_VM_GAS_THRESHOLD_MULTISIG_PER_SIGNATURE_COST (86000UL)
#define AT_VM_GAS_BLS_FAST_AGGREGATE_BASE_COST         (843000UL)
#define AT_VM_GAS_BLS_FAST_AGGREGATE_PER_SIGNER_COST   (70000UL)

/* TOS daemon/src/tako_integration/transaction_cost.rs */
#define AT_VM_GAS_BASE_TRANSACTION_COST                (5000UL)
#define AT_VM_GAS_CONTRACT_COST_PER_KB                 (10000UL)
#define AT_VM_GAS_MAX_TRANSACTION_COMPUTE_BUDGET       (10000000UL)

/* Precompile IDs */
#define AT_VM_PRECOMPILE_ID_SECP256K1   (2U)
#define AT_VM_PRECOMPILE_ID_ED25519     (3U)
#define AT_VM_PRECOMPILE_ID_SCHNORR     (4U)
#define AT_VM_PRECOMPILE_ID_THRESHOLD   (5U)
#define AT_VM_PRECOMPILE_ID_BLS         (6U)
#define AT_VM_PRECOMPILE_ID_SECP256R1   (113U)

typedef struct at_vm_instruction_cost_view {
  uchar const * program_id;  /* 32 bytes */
  uchar const * data;
  ulong         data_sz;
} at_vm_instruction_cost_view_t;

typedef struct at_vm_tx_cost {
  ulong base_cost;
  ulong contract_cost;
  ulong precompile_cost;
  ulong total_cost;
} at_vm_tx_cost_t;

enum {
  AT_VM_GAS_OK                   = 0,
  AT_VM_GAS_ERR_INVALID          = -1,
  AT_VM_GAS_ERR_UNKNOWN_PRECOMPILE = -2,
  AT_VM_GAS_ERR_BUDGET_EXCEEDED  = -3
};

AT_PROTOTYPES_BEGIN

int
at_vm_is_precompile_program_id( uchar const program_id[32] );

int
at_vm_estimate_single_precompile_cost( uchar const program_id[32],
                                       uchar const * data,
                                       ulong         data_sz,
                                       ulong *       cost_out );

int
at_vm_estimate_transaction_precompile_cost( at_vm_instruction_cost_view_t const * instructions,
                                            ulong                                 instruction_cnt,
                                            ulong *                               cost_out );

int
at_vm_estimate_transaction_cost( uchar const *                        contract_bytecode,
                                 ulong                                contract_bytecode_sz,
                                 at_vm_instruction_cost_view_t const * precompile_instructions,
                                 ulong                                precompile_instruction_cnt,
                                 at_vm_tx_cost_t *                    out );

int
at_vm_validate_transaction_cost( at_vm_tx_cost_t const * cost,
                                 ulong                   budget );

AT_PROTOTYPES_END

#endif /* HEADER_at_vm_at_vm_gas_h */
