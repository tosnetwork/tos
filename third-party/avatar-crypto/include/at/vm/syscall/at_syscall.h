#ifndef HEADER_at_vm_syscall_at_syscall_h
#define HEADER_at_vm_syscall_at_syscall_h

/* at_syscall.h - TOS syscall registration and dispatch

   This module provides:
   - Syscall registration API
   - Compute unit cost definitions
   - Common syscall utilities */

#include "at/vm/at_vm.h"
#include "at/crypto/tbpf/at_tbpf_loader.h"
#include "at/crypto/murmur3/at_murmur3.h"

/* ============================================================================
   Compute Unit Costs (from TAKO)
   ============================================================================ */

/* Logging */
#define AT_CU_LOG_BASE              (100UL)
#define AT_CU_LOG_PER_BYTE          (1UL)
#define AT_CU_LOG_64_UNITS          (100UL)
#define AT_CU_LOG_PUBKEY_UNITS      (100UL)
#define AT_CU_LOG_DATA_UNITS        (100UL)

/* Blockchain/Environment */
#define AT_CU_GET_STATE             (50UL)

/* Balance */
#define AT_CU_GET_BALANCE           (200UL)
#define AT_CU_TRANSFER              (300UL)

/* Storage (CPI per-byte cost only; persistent/transient gas costs are in at_fee.h) */
#define AT_CU_STORAGE_PER_BYTE      (1UL)

/* CPI */
#define AT_CU_INVOKE_BASE           (1000UL)

/* Crypto */
#define AT_CU_BLAKE3_BASE           (75UL)
#define AT_CU_BLAKE3_PER_BYTE       (1UL)
#define AT_CU_SHA256_BASE           (85UL)
#define AT_CU_SHA256_PER_BYTE       (1UL)
#define AT_CU_KECCAK256_BASE        (117UL)
#define AT_CU_KECCAK256_PER_BYTE    (1UL)
#define AT_CU_SECP256K1_RECOVER     (11500UL)
#define AT_CU_POSEIDON_BASE         (1800UL)

/* Memory operations */
#define AT_CU_MEM_OP_BASE           (10UL)
#define AT_CU_CPI_BYTES_PER_UNIT    (250UL)  /* 1 CU per 250 bytes */

/* Scheduled Execution (OFFERCALL) */
#define AT_CU_GET_SCHEDULED         (500UL)
#define AT_CU_CANCEL_SCHEDULED      (500UL)

/* Runtime */
#define AT_CU_SYSCALL_BASE          (100UL)

/* ============================================================================
   Memory translation macros for syscalls
   ============================================================================ */

/* AT_VM_MEM_HADDR_LD translates a virtual address for reading.
   Returns the host address on success, or jumps to 'label' on failure.

   Usage:
     uchar const * data = AT_VM_MEM_HADDR_LD( vm, vaddr, sz, alignof(type), label );
     if( !data ) goto label; */
#define AT_VM_MEM_HADDR_LD( vm, vaddr, sz, align, label )                     \
  (__extension__({                                                             \
    ulong _vaddr = (vaddr);                                                    \
    ulong _sz    = (sz);                                                       \
    ulong _align = (align);                                                    \
    /* Check alignment */                                                      \
    if( at_vm_is_check_align_enabled(vm) && (_vaddr & (_align-1UL)) ) {       \
      goto label;                                                              \
    }                                                                          \
    /* Translate address */                                                    \
    ulong _haddr = at_vm_mem_haddr( vm, _vaddr, _sz,                          \
                                    vm->region_haddr, vm->region_ld_sz,       \
                                    0, 0UL );                                  \
    if( !_haddr && _sz ) goto label;                                          \
    (void const *)_haddr;                                                      \
  }))

/* AT_VM_MEM_HADDR_ST translates a virtual address for writing.
   Same as AT_VM_MEM_HADDR_LD but for store operations. */
#define AT_VM_MEM_HADDR_ST( vm, vaddr, sz, align, label )                     \
  (__extension__({                                                             \
    ulong _vaddr = (vaddr);                                                    \
    ulong _sz    = (sz);                                                       \
    ulong _align = (align);                                                    \
    /* Check alignment */                                                      \
    if( at_vm_is_check_align_enabled(vm) && (_vaddr & (_align-1UL)) ) {       \
      goto label;                                                              \
    }                                                                          \
    /* Translate address */                                                    \
    ulong _haddr = at_vm_mem_haddr( vm, _vaddr, _sz,                          \
                                    vm->region_haddr, vm->region_st_sz,       \
                                    1, 0UL );                                  \
    if( !_haddr && _sz ) goto label;                                          \
    (void *)_haddr;                                                            \
  }))

/* ============================================================================
   Simplified error logging macros (no instr_ctx dependency)
   ============================================================================ */

/* AT_VM_SYSCALL_ERR_LOG logs a syscall error without context dependency.
   For now, these are no-ops - will be implemented when InvokeContext is ready. */
#define AT_VM_SYSCALL_ERR_LOG( vm, err ) ((void)(vm), (void)(err))

/* ============================================================================
   Compute unit consumption macros
   ============================================================================ */

/* AT_VM_CU_UPDATE consumes compute units from the VM.
   Returns error if insufficient CUs remain. */
#define AT_VM_CU_UPDATE( vm, cost )                                           \
  do {                                                                         \
    ulong _cost = (cost);                                                      \
    if( AT_UNLIKELY( (vm)->cu < _cost ) ) {                                   \
      (vm)->cu = 0UL;                                                          \
      return AT_VM_ERR_SIGCOST;                                               \
    }                                                                          \
    (vm)->cu -= _cost;                                                         \
  } while(0)

/* AT_VM_CU_MEM_UPDATE consumes compute units for memory operations.
   Cost = base + (sz / 250) */
#define AT_VM_CU_MEM_UPDATE( vm, sz )                                         \
  AT_VM_CU_UPDATE( vm, AT_CU_MEM_OP_BASE + ((sz) / AT_CU_CPI_BYTES_PER_UNIT) )

/* ============================================================================
   Syscall registration API
   ============================================================================ */

AT_PROTOTYPES_BEGIN

/* at_syscall_hash computes the Murmur3 hash for a syscall name.
   This hash is used to look up syscalls in the syscall map. */
static inline ulong
at_syscall_hash( char const * name ) {
  ulong len = 0UL;
  while( name[len] ) len++;
  return (ulong)at_murmur3_32( name, len, 0U );
}

/* at_syscall_register registers a syscall in the syscall map.
   Returns 0 on success, -1 if the map is full. */
int
at_syscall_register( at_tbpf_syscalls_t *     syscalls,
                     char const *             name,
                     at_tbpf_syscall_func_t   func,
                     ulong                    cu_cost );

/* at_syscall_register_all registers all TOS syscalls.
   This is the main entry point for syscall registration. */
void
at_syscall_register_all( at_tbpf_syscalls_t * syscalls );

/* ============================================================================
   Individual syscall registration functions
   ============================================================================ */

/* Register logging syscalls */
void at_syscall_register_log( at_tbpf_syscalls_t * syscalls );

/* Register memory syscalls */
void at_syscall_register_memory( at_tbpf_syscalls_t * syscalls );

/* Register runtime syscalls */
void at_syscall_register_runtime( at_tbpf_syscalls_t * syscalls );

/* Register crypto syscalls */
void at_syscall_register_crypto( at_tbpf_syscalls_t * syscalls );

/* Register blockchain state syscalls */
void at_syscall_register_blockchain( at_tbpf_syscalls_t * syscalls );

/* Register input/output syscalls */
void at_syscall_register_io( at_tbpf_syscalls_t * syscalls );

/* Register storage syscalls */
void at_syscall_register_storage( at_tbpf_syscalls_t * syscalls );

/* Register balance syscalls */
void at_syscall_register_balance( at_tbpf_syscalls_t * syscalls );

/* Register CPI (Cross-Program Invocation) syscalls */
void at_syscall_register_cpi( at_tbpf_syscalls_t * syscalls );

/* ============================================================================
   Phase 8.4: TOS-Specific Syscall Registration Functions
   ============================================================================ */

/* Register transient storage syscalls (EIP-1153) */
void at_syscall_register_transient( at_tbpf_syscalls_t * syscalls );

/* Register VRF (Verifiable Random Function) syscalls */
void at_syscall_register_vrf( at_tbpf_syscalls_t * syscalls );

/* Register native system syscalls (KYC, Referral, NFT, Asset) */
void at_syscall_register_native( at_tbpf_syscalls_t * syscalls );

/* ============================================================================
   Phase 8.5: Code Operations and Deprecated Opcodes
   ============================================================================ */

/* Register code operation syscalls (CODESIZE, CODECOPY, EXTCODESIZE, EXTCODECOPY) */
void at_syscall_register_code( at_tbpf_syscalls_t * syscalls );

/* Register deprecated EVM opcode syscalls (CALLCODE, SELFDESTRUCT) */
void at_syscall_register_deprecated( at_tbpf_syscalls_t * syscalls );

/* ============================================================================
   Phase 8.6: Advanced Cryptography and Extension Syscalls
   ============================================================================ */

/* Register commit-reveal randomness syscalls */
void at_syscall_register_randomness( at_tbpf_syscalls_t * syscalls );

/* Register advanced cryptography syscalls (EVM precompiles) */
void at_syscall_register_crypto_advanced( at_tbpf_syscalls_t * syscalls );

/* KZG trusted setup management */
int  at_kzg_load_trusted_setup( char const * path );
void at_kzg_free_trusted_setup( void );

/* Register Curve25519 syscalls (Edwards/Ristretto) */
void at_syscall_register_curve25519( at_tbpf_syscalls_t * syscalls );

/* Register BLS12-381 syscalls */
void at_syscall_register_bls12381( at_tbpf_syscalls_t * syscalls );

/* Register P256 (secp256r1) syscalls */
void at_syscall_register_p256( at_tbpf_syscalls_t * syscalls );

/* Register OFFERCALL (scheduled execution) syscalls */
void at_syscall_register_offercall( at_tbpf_syscalls_t * syscalls );

AT_PROTOTYPES_END

#endif /* HEADER_at_vm_syscall_at_syscall_h */
