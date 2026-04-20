#ifndef HEADER_at_ballet_tbpf_at_tbpf_loader_h
#define HEADER_at_ballet_tbpf_at_tbpf_loader_h

/* TBPF (TOS BPF) loader definitions
   This provides types and utilities for loading and validating TBPF programs. */

#include "at/infra/at_util_base.h"

/* TBPF program version flags */
#define AT_TBPF_VERSION_V0 (0U)
#define AT_TBPF_VERSION_V1 (1U)
#define AT_TBPF_VERSION_V2 (2U)
#define AT_TBPF_VERSION_V3 (3U)
#define AT_TBPF_VERSION_COUNT (4U) /* Number of TBPF versions */

/* Short aliases for common types */
#define AT_TBPF_V0 AT_TBPF_VERSION_V0
#define AT_TBPF_V1 AT_TBPF_VERSION_V1
#define AT_TBPF_V2 AT_TBPF_VERSION_V2
#define AT_TBPF_V3 AT_TBPF_VERSION_V3

/* Aliases for TBPF (TOS BPF) */
#define AT_TBPF_V0 AT_TBPF_VERSION_V0
#define AT_TBPF_V1 AT_TBPF_VERSION_V1
#define AT_TBPF_V2 AT_TBPF_VERSION_V2
#define AT_TBPF_V3 AT_TBPF_VERSION_V3

/* TBPF limits */
#define AT_TBPF_RODATA_MAX         (16UL*1024UL*1024UL) /* 16 MiB max rodata */
#define AT_TBPF_TEXT_MAX           (16UL*1024UL*1024UL) /* 16 MiB max text */
#define AT_TBPF_CALLDESTS_MAX      (1UL<<20)            /* 1M max call destinations */
#define AT_TBPF_SYSCALLS_MAX       (256UL)              /* Max registered syscalls */

/* Forward declaration of VM structure */
struct at_vm;
typedef struct at_vm at_vm_t;

/* TBPF syscall function signature

   A syscall receives:
   - vm:  Pointer to the VM context
   - r1-r5: Arguments passed from the BPF program
   - _ret: Pointer to store the return value

   Returns an error code (0 for success, negative for error) */
typedef int (*at_tbpf_syscall_func_t)( void *  _vm,
                                       ulong   r1,
                                       ulong   r2,
                                       ulong   r3,
                                       ulong   r4,
                                       ulong   r5,
                                       ulong * _ret );

/* TBPF syscall entry in the syscall map */
struct at_tbpf_syscall {
  ulong                    hash;     /* Murmur3 hash of syscall name */
  char const *             name;     /* Syscall name (for debugging) */
  at_tbpf_syscall_func_t   func;     /* Syscall implementation */
  ulong                    cu_cost;  /* Compute unit cost (0 = use default) */
};
typedef struct at_tbpf_syscall at_tbpf_syscall_t;

/* TBPF syscall map */
struct at_tbpf_syscalls {
  ulong               cnt;                          /* Number of registered syscalls */
  at_tbpf_syscall_t   map[ AT_TBPF_SYSCALLS_MAX ];  /* Syscall entries */
};
typedef struct at_tbpf_syscalls at_tbpf_syscalls_t;

/* TBPF program info - metadata about a loaded program */
struct at_tbpf_program_info {
  /* Program version and flags */
  uint    tbpf_version;       /* AT_TBPF_VERSION_V* */

  /* Text section */
  ulong   text_off;           /* Offset of text section in rodata */
  ulong   text_cnt;           /* Number of 8-byte words in text */

  /* Entry point */
  ulong   entry_pc;           /* Entry point program counter */

  /* Call destinations bitmap (for static calls) */
  ulong   calldests_cnt;      /* Number of valid call destinations */
};
typedef struct at_tbpf_program_info at_tbpf_program_info_t;

AT_PROTOTYPES_BEGIN

/* Syscall map operations */

static inline void
at_tbpf_syscalls_init( at_tbpf_syscalls_t * syscalls ) {
  syscalls->cnt = 0UL;
}

static inline void
at_tbpf_syscalls_clear( at_tbpf_syscalls_t * syscalls ) {
  syscalls->cnt = 0UL;
}

/* at_tbpf_syscalls_key_null returns the null/empty key value */
static inline ulong
at_tbpf_syscalls_key_null( void ) {
  return 0UL;
}

/* at_tbpf_syscalls_query looks up a syscall by its hash.
   Returns a pointer to the syscall entry if found, NULL otherwise.
   The opt_idx parameter is optional (can be NULL) and if provided,
   receives the index of the found entry. */
static inline at_tbpf_syscall_t *
at_tbpf_syscalls_query( at_tbpf_syscalls_t * syscalls,
                        ulong                hash,
                        ulong *              opt_idx ) {
  for( ulong i=0UL; i<syscalls->cnt; i++ ) {
    if( syscalls->map[i].hash == hash ) {
      if( opt_idx ) *opt_idx = i;
      return &syscalls->map[i];
    }
  }
  return NULL;
}

static inline at_tbpf_syscall_t const *
at_tbpf_syscalls_query_const( at_tbpf_syscalls_t const * syscalls,
                              ulong                      hash,
                              ulong *                    opt_idx ) {
  for( ulong i=0UL; i<syscalls->cnt; i++ ) {
    if( syscalls->map[i].hash == hash ) {
      if( opt_idx ) *opt_idx = i;
      return &syscalls->map[i];
    }
  }
  return NULL;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_tbpf_at_tbpf_loader_h */