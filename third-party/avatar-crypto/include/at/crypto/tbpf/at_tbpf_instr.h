#ifndef HEADER_at_ballet_tbpf_at_tbpf_instr_h
#define HEADER_at_ballet_tbpf_at_tbpf_instr_h

#include "at/infra/at_util_base.h"
#include "at_tbpf_loader.h"

struct at_tbpf_opcode_any {
  uchar op_class  : 3;
  uchar _unknown  : 5;
};
typedef struct at_tbpf_opcode_any at_tbpf_opcode_any_t;

struct at_tbpf_opcode_normal {
  uchar op_class  : 3;
  uchar op_src    : 1;
  uchar op_mode   : 4;
};
typedef struct at_tbpf_opcode_normal at_tbpf_opcode_normal_t;

struct at_tbpf_opcode_mem {
  uchar op_class       : 3;
  uchar op_size        : 2;
  uchar op_addr_mode   : 3;
};
typedef struct at_tbpf_opcode_mem at_tbpf_opcode_mem_t;

union at_tbpf_opcode {
  uchar raw;
  at_tbpf_opcode_any_t any;
  at_tbpf_opcode_normal_t normal;
  at_tbpf_opcode_mem_t mem;
};
typedef union at_tbpf_opcode at_tbpf_opcode_t;

struct at_tbpf_instr {
  at_tbpf_opcode_t opcode;
  uchar dst_reg : 4;
  uchar src_reg : 4;
  short offset;
  uint imm;
};
typedef struct at_tbpf_instr at_tbpf_instr_t;

AT_PROTOTYPES_BEGIN

/* at_tbpf_instr decodes a 64-bit word into an instruction struct */
AT_FN_CONST static inline at_tbpf_instr_t
at_tbpf_instr( ulong u ) {
  union { ulong u; at_tbpf_instr_t instr; } _;
  _.u = u;
  return _.instr;
}

/* at_tbpf_ulong encodes an instruction struct into a 64-bit word */
AT_FN_CONST static inline ulong
at_tbpf_ulong( at_tbpf_instr_t instr ) {
  union { ulong u; at_tbpf_instr_t instr; } _;
  _.instr = instr;
  return _.u;
}

/* at_tbpf_is_function_start returns 1 if instruction marks function start
   (r10 = r10 + imm pattern used by TBPF linker) */
AT_FN_CONST static inline int
at_tbpf_is_function_start( at_tbpf_instr_t instr ) {
  return instr.opcode.raw == 0x07 && instr.dst_reg == 0x0A;
}

/* at_tbpf_is_function_end returns 1 if instruction ends a function
   (JA unconditional jump or EXIT instruction) */
AT_FN_CONST static inline int
at_tbpf_is_function_end( at_tbpf_instr_t instr ) {
  return instr.opcode.raw == 0x05 || instr.opcode.raw == 0x9D;
}

/* at_tbpf_enable_stricter_elf_headers_enabled returns 1 if the given
   TBPF version enables stricter ELF header validation (v3+) */
AT_FN_CONST static inline int
at_tbpf_enable_stricter_elf_headers_enabled( ulong tbpf_version ) {
  return tbpf_version >= AT_TBPF_VERSION_V3;
}

/* at_tbpf_dynamic_stack_frames_enabled returns 1 if dynamic stack frames
   are enabled for the given TBPF version (v2+) */
AT_FN_CONST static inline int
at_tbpf_dynamic_stack_frames_enabled( ulong tbpf_version ) {
  return tbpf_version >= AT_TBPF_VERSION_V2;
}

/* at_tbpf_callx_uses_src_reg_enabled returns 1 if CALLX instruction uses
   src_reg to determine the target (v2+), otherwise uses imm field */
AT_FN_CONST static inline int
at_tbpf_callx_uses_src_reg_enabled( ulong tbpf_version ) {
  return tbpf_version >= AT_TBPF_VERSION_V2;
}

/* at_tbpf_calldests_test tests if the given PC is a valid call destination
   in the calldests bit vector.  Returns 1 if valid, 0 otherwise. */
AT_FN_PURE static inline int
at_tbpf_calldests_test( ulong const * calldests,
                        ulong         pc ) {
  /* calldests is a bit vector where bit pc is set if pc is a valid
     call destination.  Each ulong holds 64 bits. */
  return (int)( ( calldests[ pc >> 6 ] >> ( pc & 63UL ) ) & 1UL );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_tbpf_at_tbpf_instr_h */