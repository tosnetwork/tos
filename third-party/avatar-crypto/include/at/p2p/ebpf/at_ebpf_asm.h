/* at_ebpf_asm.h - eBPF instruction encoding macros */

#ifndef HEADER_at_p2p_ebpf_at_ebpf_asm_h
#define HEADER_at_p2p_ebpf_at_ebpf_asm_h

/* eBPF register names */
#define AT_EBPF_ASM_r0   0
#define AT_EBPF_ASM_r1   1
#define AT_EBPF_ASM_r2   2
#define AT_EBPF_ASM_r3   3
#define AT_EBPF_ASM_r4   4
#define AT_EBPF_ASM_r5   5

/* Load instructions with indirect addressing */
#define AT_EBPF_ASM_LOAD_IND( op, dst, src, off ) ((op) | ((AT_EBPF_ASM_##dst)<<8) | ((AT_EBPF_ASM_##src)<<12) | (((off)&0xFFFFUL)<<16))
#define AT_EBPF_ASM_ldxb( dst, src, off ) AT_EBPF_ASM_LOAD_IND( 0x71, dst, src, off )
#define AT_EBPF_ASM_ldxh( dst, src, off ) AT_EBPF_ASM_LOAD_IND( 0x69, dst, src, off )
#define AT_EBPF_ASM_ldxw( dst, src, off ) AT_EBPF_ASM_LOAD_IND( 0x61, dst, src, off )
#define AT_EBPF_ASM_lddw( dst, imm      ) (0x1018 | ((AT_EBPF_ASM_##dst)<<8) | ((((uint)imm)&0xFFFFFFFFUL)<<32))

/* ALU instructions */
#define AT_EBPF_ALU_IMM( op, dst, imm ) (op | ((AT_EBPF_ASM_##dst)<<8) | ((((uint)imm)&0xFFFFFFFFUL)<<32))
#define AT_EBPF_ALU_REG( op, dst, src ) (op | ((AT_EBPF_ASM_##dst)<<8) | ((AT_EBPF_ASM_##src)<<12))
#define AT_EBPF_ASM_mov64_imm( dst, imm ) AT_EBPF_ALU_IMM( 0xb7, dst, imm )
#define AT_EBPF_ASM_mov64_reg( dst, src ) AT_EBPF_ALU_REG( 0xbf, dst, src )
#define AT_EBPF_ASM_add64_imm( dst, imm ) AT_EBPF_ALU_IMM( 0x07, dst, imm )
#define AT_EBPF_ASM_add64_reg( dst, src ) AT_EBPF_ALU_REG( 0x0f, dst, src )
#define AT_EBPF_ASM_and64_imm( dst, imm ) AT_EBPF_ALU_IMM( 0x57, dst, imm )
#define AT_EBPF_ASM_lsh64_imm( dst, imm ) AT_EBPF_ALU_IMM( 0x67, dst, imm )

/* Jump instructions */
#define AT_EBPF_ASM_ja( off ) ( 0x05 | (((off)&0xFFFFUL)<<16) )
#define AT_EBPF_ASM_JUMP_COND_IMM( op, dst, imm, off ) (op | ((AT_EBPF_ASM_##dst)<<8) | (((off)&0xFFFFUL)<<16)) | (((imm)&0xFFFFFFFFUL)<<32)
#define AT_EBPF_ASM_JUMP_COND_REG( op, dst, src, off ) (op | ((AT_EBPF_ASM_##dst)<<8) | ((AT_EBPF_ASM_##src)<<12) | ((off&0xFFFFUL)<<16))
#define AT_EBPF_ASM_jeq_imm( dst, imm, off ) AT_EBPF_ASM_JUMP_COND_IMM( 0x15, dst, imm, off )
#define AT_EBPF_ASM_jne_imm( dst, imm, off ) AT_EBPF_ASM_JUMP_COND_IMM( 0x55, dst, imm, off )
#define AT_EBPF_ASM_jgt_reg( dst, src, off ) AT_EBPF_ASM_JUMP_COND_REG( 0x2d, dst, src, off )
#define AT_EBPF_ASM_jlt_imm( dst, imm, off ) AT_EBPF_ASM_JUMP_COND_IMM( 0xa5, dst, imm, off )

/* Function call */
#define AT_EBPF_ASM_call( off ) (0x85 | ((off&0xFFFFFFFFUL)<<32))

/* Convenience macro */
#define AT_EBPF( op, ... ) AT_EBPF_ASM_##op( __VA_ARGS__ )
#define AT_EBPF_exit 0x95

#endif /* HEADER_at_p2p_ebpf_at_ebpf_asm_h */
