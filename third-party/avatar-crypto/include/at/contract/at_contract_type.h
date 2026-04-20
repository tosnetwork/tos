#ifndef HEADER_at_contract_at_contract_type_h
#define HEADER_at_contract_at_contract_type_h

#include "at/contract/at_contract_base.h"

AT_PROTOTYPES_BEGIN

/* Validate ELF bytecode format (TOS Kernel contract format). */
int
at_contract_validate_bytecode( uchar const * bytecode,
                               ulong         bytecode_sz );

/* Quick ELF magic check (without full minimum-size validation). */
int
at_contract_is_elf_bytecode( uchar const * bytecode,
                             ulong         bytecode_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_type_h */
