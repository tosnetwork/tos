/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#ifndef AVATA_CODEGEN_ASSEMBLER_X86_DETECT_H
#define AVATA_CODEGEN_ASSEMBLER_X86_DETECT_H

#include <avata/codegen/assembler.h>

namespace avata {
namespace codegen {
namespace x86 {

class ArchitectureContext;

bool useSSE(ArchitectureContext* c);

}  // namespace x86
}  // namespace codegen
}  // namespace avata

#endif  // AVATA_CODEGEN_ASSEMBLER_X86_DETECT_H
