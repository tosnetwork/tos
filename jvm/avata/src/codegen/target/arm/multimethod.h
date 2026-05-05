/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#ifndef AVATA_CODEGEN_ASSEMBLER_ARM_MULTIMETHOD_H
#define AVATA_CODEGEN_ASSEMBLER_ARM_MULTIMETHOD_H

#include <avata/codegen/lir.h>
#include <avata/codegen/assembler.h>

#define CAST1(x) reinterpret_cast<UnaryOperationType>(x)
#define CAST2(x) reinterpret_cast<BinaryOperationType>(x)
#define CAST3(x) reinterpret_cast<TernaryOperationType>(x)
#define CAST_BRANCH(x) reinterpret_cast<BranchOperationType>(x)

namespace avata {
namespace codegen {
namespace arm {

unsigned index(ArchitectureContext*,
               lir::BinaryOperation operation,
               lir::Operand::Type operand1,
               lir::Operand::Type operand2);

unsigned index(ArchitectureContext* con UNUSED,
               lir::TernaryOperation operation,
               lir::Operand::Type operand1);

unsigned branchIndex(ArchitectureContext* con UNUSED,
                     lir::Operand::Type operand1,
                     lir::Operand::Type operand2);

void populateTables(ArchitectureContext* con);

}  // namespace arm
}  // namespace codegen
}  // namespace avata

#endif  // AVATA_CODEGEN_ASSEMBLER_ARM_MULTIMETHOD_H
