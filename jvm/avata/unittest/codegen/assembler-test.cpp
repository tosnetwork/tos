/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include <stdio.h>

#include "avata/common.h"
#include <avata/heap/heap.h>
#include <avata/system/system.h>
#include "avata/target.h"

#include <avata/codegen/assembler.h>
#include <avata/codegen/architecture.h>
#include <avata/codegen/targets.h>
#include <avata/codegen/lir.h>

#include "test-harness.h"

using namespace avata::codegen;
using namespace vm;

class BasicEnv {
 public:
  System* s;
  Heap* heap;
  Architecture* arch;

  BasicEnv()
      : s(makeSystem()),
        heap(makeHeap(s, 32 * 1024)),
        arch(makeArchitectureNative(s, true))
  {
    arch->acquire();
  }

  ~BasicEnv()
  {
    arch->release();
    s->dispose();
  }
};

class Asm {
 public:
  Zone zone;
  Assembler* a;

  Asm(BasicEnv& env)
      : zone(env.heap, 8192), a(env.arch->makeAssembler(env.heap, &zone))
  {
  }

  ~Asm()
  {
    a->dispose();
  }
};

TEST(BasicAssembler)
{
  BasicEnv env;
  Asm a(env);
}

TEST(ArchitecturePlan)
{
  BasicEnv env;

  for (int op = (int)lir::Call; op < (int)lir::AlignedJump; op++) {
    bool thunk;
    OperandMask mask;
    env.arch->plan(
        (lir::UnaryOperation)op, vm::TargetBytesPerWord, mask, &thunk);
    assertFalse(thunk);
    assertNotEqual(static_cast<uint8_t>(0), mask.typeMask);
    assertNotEqual(static_cast<uint64_t>(0), (uint64_t)mask.lowRegisterMask);
  }
}
