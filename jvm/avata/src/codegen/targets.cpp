/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include "avata/common.h"

#include <avata/codegen/targets.h>

#include "avata/environment.h"

namespace avata {
namespace codegen {

Architecture* makeArchitectureNative(vm::System* system,
                                     bool useNativeFeatures UNUSED)
{
#ifndef AVATA_TARGET_ARCH
#error "Must specify native target!"
#endif

#if AVATA_TARGET_ARCH == AVATA_ARCH_UNKNOWN
  system->abort();
  return 0;
#elif(AVATA_TARGET_ARCH == AVATA_ARCH_X86) \
    || (AVATA_TARGET_ARCH == AVATA_ARCH_X86_64)
  return makeArchitectureX86(system, useNativeFeatures);
#elif (AVATA_TARGET_ARCH == AVATA_ARCH_ARM) \
    || (AVATA_TARGET_ARCH == AVATA_ARCH_ARM64)
  return makeArchitectureArm(system, useNativeFeatures);
#else
#error "Unsupported codegen target"
#endif
}

}  // namespace codegen
}  // namespace avata
