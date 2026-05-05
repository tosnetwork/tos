/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#ifndef AVATA_ENVIRONMENT_H
#define AVATA_ENVIRONMENT_H

#ifndef AVATA_TARGET_FORMAT
#error build system should have defined AVATA_TARGET_FORMAT
#endif

#ifndef AVATA_TARGET_ARCH
#error build system should have defined AVATA_TARGET_ARCH
#endif

#define AVATA_FORMAT_UNKNOWN 0
#define AVATA_FORMAT_ELF 1
#define AVATA_FORMAT_PE 2
#define AVATA_FORMAT_MACHO 3

#define AVATA_ARCH_UNKNOWN 0
#define AVATA_ARCH_X86 (1 << 8)
#define AVATA_ARCH_X86_64 (2 << 8)
#define AVATA_ARCH_ARM (3 << 8)
#define AVATA_ARCH_ARM64 (4 << 8)

#endif
