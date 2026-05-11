/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include <avata/system/signal.h>
#include <avata/util/abort.h>

namespace avata {
namespace util {

void NO_RETURN abortWithoutContext()
{
  avata::system::crash();
}

}  // namespace util
}  // namespace avata
