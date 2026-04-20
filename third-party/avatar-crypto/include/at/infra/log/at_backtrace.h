#ifndef HEADER_at_src_util_log_at_backtrace_h
#define HEADER_at_src_util_log_at_backtrace_h

#include "../at_util_base.h"

/* at_backtrace_log prints a simple backtrace to stderr. */

void
at_backtrace_log( void ** addrs,
                  ulong   addrs_cnt );

#endif /* HEADER_at_src_util_log_at_backtrace_h */