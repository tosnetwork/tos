#ifndef HEADER_at_src_util_tile_at_tile_private_h
#define HEADER_at_src_util_tile_at_tile_private_h

#include "at_tile.h"

/* at_cpuset_t is an internal replacement for libc cpu_set_t.  It exists
   to work around stability issues working with the cpu_set_t API which
   is opaque, and in the case of musl libc, broken due to strict
   aliasing violations:

     error: dereferencing type-punned pointer might break strict-aliasing rules [-Werror=strict-aliasing]
     CPU_SET( args->cpu_idx, cpu_set );

   This API is intended for internal use within at_tile.  Example usage:

     AT_CPUSET_DECL( cpuset );
     at_cpuset_insert( cpuset, 2UL );

   See util/tmpl/at_set.c for available methods.

   Safety notes:
   - DO NOT declare by at_cpuset_t x; Instead use AT_CPUSET_DECL(x).
   - DO NOT use sizeof(at_cpuset_t).  Instead use at_cpuset_footprint(). */

#define SET_NAME at_cpuset
#define SET_MAX AT_TILE_MAX
#include "../tmpl/at_set.c"

/* AT_CPUSET_DECL declares an empty at_cpuset_t with the given name in
   the current scope that is able to hold AT_TILE_MAX bits. */

#define AT_CPUSET_DECL(name) at_cpuset_t name [ at_cpuset_word_cnt ] = {0}

AT_PROTOTYPES_BEGIN

/* at_cpuset_{get,set}affinity wrap sched_{get,set}affinity for at_tile
   internal use.  Serves to fix type-punning issues.  tid is the thread
   ID (pid_t).  tid==0 implies current thread.

   Note that at_cpuset_getaffinity will silently truncate CPUs if the number
   of host CPUs exceeds AT_TILE_MAX.

   To set tile affinity, use the public at_tile.h API.
   at_sched_set_affinity can result in sub-optimal core/memory affinity,
   silent failures, and various other performance and stability issues. */

int
at_cpuset_getaffinity( ulong         tid,
                       at_cpuset_t * mask );

int
at_cpuset_setaffinity( ulong               tid,
                       at_cpuset_t const * mask );

/* at_tile_private_sibling_idx returns the sibling CPU (hyperthreaded
   pair) of the provided CPU, if there is one, otherwise return ULONG_MAX.
   On error, logs an error and exits the process. */

ulong
at_tile_private_sibling_idx( ulong cpu_idx );

/* These functions are for at_tile internal use only. */

void *
at_tile_private_stack_new( int   optimize,
                           ulong cpu_idx );

ulong
at_tile_private_cpus_parse( char const * cstr,
                            ushort *     tile_to_cpu );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_tile_at_tile_private_h */