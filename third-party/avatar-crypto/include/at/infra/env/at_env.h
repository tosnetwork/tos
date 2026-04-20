#ifndef HEADER_at_src_util_env_at_env_h
#define HEADER_at_src_util_env_at_env_h

/* APIs for getting information from the environment */

#include "../cstr/at_cstr.h"

AT_PROTOTYPES_BEGIN

/* at_env_strip_cmdline_ulong first searches the environment for
   "[env_key]=[val]" and then C-style command line arguments
   sequentially for "[key] [val]", converts any found "[val]" to a ulong
   and returns last found val.  If there are no such val found, returns
   def.

   All instances of "[key] [val]" will be stripped from the command line
   to facilitate modularizing command line parsing between independently
   developed units of the code.  If multiple key-val pairs are found,
   the last pair on the command line takes takes precedence.

   Similarly for the other types.

   These mirror the above at_cstr_to_* converters and, unsurprisingly,
   use these to do argument conversion.  As such,
   at_env_strip_cmdline_cstr will return the actual pointer to the
   matching POSIX environment val cstr, command line val cstr or def cstr
   with the corresponding lifetime implications.

   A NULL pargc, pargv or key indicates the command line should not be
   searched / stripped.  A NULL env_key indicates the environment should
   not be searched.  env_key will be ignored on build targets that do
   not have a POSIX-ish environment (e.g. ignored if not AT_HAS_HOSTED). */

#define AT_ENV_STRIP_CMDLINE_DECL( T, what )         \
T                                                    \
at_env_strip_cmdline_##what( int        *   pargc,   \
                             char       *** pargv,   \
                             char const *   key,     \
                             char const *   env_key, \
                             T              def )

AT_ENV_STRIP_CMDLINE_DECL( char const *, cstr   );
AT_ENV_STRIP_CMDLINE_DECL( char,         char   );
AT_ENV_STRIP_CMDLINE_DECL( schar,        schar  );
AT_ENV_STRIP_CMDLINE_DECL( short,        short  );
AT_ENV_STRIP_CMDLINE_DECL( int,          int    );
AT_ENV_STRIP_CMDLINE_DECL( long,         long   );
AT_ENV_STRIP_CMDLINE_DECL( uchar,        uchar  );
AT_ENV_STRIP_CMDLINE_DECL( ushort,       ushort );
AT_ENV_STRIP_CMDLINE_DECL( uint,         uint   );
AT_ENV_STRIP_CMDLINE_DECL( ulong,        ulong  );
AT_ENV_STRIP_CMDLINE_DECL( float,        float  );
#if AT_HAS_DOUBLE
AT_ENV_STRIP_CMDLINE_DECL( double,       double );
#endif
/* FIXME: ADD COVERAGE FOR INT128/UINT128? */

#undef AT_ENV_STRIP_CMDLINE_DECL

/* returns 1 if the command line contains the given key, and removes
   it from the args, otherwise returns 0. */

int
at_env_strip_cmdline_contains( int *        pargc,
                               char ***     pargv,
                               char const * key );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_env_at_env_h */