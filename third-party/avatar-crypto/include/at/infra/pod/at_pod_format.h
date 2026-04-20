#ifndef HEADER_at_src_util_pod_at_pod_format_h
#define HEADER_at_src_util_pod_at_pod_format_h

#include "at/infra/pod/at_pod.h"

#include <stdarg.h>
#include <stdio.h>

/* at_pod_insertf_[type] inserts the [type] val into the pod at the
   given path.  The path is constructed from the given format string.
   Returns offset where val was inserted, 0 on failure.  The inserted
   representation might be compressed.  This offset is valid for the
   pod's lifetime or an invalidating operation is done on the pod.

   IMPORTANT!  THIS IS AN INVALIDATING OPERATION */

#define AT_POD_IMPL(type)                                                       \
__attribute__ ((format (printf, 3, 4)))                                         \
static inline ulong                                                             \
at_pod_insertf_##type( uchar      * AT_RESTRICT pod,                            \
                       type                     val,                            \
                       char const * AT_RESTRICT fmt, ... ) {                    \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  return at_pod_insert_##type( pod, buf, val );                                 \
}

AT_POD_IMPL( ushort )
AT_POD_IMPL( uint   )
AT_POD_IMPL( ulong  )
AT_POD_IMPL( short  )
AT_POD_IMPL( int    )
AT_POD_IMPL( long   )
AT_POD_IMPL( char   )
AT_POD_IMPL( schar  )
AT_POD_IMPL( uchar  )
AT_POD_IMPL( float  )
#if AT_HAS_DOUBLE
AT_POD_IMPL( double )
#endif

#undef AT_POD_IMPL

__attribute__ ((format (printf, 3, 4)))
static inline ulong
at_pod_insertf_cstr( uchar      * AT_RESTRICT pod,
                     char const * AT_RESTRICT str,
                     char const * AT_RESTRICT fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  char buf[ 128UL ];
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;
  return at_pod_insert_cstr( pod, buf, str );
}

/* at_pod_replacef_[type] replaces the [type] val into the pod at the
   given path.  The path is constructed from the given format string.
   If the path does not exist, it is created.  Returns AT_POD_SUCCESS
   on success, or AT_POD_ERR_* on failure.

   IMPORTANT!  THIS IS AN INVALIDATING OPERATION */

#define AT_POD_IMPL(type)                                                       \
__attribute__ ((format (printf, 3, 4)))                                         \
static inline int                                                               \
at_pod_replacef_##type( uchar      * AT_RESTRICT pod,                           \
                        type                     val,                           \
                        char const * AT_RESTRICT fmt, ... ) {                   \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  int result = at_pod_remove( pod, buf );                                       \
  if( AT_UNLIKELY( result!=AT_POD_SUCCESS && result!=AT_POD_ERR_RESOLVE ) )     \
    return result;                                                              \
  if( AT_UNLIKELY( !at_pod_insert_##type( pod, buf, val ) ) )                   \
    return AT_POD_ERR_FULL;                                                     \
  return AT_POD_SUCCESS;                                                        \
}

AT_POD_IMPL( ushort )
AT_POD_IMPL( uint   )
AT_POD_IMPL( ulong  )
AT_POD_IMPL( short  )
AT_POD_IMPL( int    )
AT_POD_IMPL( long   )
AT_POD_IMPL( char   )
AT_POD_IMPL( schar  )
AT_POD_IMPL( uchar  )
AT_POD_IMPL( float  )
#if AT_HAS_DOUBLE
AT_POD_IMPL( double )
#endif

#undef AT_POD_IMPL

/* at_pod_queryf_[type] queries for the [type] in pod at path.  The path
   is constructed from the given format string.  Returns the query
   result on success or def on failure. */

#define AT_POD_IMPL(type)                                                       \
__attribute__ ((format (printf, 3, 4)))                                         \
static inline type                                                              \
at_pod_queryf_##type( uchar const * AT_RESTRICT pod,                            \
                      type                      def,                            \
                      char const *  AT_RESTRICT fmt, ... ) {                    \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  return at_pod_query_##type( pod, buf, def );                                  \
}

AT_POD_IMPL( ushort )
AT_POD_IMPL( uint   )
AT_POD_IMPL( ulong  )
AT_POD_IMPL( short  )
AT_POD_IMPL( int    )
AT_POD_IMPL( long   )
AT_POD_IMPL( char   )
AT_POD_IMPL( schar  )
AT_POD_IMPL( uchar  )
AT_POD_IMPL( float  )
#if AT_HAS_DOUBLE
AT_POD_IMPL( double )
#endif

__attribute__ ((format (printf, 2, 3)))
static inline uchar const *
at_pod_queryf_subpod( uchar const * AT_RESTRICT pod,
                      char const *  AT_RESTRICT fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  char buf[ 128UL ];
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;
  return at_pod_query_subpod( pod, buf );
}

#undef AT_POD_IMPL

__attribute__ ((format (printf, 3, 4)))
static inline char const *
at_pod_queryf_cstr( uchar const * AT_RESTRICT pod,
                    char const  * AT_RESTRICT def,
                    char const  * AT_RESTRICT fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  char buf[ 128UL ];
  int   ret = at_vsnprintf( buf, 128UL, fmt, ap );
  ulong len = at_ulong_if( ret<0, 0UL, at_ulong_min( (ulong)ret, 128UL-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( AT_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;
  return at_pod_query_cstr( pod, buf, def );
}

#endif /* HEADER_at_src_util_pod_at_pod_format_h */