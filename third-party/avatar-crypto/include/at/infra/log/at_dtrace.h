#ifndef HEADER_at_src_util_log_at_dtrace_h
#define HEADER_at_src_util_log_at_dtrace_h

/* at_dtrace.h provides wrappers for software-defined trace points. */

#ifdef __has_include
#if __has_include(<sys/sdt.h>) && defined(__linux__)
#define AT_HAS_SDT 1
#endif
#endif

#ifndef AT_HAS_SDT
#define AT_HAS_SDT 0
#endif

#if AT_HAS_SDT

#if defined(__clang__) && (__clang_major__ == 19)
/* Work around an incompatibility between Clang 19 and SystemTap SDT */
#pragma GCC diagnostic ignored "-Wc23-extensions"
#endif

#include <sys/sdt.h>

#define AT_DTRACE_PROBE(name)                  DTRACE_PROBE(Reference,name)
#define AT_DTRACE_PROBE_1(name,a1)             DTRACE_PROBE1(Reference,name,a1)
#define AT_DTRACE_PROBE_2(name,a1,a2)          DTRACE_PROBE2(Reference,name,a1,a2)
#define AT_DTRACE_PROBE_3(name,a1,a2,a3)       DTRACE_PROBE3(Reference,name,a1,a2,a3)
#define AT_DTRACE_PROBE_4(name,a1,a2,a3,a4)    DTRACE_PROBE4(Reference,name,a1,a2,a3,a4)
#define AT_DTRACE_PROBE_5(name,a1,a2,a3,a4,a5) DTRACE_PROBE5(Reference,name,a1,a2,a3,a4,a5)

#else

#define AT_DTRACE_PROBE(name)
#define AT_DTRACE_PROBE_1(name,a1)             (void)((a1));
#define AT_DTRACE_PROBE_2(name,a1,a2)          (void)((a1)); (void)((a2));
#define AT_DTRACE_PROBE_3(name,a1,a2,a3)       (void)((a1)); (void)((a2)); (void)((a3));
#define AT_DTRACE_PROBE_4(name,a1,a2,a3,a4)    (void)((a1)); (void)((a2)); (void)((a3)); (void)((a4));
#define AT_DTRACE_PROBE_5(name,a1,a2,a3,a4,a5) (void)((a1)); (void)((a2)); (void)((a3)); (void)((a4)); (void)((a5));

#endif /* AT_HAS_SDT */

#endif /* HEADER_at_src_util_log_at_dtrace_h */