#ifndef HEADER_at_disco_seccomp_h
#define HEADER_at_disco_seccomp_h

/* at_seccomp.h - seccomp sandbox support for Avatar tiles (Linux only)

   seccomp (secure computing mode) uses BPF filters to restrict which
   system calls a process can make. This provides defense-in-depth
   security by limiting the attack surface if a tile is compromised.

   On macOS, seccomp is not available. The populate_allowed_seccomp
   and populate_allowed_fds callbacks are simply not set in the
   tile interface on non-Linux platforms. */

#if defined(__linux__)

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stddef.h>

/* Architecture detection for seccomp */
#if defined(__i386__)
# define AT_SECCOMP_ARCH_NR AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define AT_SECCOMP_ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define AT_SECCOMP_ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif

/* at_log_private_logfile_fd returns the file descriptor of the logfile,
   or -1 if logging to file is disabled.
   TODO: Implement this in at_log.c */
int at_log_private_logfile_fd( void );

#endif /* defined(__linux__) */

#endif /* HEADER_at_disco_seccomp_h */