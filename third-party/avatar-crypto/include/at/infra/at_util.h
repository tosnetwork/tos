#ifndef HEADER_at_src_util_at_util_h
#define HEADER_at_src_util_at_util_h

//#include "at_util_base.h"          /* includes stdalign.h string.h limits.h float.h */
//#include "sanitize/at_sanitize.h"  /* includes at_util_base.h (at_asan.h at_msan.h) */
//#include "bits/at_bits.h"          /* includes sanitize/at_sanitize.h (at_bits_find_lsb.h at_bits_find_msb.h at_bits_tg.h) */
//#include "io/at_io.h"              /* includes bits/at_bits.h */
//#include "cstr/at_cstr.h"          /* includes bits/at_bits.h */
#include "rng/at_rng.h"              /* includes bits/at_bits.h */
#include "spad/at_spad.h"            /* includes bits/at_bits.h */
//#include "env/at_env.h"            /* includes cstr/at_cstr.h */
//#include "log/at_log.h"            /* includes env/at_env.h io/at_io.h */
//#include "checkpt/at_checkpt.h"    /* includes log/at_log.h */
//#include "shmem/at_shmem.h"        /* includes log/at_log.h */
//#include "tile/at_tile.h"          /* includes shmem/at_shmem.h */
//#include "scratch/at_scratch.h"    /* includes tile/at_tile.h */ /* FIXME: deprecate non alloca parts? */
//#include "tpool/at_tpool.h"        /* includes scratch/at_scratch.h */
//#include "wksp/at_wksp.h"          /* includes tpool/at_tpool.h checkpt/at_checkpt.h */
#include "alloc/at_alloc.h"          /* includes wksp/at_wksp.h */

#include "sandbox/at_sandbox.h"      /* includes at_util_base.h */ /* FIXME: should this be included by default? */
#include "bits/at_sat.h"             /* includes bits/at_bits.h */ /* FIXME: should this be incldued by default? */

/* Additional at_util APIs that are not included by default */

//#include "archive/at_ar.h"         /* includes at_util_base.h */
//#include "archive/at_tar.h"        /* includes at_io.h */
//#include "bits/at_float.h"         /* includes bits/at_bits.h */
//#include "bits/at_uwide.h"         /* includes bits/at_bits.h */
//#include "hist/at_histf.h"         /* includes log/at_log.h math.h (AT_HAS_AVX) at_avx.h */
//#include "math/at_stat.h"          /* includes bits/at_bits.h */
//#include "math/at_sqrt.h"          /* includes bits/at_bits.h */
//#include "math/at_fxp.h"           /* includes math/at_sqrt.h, (!AT_HAS_INT128) bits/at_uwide.h */
//#include "net/at_pcapng.h"         /* includes at_util_base.h */
//#include "net/at_eth.h"            /* includes bits/at_bits.h */
//#include "net/at_ip4.h"            /* includes bits/at_bits.h */
//#include "net/at_igmp.h"           /* includes net/at_ip4.h */
//#include "net/at_udp.h"            /* includes net/at_ip4.h */
//#include "net/at_net_headers.h */  /* includes net/at_udp.h net/at_eth.h */
//#include "net/at_pcap.h"           /* includes net/at_eth.h log/at_log.h */
//#include "pod/at_pod.h"            /* includes cstr/at_cstr.h */
//#include "sanitize/at_fuzz.h"      /* includes at_util_base.h */
//#include "sanitize/at_backtrace.h" /* FIXME: this probably should be merged with another header */
//#include "simd/at_sse.h"           /* includes bits/at_bits.h, requires AT_HAS_SSE */
//#include "simd/at_avx.h"           /* includes bits/at_bits.h, requires AT_HAS_AVX */
//#include "simd/at_avx512.h"        /* includes bits/at_bits.h, requires AT_HAS_AVX512 */

AT_PROTOTYPES_BEGIN

/* Boot/halt all at_util services.  at_boot is intended to be called
   explicitly once immediately after the main thread in a thread group
   starts.  at_halt is intended to be called explicitly once immediately
   before normal thread group shutdown.

   Command line / environment options (last option on command line takes
   precedence, command line will be stripped of these options):

     --log-path [cstr] / AT_LOG_PATH=[cstr]

       Provides the location where the permanent log for this process
       should be appended (created if not already existing).  If not
       specified, will autogenerate a descriptive log path that will
       almost certainly be globally unique.  If specified as an empty
       string, will disable the permanent log for this process.  If
       specified as "-", the permanent log will be written to stdout.
       The shortened ephemeral log will always be written to stderr.
       This option might be ignored by some targets (e.g. unhosted
       machine targets).

     --log-dedup [int] / AT_LOG_DEDUP=[int]

       Zero indicates the logger should not try to do any log message
       deduplication.  Non-zero indicates it should.  Defaults to 1.
       This option might be ignored by some targets (e.g. unhosted
       machine targets where deduplication would be handled by the
       pretty printer at the other side of the tether).

     --log-backtrace [int] / AT_LOG_BACKTRACE=[int]

       Zero indicates the logging should not try to any backtracing in
       response to signals that (by default) terminate the thread group.
       Non-zero indicates it should.  Defaults to 1.  This option might
       be ignored by some targets (e.g. unhosted machine targets where
       backtracing would be handled by the pretty printer at the other
       side of the tether).

     --log-app-id [ulong] / AT_LOG_APP_ID=[ulong]

       Provides the application id of the application running the
       caller.  If not provided, defaults to 0.  An application id is
       intended to be, at a minimum, enterprise unique over all
       currently running applications.  It is the thread group
       launcher's responsibility for determining this.

     --log-app [cstr] / AT_LOG_APP=[cstr]

       Provides an application description.  If that is not available,
       falls back to "[app]".  This string might be truncated and
       sanitized as needed for logging.

     --log-thread-id [ulong] / AT_LOG_THREAD_ID=[ulong]

       Provides the first application thread id to use in the
       application thread group to which the caller belongs.  If not
       provided defaults to 0.  A thread id is intended to be, at a
       minimum, application wide unique over all currently running
       threads in the application (this is neither a tid nor
       contiguous).  The caller will be assigned this first id.  If
       there can be more than one thread in the thread group to which
       the caller belongs, subsequently created threads will be assigned
       thread ids sequentially from this.  The thread group launcher is
       responsible for setting the initial thread id for each
       application thread group such that ids will not collide with
       application ids from other thread groups (e.g. assign
       non-overlapping blocks of thread ids to each application thread
       group and pass the first thread each block for the at_boot to the
       corresponding thread group here ... note that as a result, it is
       possible for a launcher to assign thread ids to all application
       threads sequentially from zero in the common case of applications
       that have a fixed number of threads for the application's
       lifetime).

     --log-thread [cstr] / AT_LOG_THREAD=[cstr]

       Provides the caller's threads description.  If not provided,
       falls back to a target specific default (e.g. "[tid]@[cpu]").
       This string might be truncated and sanitized as needed for
       logging.

     --log-host-id [ulong] / AT_LOG_HOST_ID=[ulong]

       Provides the host id of the host running the caller.  If not
       provided, defaults to 0.  It is intended that this be, at a
       minimum, application wide unique over all hosts currently running
       application threads.  It is the thread group launcher's
       responsibility for guaranteeing this.

     --log-host [cstr] / AT_LOG_HOST=[cstr]

       Provides the host description for the thread group to which the
       caller belongs.  If not provided, falls back to gethostname().
       If that is not available, falls back to a target specific default
       (e.g. host's name).  This string might be truncated and sanitized
       as needed for logging.

     --log-cpu-id [ulong] / AT_LOG_CPU_ID=[ulong]

       Provides the cpu id of the cpu running the caller.  If not
       provided, defaults to 0.  It is intended that a cpu id be unique
       over all cpus currently available on a host.  This is stripped
       but otherwise ignored on targets where an underlying OS assigns
       this (e.g. the lowest indexed core in a /proc/cpuinfo sense the
       caller is allowed to run on).

     --log-cpu [cstr] / AT_LOG_CPU=[cstr]

       Provides the description for the cpu running the caller the
       thread group to which the caller belongs.  If not provided, falls
       back to a target specific default (e.g. the cpu-id pretty
       printed).  This string might be truncated and sanitized as needed
       for logging.

     --log-group-id [ulong] / AT_LOG_GROUP_ID=[ulong]

       Provides the group id of the thread group to which the caller
       belongs.  If not provided, defaults to 0.  This is stripped but
       otherwise ignored on targets where an underlying OS assigns this
       (e.g. the pid of the process containing the caller).

     --log-group [cstr] / AT_LOG_GROUP=[cstr]

       Provides the description of the cpu running the caller.  If not
       provided, falls back to program_invocation_short_name (if
       applicable).  If that is not available, falls back to argv[0] (if
       applicable).  This string might be truncated and sanitized as
       needed for logging.

     --log-tid [ulong] / AT_LOG_TID=[ulong]

       Provides the tid of the caller in the caller's thread group.  If
       not provided, defaults to 0.  This is stripped but otherwise
       ignored on targets where the underlying OS assigns this (e.g. the
       tid of the process containing the caller).

     --log-user-id [ulong] / AT_LOG_USER_ID=[ulong]

       Provides the user id of the user responsible for the caller.  If
       not provided, defaults to 0.  This is stripped but otherwise
       ignored on targets where an underlying OS assigns this (e.g. the
       user ID of the person who started the caller's process).

     --log-user [cstr] / AT_LOG_USER=[cstr]

       Provides the user of the caller's thread group.  If not provided,
       falls back to the environment LOGNAME value (if applicable).  If
       that is not available, falls back on getlogin() (if applicable).
       If that is not available, falls back to "[user]".  This string
       might be truncated and sanitized as needed for logging.

     --log-colorize      [int] / AT_LOG_COLORIZE=[int]      / default system
     --log-level-logfile [int] / AT_LOG_LEVEL_LOGFILE=[int] / default 1 ... >=INFO
     --log-level-stderr  [int] / AT_LOG_LEVEL_STDERR=[int]  / default 2 ... >=NOTICE
     --log-level-flush   [int] / AT_LOG_LEVEL_FLUSH=[int]   / default 3 ... >=WARNING
     --log-level-core    [int] / AT_LOG_LEVEL_CORE=[int]    / default 5 ... >=CRIT

       These configure the behaviors of the logger.

       A non-zero colorize indicates stderr log messages should be
       colorized.  default is disabled unless either
       COLORTERM==truecolor or TERM==*256color* in the environment.
       (This can also be enabled / disabled on the fly by the program
       itself.) Note that the permanent log is _never_ colorized to aid
       in robust log file message archiving.

       logfile is the minimal level for which the logger should write
       detailed messages to the permanent log file (if there is one).
       stderr is the minimal level for which the logger should write
       summarized messages to the ephemeral log stream.  flush is the
       minimal level at which the logger should try to immediately flush
       out messages.  core is the level at which an abortive log message
       should attempt to write out a core and do a backtrace.

         0 - DEBUG
         1 - INFO
         2 - NOTICE
         3 - WARNING
         4 - ERR
         5 - CRIT
         6 - ALERT
         7 - EMERG

       If these are set weirdly (i.e. decreasing or core is not at least
       4), they will be overridden to values that are sensible.

       Setting logfile, stderr, flush <=0 and core==4 makes the log
       maximally chatty.  Setting logfile, stderr, flush, core >7 makes
       the log minimally chatty.

     --shmem-path [path] / AT_SHMEM_PATH=[path]

       Give the location of the hugetlbs mounts for the shared memory
       domain this thread group will use.  Defaults to "/mnt/.at" on Linux
       or "/tmp/.fd" on macOS if not specified.  Ignored if not a hosted
       implementation.

     --tile-cpus [cpu-list] / AT_TILE_CPUS=[cpu-list]

       For a thread group of an application on a hosted target, this
       specifies the cpus to use.  E.g.

         --tile-cpus f,1-3,f2,9,7,11-17/2

       specifies this application thread group has 12 tiles that should
       be mapped to cpus on this host as:

         tile  0 on floating
         tile  1 on cpu 1
         tile  2 on cpu 2
         tile  3 on cpu 3
         tile  4 on floating
         tile  5 on floating
         tile  6 on cpu 9
         tile  7 on cpu 7
         tile  8 on cpu 11
         tile  9 on cpu 13
         tile 10 on cpu 15
         tile 11 on cpu 17

       Floating tiles run on the cores the job launcher initially the
       thread group with whatever priority was initially assigned the
       thread group.  Fixed tiles run on the specified tile with high
       scheduler priority.  Tile 0's stack is the default stack used by
       the job launcher.  Floating tiles use the default stack provided
       by pthread_create.  All other tiles (i.e. high performance fixed
       tiles) use an 8 MiB huge page backed numa optimized stack (if
       possible).

       The booter will become tile 0.  The non-floating cpus in the list
       must be unique (e.g. multiple non-floating tiles cannot be
       assigned to the same cpu) and ranges in the list ("x-y") must be
       non-empty (i.e. x<=y).  If --tile-cpus is not provided, this
       thread group will be assumed to be single threaded and the cpu
       will be whatever the OS assigned to the booter (equivalent to
       "--tile-cpus f").

       Strides for a range of cores can be specified with a '/' or
       (taskset style) with a ':'.

       If tile 0 is not a floating tile, recommend using
       "taskset -c [cpu for tile 0]" or equivalent at thread group launch
       to have the OS place the booter on the correct cpu from the start. */

void
at_boot( int *    pargc,
         char *** pargv );

void
at_halt( void );

#if AT_HAS_HOSTED

/* Depending on the glibc version, the "poll" library function either calls
   "poll" or "ppoll".  at_syscall_poll standardizes this behaviour by always
   calling "ppoll" under the hood on Linux systems (and falls back on "poll"
   otherwise).  Since the Reference sandbox needs to whitelist syscalls and
   "poll" is not available on arm64 architecture, using this function also
   lets us use the same seccomp policy for allowing syscalls.

   The arguments to at_syscall_poll match the arguments to "poll".  The return
   value matches the return of "poll" (and "ppoll").  On error (return -1),
   "errno" is set to indicate the error. */

struct pollfd;

int
at_syscall_poll( struct pollfd * fds,
                 uint            nfds,
                 int             timeout );

#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_at_util_h */