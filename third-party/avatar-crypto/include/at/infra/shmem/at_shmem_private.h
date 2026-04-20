#ifndef HEADER_at_src_util_shmem_at_shmem_private_h
#define HEADER_at_src_util_shmem_at_shmem_private_h

#include "at_shmem.h"

#if AT_HAS_THREADS
#include <pthread.h>
#endif

/* Want at_strlen(base)+at_strlen("/.")+at_strlen(page)+at_strlen("/")+at_strlen(name)+1 <= BUF_MAX
     -> BASE_MAX-1  +2           +PAGE_MAX-1  +1          +NAME_MAX-1  +1 == BUF_MAX
     -> BASE_MAX == BUF_MAX - NAME_MAX - PAGE_MAX - 1 */

#define AT_SHMEM_PRIVATE_PATH_BUF_MAX (256UL)
#define AT_SHMEM_PRIVATE_BASE_MAX     (AT_SHMEM_PRIVATE_PATH_BUF_MAX-AT_SHMEM_NAME_MAX-AT_SHMEM_PAGE_SZ_CSTR_MAX-1UL)

#if AT_HAS_THREADS
#define AT_SHMEM_LOCK   pthread_mutex_lock(   at_shmem_private_lock )
#define AT_SHMEM_UNLOCK pthread_mutex_unlock( at_shmem_private_lock )
#else
#define AT_SHMEM_LOCK   ((void)0)
#define AT_SHMEM_UNLOCK ((void)0)
#endif

AT_PROTOTYPES_BEGIN

/* NUMA backend ******************************************************/

/* at_numa_node_cnt / at_numa_cpu_cnt determines the current number of
   configured numa nodes / cpus (roughly equivalent to libnuma's
   numa_num_configured_nodes / numa_num_configured_cpus).  Returns 0 if
   this could not be determined (logs details on failure).  These
   function are only used during shmem initialization as part of
   topology discovery so should not do any fancy caching under the hood. */

ulong
at_numa_node_cnt( void );

ulong
at_numa_cpu_cnt( void );

/* at_numa_node_idx determines the numa node closest to the given
   cpu_idx (roughly equivalent to libnuma's numa_node_of_cpu).  Returns
   ULONG_MAX if this could not be determined (logs details on failure).
   This function is only used during shmem initialization as part of
   topology discovery so should not do any fancy caching under the hood. */

ulong
at_numa_node_idx( ulong cpu_idx );

/* FIXME: probably should clean up the below APIs to get something
   that allows for cleaner integration with at_shmem_admin.c (e.g. if we
   are going to replace libnuma calls with our own, no reason to use the
   historical clunky APIs). */

/* at_numa_mlock locks the memory region to reside at a stable position
   in physical DRAM.  Wraps the `mlock(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/mlock.2.html */

int
at_numa_mlock( void const * addr,
               ulong        len );

/* at_numa_mlock unlocks the memory region.  Wraps the `munlock(2)`
   Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/munlock.2.html */

int
at_numa_munlock( void const * addr,
                 ulong        len );

/* at_numa_get_mempolicy retrieves the NUMA memory policy of the
   current thread.  Wraps the `get_mempolicy(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/get_mempolicy.2.html */

long
at_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags );

/* at_numa_set_mempolicy sets the default NUMA memory policy of the
   current thread and its children.  Wraps the `set_mempolicy(2)` Linux
   syscall.  See:

     https://man7.org/linux/man-pages/man2/set_mempolicy.2.html */

long
at_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode );

/* at_numa_mbind sets the NUMA memory policy for a range of memory.
   Wraps the `mbind(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/mbind.2.html */

long
at_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags );

/* at_numa_move_page moves pages of a process to another node.  Wraps
   the `move_pages(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/move_pages.2.html

   Also useful to detect the true NUMA node ownership of pages of memory
   after calls to `mlock(2)` and `mbind(2)`. */

long
at_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags );

/**********************************************************************/

#if AT_HAS_THREADS
extern pthread_mutex_t at_shmem_private_lock[1];
#endif

extern char  at_shmem_private_base[ AT_SHMEM_PRIVATE_BASE_MAX ]; /* ""  at thread group start, initialized at boot */
extern ulong at_shmem_private_base_len;                          /* 0UL at ",                  initialized at boot */

static inline char *                         /* ==buf always */
at_shmem_private_path( char const * name,    /* Valid name */
                       ulong        page_sz, /* Valid page size (normal, huge, gigantic) */
                       char *       buf ) {  /* Non-NULL with AT_SHMEM_PRIVATE_PATH_BUF_MAX bytes */
  return at_cstr_printf( buf, AT_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s/%s",
                         at_shmem_private_base, at_shmem_page_sz_to_cstr( page_sz ), name );
}

/* at_shmem_private_map_rand maps a private+anonymous pages of default
   page size at a random virtual address.  align specifies the minimum
   alignment of the first byte to map.  size is the minimum number of
   bytes to map.  Returns a virtual address on success, and MAP_FAILED
   on failure. */

void *
at_shmem_private_map_rand( ulong size,
                           ulong align,
                           int   prot );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_shmem_at_shmem_private_h */