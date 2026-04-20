/* at_linux_bpf.h - BPF syscall wrappers */

#ifndef HEADER_at_p2p_ebpf_at_linux_bpf_h
#define HEADER_at_p2p_ebpf_at_linux_bpf_h

#include "at/infra/at_util_base.h"

#if defined(__linux__)

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

/* bpf Linux syscall wrapper */

static inline long
at_bpf( int              cmd,
        union bpf_attr * attr,
        ulong            attr_sz ) {
  return syscall( SYS_bpf, cmd, attr, attr_sz );
}

/* at_bpf_map_get_next_key wraps bpf(2) op BPF_MAP_GET_NEXT_KEY.
   Returns 0 on success and -1 on failure (sets errno).
   Sets errno to ENOENT if given key is last in map. */

static inline int
at_bpf_map_get_next_key( int          map_fd,
                         void const * key,
                         void       * next_key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .next_key = (ulong)next_key
  };
  return (int)at_bpf( BPF_MAP_GET_NEXT_KEY, &attr, sizeof(union bpf_attr) );
}

/* at_bpf_map_update_elem wraps bpf(2) op BPF_MAP_UPDATE_ELEM.
   Creates or updates an entry in a BPF map.
   Returns 0 on success and -1 on failure. */

static inline int
at_bpf_map_update_elem( int          map_fd,
                        void const * key,
                        void const * value,
                        ulong        flags ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .value    = (ulong)value,
    .flags    = flags
  };
  return (int)at_bpf( BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr) );
}

/* at_bpf_map_delete_elem wraps bpf(2) op BPF_MAP_DELETE_ELEM.
   Returns 0 on success and -1 on failure. */

static inline int
at_bpf_map_delete_elem( int          map_fd,
                        void const * key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key
  };
  return (int)at_bpf( BPF_MAP_DELETE_ELEM, &attr, sizeof(union bpf_attr) );
}

/* at_bpf_obj_get wraps bpf(2) op BPF_OBJ_GET.
   Opens a BPF map at given filesystem path.
   Returns fd number on success and negative integer on failure. */

static inline int
at_bpf_obj_get( char const * pathname ) {
  union bpf_attr attr = {
    .pathname = (ulong)pathname
  };
  return (int)at_bpf( BPF_OBJ_GET, &attr, sizeof(union bpf_attr) );
}

/* at_bpf_obj_pin wraps bpf(2) op BPF_OBJ_PIN.
   Pins a bpf syscall API object at given filesystem path.
   Returns 0 on success and -1 on failure. */

static inline int
at_bpf_obj_pin( int          bpf_fd,
                char const * pathname ) {
  union bpf_attr attr = {
    .bpf_fd   = (uint)bpf_fd,
    .pathname = (ulong)pathname
  };
  return (int)at_bpf( BPF_OBJ_PIN, &attr, sizeof(union bpf_attr) );
}

#endif /* defined(__linux__) */

#endif /* HEADER_at_p2p_ebpf_at_linux_bpf_h */
