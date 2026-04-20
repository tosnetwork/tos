#ifndef HEADER_at_p2p_at_object_tracker_h
#define HEADER_at_p2p_at_object_tracker_h

/* at_object_tracker.h - Simplified object request tracker

   Provides a lightweight queue with timeout and deduplication,
   inspired by tos/daemon/src/p2p/tracker/mod.rs. */

#include "at/infra/at_util_base.h"
#include <limits.h>

AT_PROTOTYPES_BEGIN

/* Maximum number of tracked objects */
#define AT_OBJECT_TRACKER_MAX (1024UL)
/* Maximum number of cached (ignored) objects */
#define AT_OBJECT_TRACKER_CACHE_MAX (1024UL)
/* No-group sentinel */
#define AT_OBJECT_TRACKER_GROUP_NONE (ULONG_MAX)

typedef struct {
  uchar hash[32];
  uchar obj_type;
  uchar _pad[3];
  uint  peer_idx;
  ulong first_request;
  ulong last_request;
  uint  request_cnt;
  uint  inflight;
  ulong requested_at;
  ulong seq;
  ulong group_id;
} at_object_tracker_entry_t;

typedef struct {
  uchar hash[32];
  ulong stored_at;
} at_object_tracker_cache_entry_t;

typedef struct {
  at_object_tracker_entry_t entries[AT_OBJECT_TRACKER_MAX];
  ulong entry_cnt;
  ulong inflight_cnt;
  ulong next_seq;
  ulong timeout_ns;
  ulong retry_interval_ns;
  uint  max_retry_cnt;
  at_object_tracker_cache_entry_t cache[AT_OBJECT_TRACKER_CACHE_MAX];
  ulong cache_cnt;
  ulong cache_ttl_ns;
} at_object_tracker_t;

void
at_object_tracker_init( at_object_tracker_t * tracker,
                        ulong                timeout_ns,
                        ulong                retry_interval_ns,
                        uint                 max_retry_cnt );

int
at_object_tracker_add( at_object_tracker_t * tracker,
                       uchar const          hash[32],
                       uchar                obj_type,
                       ulong                now );

int
at_object_tracker_add_with_group( at_object_tracker_t * tracker,
                                  uchar const          hash[32],
                                  uchar                obj_type,
                                  ulong                group_id,
                                  ulong                now );

int
at_object_tracker_on_response( at_object_tracker_t * tracker,
                               uchar const          hash[32] );

int
at_object_tracker_timeout_sweep( at_object_tracker_t * tracker,
                                 ulong                now );

at_object_tracker_entry_t *
at_object_tracker_next_ready( at_object_tracker_t * tracker,
                              ulong                now );

int
at_object_tracker_mark_sent( at_object_tracker_t * tracker,
                             uchar const          hash[32],
                             uint                 peer_idx,
                             ulong                now );

int
at_object_tracker_clear_inflight( at_object_tracker_t * tracker,
                                  uchar const          hash[32] );

int
at_object_tracker_is_tracked( at_object_tracker_t const * tracker,
                              uchar const                hash[32],
                              uchar                      obj_type );

void
at_object_tracker_mark_group_failed( at_object_tracker_t * tracker,
                                     ulong                group_id,
                                     ulong                now );

void
at_object_tracker_cache_add( at_object_tracker_t * tracker,
                             uchar const          hash[32],
                             ulong                now );

int
at_object_tracker_cache_has( at_object_tracker_t * tracker,
                             uchar const          hash[32],
                             ulong                now );

static inline ulong
at_object_tracker_inflight_cnt( at_object_tracker_t const * tracker ) {
  return tracker ? tracker->inflight_cnt : 0UL;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_p2p_at_object_tracker_h */
