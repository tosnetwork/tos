/* at_metrics.h - Avatar Metrics System

   Provides shared memory metrics for monitoring tile performance.

   The metrics system allows tiles to publish performance counters
   that can be read by external monitoring tools.

   Layout in shared memory:
     [ in_link_cnt (ulong) ]
     [ out_link_cnt (ulong) ]
     [ in_link_0_metrics ... in_link_N_metrics ]
     [ out_link_0_metrics ... out_link_N_metrics ]
     [ tile_metrics ]
*/

#ifndef HEADER_at_disco_at_metrics_h
#define HEADER_at_disco_at_metrics_h

#include "at/infra/at_util_base.h"
#include "at/infra/ipc/at_tempo.h"

AT_PROTOTYPES_BEGIN

/* Metrics type constants */
#define AT_METRICS_TYPE_GAUGE     (0UL)
#define AT_METRICS_TYPE_COUNTER   (1UL)
#define AT_METRICS_TYPE_HISTOGRAM (2UL)

/* Link metrics offsets - these are the standard metrics for each link */
#define AT_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF              (0UL)
#define AT_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF         (1UL)
#define AT_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF              (2UL)
#define AT_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_OFF         (3UL)
#define AT_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF       (4UL)
#define AT_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF  (5UL)
#define AT_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF       (6UL)
#define AT_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF  (7UL)

/* Total metrics per input link */
#define AT_METRICS_ALL_LINK_IN_TOTAL (8UL)

/* Output link metrics */
#define AT_METRICS_COUNTER_LINK_SLOW_COUNT_OFF (0UL)

/* Total metrics per output link (reliable consumer) */
#define AT_METRICS_ALL_LINK_OUT_TOTAL (1UL)

/* Tile regime count for metrics */
#define AT_METRICS_ENUM_TILE_REGIME_CNT (8UL)

/* Tile-specific gauge metrics.
   These offsets are relative to the tile metrics area returned by at_metrics_tile(). */
#define AT_METRICS_GAUGE_TILE_REGIME_OFF          (0UL)
#define AT_METRICS_GAUGE_TILE_STATUS_OFF          (1UL)
#define AT_METRICS_GAUGE_TILE_PID_OFF             (2UL)
#define AT_METRICS_GAUGE_TILE_HEARTBEAT_OFF       (8UL)  /* Tile heartbeat offset */
#define AT_METRICS_GAUGE_TILE_IN_BACKP_OFF        (9UL)
#define AT_METRICS_GAUGE_TILE_OUT_BACKP_OFF       (10UL)

/* Total tile gauge metrics */
#define AT_METRICS_GAUGE_TILE_TOTAL (16UL)

/* Total tile counter metrics */
#define AT_METRICS_COUNTER_TILE_TOTAL (AT_METRICS_ENUM_TILE_REGIME_CNT)

/* Total tile metrics (gauges + counters) */
#define AT_METRICS_TILE_TOTAL (AT_METRICS_GAUGE_TILE_TOTAL + AT_METRICS_COUNTER_TILE_TOTAL)

/* Extra experimental tile-local counter slots for tile-specific metrics.
   Keep generic macro usage intact while exposing targeted observability. */
#define AT_METRICS_BANK_METADATA_PERSIST_FAIL_OFF (AT_METRICS_TILE_TOTAL + 0UL)

/* Netlink tile-specific gauge metrics
   Used by netlink tile for monitoring network interface state */
#define AT_METRICS_GAUGE_NETLNK_INTERFACE_COUNT_OFF      (0UL)
#define AT_METRICS_GAUGE_NETLNK_ROUTE_COUNT_LOCAL_OFF    (1UL)
#define AT_METRICS_GAUGE_NETLNK_ROUTE_COUNT_MAIN_OFF     (2UL)

/* NET/XDP tile-specific gauge metrics
   Used by XDP tile for tracking RX/TX busy/idle cycles */
#define AT_METRICS_GAUGE_NET_RX_BUSY_CNT_OFF  (0UL)
#define AT_METRICS_GAUGE_NET_RX_IDLE_CNT_OFF  (1UL)
#define AT_METRICS_GAUGE_NET_TX_BUSY_CNT_OFF  (2UL)
#define AT_METRICS_GAUGE_NET_TX_IDLE_CNT_OFF  (3UL)

/* Total tile-specific metrics size (placeholder - expand as needed) */
#define AT_METRICS_TOTAL_SZ (256UL * sizeof(ulong))

/* Metrics alignment */
#define AT_METRICS_ALIGN (128UL)

/* Calculate footprint for metrics region */
#define AT_METRICS_FOOTPRINT(in_link_cnt, out_link_reliable_consumer_cnt)                                 \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND ( AT_LAYOUT_APPEND ( AT_LAYOUT_INIT, \
    8UL, 16UL ),                                                                                            \
    8UL, (in_link_cnt)*AT_METRICS_ALL_LINK_IN_TOTAL*sizeof(ulong) ),                                        \
    8UL, (out_link_reliable_consumer_cnt)*AT_METRICS_ALL_LINK_OUT_TOTAL*sizeof(ulong) ),                    \
    8UL, AT_METRICS_TOTAL_SZ ),                                                                             \
    AT_METRICS_ALIGN )

/* Thread local metrics pointers */
extern AT_TL ulong * at_metrics_base_tl;
extern AT_TL volatile ulong * at_metrics_tl;

/* at_metrics_tile returns a pointer to the tile-specific metrics area
   for the given metrics object. */
static inline volatile ulong *
at_metrics_tile( ulong * metrics ) {
  return metrics + 2UL + AT_METRICS_ALL_LINK_IN_TOTAL*metrics[ 0 ] + AT_METRICS_ALL_LINK_OUT_TOTAL*metrics[ 1 ];
}

/* at_metrics_link_in returns a pointer the in-link metrics area for the
   given in link index of this metrics object. */
static inline volatile ulong *
at_metrics_link_in( ulong * metrics, ulong in_idx ) {
  if( AT_UNLIKELY( !metrics ) ) {
    static ulong dummy[AT_METRICS_ALL_LINK_IN_TOTAL];
    return dummy;
  }
  return metrics + 2UL + AT_METRICS_ALL_LINK_IN_TOTAL*in_idx;
}

/* at_metrics_link_out returns a pointer the out-link metrics area for the
   given out link index of this metrics object. */
static inline volatile ulong *
at_metrics_link_out( ulong * metrics, ulong out_idx ) {
  if( AT_UNLIKELY( !metrics ) ) {
    static ulong dummy[AT_METRICS_ALL_LINK_OUT_TOTAL];
    return dummy;
  }
  return metrics + 2UL + AT_METRICS_ALL_LINK_IN_TOTAL*metrics[0] + AT_METRICS_ALL_LINK_OUT_TOTAL*out_idx;
}

/* at_metrics_new formats an unused memory region for use as metrics.
   All metrics will be initialized to zero. */
static inline void *
at_metrics_new( void * shmem,
                ulong  in_link_cnt,
                ulong  out_link_consumer_cnt ) {
  if( AT_UNLIKELY( !shmem ) ) return NULL;
  at_memset( shmem, 0, AT_METRICS_FOOTPRINT(in_link_cnt, out_link_consumer_cnt) );
  ulong * metrics = shmem;
  metrics[0] = in_link_cnt;
  metrics[1] = out_link_consumer_cnt;
  return shmem;
}

/* at_metrics_register sets the thread local values used by the macros
   like AT_MCNT_SET to point to the provided metrics object. */
static inline ulong *
at_metrics_register( ulong * metrics ) {
  if( AT_UNLIKELY( !metrics ) ) {
    AT_LOG_WARNING(( "at_metrics_register: NULL metrics" ));
    return NULL;
  }

  at_metrics_base_tl = metrics;
  at_metrics_tl = at_metrics_tile( metrics );
  return metrics;
}

static inline ulong * at_metrics_join  ( void * mem ) { return mem; }
static inline void *  at_metrics_leave ( void * mem ) { return (void *)mem; }
static inline void *  at_metrics_delete( void * mem ) { return (void *)mem; }

/* Conversion helpers for histogram metrics */
static inline ulong
at_metrics_convert_seconds_to_ticks( double seconds ) {
  double tick_per_ns = at_tempo_tick_per_ns( NULL );
  return (ulong)(seconds * tick_per_ns * 1e9);
}

static inline double
at_metrics_convert_ticks_to_seconds( ulong ticks ) {
  double tick_per_ns = at_tempo_tick_per_ns( NULL );
  return (double)ticks / (tick_per_ns * 1e9);
}

static inline ulong
at_metrics_convert_ticks_to_nanoseconds( ulong ticks ) {
  double tick_per_ns = at_tempo_tick_per_ns( NULL );
  return (ulong)((double)ticks / tick_per_ns);
}

AT_PROTOTYPES_END

/* Metric update macros - these compile to single writes to shared memory */

#define AT_MGAUGE_SET( group, name, val ) do {                                              \
    if( AT_LIKELY( at_metrics_tl ) ) {                                                      \
      at_metrics_tl[ AT_METRICS_GAUGE_##group##_##name##_OFF ] = (ulong)(val);             \
    }                                                                                       \
  } while(0)

#define AT_MCNT_INC( group, name, val ) do {                         \
    if( AT_LIKELY( at_metrics_tl ) ) {                               \
      /* TODO: Use proper offset when metrics are fully defined */   \
      (void)(val);                                                   \
    }                                                                \
  } while(0)

#define AT_MCNT_SET( group, name, val ) do {                         \
    if( AT_LIKELY( at_metrics_tl ) ) {                               \
      /* TODO: Use proper offset when metrics are fully defined */   \
      (void)(val);                                                   \
    }                                                                \
  } while(0)

#define AT_MCNT_ENUM_COPY( group, name, arr ) do {                   \
    if( AT_LIKELY( at_metrics_tl ) ) {                               \
      /* TODO: Use proper offset when metrics are fully defined */   \
      (void)(arr);                                                   \
    }                                                                \
  } while(0)

#endif /* HEADER_at_disco_at_metrics_h */
