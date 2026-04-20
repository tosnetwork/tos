#ifndef HEADER_at_rocks_at_rocks_events_h
#define HEADER_at_rocks_at_rocks_events_h

/* at_rocks_events.h - Event logging for at_rocks

   Provides event storage and indexing for EVM LOG0-LOG4 opcodes.

   Events are indexed by:
   - Contract address + topoheight + log_index (primary)
   - Transaction hash + log_index
   - Contract address + topic0 + topoheight + log_index

   log_index is GLOBAL per topoheight (block-level unique), not per-transaction.
   This matches Ethereum's log indexing where indices are unique within a block.

   Usage:
     at_event_t event = {
       .topoheight = current_topo,
       .tx_index = 0,
       .log_index = 0,
       .topic_count = 2,
       .data = event_data,
       .data_sz = event_data_sz,
     };
     at_memcpy( event.address, contract_addr, 32 );
     at_memcpy( event.tx_hash, tx_hash, 32 );
     at_memcpy( event.topics[0], topic0, 32 );
     at_memcpy( event.topics[1], topic1, 32 );
     at_rocks_event_store( db, &event );

     // Query events
     at_event_t * events;
     ulong count;
     at_rocks_events_by_topo( db, start_topo, end_topo, &events, &count );
     // ... use events ...
     at_rocks_events_free( events, count );
*/

#include "at_rocks.h"

AT_PROTOTYPES_BEGIN

/* Maximum number of topics per event (LOG0-LOG4) */
#define AT_EVENT_MAX_TOPICS 4

/* Event structure (EVM LOG0-LOG4) */
typedef struct at_event {
  uchar  address[32];              /* Contract that emitted the event */
  uchar  tx_hash[32];              /* Transaction hash */
  ulong  topoheight;               /* Block topoheight */
  uint   tx_index;                 /* Transaction index in block */
  uint   log_index;                /* Log index (global within block) */
  uint   topic_count;              /* 0-4 topics */
  uchar  topics[AT_EVENT_MAX_TOPICS][32]; /* LOG topics */
  uchar * data;                    /* Event data (variable length) */
  ulong  data_sz;                  /* Size of event data */
} at_event_t;

/* Query filter for event searches */
typedef struct at_event_filter {
  uchar const * address;           /* Filter by contract (NULL = any) */
  uchar const * topic0;            /* Filter by topic0 (NULL = any) */
  uchar const * topic1;            /* Filter by topic1 (NULL = any) */
  uchar const * topic2;            /* Filter by topic2 (NULL = any) */
  uchar const * topic3;            /* Filter by topic3 (NULL = any) */
  ulong topo_start;                /* Start topoheight (inclusive) */
  ulong topo_end;                  /* End topoheight (inclusive) */
  ulong max_results;               /* Maximum results to return (0 = unlimited) */
} at_event_filter_t;

/* ============================================================================
   Event Storage
   ============================================================================ */

/* at_rocks_event_store stores an event with all indices.
   The event struct is copied; data is also copied.
   Returns AT_ROCKS_OK on success. */
int
at_rocks_event_store( at_rocks_t * db, at_event_t const * event );

/* at_rocks_event_store_batch stores an event using a batch.
   Use for atomic storage of multiple events in a transaction. */
int
at_rocks_event_store_batch( at_rocks_batch_t * batch, at_event_t const * event );

/* ============================================================================
   Event Queries
   ============================================================================ */

/* at_rocks_events_by_topo queries events by topoheight range.
   Returns all events in [topo_start, topo_end] inclusive.
   Caller must call at_rocks_events_free() on result. */
int
at_rocks_events_by_topo( at_rocks_t * db,
                          ulong topo_start,
                          ulong topo_end,
                          at_event_t ** events_out,
                          ulong * count_out );

/* at_rocks_events_by_tx queries events by transaction hash.
   Returns all events for the given transaction.
   Caller must call at_rocks_events_free() on result. */
int
at_rocks_events_by_tx( at_rocks_t * db,
                        uchar const tx_hash[32],
                        at_event_t ** events_out,
                        ulong * count_out );

/* at_rocks_events_by_topic queries events by contract and topic0.
   Optimized query for eth_getLogs by event signature.
   Caller must call at_rocks_events_free() on result. */
int
at_rocks_events_by_topic( at_rocks_t * db,
                           uchar const contract[32],
                           uchar const topic0[32],
                           ulong topo_start,
                           ulong topo_end,
                           at_event_t ** events_out,
                           ulong * count_out );

/* at_rocks_events_by_contract queries events by contract address.
   Returns all events for a contract in the given topo range.
   Caller must call at_rocks_events_free() on result. */
int
at_rocks_events_by_contract( at_rocks_t * db,
                              uchar const contract[32],
                              ulong topo_start,
                              ulong topo_end,
                              at_event_t ** events_out,
                              ulong * count_out );

/* at_rocks_events_filter queries events with arbitrary filters.
   Supports filtering by multiple topics.
   Caller must call at_rocks_events_free() on result. */
int
at_rocks_events_filter( at_rocks_t * db,
                         at_event_filter_t const * filter,
                         at_event_t ** events_out,
                         ulong * count_out );

/* at_rocks_events_free frees an events array returned by query functions. */
void
at_rocks_events_free( at_event_t * events, ulong count );

/* ============================================================================
   Event Count and Existence
   ============================================================================ */

/* at_rocks_events_count_by_topo counts events in a topoheight range.
   More efficient than query when only count is needed. */
int
at_rocks_events_count_by_topo( at_rocks_t * db,
                                ulong topo_start,
                                ulong topo_end,
                                ulong * count_out );

/* at_rocks_events_count_by_tx counts events for a transaction. */
int
at_rocks_events_count_by_tx( at_rocks_t * db,
                              uchar const tx_hash[32],
                              ulong * count_out );

/* ============================================================================
   Event Iterator
   ============================================================================ */

typedef struct at_rocks_event_iter at_rocks_event_iter_t;

/* at_rocks_event_iter_new creates an iterator over events.
   Iterates events in (topo_start, topo_end] for the given contract.
   If contract is NULL, iterates all events. */
at_rocks_event_iter_t *
at_rocks_event_iter_new( at_rocks_t * db,
                          uchar const * contract,
                          ulong topo_start,
                          ulong topo_end );

/* at_rocks_event_iter_valid returns 1 if at a valid position. */
int
at_rocks_event_iter_valid( at_rocks_event_iter_t * iter );

/* at_rocks_event_iter_next advances to the next event. */
void
at_rocks_event_iter_next( at_rocks_event_iter_t * iter );

/* at_rocks_event_iter_get copies the current event.
   Caller owns the event and must free event->data. */
int
at_rocks_event_iter_get( at_rocks_event_iter_t * iter, at_event_t * event_out );

/* at_rocks_event_iter_destroy destroys the iterator. */
void
at_rocks_event_iter_destroy( at_rocks_event_iter_t * iter );

/* ============================================================================
   Log Index Management
   ============================================================================ */

/* at_rocks_events_get_next_log_index returns the next log index for a topoheight.
   Use this to assign log_index when storing events. */
uint
at_rocks_events_get_next_log_index( at_rocks_t * db, ulong topoheight );

/* at_rocks_events_reset_log_index resets the log index counter for a topoheight.
   Use when reprocessing a block. */
int
at_rocks_events_reset_log_index( at_rocks_t * db, ulong topoheight );

AT_PROTOTYPES_END

#endif /* HEADER_at_rocks_at_rocks_events_h */