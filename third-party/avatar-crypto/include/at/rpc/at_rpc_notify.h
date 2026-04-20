#ifndef HEADER_at_rpc_notify_h
#define HEADER_at_rpc_notify_h

/* at_rpc_notify.h - WebSocket subscription and notification system

   This module provides real-time event notifications to WebSocket clients.
   Clients can subscribe to specific event types and receive JSON-RPC
   notifications when those events occur.

   Usage:
   1. Initialize with at_rpc_notify_init() when starting the RPC server
   2. Call at_rpc_notify_ws_open/close from WebSocket callbacks
   3. Handle subscribe/unsubscribe RPC requests
   4. Call at_rpc_notify_event() when events occur
   5. Cleanup with at_rpc_notify_fini() on shutdown

   Thread safety: Single-threaded, must be called from RPC tile only. */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Forward declaration */
struct at_http_server_private;
typedef struct at_http_server_private at_http_server_t;

/* ============================================================================
   Event Types (21 types)
   ============================================================================ */

typedef enum {
  AT_RPC_NOTIFY_NEW_BLOCK = 0,
  AT_RPC_NOTIFY_BLOCK_ORDERED,
  AT_RPC_NOTIFY_BLOCK_ORPHANED,
  AT_RPC_NOTIFY_STABLE_HEIGHT_CHANGED,
  AT_RPC_NOTIFY_STABLE_TOPOHEIGHT_CHANGED,
  AT_RPC_NOTIFY_TRANSACTION_ORPHANED,
  AT_RPC_NOTIFY_TRANSACTION_ADDED_IN_MEMPOOL,
  AT_RPC_NOTIFY_TRANSACTION_EXECUTED,
  AT_RPC_NOTIFY_ESCROW_AUTO_RELEASED,
  AT_RPC_NOTIFY_INVOKE_CONTRACT,
  AT_RPC_NOTIFY_CONTRACT_TRANSFER,
  AT_RPC_NOTIFY_CONTRACT_EVENT,
  AT_RPC_NOTIFY_DEPLOY_CONTRACT,
  AT_RPC_NOTIFY_NEW_ASSET,
  AT_RPC_NOTIFY_PEER_CONNECTED,
  AT_RPC_NOTIFY_PEER_DISCONNECTED,
  AT_RPC_NOTIFY_PEER_PEERLIST_UPDATED,
  AT_RPC_NOTIFY_PEER_STATE_UPDATED,
  AT_RPC_NOTIFY_PEER_PEER_DISCONNECTED,
  AT_RPC_NOTIFY_NEW_BLOCK_TEMPLATE,
  AT_RPC_NOTIFY_SCHEDULED_EXECUTION_EXECUTED
} at_rpc_notify_event_type_t;

/* Event payload structure */
typedef struct {
  at_rpc_notify_event_type_t type;
  uchar data[32];   /* Primary data: contract/hash/address */
  uchar data2[32];  /* Secondary data: address or hash */
  ulong id;         /* Event sequence ID */
} at_rpc_notify_event_t;

/* ============================================================================
   Initialization
   ============================================================================ */

/* Initialize the notification system. Must be called before any other
   functions. http is the HTTP server instance to use for sending
   WebSocket messages. */
void
at_rpc_notify_init( at_http_server_t * http );

/* Cleanup the notification system. Call on shutdown. */
void
at_rpc_notify_fini( void );

/* ============================================================================
   WebSocket Connection Management
   ============================================================================ */

/* Called when a WebSocket connection is opened. Registers the connection
   for potential subscriptions. */
void
at_rpc_notify_ws_open( ulong ws_conn_id );

/* Called when a WebSocket connection is closed. Removes all subscriptions
   for this connection. */
void
at_rpc_notify_ws_close( ulong ws_conn_id );

/* ============================================================================
   Subscription Management
   ============================================================================ */

/* Subscribe a WebSocket connection to an event type.
   filter_addr and filter_contract are optional (can be NULL) and filter
   events to only those matching the specified address or contract.
   Returns 0 on success, -1 on error. */
int
at_rpc_notify_subscribe( ulong                      ws_conn_id,
                         at_rpc_notify_event_type_t event_type,
                         uchar const *              filter_addr,     /* Optional, 32 bytes */
                         uchar const *              filter_contract  /* Optional, 32 bytes */ );

/* Unsubscribe a WebSocket connection from an event type.
   Returns 0 on success, -1 on error. */
int
at_rpc_notify_unsubscribe( ulong                      ws_conn_id,
                           at_rpc_notify_event_type_t event_type );

/* Unsubscribe a WebSocket connection from all event types.
   Returns 0 on success, -1 on error. */
int
at_rpc_notify_unsubscribe_all( ulong ws_conn_id );

/* ============================================================================
   Event Notification
   ============================================================================ */

/* Check if any WebSocket session is tracking the given event type.
   This is a fast check that can be used to skip expensive event
   serialization when no clients are interested.
   Returns non-zero if at least one client is subscribed. */
int
at_rpc_is_event_tracked( at_rpc_notify_event_t const * event );

/* Notify subscribed WebSocket sessions of an event.
   value_json is the JSON representation of the event payload.
   Returns the number of clients notified, or -1 on error. */
int
at_rpc_notify_event( at_rpc_notify_event_t const * event,
                     char const *                  value_json,
                     ulong                         value_json_len );

/* ============================================================================
   Event Type Utilities
   ============================================================================ */

/* Convert event type to string name.
   Returns a static string (do not free). */
char const *
at_rpc_notify_event_type_str( at_rpc_notify_event_type_t type );

/* Parse event type from string name.
   Returns the event type, or (at_rpc_notify_event_type_t)-1 if not found. */
at_rpc_notify_event_type_t
at_rpc_notify_event_type_from_str( char const * str, ulong str_len );

/* ============================================================================
   Statistics
   ============================================================================ */

/* Get the number of WebSocket connections with active subscriptions. */
ulong
at_rpc_notify_connection_count( void );

/* Get the number of subscriptions for a specific event type. */
ulong
at_rpc_notify_subscription_count( at_rpc_notify_event_type_t event_type );

AT_PROTOTYPES_END

#endif /* HEADER_at_rpc_notify_h */
