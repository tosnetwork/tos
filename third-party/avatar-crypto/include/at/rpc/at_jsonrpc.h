#ifndef HEADER_at_src_waltz_http_at_jsonrpc_h
#define HEADER_at_src_waltz_http_at_jsonrpc_h

/* at_jsonrpc.h provides a JSON-RPC 2.0 framework for Avatar RPC.

   JSON-RPC 2.0 Specification: https://www.jsonrpc.org/specification

   Request format:
   {
     "jsonrpc": "2.0",
     "method": "methodName",
     "params": [...],  // or {...}
     "id": 1
   }

   Response format (success):
   {
     "jsonrpc": "2.0",
     "result": {...},
     "id": 1
   }

   Response format (error):
   {
     "jsonrpc": "2.0",
     "error": {
       "code": -32600,
       "message": "Invalid Request"
     },
     "id": null
   }
*/

#include "at/infra/at_util_base.h"

/* JSON-RPC 2.0 standard error codes */
#define AT_JSONRPC_PARSE_ERROR      (-32700)  /* Invalid JSON */
#define AT_JSONRPC_INVALID_REQUEST  (-32600)  /* Not a valid Request object */
#define AT_JSONRPC_METHOD_NOT_FOUND (-32601)  /* Method does not exist */
#define AT_JSONRPC_INVALID_PARAMS   (-32602)  /* Invalid method parameters */
#define AT_JSONRPC_INTERNAL_ERROR   (-32603)  /* Internal error */

/* Server-defined error codes (reserved range: -32000 to -32099) */
#define AT_JSONRPC_SERVER_ERROR_MIN     (-32099)
#define AT_JSONRPC_SERVER_ERROR_MAX     (-32000)

/* TOS-compatible error codes */
#define AT_RPC_ERR_BLOCK_NOT_AVAILABLE     (-32001)
#define AT_RPC_ERR_BLOCK_CLEANED           (-32002)
#define AT_RPC_ERR_SLOT_SKIPPED            (-32003)
#define AT_RPC_ERR_NO_SNAPSHOT             (-32004)
#define AT_RPC_ERR_LONG_TERM_STORAGE       (-32005)
#define AT_RPC_ERR_KEY_EXCLUDED            (-32006)
#define AT_RPC_ERR_TX_PRECOMPILE_FAIL      (-32007)
#define AT_RPC_ERR_NODE_UNHEALTHY          (-32008)
#define AT_RPC_ERR_TX_SIG_VERIFY_FAIL      (-32009)
#define AT_RPC_ERR_BLOCK_STATUS_NOT_YET    (-32010)
#define AT_RPC_ERR_UNSUPPORTED_TX_VERSION  (-32011)
#define AT_RPC_ERR_MIN_CONTEXT_SLOT        (-32012)

/* JSON value types */
#define AT_JSON_NULL    0
#define AT_JSON_BOOL    1
#define AT_JSON_NUMBER  2
#define AT_JSON_STRING  3
#define AT_JSON_ARRAY   4
#define AT_JSON_OBJECT  5

/* Forward declarations */
struct at_json_value;
typedef struct at_json_value at_json_value_t;

/* JSON value structure (simple DOM representation) */
struct at_json_value {
  int type;                    /* AT_JSON_* */
  union {
    int    bool_val;           /* AT_JSON_BOOL */
    double number_val;         /* AT_JSON_NUMBER */
    struct {
      char const * str;
      ulong        len;
    } string_val;              /* AT_JSON_STRING */
    struct {
      at_json_value_t * items;
      ulong             cnt;
    } array_val;               /* AT_JSON_ARRAY */
    struct {
      char const **       keys;
      ulong *             key_lens;
      at_json_value_t *   values;
      ulong               cnt;
    } object_val;              /* AT_JSON_OBJECT */
  };
};

/* JSON-RPC request structure */
struct at_jsonrpc_request {
  char const *      method;       /* Method name (NUL-terminated) */
  ulong             method_len;   /* Method name length */
  at_json_value_t * params;       /* Parameters (array or object, may be NULL) */
  long              id;           /* Request ID (-1 if notification) */
  int               has_id;       /* 1 if id was provided */
  ulong             ws_conn_id;   /* WebSocket connection ID (0 if HTTP) */
};

typedef struct at_jsonrpc_request at_jsonrpc_request_t;

/* JSON-RPC response structure */
struct at_jsonrpc_response {
  int    is_error;             /* 1 if error response */
  long   id;                   /* Request ID */
  int    has_id;               /* 1 if id should be included */

  /* For success response */
  char const * result_json;    /* Pre-formatted JSON result */
  ulong        result_json_len;

  /* For error response */
  int          error_code;     /* Error code */
  char const * error_message;  /* Error message */
  char const * error_data;     /* Optional error data (JSON) */
};

typedef struct at_jsonrpc_response at_jsonrpc_response_t;

/* RPC method handler function type.
   Returns 0 on success, non-zero on error.
   Handler should populate response with either result or error. */
typedef int (* at_rpc_method_fn)( at_jsonrpc_request_t const * request,
                                  at_jsonrpc_response_t *      response,
                                  void *                       ctx );

/* RPC method registration entry */
struct at_rpc_method {
  char const *      name;      /* Method name */
  at_rpc_method_fn  handler;   /* Handler function */
};

typedef struct at_rpc_method at_rpc_method_t;

/* JSON-RPC context */
struct at_jsonrpc_ctx {
  at_rpc_method_t const * methods;     /* Array of registered methods */
  ulong                   method_cnt;  /* Number of methods */
  void *                  user_ctx;    /* User-provided context for handlers */

  /* Scratch buffer for JSON parsing */
  uchar * scratch;
  ulong   scratch_sz;
};

typedef struct at_jsonrpc_ctx at_jsonrpc_ctx_t;

AT_PROTOTYPES_BEGIN

/* Initialize JSON-RPC context.
   scratch is a buffer for temporary allocations during parsing.
   methods is an array of method registrations (can be NULL if method_cnt==0). */
void
at_jsonrpc_ctx_init( at_jsonrpc_ctx_t *        ctx,
                     at_rpc_method_t const *   methods,
                     ulong                     method_cnt,
                     void *                    user_ctx,
                     uchar *                   scratch,
                     ulong                     scratch_sz );

void
at_jsonrpc_ctx_set_user_ctx( at_jsonrpc_ctx_t * ctx, void * user_ctx );

/* Parse a JSON-RPC request from raw JSON.
   Returns 0 on success, error code on failure.
   On success, request is populated with parsed data. */
int
at_jsonrpc_parse_request( at_jsonrpc_ctx_t *      ctx,
                          char const *            json,
                          ulong                   json_len,
                          at_jsonrpc_request_t *  request );

/* Dispatch a parsed request to the appropriate method handler.
   Returns 0 on success, non-zero if method not found or handler error. */
int
at_jsonrpc_dispatch( at_jsonrpc_ctx_t *             ctx,
                     at_jsonrpc_request_t const *   request,
                     at_jsonrpc_response_t *        response );

/* Format a JSON-RPC response into the output buffer.
   Returns the number of bytes written, or 0 on error.
   If out_sz is too small, returns the required size (without writing). */
ulong
at_jsonrpc_format_response( at_jsonrpc_response_t const * response,
                            char *                        out,
                            ulong                         out_sz );

/* Format a JSON-RPC error response into the output buffer.
   Convenience function for creating error responses. */
ulong
at_jsonrpc_format_error( int          error_code,
                         char const * error_message,
                         long         id,
                         int          has_id,
                         char *       out,
                         ulong        out_sz );

/* Helper functions for building JSON responses */

/* Get array item at index (returns NULL if out of bounds or not array) */
at_json_value_t *
at_json_array_get( at_json_value_t * arr, ulong idx );

/* Get array length (returns 0 if not array) */
ulong
at_json_array_len( at_json_value_t * arr );

/* Get object field by key (returns NULL if not found or not object) */
at_json_value_t *
at_json_object_get( at_json_value_t * obj, char const * key );

/* Get string value (returns NULL if not string) */
char const *
at_json_get_string( at_json_value_t * val, ulong * out_len );

/* Get number value (returns 0.0 if not number) */
double
at_json_get_number( at_json_value_t * val );

/* Get integer value (returns 0 if not number) */
long
at_json_get_int( at_json_value_t * val );

/* Get boolean value (returns 0 if not boolean) */
int
at_json_get_bool( at_json_value_t * val );

/* Check if value is null */
int
at_json_is_null( at_json_value_t * val );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_http_at_jsonrpc_h */