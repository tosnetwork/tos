#ifndef HEADER_at_disco_keyguard_at_keyguard_client_h
#define HEADER_at_disco_keyguard_at_keyguard_client_h

/* at_keyguard_client.h - Client for remote signing service

   A simple blocking client to a remote signing server, based on a pair
   of (input, output) mcaches and data regions.

   For maximum security, the caller should ensure a few things before
   using:

    (a) The request mcache and data region are placed in a shared memory
        map that is accessible exclusively to the calling tile, and the
        keyguard tile. The keyguard tile should map the memory as read
        only.

    (b) The response mcache and data region are placed in a shared
        memory map that is accessible exclusively to the calling tile,
        and the keyguard tile. The calling tile should map the memory
        as read only.

    (c) No other data is placed in these shared memory maps, and no
        other tiles have access to them.

    (d) Each input/output mcache correspond to a single role, and the
        keyguard tile verifies that all incoming requests are
        specifically formatted for that role. */

#include "at/infra/ipc/at_tango_base.h"

#define AT_KEYGUARD_CLIENT_ALIGN (128UL)
#define AT_KEYGUARD_CLIENT_FOOTPRINT (128UL)

struct __attribute__((aligned(AT_KEYGUARD_CLIENT_ALIGN))) at_keyguard_client {
  at_frag_meta_t * request;
  ulong            request_seq;
  ulong            request_depth;
  void *           request_mem;       /* Base memory for chunk addressing */
  ulong            request_chunk;
  ulong            request_chunk0;
  ulong            request_wmark;
  ulong            request_mtu;

  at_frag_meta_t * response;
  ulong            response_seq;
  ulong            response_depth;
  void *           response_mem;      /* Base memory for chunk addressing */
  ulong            response_chunk0;
  ulong            response_wmark;
};
typedef struct at_keyguard_client at_keyguard_client_t;

AT_PROTOTYPES_BEGIN

void *
at_keyguard_client_new( void *           shmem,
                        at_frag_meta_t * request_mcache,
                        uchar *          request_dcache,
                        void *           request_mem,
                        at_frag_meta_t * response_mcache,
                        uchar *          response_dcache,
                        void *           response_mem,
                        ulong            request_mtu );

static inline at_keyguard_client_t *
at_keyguard_client_join( void * shclient ) { return (at_keyguard_client_t*)shclient; }

static inline void *
at_keyguard_client_leave( at_keyguard_client_t * client ) { return (void*)client; }

static inline void *
at_keyguard_client_delete( void * shclient ) { return shclient; }

/* at_keyguard_client_sign sends a remote signing request to the signing
   server, and blocks (spins) until the response is received.

   Signing is treated as infallible, and there are no error codes or
   results. If the remote signer is stuck or not running, this function
   will not timeout and instead hangs forever waiting for a response.
   This is currently by design.

   sign_data should be a pointer to a buffer, with length sign_data_len
   that will be signed. The data should correspond to one of the
   roles described in at_keyguard.h. If the remote signing tile
   receives a malformed signing request, or one for a role that does
   not correspond to the role assigned to the receiving mcache, it
   will abort the whole program with a critical error.

   The response, a 64 byte Schnorr signature, will be written into the
   signature buffer, which must be at least this size.

   sign_type is in AT_KEYGUARD_SIGN_TYPE_{...}. */

void
at_keyguard_client_sign( at_keyguard_client_t * client,
                         uchar *                signature,
                         uchar const *          sign_data,
                         ulong                  sign_data_len,
                         int                    sign_type );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_keyguard_at_keyguard_client_h */
