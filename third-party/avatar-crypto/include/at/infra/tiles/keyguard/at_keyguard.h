#ifndef HEADER_at_disco_keyguard_at_keyguard_h
#define HEADER_at_disco_keyguard_at_keyguard_h

/* at_keyguard.h - Digital signing service for validator components

   The keyguard creates digital signatures on behalf of validator
   components using Schnorr signatures on Ristretto255 with SHA3-512. */

#include "../at_disco_base.h"

AT_PROTOTYPES_BEGIN

/* AT_KEYGUARD_SIGN_REQ_MTU is the maximum size (inclusive) of a signing
   request payload. */

#define AT_KEYGUARD_SIGN_REQ_MTU (2048UL)

/* Role definitions ***************************************************

   Each role represents a validator component that may request
   signatures from the keyguard. */

#define AT_KEYGUARD_ROLE_VOTER    (0)  /* Vote transaction sender */
#define AT_KEYGUARD_ROLE_GOSSIP   (1)  /* Gossip protocol participant */
#define AT_KEYGUARD_ROLE_LEADER   (2)  /* Block producer */
#define AT_KEYGUARD_ROLE_REPAIR   (3)  /* Repair protocol */
#define AT_KEYGUARD_ROLE_WITNESS  (4)  /* Witness attestations */
#define AT_KEYGUARD_ROLE_CNT      (5)  /* Number of known roles */

/* Payload types ******************************************************

   Each payload type represents a category of message that can be
   signed. */

#define AT_KEYGUARD_PAYLOAD_LG_TXN     (0)  /* TOS transaction message */
#define AT_KEYGUARD_PAYLOAD_LG_GOSSIP  (1)  /* Gossip CrdsData */
#define AT_KEYGUARD_PAYLOAD_LG_PRUNE   (2)  /* Gossip PruneData */
#define AT_KEYGUARD_PAYLOAD_LG_BLOCK   (3)  /* Block header/shred */
#define AT_KEYGUARD_PAYLOAD_LG_REPAIR  (4)  /* RepairProtocol */
#define AT_KEYGUARD_PAYLOAD_LG_PING    (5)  /* Gossip ping protocol */
#define AT_KEYGUARD_PAYLOAD_LG_PONG    (6)  /* Gossip/Repair pong protocol */
#define AT_KEYGUARD_PAYLOAD_LG_WITNESS (7)  /* Witness attestation */

#define AT_KEYGUARD_PAYLOAD_TXN     (1UL<<AT_KEYGUARD_PAYLOAD_LG_TXN    )
#define AT_KEYGUARD_PAYLOAD_GOSSIP  (1UL<<AT_KEYGUARD_PAYLOAD_LG_GOSSIP )
#define AT_KEYGUARD_PAYLOAD_PRUNE   (1UL<<AT_KEYGUARD_PAYLOAD_LG_PRUNE  )
#define AT_KEYGUARD_PAYLOAD_BLOCK   (1UL<<AT_KEYGUARD_PAYLOAD_LG_BLOCK  )
#define AT_KEYGUARD_PAYLOAD_REPAIR  (1UL<<AT_KEYGUARD_PAYLOAD_LG_REPAIR )
#define AT_KEYGUARD_PAYLOAD_PING    (1UL<<AT_KEYGUARD_PAYLOAD_LG_PING   )
#define AT_KEYGUARD_PAYLOAD_PONG    (1UL<<AT_KEYGUARD_PAYLOAD_LG_PONG   )
#define AT_KEYGUARD_PAYLOAD_WITNESS (1UL<<AT_KEYGUARD_PAYLOAD_LG_WITNESS)

/* Sign types *********************************************************

   TOS uses Schnorr signatures. These types indicate how the payload
   should be processed before signing. */

#define AT_KEYGUARD_SIGN_TYPE_SCHNORR        (0)  /* schnorr_sign(input) */
#define AT_KEYGUARD_SIGN_TYPE_SHA3_SCHNORR   (1)  /* schnorr_sign(sha3_512(data)) */

/* Type confusion/ambiguity checks ************************************/

/* at_keyguard_payload_match returns a bitwise OR of
   AT_KEYGUARD_PAYLOAD_{...}.

   [data,data+sz) is the payload that is requested to be signed.

   sign_type is in AT_KEYGUARD_SIGN_TYPE_{...}.

   Returns 0 if none matched. at_ulong_popcnt(return value) is 1 if the
   payload is unambiguously of a single type. */

AT_FN_PURE ulong
at_keyguard_payload_match( uchar const * data,
                           ulong         sz,
                           int           sign_type );

/* Authorization ******************************************************/

struct at_keyguard_authority {
  uchar identity_pubkey[32];
};

typedef struct at_keyguard_authority at_keyguard_authority_t;

/* at_keyguard_payload_authorize decides whether the keyguard accepts
   a signing request.

   [data,data+sz) is the payload that is requested to be signed.

   role is one of AT_KEYGUARD_ROLE_{...}. It is assumed that the origin
   of the request was previously authorized for the given role.

   Returns 1 if authorized, otherwise 0.

   This function is more restrictive than the respective
   at_keyguard_payload_matches functions. */

int
at_keyguard_payload_authorize( at_keyguard_authority_t const * authority,
                               uchar const *                   data,
                               ulong                           sz,
                               int                             role,
                               int                             sign_type );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_keyguard_at_keyguard_h */