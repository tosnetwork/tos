#ifndef HEADER_at_waltz_p2p_at_p2p_security_h
#define HEADER_at_waltz_p2p_at_p2p_security_h

/* at_p2p_security.h - P2P Security Layer

   Provides DDoS protection mechanisms:
   - Ping-pong challenge for unknown peer validation
   - Connection rate limiting per IP
   - Activity window tracking for stale peer detection
*/

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p_msg.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

/* Ping challenge tracking */
#define AT_PING_CHALLENGE_MAX       (1024)
#define AT_PING_CHALLENGE_TIMEOUT   (20UL * 1000000000UL)  /* 20 seconds */
#define AT_PING_CHALLENGE_SZ        (32UL)

/* Activity window for stale peer detection */
#define AT_ACTIVITY_WINDOW          (120UL * 1000000000UL)  /* 2 minutes */

/* Connection rate limiting */
#define AT_RATE_LIMIT_MAX           (4096)
#define AT_RATE_LIMIT_WINDOW        (60UL * 1000000000UL)   /* 1 minute */
#define AT_RATE_LIMIT_MAX_ATTEMPTS  (10)                     /* Max per minute */

/**********************************************************************/
/* Ping Challenge Tracker                                             */
/**********************************************************************/

/* Challenge state for validating unknown peers */
typedef struct {
  at_peer_addr_t addr;           /* Peer address */
  uchar          challenge[32];  /* Random challenge bytes */
  ulong          sent_at;        /* When challenge was sent */
} at_ping_challenge_t;

typedef struct {
  at_ping_challenge_t challenges[AT_PING_CHALLENGE_MAX];
  uint                challenge_cnt;
} at_ping_tracker_t;

/* at_ping_tracker_init initializes a ping tracker.
   Returns tracker on success, NULL on failure. */
at_ping_tracker_t *
at_ping_tracker_init( at_ping_tracker_t * tracker );

/* at_ping_tracker_challenge creates and sends a challenge to a peer.
   Generates random challenge bytes and stores them for later verification.
   out_challenge must be 32 bytes.
   Returns 0 on success, -1 if tracker is full. */
int
at_ping_tracker_challenge( at_ping_tracker_t *    tracker,
                           at_peer_addr_t const * addr,
                           ulong                  now,
                           uchar                  out_challenge[32] );

/* at_ping_tracker_challenge_ip4 creates challenge for IPv4 address. */
int
at_ping_tracker_challenge_ip4( at_ping_tracker_t * tracker,
                               uint                ip4_addr,
                               ushort              port,
                               ulong               now,
                               uchar               out_challenge[32] );

/* at_ping_tracker_verify verifies a challenge response.
   Checks if the response_sig is a valid signature over the challenge.
   pubkey is the peer's claimed public key (32 bytes).
   Returns 1 if valid, 0 if invalid or expired. */
int
at_ping_tracker_verify( at_ping_tracker_t *    tracker,
                        at_peer_addr_t const * addr,
                        uchar const            response_sig[64],
                        uchar const            pubkey[32],
                        ulong                  now );

/* at_ping_tracker_verify_ip4 verifies challenge for IPv4 address. */
int
at_ping_tracker_verify_ip4( at_ping_tracker_t * tracker,
                            uint                ip4_addr,
                            ushort              port,
                            uchar const         response_sig[64],
                            uchar const         pubkey[32],
                            ulong               now );

/* at_ping_tracker_expire removes expired challenges. */
void
at_ping_tracker_expire( at_ping_tracker_t * tracker, ulong now );

/* at_ping_tracker_find finds a pending challenge for an address.
   Returns pointer to challenge or NULL if not found. */
at_ping_challenge_t *
at_ping_tracker_find( at_ping_tracker_t *    tracker,
                      at_peer_addr_t const * addr );

/**********************************************************************/
/* Connection Rate Limiter                                            */
/**********************************************************************/

/* Rate limit entry for a single IP */
typedef struct {
  at_peer_addr_t addr;           /* IP address */
  ulong          first_attempt;  /* First connection attempt time */
  uint           attempt_cnt;    /* Attempts within window */
} at_rate_limit_entry_t;

typedef struct {
  at_rate_limit_entry_t entries[AT_RATE_LIMIT_MAX];
  uint                  entry_cnt;
} at_rate_limiter_t;

/* at_rate_limiter_init initializes a rate limiter.
   Returns limiter on success, NULL on failure. */
at_rate_limiter_t *
at_rate_limiter_init( at_rate_limiter_t * limiter );

/* at_rate_limiter_allow checks if a connection attempt should be allowed.
   Returns 1 if allowed, 0 if rate limited.
   Automatically tracks the attempt if allowed. */
int
at_rate_limiter_allow( at_rate_limiter_t *    limiter,
                       at_peer_addr_t const * addr,
                       ulong                  now );

/* at_rate_limiter_allow_ip4 checks rate limit for IPv4 address. */
int
at_rate_limiter_allow_ip4( at_rate_limiter_t * limiter,
                           uint                ip4_addr,
                           ulong               now );

/* at_rate_limiter_expire removes expired entries. */
void
at_rate_limiter_expire( at_rate_limiter_t * limiter, ulong now );

/* at_rate_limiter_clear resets all entries. */
void
at_rate_limiter_clear( at_rate_limiter_t * limiter );

/**********************************************************************/
/* Activity Tracking                                                  */
/**********************************************************************/

/* at_peer_is_stale checks if a peer should be considered stale.
   A peer becomes stale if no activity within AT_ACTIVITY_WINDOW.
   Stale peers require re-validation via ping-pong.
   Returns 1 if stale, 0 if active. */
static inline int
at_peer_is_stale( ulong last_seen, ulong now ) {
  if( now <= last_seen ) return 0;
  return (now - last_seen) > AT_ACTIVITY_WINDOW;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_security_h */