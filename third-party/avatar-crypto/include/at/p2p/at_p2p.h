#ifndef HEADER_at_waltz_p2p_at_p2p_h
#define HEADER_at_waltz_p2p_at_p2p_h

/* at_p2p.h - TOS P2P Encrypted Session

   Provides secure peer-to-peer communication using:
   - X25519 for key exchange (DH)
   - ChaCha20-Poly1305 for authenticated encryption (RFC 8439)

   Compatible with TOS Rust P2P encryption.

   TOS Key Exchange Protocol (2-Phase):

   Phase 1: DH Public Key Exchange
   ┌──────────┐                      ┌──────────┐
   │ Initiator│                      │Responder │
   └────┬─────┘                      └────┬─────┘
        │  X25519 pubkey (32 bytes)       │
        │────────────────────────────────►│
        │                                 │
        │  X25519 pubkey (32 bytes)       │
        │◄────────────────────────────────│
        │                                 │
        │  Both compute shared_secret     │
        │  via X25519 DH                  │

   Phase 2: Symmetric Key Exchange
        │                                 │
        │  Encrypt(shared_secret, random_key_init)
        │────────────────────────────────►│
        │                                 │ Decrypt → key_init
        │                                 │ Generate random_key_resp
        │  Encrypt(shared_secret, random_key_resp)
        │◄────────────────────────────────│
        │ Decrypt → key_resp              │
        │                                 │
        │  Initiator:                     │  Responder:
        │    our_key = key_init           │    our_key = key_resp
        │    peer_key = key_resp          │    peer_key = key_init

   Nonce Format (TOS compatible, 12 bytes):
   - First 8 bytes: 64-bit counter (big-endian)
   - Last 4 bytes: zeros
*/

#include "at/crypto/at_x25519.h"
#include "at/crypto/at_chacha20_poly1305.h"
#include "at/crypto/at_sha256.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define AT_P2P_PUBKEY_SZ     (32UL)
#define AT_P2P_SECRET_SZ     (32UL)
#define AT_P2P_KEY_SZ        (32UL)
#define AT_P2P_NONCE_SZ      (12UL)
#define AT_P2P_TAG_SZ        (16UL)

/* DH exchange message size (just the public key) */
#define AT_P2P_DH_MSG_SZ     (32UL)

/* Encrypted key message size: ciphertext(32) + tag(16) = 48 bytes */
#define AT_P2P_KEY_MSG_SZ    (32UL + AT_P2P_TAG_SZ)

/* Maximum encrypted payload (64KB - overhead) */
#define AT_P2P_MAX_PAYLOAD   (65535UL - AT_P2P_TAG_SZ)

/* Key rotation threshold (1 GB) */
#define AT_P2P_KEY_ROTATE_BYTES  (1024UL * 1024UL * 1024UL)

/**********************************************************************/
/* Session States                                                     */
/**********************************************************************/

#define AT_P2P_STATE_INIT        (0)   /* Not started */
#define AT_P2P_STATE_DH_SENT     (1)   /* Sent our DH pubkey, waiting for peer's */
#define AT_P2P_STATE_DH_DONE     (2)   /* DH complete, ready for key exchange */
#define AT_P2P_STATE_KEY_SENT    (3)   /* Sent our symmetric key, waiting for peer's */
#define AT_P2P_STATE_ESTABLISHED (4)   /* Both keys exchanged, session ready */
#define AT_P2P_STATE_ERROR       (-1)  /* Error state */

/**********************************************************************/
/* Error Codes                                                        */
/**********************************************************************/

#define AT_P2P_SUCCESS           (0)
#define AT_P2P_ERR_INVAL         (-1)
#define AT_P2P_ERR_STATE         (-2)
#define AT_P2P_ERR_CRYPTO        (-3)
#define AT_P2P_ERR_AUTH          (-4)  /* Authentication failed */
#define AT_P2P_ERR_OVERFLOW      (-5)

/**********************************************************************/
/* Session Structure                                                  */
/**********************************************************************/

typedef struct {
  /* DH keys for initial key exchange */
  uchar local_dh_privkey[32];    /* Our ephemeral X25519 private key */
  uchar local_dh_pubkey[32];     /* Our ephemeral X25519 public key */
  uchar remote_dh_pubkey[32];    /* Peer's X25519 public key */
  uchar dh_shared_secret[32];    /* X25519 shared secret (for key transport) */

  /* Symmetric keys (randomly generated, exchanged via DH)
     TOS terminology: our_key = key we use to encrypt outbound messages
                      peer_key = key peer uses (we use to decrypt inbound) */
  uchar our_key[32];             /* Key we use for encryption (outbound) */
  uchar peer_key[32];            /* Key peer uses for encryption (inbound) */

  /* Nonce counters (incremented after each message)
     TOS format: [8-byte counter BE][4-byte zeros] */
  ulong tx_nonce;                /* Outbound nonce counter */
  ulong rx_nonce;                /* Inbound nonce counter */

  /* Byte counters for key rotation tracking */
  ulong tx_bytes;                /* Total bytes encrypted with current our_key */
  ulong rx_bytes;                /* Total bytes decrypted with current peer_key */

  /* Session state */
  int   state;                   /* AT_P2P_STATE_* */
  int   is_initiator;            /* 1 if we initiated the connection */

} at_p2p_session_t;

/**********************************************************************/
/* Session Lifecycle                                                  */
/**********************************************************************/

/* at_p2p_session_init initializes a session for handshake.
   Generates ephemeral DH keypair.
   is_initiator: 1 if we are initiating the connection, 0 if responding.
   Returns session on success, NULL on failure. */
at_p2p_session_t *
at_p2p_session_init( at_p2p_session_t * session,
                     int                is_initiator );

/* at_p2p_session_fini securely wipes session state. */
void
at_p2p_session_fini( at_p2p_session_t * session );

/**********************************************************************/
/* Phase 1: DH Key Exchange                                           */
/**********************************************************************/

/* at_p2p_dh_start begins DH exchange by writing our public key.
   Call this first as initiator, or after receiving peer's DH as responder.
   Writes our DH public key to out_pubkey (must be 32 bytes).
   Returns 0 on success, error code on failure. */
int
at_p2p_dh_start( at_p2p_session_t * session,
                 uchar              out_pubkey[AT_P2P_DH_MSG_SZ] );

/* at_p2p_dh_finish completes DH exchange after receiving peer's public key.
   Computes the shared secret.
   peer_pubkey is the peer's DH public key (32 bytes).
   Returns 0 on success, error code on failure. */
int
at_p2p_dh_finish( at_p2p_session_t * session,
                  uchar const        peer_pubkey[AT_P2P_DH_MSG_SZ] );

/**********************************************************************/
/* Phase 2: Symmetric Key Exchange                                    */
/**********************************************************************/

/* at_p2p_key_send generates a random symmetric key, encrypts it with
   the DH shared secret, and writes to out_encrypted_key.
   out_encrypted_key must be AT_P2P_KEY_MSG_SZ (48) bytes.
   Returns 0 on success, error code on failure. */
int
at_p2p_key_send( at_p2p_session_t * session,
                 uchar              out_encrypted_key[AT_P2P_KEY_MSG_SZ] );

/* at_p2p_key_recv decrypts the peer's symmetric key and installs it.
   encrypted_key is AT_P2P_KEY_MSG_SZ (48) bytes.
   After both key_send and key_recv complete, session is ESTABLISHED.
   Returns 0 on success, AT_P2P_ERR_AUTH if decryption fails. */
int
at_p2p_key_recv( at_p2p_session_t * session,
                 uchar const        encrypted_key[AT_P2P_KEY_MSG_SZ] );

/**********************************************************************/
/* Session State Queries                                              */
/**********************************************************************/

/* at_p2p_is_established returns 1 if session is established, 0 otherwise. */
static inline int
at_p2p_is_established( at_p2p_session_t const * session ) {
  return session && session->state == AT_P2P_STATE_ESTABLISHED;
}

/* at_p2p_get_state returns current session state. */
static inline int
at_p2p_get_state( at_p2p_session_t const * session ) {
  return session ? session->state : AT_P2P_STATE_ERROR;
}

/**********************************************************************/
/* Encryption/Decryption (TOS Compatible)                             */
/**********************************************************************/

/* at_p2p_encrypt_in_place encrypts data in place.
   Buffer must have AT_P2P_TAG_SZ (16) extra bytes for the tag.
   The nonce is NOT prepended - TOS uses implicit nonce from counter.
   Output format: [ciphertext][16-byte tag]
   Updates tx_bytes counter.
   Returns 0 on success, error code on failure. */
int
at_p2p_encrypt_in_place( at_p2p_session_t * session,
                         void *             buf,
                         ulong              buf_len );

/* at_p2p_decrypt_in_place decrypts data in place.
   Input format: [ciphertext][16-byte tag]
   buf_len must include the 16-byte tag.
   Updates rx_bytes counter.
   Returns 0 on success, AT_P2P_ERR_AUTH if authentication fails. */
int
at_p2p_decrypt_in_place( at_p2p_session_t * session,
                         void *             buf,
                         ulong              buf_len );

/**********************************************************************/
/* Encryption/Decryption (with separate buffers)                      */
/**********************************************************************/

/* at_p2p_encrypt encrypts plaintext and produces ciphertext with auth tag.
   Output format: [ciphertext][16-byte tag]
   cipher_sz must point to available size (>= plain_sz + 16).
   Updates tx_bytes counter.
   Returns 0 on success, error code on failure. */
int
at_p2p_encrypt( at_p2p_session_t * session,
                void const *       plain,
                ulong              plain_sz,
                void *             cipher,
                ulong *            cipher_sz );

/* at_p2p_decrypt decrypts and authenticates ciphertext.
   Input format: [ciphertext][16-byte tag]
   cipher_sz must include the 16-byte tag.
   Updates rx_bytes counter.
   Returns 0 on success, AT_P2P_ERR_AUTH if authentication fails. */
int
at_p2p_decrypt( at_p2p_session_t * session,
                void const *       cipher,
                ulong              cipher_sz,
                void *             plain,
                ulong *            plain_sz );

/**********************************************************************/
/* Key Rotation (TOS Compatible)                                      */
/**********************************************************************/

/* at_p2p_needs_key_rotation returns 1 if key rotation is needed.
   Call periodically to check if tx_bytes or rx_bytes exceeds threshold. */
int
at_p2p_needs_key_rotation( at_p2p_session_t const * session );

/* at_p2p_needs_tx_key_rotation returns 1 if TX key rotation is needed. */
static inline int
at_p2p_needs_tx_key_rotation( at_p2p_session_t const * session ) {
  return session && session->tx_bytes >= AT_P2P_KEY_ROTATE_BYTES;
}

/* at_p2p_needs_rx_key_rotation returns 1 if RX key rotation is needed. */
static inline int
at_p2p_needs_rx_key_rotation( at_p2p_session_t const * session ) {
  return session && session->rx_bytes >= AT_P2P_KEY_ROTATE_BYTES;
}

/* at_p2p_rotate_our_key generates a new random key for outbound encryption.
   The new key is encrypted with the CURRENT our_key and written to out_encrypted_new_key.
   After calling, the new key is installed and tx_bytes/tx_nonce are reset.
   out_encrypted_new_key must be AT_P2P_KEY_MSG_SZ (48) bytes.
   This is transmitted via AT_PKT_KEY_EXCHANGE (type 0) packet.
   Returns 0 on success, error code on failure. */
int
at_p2p_rotate_our_key( at_p2p_session_t * session,
                       uchar              out_encrypted_new_key[AT_P2P_KEY_MSG_SZ] );

/* at_p2p_rotate_peer_key receives and installs a new peer key.
   The encrypted_new_key is decrypted with the CURRENT peer_key.
   After calling, the new key is installed and rx_bytes/rx_nonce are reset.
   encrypted_new_key is AT_P2P_KEY_MSG_SZ (48) bytes.
   Returns 0 on success, AT_P2P_ERR_AUTH if decryption fails. */
int
at_p2p_rotate_peer_key( at_p2p_session_t * session,
                        uchar const        encrypted_new_key[AT_P2P_KEY_MSG_SZ] );

/**********************************************************************/
/* Legacy API (for backward compatibility during transition)          */
/**********************************************************************/


/**********************************************************************/
/* Utility                                                            */
/**********************************************************************/

/* at_p2p_session_get_local_pubkey returns pointer to local DH public key. */
static inline uchar const *
at_p2p_session_get_local_pubkey( at_p2p_session_t const * session ) {
  return session ? session->local_dh_pubkey : NULL;
}

/* at_p2p_session_get_remote_pubkey returns pointer to remote DH public key.
   Only valid after DH exchange is complete. */
static inline uchar const *
at_p2p_session_get_remote_pubkey( at_p2p_session_t const * session ) {
  return session ? session->remote_dh_pubkey : NULL;
}

/* at_p2p_get_tx_nonce returns the current TX nonce value. */
static inline ulong
at_p2p_get_tx_nonce( at_p2p_session_t const * session ) {
  return session ? session->tx_nonce : 0;
}

/* at_p2p_get_rx_nonce returns the current RX nonce value. */
static inline ulong
at_p2p_get_rx_nonce( at_p2p_session_t const * session ) {
  return session ? session->rx_nonce : 0;
}

/* at_p2p_get_tx_bytes returns total bytes encrypted. */
static inline ulong
at_p2p_get_tx_bytes( at_p2p_session_t const * session ) {
  return session ? session->tx_bytes : 0;
}

/* at_p2p_get_rx_bytes returns total bytes decrypted. */
static inline ulong
at_p2p_get_rx_bytes( at_p2p_session_t const * session ) {
  return session ? session->rx_bytes : 0;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_h */