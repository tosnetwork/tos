#ifndef HEADER_at_waltz_p2p_at_p2p_dh_db_h
#define HEADER_at_waltz_p2p_at_p2p_dh_db_h

/* at_p2p_dh_db.h - lightweight DH key persistence (IPv4) */

#include "at/p2p/at_peer.h"

AT_PROTOTYPES_BEGIN

/* Default workspace sizing for DH DB allocator. */
#define AT_P2P_DH_DB_DEFAULT_WKSP_PAGES (256UL)
#define AT_P2P_DH_DB_DEFAULT_WKSP_PART_MAX (128UL)

/* Configure the internal DH DB allocator workspace size.
   Must be called before any load/save to take effect. */
int
at_p2p_dh_db_configure( ulong wksp_pages,
                        ulong wksp_part_max );

/* Load DH keys from JSON file into peer pool.
   Returns 0 on success, non-zero on failure. */
int
at_p2p_dh_db_load( at_peer_pool_t * pool,
                   char const *     path );

/* Save DH keys from peer pool to JSON file (atomic write).
   Returns 0 on success, non-zero on failure. */
int
at_p2p_dh_db_save( at_peer_pool_t * pool,
                   char const *     path );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_dh_db_h */