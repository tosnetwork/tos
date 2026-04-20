#ifndef AT_TOS_ASSET_H
#define AT_TOS_ASSET_H

#include "at/core/storage/at_store.h"

/* ============================================================================
   TOS-Compatible Asset Structure
   See: tos/daemon/src/core/storage/rocksdb/types/asset.rs

   Serialization Order (all big-endian):
     1. id (u64, 8 bytes)
     2. data_pointer (Option<u64>)
     3. supply_pointer (Option<u64>)
   ============================================================================ */

typedef struct at_asset {
  ulong id;
  int   has_data_pointer;
  ulong data_pointer;
  int   has_supply_pointer;
  ulong supply_pointer;
} at_asset_t;

#define AT_ASSET_SERIALIZED_MAX_SIZE 26  /* 8 + 9 + 9 */

/* Deserialize Asset from TOS-compatible binary format. */
int
at_asset_deserialize( uchar const * buf, ulong buf_sz, at_asset_t * asset_out );

/* Serialize Asset to TOS-compatible binary format. */
int
at_asset_serialize( at_asset_t const * asset, uchar * buf, ulong buf_sz );

/* Resolve asset hash to asset id. Returns AT_STORE_OK or AT_STORE_ERR_NOT_FOUND. */
int
at_asset_get_id( at_store_t * store, uchar const asset[32], ulong * id_out );

/* Resolve asset id to asset hash. Returns AT_STORE_OK or AT_STORE_ERR_NOT_FOUND. */
int
at_asset_get_hash_from_id( at_store_t * store, ulong asset_id, uchar hash_out[32] );

#endif /* AT_TOS_ASSET_H */
