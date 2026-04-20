#ifndef HEADER_at_blockdag_at_ingest_h
#define HEADER_at_blockdag_at_ingest_h

/* at_ingest.h - Shared block/tx ingest entry points for gossip/sync/repair */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/block/at_block.h"

AT_PROTOTYPES_BEGIN

/* Parse TOS wire-format block header.
   Returns 0 on success, -1 on error. */
int
at_block_parse_header_wire( uchar const *     buf,
                            ulong             buf_sz,
                            at_block_header_t * out_header,
                            ushort *          out_txs_cnt,
                            ulong *           out_header_sz );

/* Parse TOS wire-format block header and optional tx hashes.
   If out_tx_hashes is non-NULL, max_txs must be >= txs_count.
   Returns 0 on success, -1 on error. */
int
at_block_parse_header_wire_with_hashes( uchar const *      buf,
                                        ulong              buf_sz,
                                        at_block_header_t * out_header,
                                        uchar             (*out_tx_hashes)[32],
                                        ushort             max_txs,
                                        ushort *           out_txs_cnt,
                                        ulong *            out_header_sz );

/* Ingest a block header into DAG (updates height/tips/topoheight).
   network selects minimum difficulty (mainnet/testnet/stagenet/devnet). */
int
at_block_ingest_header( at_dag_provider_t *    dag,
                        at_block_header_t const * header,
                        ulong                  txs_cnt,
                        uchar const            hash[32],
                        uchar                  network );

/* Store wire-format block header bytes in persistent storage. */
int
at_block_store_header_wire( at_dag_provider_t * dag,
                            uchar const *       hash,
                            uchar const *       header_data,
                            ulong               header_sz );

/* Ingest a full block from wire (header + txs).
   If store_txs is non-zero, stores txs into DB when possible.
   network selects minimum difficulty (mainnet/testnet/stagenet/devnet). */
int
at_block_ingest_block_from_wire( at_dag_provider_t * dag,
                                 uchar const *       block_data,
                                 ulong               block_sz,
                                 int                 store_txs,
                                 ulong *             out_txs_ingested,
                                 uchar               out_block_hash[32],
                                 uchar               network );

/* Ingest a raw transaction from wire into storage (if available).
   Returns 0 on success, -1 on error. */
int
at_tx_ingest_from_wire( at_dag_provider_t * dag,
                        uchar const *       tx_data,
                        ulong               tx_sz,
                        uchar               out_tx_hash[32] );

/* Serialize block header to TOS wire format.
   tx_hashes required for wire format (stored separately from header).
   Wire format uses big-endian integers for all multi-byte values.
   Returns number of bytes written, or 0 on error. */
ulong
at_block_serialize_header_wire( uchar                   * out,
                                ulong                     out_max,
                                at_block_header_t const * header,
                                uchar const            (* tx_hashes)[32],
                                ushort                    tx_cnt );

AT_PROTOTYPES_END

#endif /* HEADER_at_blockdag_at_ingest_h */
