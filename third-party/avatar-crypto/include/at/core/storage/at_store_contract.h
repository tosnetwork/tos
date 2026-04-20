#ifndef HEADER_at_core_storage_at_store_contract_h
#define HEADER_at_core_storage_at_store_contract_h

/* at_store_contract.h - Contract module storage helpers (TOS-aligned)
 *
 * Contract metadata layout (AT_CF_CONTRACTS):
 *   - id (u64 BE)
 *   - module_pointer (Option<u64>): 1 byte flag + u64 if Some
 *
 * Versioned contract layout (AT_CF_VERSIONED_CONTRACTS):
 *   key: topoheight(8 BE) + contract_id(8 BE)
 *   val: Versioned<Option<Module>>
 *        - previous_topoheight (Option<u64>)
 *        - module (Option<Module>): bool + [u32 len + bytes] if Some
 */

#include "at_store.h"

AT_PROTOTYPES_BEGIN

/* Read contract metadata. */
int
at_store_contract_get_meta( at_store_t * store,
                            uchar const  contract[32],
                            ulong *      id_out,
                            int *        has_module_ptr_out,
                            ulong *      module_ptr_out );

/* Get or create a contract metadata record and ID mapping. */
int
at_store_contract_get_or_create_meta( at_store_t * store,
                                      uchar const  contract[32],
                                      ulong *      id_out,
                                      int *        has_module_ptr_out,
                                      ulong *      module_ptr_out );

/* Update module pointer in metadata only (set to None). */
int
at_store_contract_clear_module_pointer( at_store_t * store,
                                        uchar const  contract[32] );

/* Store a versioned module and set module_pointer=topoheight. */
int
at_store_contract_set_last_module( at_store_t * store,
                                   uchar const  contract[32],
                                   uchar const *module,
                                   ulong        module_sz,
                                   ulong        topoheight,
                                   int          module_present );

/* Load contract module at maximum topoheight (<= maximum_topoheight). */
int
at_store_contract_load_module_at_max_topoheight( at_store_t * store,
                                                 uchar const  contract[32],
                                                 ulong        maximum_topoheight,
                                                 uchar **     module_out,
                                                 ulong *      module_sz_out,
                                                 ulong *      found_topo_out );

/* Load latest contract module (uses current module pointer). */
int
at_store_contract_load_module_latest( at_store_t * store,
                                      uchar const  contract[32],
                                      uchar **     module_out,
                                      ulong *      module_sz_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_core_storage_at_store_contract_h */
