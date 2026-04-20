#ifndef HEADER_at_contract_opaque_at_contract_opaque_random_h
#define HEADER_at_contract_opaque_at_contract_opaque_random_h

#include "at/contract/at_contract_mod.h"
#include "at/contract/at_contract_random.h"
#include "at/infra/uint256/at_uint256.h"

AT_PROTOTYPES_BEGIN

int
at_contract_opaque_random_init_if_needed( at_contract_chain_state_t * state );

int
at_contract_opaque_random_u8( at_contract_chain_state_t * state,
                              uchar *                     out );

int
at_contract_opaque_random_u16( at_contract_chain_state_t * state,
                               ushort *                    out );

int
at_contract_opaque_random_u32( at_contract_chain_state_t * state,
                               uint *                      out );

int
at_contract_opaque_random_u64( at_contract_chain_state_t * state,
                               ulong *                     out );

int
at_contract_opaque_random_u128( at_contract_chain_state_t * state,
                                unsigned __int128 *         out );

int
at_contract_opaque_random_u256( at_contract_chain_state_t * state,
                                at_uint256_t *             out );

int
at_contract_opaque_random_bool( at_contract_chain_state_t * state,
                                int *                       out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_at_contract_opaque_random_h */
