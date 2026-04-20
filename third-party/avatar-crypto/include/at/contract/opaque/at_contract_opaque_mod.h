#ifndef HEADER_at_contract_opaque_at_contract_opaque_mod_h
#define HEADER_at_contract_opaque_at_contract_opaque_mod_h

#include "at/contract/at_contract_base.h"
#include "at/contract/at_contract_mod.h"
#include "at/contract/at_contract_provider.h"
#include "at/crypto/at_schnorr.h"

AT_PROTOTYPES_BEGIN

/* Opaque IDs aligned to tos/common/src/contract/opaque/mod.rs */
#define AT_CONTRACT_OPAQUE_ID_HASH                     (0U)
#define AT_CONTRACT_OPAQUE_ID_ADDRESS                  (1U)
#define AT_CONTRACT_OPAQUE_ID_SIGNATURE                (2U)
#define AT_CONTRACT_OPAQUE_ID_CIPHERTEXT               (3U)
#define AT_CONTRACT_OPAQUE_ID_CIPHERTEXT_VALIDITY_PROOF (4U)
#define AT_CONTRACT_OPAQUE_ID_RANGE_PROOF              (5U)

typedef struct {
  uchar bytes[32];
} at_contract_opaque_hash_t;

typedef struct {
  uchar public_key[32];
  int   mainnet;
} at_contract_opaque_address_t;

typedef struct {
  at_schnorr_signature_t value;
} at_contract_opaque_signature_t;

typedef struct {
  at_contract_provider_t const * provider;
  at_contract_chain_state_t *    state;
} at_contract_opaque_context_t;

typedef struct at_contract_environment at_contract_environment_t;

typedef enum {
  AT_CONTRACT_ENV_BINDING_STATIC = 0,
  AT_CONTRACT_ENV_BINDING_METHOD = 1,
  AT_CONTRACT_ENV_BINDING_GLOBAL = 2
} at_contract_env_binding_kind_t;

typedef struct {
  uint         opaque_id;
  char const * name;
  int          allow_entry_input;
} at_contract_opaque_type_desc_t;

typedef struct {
  char const *                  scope;
  char const *                  name;
  char const *                  impl_symbol;
  at_contract_env_binding_kind_t kind;
} at_contract_env_binding_desc_t;

static inline void
at_contract_opaque_context_init( at_contract_opaque_context_t *     ctx,
                                 at_contract_provider_t const *      provider,
                                 at_contract_chain_state_t *         state ) {
  if( !ctx ) return;
  ctx->provider = provider;
  ctx->state = state;
}

int
at_contract_opaque_register_types( void );

int
at_contract_opaque_get_environment( at_contract_environment_t const ** env_out );

ulong
at_contract_opaque_types_count( at_contract_environment_t const * env );

ulong
at_contract_opaque_bindings_count( at_contract_environment_t const * env );

int
at_contract_opaque_type_desc_at( at_contract_environment_t const *     env,
                                 ulong                                 index,
                                 at_contract_opaque_type_desc_t const **desc_out );

int
at_contract_opaque_binding_desc_at( at_contract_environment_t const *    env,
                                    ulong                                index,
                                    at_contract_env_binding_desc_t const **desc_out );

int
at_contract_opaque_find_binding( at_contract_environment_t const *    env,
                                 char const *                         scope_opt,
                                 char const *                         name,
                                 at_contract_env_binding_desc_t const **desc_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_at_contract_opaque_mod_h */
