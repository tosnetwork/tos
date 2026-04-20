#ifndef HEADER_at_contract_at_contract_base_h
#define HEADER_at_contract_at_contract_base_h

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Contract module return codes */
#define AT_CONTRACT_OK            (0)
#define AT_CONTRACT_ERR_INVAL    (-1)
#define AT_CONTRACT_ERR_NOMEM    (-2)
#define AT_CONTRACT_ERR_CORRUPT  (-3)
#define AT_CONTRACT_ERR_NOTFOUND (-4)
#define AT_CONTRACT_ERR_UNSUP    (-5)

/* Rust VersionedState equivalent used by contract cache/provider APIs. */
typedef enum {
  AT_CONTRACT_VERSIONED_NEW        = 0,
  AT_CONTRACT_VERSIONED_FETCHED_AT = 1,
  AT_CONTRACT_VERSIONED_UPDATED    = 2
} at_contract_versioned_state_kind_t;

typedef struct {
  at_contract_versioned_state_kind_t kind;
  ulong                              topoheight;
} at_contract_versioned_state_t;

static inline at_contract_versioned_state_t
at_contract_versioned_new( void ) {
  at_contract_versioned_state_t s;
  s.kind = AT_CONTRACT_VERSIONED_NEW;
  s.topoheight = 0UL;
  return s;
}

static inline at_contract_versioned_state_t
at_contract_versioned_fetched_at( ulong topoheight ) {
  at_contract_versioned_state_t s;
  s.kind = AT_CONTRACT_VERSIONED_FETCHED_AT;
  s.topoheight = topoheight;
  return s;
}

static inline at_contract_versioned_state_t
at_contract_versioned_updated( ulong topoheight ) {
  at_contract_versioned_state_t s;
  s.kind = AT_CONTRACT_VERSIONED_UPDATED;
  s.topoheight = topoheight;
  return s;
}

static inline void
at_contract_versioned_mark_updated( at_contract_versioned_state_t * s ) {
  if( !s ) return;
  if( s->kind == AT_CONTRACT_VERSIONED_NEW ) return;
  s->kind = AT_CONTRACT_VERSIONED_UPDATED;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_base_h */
