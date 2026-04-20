#ifndef HEADER_at_tos_at_hard_fork_h
#define HEADER_at_tos_at_hard_fork_h

/* at_hard_fork.h - Hard fork activation and version gating (TOS-aligned) */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_config.h"
#include "at/app/at_daemon_config.h"

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_FORK_COND_BLOCK = 0,
  AT_FORK_COND_TIMESTAMP,
  AT_FORK_COND_TCD,
  AT_FORK_COND_NEVER
} at_fork_condition_kind_t;

typedef struct {
  at_fork_condition_kind_t kind;
  ulong                    value;  /* height, timestamp(ms), or tcd */
} at_fork_condition_t;

typedef struct {
  at_fork_condition_t condition;
  uint                version;              /* Block version */
  char const *        changelog;
  char const *        version_requirement;  /* semver requirement string, may be NULL */
} at_hard_fork_t;

/* Returns 1 if version is allowed at height, 0 if not allowed, -1 on parse error. */
int
at_hard_fork_is_version_allowed_at_height( at_network_t network,
                                           ulong        height,
                                           char const * version );

/* Returns block version active at given height (TOS get_version_at_height parity). */
uint
at_hard_fork_get_block_version_at_height( at_network_t network,
                                          ulong        height );

/* Get all hard forks (for RPC) */
at_hard_fork_t const *
at_hard_fork_get_all( ulong * count_out );

/* Returns 1 when smart contract transactions are enabled at the given height.
   Current rollout: disabled on mainnet, enabled on testnet/stagenet/devnet. */
static inline int
at_hard_fork_is_smart_contracts_enabled_at_height( at_network_t network,
                                                    ulong        height ) {
  (void)height;
  switch( network ) {
    case AT_NETWORK_MAINNET:
      return 0;
    case AT_NETWORK_TESTNET:
    case AT_NETWORK_STAGENET:
    case AT_NETWORK_DEVNET:
      return 1;
    default:
      return 1;
  }
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_hard_fork_h */
